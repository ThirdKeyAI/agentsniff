use agentpin::credential::issue_credential;
use agentpin::crypto;
use agentpin::delegation::create_attestation;
use agentpin::discovery::build_discovery_document;
use agentpin::jwk::verifying_key_to_jwk;
use agentpin::pinning::KeyPinStore;
use agentpin::revocation::{add_revoked_credential, build_revocation_document};
use agentpin::types::bundle::TrustBundle;
use agentpin::types::capability::Capability;
use agentpin::types::constraint::Constraints;
use agentpin::types::credential::DelegationRole;
use agentpin::types::discovery::{AgentDeclaration, AgentStatus, EntityType};
use agentpin::types::revocation::RevocationReason;
use agentsniff::agentpin::{verify_credential_from_bundle, AgentpinVerificationPolicy};
use chrono::Utc;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn make_agent(domain: &str, name: &str, ttl: u64) -> AgentDeclaration {
    AgentDeclaration {
        agent_id: format!("urn:agentpin:{domain}:{name}"),
        agent_type: None,
        name: name.to_string(),
        description: Some("AgentSniff verification fixture".to_string()),
        version: Some("1.0.0".to_string()),
        capabilities: vec![Capability::from("read:data")],
        constraints: None,
        maker_attestation: None,
        credential_ttl_max: Some(ttl),
        status: AgentStatus::Active,
        directory_listing: Some(false),
    }
}

fn basic_fixture(ttl: u64, credential_ttl: u64) -> (String, TrustBundle) {
    fixture_with_capabilities(ttl, credential_ttl, vec![Capability::from("read:data")])
}

fn fixture_with_capabilities(
    ttl: u64,
    credential_ttl: u64,
    capabilities: Vec<Capability>,
) -> (String, TrustBundle) {
    let domain = "example.com";
    let key_pair = crypto::generate_key_pair().unwrap();
    let signing_key = crypto::load_signing_key(&key_pair.private_key_pem).unwrap();
    let verifying_key = crypto::load_verifying_key(&key_pair.public_key_pem).unwrap();
    let kid = "example-2026-01";
    let mut agent = make_agent(domain, "scanner", ttl);
    agent.capabilities = capabilities.clone();
    let discovery = build_discovery_document(
        domain,
        EntityType::Maker,
        vec![verifying_key_to_jwk(&verifying_key, kid)],
        vec![agent.clone()],
        1,
        &Utc::now().to_rfc3339(),
    );
    let credential = issue_credential(
        &signing_key,
        kid,
        domain,
        &agent.agent_id,
        Some("verifier.example"),
        capabilities,
        None,
        None,
        credential_ttl,
    )
    .unwrap();
    let bundle = TrustBundle {
        agentpin_bundle_version: "0.1".to_string(),
        created_at: Utc::now().to_rfc3339(),
        documents: vec![discovery],
        revocations: vec![build_revocation_document(domain)],
    };
    (credential, bundle)
}

#[test]
fn valid_credential_is_trusted_verified() {
    let (credential, mut bundle) = basic_fixture(3600, 3600);
    bundle.documents[0].agents[0].constraints = Some(Constraints {
        allowed_domains: Some(vec!["verifier.example".to_string()]),
        ..Constraints::default()
    });
    let mut pins = KeyPinStore::new();
    let report = verify_credential_from_bundle(
        &credential,
        &bundle,
        &mut pins,
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );

    assert!(report.valid, "{report:?}");
    assert_eq!(report.identity_assurance, "trusted_verified");
    assert!(report.signature_verified);
    assert!(report.revocation_checked);
    assert!(report.delegation_verified);
    assert!(report.warnings.is_empty());
    assert!(report.discovery_constraints.is_some());
    assert!(pins.get_domain("example.com").is_some());
}

#[test]
fn invalid_signature_is_rejected_without_poisoning_pins() {
    let (credential, bundle) = basic_fixture(3600, 3600);
    let mut bytes = credential.into_bytes();
    let last = bytes.last_mut().unwrap();
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();
    let mut pins = KeyPinStore::new();
    let report = verify_credential_from_bundle(
        &tampered,
        &bundle,
        &mut pins,
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );

    assert!(!report.valid);
    assert_eq!(report.error_code.as_deref(), Some("SIGNATURE_INVALID"));
    assert!(pins.get_domain("example.com").is_none());
}

#[test]
fn missing_revocation_document_fails_closed() {
    let (credential, mut bundle) = basic_fixture(3600, 3600);
    bundle.revocations.clear();
    let report = verify_credential_from_bundle(
        &credential,
        &bundle,
        &mut KeyPinStore::new(),
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );

    assert!(!report.valid);
    assert_eq!(report.error_code.as_deref(), Some("DISCOVERY_FETCH_FAILED"));
}

#[test]
fn credential_lifetime_must_respect_agent_declaration() {
    let (credential, bundle) = basic_fixture(60, 120);
    let report = verify_credential_from_bundle(
        &credential,
        &bundle,
        &mut KeyPinStore::new(),
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );

    assert!(!report.valid);
    assert_eq!(report.error_code.as_deref(), Some("CREDENTIAL_EXPIRED"));
}

#[test]
fn lifetime_arithmetic_overflow_is_rejected() {
    let (credential, bundle) = basic_fixture(3600, 3600);
    let (header, mut payload, _) = agentpin::jwt::decode_jwt_unverified(&credential).unwrap();
    payload.iat = i64::MIN;
    payload.exp = i64::MAX;

    let key_pair = crypto::generate_key_pair().unwrap();
    let signing_key = crypto::load_signing_key(&key_pair.private_key_pem).unwrap();
    let overflowed = agentpin::jwt::encode_jwt(&header, &payload, &signing_key).unwrap();
    let report = verify_credential_from_bundle(
        &overflowed,
        &bundle,
        &mut KeyPinStore::new(),
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );

    assert!(!report.valid);
    assert_eq!(report.error_code.as_deref(), Some("CREDENTIAL_EXPIRED"));
}

#[test]
fn expired_signing_key_is_rejected_but_unrelated_retired_key_is_allowed() {
    let (credential, mut bundle) = basic_fixture(3600, 3600);
    let mut retired_key = bundle.documents[0].public_keys[0].clone();
    retired_key.kid = "retired-2025-01".to_string();
    retired_key.exp = Some("1970-01-01T00:00:00Z".to_string());
    bundle.documents[0].public_keys.push(retired_key);

    let accepted = verify_credential_from_bundle(
        &credential,
        &bundle,
        &mut KeyPinStore::new(),
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );
    assert!(accepted.valid, "{accepted:?}");

    bundle.documents[0].public_keys[0].exp = Some("1970-01-01T00:00:00Z".to_string());
    let rejected = verify_credential_from_bundle(
        &credential,
        &bundle,
        &mut KeyPinStore::new(),
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );
    assert!(!rejected.valid);
    assert_eq!(rejected.error_code.as_deref(), Some("KEY_EXPIRED"));
}

#[test]
fn tofu_rejects_unannounced_key_changes_without_replacing_the_pin() {
    let (credential, bundle) = basic_fixture(3600, 3600);
    let mut pins = KeyPinStore::new();
    let first = verify_credential_from_bundle(
        &credential,
        &bundle,
        &mut pins,
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );
    assert!(first.valid, "{first:?}");
    let pins_before = pins.to_json().unwrap();

    let (replacement_credential, replacement_bundle) = basic_fixture(3600, 3600);
    let replacement = verify_credential_from_bundle(
        &replacement_credential,
        &replacement_bundle,
        &mut pins,
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );
    assert!(!replacement.valid);
    assert_eq!(replacement.error_code.as_deref(), Some("KEY_PIN_MISMATCH"));
    assert_eq!(pins.to_json().unwrap(), pins_before);
}

#[test]
fn preannounced_rotation_keys_are_pinned_on_first_use() {
    let domain = "example.com";
    let first_pair = crypto::generate_key_pair().unwrap();
    let second_pair = crypto::generate_key_pair().unwrap();
    let first_signing = crypto::load_signing_key(&first_pair.private_key_pem).unwrap();
    let second_signing = crypto::load_signing_key(&second_pair.private_key_pem).unwrap();
    let first_verifying = crypto::load_verifying_key(&first_pair.public_key_pem).unwrap();
    let second_verifying = crypto::load_verifying_key(&second_pair.public_key_pem).unwrap();
    let agent = make_agent(domain, "scanner", 3600);
    let capabilities = vec![Capability::from("read:data")];
    let first_credential = issue_credential(
        &first_signing,
        "example-2026-01",
        domain,
        &agent.agent_id,
        Some("verifier.example"),
        capabilities.clone(),
        None,
        None,
        3600,
    )
    .unwrap();
    let second_credential = issue_credential(
        &second_signing,
        "example-2026-02",
        domain,
        &agent.agent_id,
        Some("verifier.example"),
        capabilities,
        None,
        None,
        3600,
    )
    .unwrap();
    let bundle = TrustBundle {
        agentpin_bundle_version: "0.1".to_string(),
        created_at: Utc::now().to_rfc3339(),
        documents: vec![build_discovery_document(
            domain,
            EntityType::Maker,
            vec![
                verifying_key_to_jwk(&first_verifying, "example-2026-01"),
                verifying_key_to_jwk(&second_verifying, "example-2026-02"),
            ],
            vec![agent],
            1,
            &Utc::now().to_rfc3339(),
        )],
        revocations: vec![build_revocation_document(domain)],
    };
    let mut pins = KeyPinStore::new();

    let first = verify_credential_from_bundle(
        &first_credential,
        &bundle,
        &mut pins,
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );
    assert!(first.valid, "{first:?}");
    assert_eq!(pins.get_domain(domain).unwrap().pinned_keys.len(), 2);

    let second = verify_credential_from_bundle(
        &second_credential,
        &bundle,
        &mut pins,
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );
    assert!(second.valid, "{second:?}");
}

#[test]
fn current_capability_taxonomy_accepts_delete_and_rejects_empty_resources() {
    let (delete_credential, delete_bundle) =
        fixture_with_capabilities(3600, 3600, vec![Capability::from("delete:report")]);
    let accepted = verify_credential_from_bundle(
        &delete_credential,
        &delete_bundle,
        &mut KeyPinStore::new(),
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );
    assert!(accepted.valid, "{accepted:?}");

    let (empty_credential, empty_bundle) =
        fixture_with_capabilities(3600, 3600, vec![Capability::from("read:")]);
    let rejected = verify_credential_from_bundle(
        &empty_credential,
        &empty_bundle,
        &mut KeyPinStore::new(),
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );
    assert!(!rejected.valid);
    assert_eq!(rejected.error_code.as_deref(), Some("DISCOVERY_INVALID"));
}

#[test]
fn revoked_credential_is_rejected() {
    let (credential, mut bundle) = basic_fixture(3600, 3600);
    let (_, payload, _) = agentpin::jwt::decode_jwt_unverified(&credential).unwrap();
    add_revoked_credential(
        &mut bundle.revocations[0],
        &payload.jti,
        RevocationReason::KeyCompromise,
    );
    let report = verify_credential_from_bundle(
        &credential,
        &bundle,
        &mut KeyPinStore::new(),
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );

    assert!(!report.valid);
    assert_eq!(report.error_code.as_deref(), Some("CREDENTIAL_REVOKED"));
}

#[test]
fn delegation_chain_is_cryptographically_verified() {
    let maker_domain = "maker.example";
    let deployer_domain = "deployer.example";
    let maker_keys = crypto::generate_key_pair().unwrap();
    let deployer_keys = crypto::generate_key_pair().unwrap();
    let maker_signing = crypto::load_signing_key(&maker_keys.private_key_pem).unwrap();
    let deployer_signing = crypto::load_signing_key(&deployer_keys.private_key_pem).unwrap();
    let maker_verifying = crypto::load_verifying_key(&maker_keys.public_key_pem).unwrap();
    let deployer_verifying = crypto::load_verifying_key(&deployer_keys.public_key_pem).unwrap();
    let maker_agent = make_agent(maker_domain, "agent-type", 3600);
    let mut deployer_agent = make_agent(deployer_domain, "instance", 3600);
    deployer_agent.agent_type = Some(maker_agent.agent_id.clone());
    deployer_agent.maker_attestation = Some("represented-by-credential-chain".to_string());
    let capabilities = vec![Capability::from("read:data")];
    let attestation = create_attestation(
        &maker_signing,
        "maker-2026-01",
        maker_domain,
        DelegationRole::Maker,
        &maker_agent.agent_id,
        deployer_domain,
        &deployer_agent.agent_id,
        &capabilities,
    )
    .unwrap();
    let credential = issue_credential(
        &deployer_signing,
        "deployer-2026-01",
        deployer_domain,
        &deployer_agent.agent_id,
        Some("verifier.example"),
        capabilities,
        None,
        Some(vec![attestation]),
        3600,
    )
    .unwrap();
    let now = Utc::now().to_rfc3339();
    let maker_discovery = build_discovery_document(
        maker_domain,
        EntityType::Maker,
        vec![verifying_key_to_jwk(&maker_verifying, "maker-2026-01")],
        vec![maker_agent],
        1,
        &now,
    );
    let deployer_discovery = build_discovery_document(
        deployer_domain,
        EntityType::Deployer,
        vec![verifying_key_to_jwk(
            &deployer_verifying,
            "deployer-2026-01",
        )],
        vec![deployer_agent],
        1,
        &now,
    );
    let bundle = TrustBundle {
        agentpin_bundle_version: "0.1".to_string(),
        created_at: now,
        documents: vec![maker_discovery, deployer_discovery],
        revocations: vec![
            build_revocation_document(maker_domain),
            build_revocation_document(deployer_domain),
        ],
    };

    let report = verify_credential_from_bundle(
        &credential,
        &bundle,
        &mut KeyPinStore::new(),
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );
    assert!(report.valid, "{report:?}");
    assert_eq!(report.delegation_chain.len(), 1);
    assert!(report.delegation_chain[0].verified);
    assert!(report.warnings.is_empty());

    let mut mismatched_bundle = bundle.clone();
    mismatched_bundle.documents[1].agents[0].agent_type =
        Some("urn:agentpin:maker.example:different-agent-type".to_string());
    let mismatched = verify_credential_from_bundle(
        &credential,
        &mismatched_bundle,
        &mut KeyPinStore::new(),
        Some("verifier.example"),
        &AgentpinVerificationPolicy::default(),
    );
    assert!(!mismatched.valid);
    assert_eq!(mismatched.error_code.as_deref(), Some("DELEGATION_INVALID"));
}

#[test]
fn cli_verifies_credential_and_persists_pins_without_putting_the_jwt_in_argv() {
    let (credential, bundle) = basic_fixture(3600, 3600);
    let unique = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_dir = std::env::temp_dir().join(format!(
        "agentsniff-agentpin-cli-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let credential_path = temp_dir.join("credential.jwt");
    let bundle_path = temp_dir.join("bundle.json");
    std::fs::write(&credential_path, credential).unwrap();
    std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agentsniff"))
        .current_dir(&temp_dir)
        .args([
            "verify-agentpin",
            "--credential-file",
            credential_path.to_str().unwrap(),
            "--trust-bundle",
            bundle_path.to_str().unwrap(),
            "--pin-store",
            "pins.json",
            "--audience",
            "verifier.example",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(report["identity_assurance"], "trusted_verified");
    assert!(temp_dir.join("pins.json").is_file());

    std::fs::remove_dir_all(temp_dir).unwrap();
}
