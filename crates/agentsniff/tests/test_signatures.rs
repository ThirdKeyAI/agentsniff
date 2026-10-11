use agentsniff::signatures::{verify_signature, SignatureData, VerificationStatus};

#[test]
fn test_load_embedded_signatures() {
    let data = SignatureData::load_embedded();
    assert!(!data.llm_domains.is_empty());
    assert!(!data.agent_infra_domains.is_empty());
    assert!(!data.domain_suffixes.is_empty());
    assert!(!data.ports.is_empty());
    assert!(data
        .mcp_methods
        .get("protocols")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|protocols| !protocols.is_empty()));
}

#[test]
fn test_embedded_domain_counts() {
    let data = SignatureData::load_embedded();
    assert!(
        data.llm_domains.len() >= 60,
        "Expected 60+ LLM domains, got {}",
        data.llm_domains.len()
    );
    assert!(
        data.agent_infra_domains.len() >= 40,
        "Expected 40+ infra domains, got {}",
        data.agent_infra_domains.len()
    );
    assert!(
        data.domain_suffixes.len() >= 15,
        "Expected 15+ suffixes, got {}",
        data.domain_suffixes.len()
    );
}

#[test]
fn test_embedded_signatures_verified() {
    let data = SignatureData::load_embedded();
    for (name, status) in &data.verification_status {
        assert_eq!(
            *status,
            VerificationStatus::Verified,
            "Signature {} not verified",
            name
        );
    }
    assert!(data.all_verified());
    assert!(!data.has_invalid());
}

#[test]
fn test_ports_parsed_as_integers() {
    let data = SignatureData::load_embedded();
    assert!(data.ports.contains_key(&11434)); // Ollama
    assert!(data.ports.contains_key(&6333)); // Qdrant
    assert!(data.ports[&8080].len() > 1); // Ambiguous ports keep all candidates
    assert_eq!(data.ports[&30000], vec!["sglang"]);
}

#[test]
fn test_tls_fingerprints_have_capture_metadata() {
    let data = SignatureData::load_embedded();
    let fingerprints = data.tls_fingerprints["fingerprints"].as_array().unwrap();
    assert!(!fingerprints.is_empty());
    for fingerprint in fingerprints {
        for field in [
            "library",
            "versions",
            "tls_backend",
            "captured_at",
            "source",
        ] {
            assert!(fingerprint.get(field).is_some(), "missing {field}");
        }
        assert_eq!(fingerprint["confidence"], "low");
    }
}

#[test]
fn test_only_approved_mcp_registry_entries_become_domains() {
    let data = SignatureData::load_embedded();
    assert!(data.verified_mcp_remote_domains().is_empty());
}

#[test]
fn test_tamper_detection() {
    // Create tampered data
    let domains: Vec<String> = vec!["api.openai.com".into(), "evil.example.com".into()];
    let tampered = serde_json::to_value(&domains).unwrap();

    // Load the real sig file
    let sig_json = include_str!("../assets/signatures/llm_domains.sig");
    let sig_data: serde_json::Value = serde_json::from_str(sig_json).unwrap();

    let status = verify_signature(&tampered, &sig_data);
    assert_eq!(status, VerificationStatus::Invalid);
}

#[test]
fn test_sidecar_key_cannot_replace_pinned_trust_anchor() {
    let data_json = include_str!("../assets/signatures/llm_domains.json");
    let data: serde_json::Value = serde_json::from_str(data_json).unwrap();
    let sig_json = include_str!("../assets/signatures/llm_domains.sig");
    let mut sig_data: serde_json::Value = serde_json::from_str(sig_json).unwrap();
    sig_data["public_key_pem"] = serde_json::Value::String(
        "-----BEGIN PUBLIC KEY-----\ninvalid-replacement-key\n-----END PUBLIC KEY-----".into(),
    );

    assert_eq!(
        verify_signature(&data, &sig_data),
        VerificationStatus::Invalid
    );
}
