use agentsniff::signatures::{verify_signature, SignatureData, VerificationStatus};

#[test]
fn test_load_embedded_signatures() {
    let data = SignatureData::load_embedded();
    assert!(!data.llm_domains.is_empty());
    assert!(!data.agent_infra_domains.is_empty());
    assert!(!data.domain_suffixes.is_empty());
    assert!(!data.ports.is_empty());
    assert!(!data.mcp_methods.is_empty());
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
