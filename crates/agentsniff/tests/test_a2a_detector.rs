use std::collections::HashMap;

use agentsniff::config::ScanConfig;
use agentsniff::detectors::a2a_detector::{
    validate_agent_card, A2aDetector, AgentCardSignatureStatus,
};
use agentsniff::detectors::Detector;
use agentsniff::models::DetectorType;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{EncodePublicKey, LineEnding};

fn card() -> serde_json::Value {
    serde_json::json!({
        "name": "Test Agent",
        "description": "A local test agent",
        "version": "1.0.0",
        "capabilities": {},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [],
        "supportedInterfaces": [{
            "url": "https://agent.example/a2a",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0"
        }]
    })
}

#[test]
fn test_a2a_detector_name() {
    let detector = A2aDetector::new(&ScanConfig::default());
    assert_eq!(detector.name(), "a2a_detector");
    assert_eq!(detector.detector_type(), DetectorType::A2aDetector);
}

#[test]
fn test_unsigned_card_is_discovery_not_verified_identity() {
    let validation = validate_agent_card(&card(), &HashMap::new()).unwrap();
    assert_eq!(
        validation.signature_status,
        AgentCardSignatureStatus::Unsigned
    );
}

#[test]
fn test_card_requires_full_a2a_shape() {
    let incomplete = serde_json::json!({"name": "not enough"});
    assert!(validate_agent_card(&incomplete, &HashMap::new()).is_none());
}

#[test]
fn test_trusted_es256_card_signature_is_verified() {
    let signing_key = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
    let public_key = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"alg":"ES256","kid":"test-key"}"#);
    let mut signed_card = card();
    let canonical = serde_json::to_string(&signed_card).unwrap();
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonical.as_bytes());
    let signing_input = format!("{protected}.{payload}");
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    signed_card["signatures"] = serde_json::json!([{
        "protected": protected,
        "signature": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }]);

    let trusted = HashMap::from([("test-key".to_string(), public_key)]);
    let validation = validate_agent_card(&signed_card, &trusted).unwrap();
    assert_eq!(
        validation.signature_status,
        AgentCardSignatureStatus::TrustedVerified {
            kid: "test-key".into()
        }
    );
}

#[test]
fn test_self_asserted_signature_is_not_trusted() {
    let mut signed_card = card();
    signed_card["signatures"] = serde_json::json!([{
        "protected": base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"ES256","kid":"unknown"}"#),
        "signature": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64])
    }]);
    let validation = validate_agent_card(&signed_card, &HashMap::new()).unwrap();
    assert_eq!(
        validation.signature_status,
        AgentCardSignatureStatus::PresentButUntrusted
    );
}
