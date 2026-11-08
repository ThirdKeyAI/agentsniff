#![no_main]
//! Web Bot Auth (RFC 9421 over Ed25519) verification against a pinned key:
//! arbitrary headers and request lines must never panic, and must never
//! verify without a real signature.

use agentsniff_gate::webbotauth::{
    declared_signature_agent, origin_of, OkpJwk, SignedRequest, TrustedAgentKey, WebBotAuthConfig,
    WebBotAuthOutcome, WebBotAuthVerifier,
};
use arbitrary::Arbitrary;
use http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// RFC 9421 Appendix B.1.4 test-key-ed25519 public key.
const TEST_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";

const NAMES: &[&str] = &[
    "signature",
    "signature-input",
    "signature-agent",
    "content-digest",
    "user-agent",
    "host",
];

#[derive(Arbitrary, Debug)]
struct Input {
    method: String,
    scheme: String,
    authority: String,
    path: String,
    query: Option<String>,
    now: i64,
    headers: Vec<(u8, Option<String>, Vec<u8>)>,
}

fn verifier() -> &'static WebBotAuthVerifier {
    static V: OnceLock<WebBotAuthVerifier> = OnceLock::new();
    V.get_or_init(|| {
        WebBotAuthVerifier::new(WebBotAuthConfig {
            trusted_keys: vec![TrustedAgentKey {
                agent_id: "fuzz_agent".into(),
                jwk: OkpJwk {
                    kty: "OKP".into(),
                    crv: "Ed25519".into(),
                    x: TEST_X.into(),
                },
                ..Default::default()
            }],
            ..Default::default()
        })
        .expect("verifier config")
    })
}

fuzz_target!(|input: Input| {
    let mut headers = HeaderMap::new();
    for (pick, name, value) in &input.headers {
        let name = match name {
            Some(n) => HeaderName::from_bytes(n.as_bytes()).ok(),
            None => Some(HeaderName::from_static(NAMES[*pick as usize % NAMES.len()])),
        };
        let (Some(name), Ok(value)) = (name, HeaderValue::from_bytes(value)) else {
            continue;
        };
        headers.append(name, value);
    }
    let _ = declared_signature_agent(&headers);
    let _ = origin_of(&input.authority);
    let request = SignedRequest {
        method: &input.method,
        scheme: &input.scheme,
        authority: &input.authority,
        path: &input.path,
        query: input.query.as_deref(),
        headers: &headers,
    };
    let outcome = verifier().verify(&request, input.now);
    assert!(
        !matches!(outcome, WebBotAuthOutcome::Verified { .. }),
        "fuzzer forged a verified signature: {outcome:?}"
    );
});
