#![no_main]
//! The whole decision path on arbitrary requests: no panic anywhere in
//! header parsing, user-agent matching, scoring, rate tracking, or policy.

use agentsniff_gate::webbotauth::{OkpJwk, TrustedAgentKey};
use agentsniff_gate::{GateConfig, GateEngine, RequestFacts};
use arbitrary::Arbitrary;
use http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;
use std::sync::OnceLock;

const NAMES: &[&str] = &[
    "user-agent",
    "accept-language",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-ch-ua",
    "signature",
    "signature-input",
    "signature-agent",
    "x-forwarded-for",
    "cookie",
];

#[derive(Arbitrary, Debug)]
struct Input {
    ip: [u8; 16],
    ipv4: bool,
    method: String,
    scheme: String,
    authority: String,
    path: String,
    query: Option<String>,
    ja4: Option<String>,
    asn: Option<u32>,
    client_ip_is_proxy: bool,
    headers: Vec<(u8, Option<String>, Vec<u8>)>,
}

fn engine() -> &'static GateEngine {
    static E: OnceLock<GateEngine> = OnceLock::new();
    E.get_or_init(|| {
        let mut config = GateConfig::default();
        config.tripwires.paths.push("/wp-admin/trap.php".into());
        config.web_bot_auth.trusted_keys.push(TrustedAgentKey {
            agent_id: "fuzz_agent".into(),
            jwk: OkpJwk {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs".into(),
            },
            ..Default::default()
        });
        let signatures = agentsniff_signatures::SignatureData::load_embedded();
        GateEngine::from_signatures(config, &signatures).expect("engine")
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
    let client_ip: IpAddr = if input.ipv4 {
        std::net::Ipv4Addr::new(input.ip[0], input.ip[1], input.ip[2], input.ip[3]).into()
    } else {
        std::net::Ipv6Addr::from(input.ip).into()
    };
    let facts = RequestFacts {
        client_ip,
        method: input.method,
        scheme: input.scheme,
        authority: input.authority,
        path: input.path,
        query: input.query,
        headers,
        ja4: input.ja4,
        asn: input.asn,
        client_ip_is_proxy: input.client_ip_is_proxy,
    };
    let decision = engine().evaluate(&facts);
    assert!(
        (0.0..=1.0).contains(&decision.score),
        "score out of range: {}",
        decision.score
    );
});
