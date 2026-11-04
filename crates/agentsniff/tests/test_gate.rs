use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use agentsniff::gate::catalog::{AgentCatalog, AgentEntry};
use agentsniff::gate::server::{create_gate_router, GateState};
use agentsniff::gate::webbotauth::{signature_base, OkpJwk, SignedRequest, TrustedAgentKey};
use agentsniff::gate::{
    sfv, Assurance, GateAction, GateConfig, GateDecision, GateEngine, GateMode, RequestFacts,
};
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use base64::Engine;
use tokio::time::Instant;
use tower::ServiceExt;

const CHROME_157: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36";
const CHROME_139_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";
const TOKEN: &str = "0123456789abcdef0123456789abcdef-gate";

fn catalog() -> AgentCatalog {
    // The shipped datasets, parsed directly: this also checks that the
    // catalog file itself is well formed before it is signed.
    let agents: serde_json::Value =
        serde_json::from_str(include_str!("../assets/signatures/agent_clients.json")).unwrap();
    let tls: serde_json::Value =
        serde_json::from_str(include_str!("../assets/signatures/tls_fingerprints.json")).unwrap();
    AgentCatalog::from_values(&agents, &tls).unwrap()
}

fn engine(config: GateConfig) -> GateEngine {
    GateEngine::new(config, catalog()).unwrap()
}

fn enforce() -> GateConfig {
    GateConfig {
        mode: GateMode::Enforce,
        ..GateConfig::default()
    }
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn human_headers(ua: &str) -> HeaderMap {
    headers(&[
        ("user-agent", ua),
        ("accept-language", "en-US,en;q=0.9"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-site", "none"),
    ])
}

fn facts(ip: &str, headers: HeaderMap, asn: Option<u32>) -> RequestFacts {
    RequestFacts {
        client_ip: ip.parse().unwrap(),
        method: "GET".into(),
        scheme: "https".into(),
        authority: "bank.example".into(),
        path: "/accounts".into(),
        query: None,
        headers,
        ja4: None,
        asn,
        client_ip_is_proxy: false,
    }
}

fn decide(engine: &GateEngine, facts: &RequestFacts) -> GateDecision {
    engine.evaluate_at(facts, 1_800_000_000, Instant::now())
}

fn signal_ids(decision: &GateDecision) -> Vec<&'static str> {
    decision.signals.iter().map(|s| s.id).collect()
}

#[test]
fn shipped_catalog_names_muse_and_grok() {
    let catalog = catalog();
    assert!(catalog.len() >= 15);
    assert!(catalog.get("meta_muse").is_some());
    assert!(catalog.get("xai_grok_agent").is_some());
    assert_eq!(catalog.chrome_stable_major, Some(157));
    assert_eq!(
        catalog
            .match_signature_agent("https://chatgpt.com")
            .map(|a| a.id.as_str()),
        Some("openai_chatgpt_agent")
    );
}

#[test]
fn self_declared_muse_and_grok_are_blocked() {
    let gate = engine(enforce());
    for (ua, id) in [
        ("muse-agent/1.0", "meta_muse"),
        ("Mozilla/5.0 (compatible; GrokAgent/1.0)", "xai_grok_agent"),
        (
            "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            "openai_crawlers",
        ),
    ] {
        let decision = decide(&gate, &facts("203.0.113.10", human_headers(ua), None));
        let agent = decision.agent.as_ref().expect("attributed");
        assert_eq!(agent.id, id);
        assert_eq!(agent.assurance, Assurance::SelfDeclared);
        assert_eq!(decision.action, GateAction::Block, "{ua}");
    }
}

#[test]
fn monitor_mode_logs_but_allows() {
    let gate = engine(GateConfig::default());
    let decision = decide(
        &gate,
        &facts("203.0.113.10", human_headers("muse-agent/1.0"), None),
    );
    assert_eq!(decision.mode, GateMode::Monitor);
    assert_eq!(decision.action, GateAction::Allow);
    assert_eq!(decision.would_action, GateAction::Block);
}

#[test]
fn spoofed_browser_from_proxy_network_is_blocked() {
    // The pattern reported for Grok fetches: a stale Chrome UA, no browser
    // headers, from a VPN/proxy host (M247).
    let gate = engine(enforce());
    let h = headers(&[("user-agent", CHROME_139_MAC)]);
    let decision = decide(&gate, &facts("84.37.98.193", h, Some(9009)));
    let ids = signal_ids(&decision);
    assert!(
        ids.contains(&"browser_ua_without_browser_headers"),
        "{ids:?}"
    );
    assert!(ids.contains(&"stale_browser_version"), "{ids:?}");
    assert!(ids.contains(&"hosting_network"), "{ids:?}");
    assert!(decision.score >= 0.8, "{}", decision.score);
    assert_eq!(decision.action, GateAction::Block);
    assert!(decision.agent.is_none());
}

#[test]
fn ordinary_browser_is_allowed() {
    let gate = engine(enforce());
    let decision = decide(
        &gate,
        &facts("198.51.100.20", human_headers(CHROME_157), Some(7922)),
    );
    assert_eq!(decision.action, GateAction::Allow);
    assert_eq!(decision.score, 0.0);
    assert!(decision.signals.is_empty(), "{:?}", decision.signals);
}

#[test]
fn browser_from_meta_network_is_suspected_muse() {
    let gate = engine(enforce());
    let decision = decide(
        &gate,
        &facts("198.51.100.30", human_headers(CHROME_157), Some(32934)),
    );
    let agent = decision.agent.as_ref().expect("suspected attribution");
    assert_eq!(agent.id, "meta_muse");
    assert_eq!(agent.assurance, Assurance::Suspected);
    assert_eq!(decision.action, GateAction::Challenge);
}

#[test]
fn automation_client_from_hosting_is_challenged() {
    let gate = engine(enforce());
    let decision = decide(
        &gate,
        &facts(
            "92.112.92.119",
            headers(&[("user-agent", "Go-http-client/1.1")]),
            Some(212238),
        ),
    );
    assert!(signal_ids(&decision).contains(&"automation_client"));
    assert_eq!(decision.action, GateAction::Challenge);
}

#[test]
fn library_tls_behind_browser_user_agent() {
    let gate = engine(enforce());
    let mut f = facts("198.51.100.40", human_headers(CHROME_157), None);
    f.ja4 = Some("t12d3112_4a61687e4686_bf46f62802c6".into());
    let decision = decide(&gate, &f);
    assert!(signal_ids(&decision).contains(&"tls_user_agent_mismatch"));
}

#[test]
fn rapid_traffic_is_blocked_then_penalized() {
    let gate = engine(enforce());
    let start = Instant::now();
    let human = facts("198.51.100.50", human_headers(CHROME_157), None);
    let mut first_block = None;
    for i in 0..30u64 {
        let d = gate.evaluate_at(&human, 1_800_000_000, start + Duration::from_millis(i * 20));
        if d.action == GateAction::Block {
            first_block = Some((i, d));
            break;
        }
    }
    let (index, decision) = first_block.expect("burst should trip");
    assert_eq!(
        index, 20,
        "the 21st request inside one second trips the default limit"
    );
    assert!(signal_ids(&decision).contains(&"burst_velocity"));

    let later = gate.evaluate_at(&human, 1_800_000_000, start + Duration::from_secs(30));
    assert_eq!(later.action, GateAction::Block);
    assert!(signal_ids(&later).contains(&"rate_penalty"));

    let other = facts("198.51.100.51", human_headers(CHROME_157), None);
    assert_eq!(
        gate.evaluate_at(&other, 1_800_000_000, start + Duration::from_secs(30))
            .action,
        GateAction::Allow
    );
}

fn signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
}

fn pinned_chatgpt_key() -> TrustedAgentKey {
    TrustedAgentKey {
        agent_id: "openai_chatgpt_agent".into(),
        keyid: String::new(),
        jwk: OkpJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signing_key().verifying_key().to_bytes()),
        },
        signature_agent: "https://chatgpt.com".into(),
    }
}

/// A request signed the way ChatGPT agent signs, with the test key.
fn signed_facts(created: i64, nonce: &str) -> RequestFacts {
    signed_facts_with(created, &format!(r#";nonce="{nonce}""#))
}

fn signed_facts_without_nonce(created: i64) -> RequestFacts {
    signed_facts_with(created, "")
}

fn signed_facts_with(created: i64, nonce_param: &str) -> RequestFacts {
    use ed25519_dalek::Signer;
    let keyid = agentsniff::gate::webbotauth::jwk_thumbprint(&pinned_chatgpt_key().jwk);
    let input = format!(
        r#"sig1=("@authority" "signature-agent";key="agent1");created={created};expires={};keyid="{keyid}";alg="ed25519"{nonce_param};tag="web-bot-auth""#,
        created + 60
    );
    let mut h = human_headers(CHROME_157);
    h.insert(
        "signature-agent",
        HeaderValue::from_static(r#"agent1="https://chatgpt.com""#),
    );
    h.insert("signature-input", HeaderValue::from_str(&input).unwrap());
    let sfv::Member::InnerList(covered) = sfv::parse_dictionary(&input).unwrap().remove(0).1 else {
        panic!("signature input is not an inner list");
    };
    let request = SignedRequest {
        method: "GET",
        scheme: "https",
        authority: "bank.example",
        path: "/accounts",
        query: None,
        headers: &h,
    };
    let base = signature_base(&request, &covered).unwrap();
    let signature = signing_key().sign(base.as_bytes());
    h.insert(
        "signature",
        HeaderValue::from_str(&format!(
            "sig1=:{}:",
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        ))
        .unwrap(),
    );
    facts("198.51.100.60", h, None)
}

#[test]
fn verified_agent_can_be_allowed_but_claims_cannot() {
    let mut config = enforce();
    config.web_bot_auth.trusted_keys = vec![pinned_chatgpt_key()];
    config.allow_verified_agents = vec!["openai_chatgpt_agent".into()];
    let gate = engine(config);

    let now = 1_800_000_000;
    let verified = gate.evaluate_at(&signed_facts(now - 5, "n1"), now, Instant::now());
    let agent = verified.agent.as_ref().unwrap();
    assert_eq!(agent.id, "openai_chatgpt_agent");
    assert_eq!(agent.assurance, Assurance::TrustedVerified);
    assert_eq!(verified.action, GateAction::Allow);

    // Replaying the same signed request is only a claim now.
    let replay = gate.evaluate_at(&signed_facts(now - 5, "n1"), now, Instant::now());
    assert_eq!(
        replay.agent.as_ref().unwrap().assurance,
        Assurance::SelfDeclared
    );
    assert_eq!(replay.action, GateAction::Block);

    // Naming chatgpt.com without a valid signature is a claim, not identity.
    let mut forged = signed_facts(now - 5, "n2");
    forged.authority = "other.example".into();
    let claim = gate.evaluate_at(&forged, now, Instant::now());
    assert_eq!(claim.agent.as_ref().unwrap().id, "openai_chatgpt_agent");
    assert_eq!(
        claim.agent.as_ref().unwrap().assurance,
        Assurance::SelfDeclared
    );
    assert!(signal_ids(&claim).contains(&"web_bot_auth_unverified"));
    assert_eq!(claim.action, GateAction::Block);
}

#[test]
fn policy_overrides_by_kind_and_id() {
    let mut config = enforce();
    config
        .kind_actions
        .insert("crawler".into(), GateAction::Allow);
    config
        .agent_actions
        .insert("anthropic_crawlers".into(), GateAction::Challenge);
    config.custom_agents = vec![AgentEntry {
        id: "acme_agent".into(),
        kind: "user_triggered_agent".into(),
        user_agent_tokens: vec!["AcmeAgent".into()],
        ..AgentEntry::default()
    }];
    let gate = engine(config);
    let action = |ua: &str| decide(&gate, &facts("203.0.113.70", human_headers(ua), None)).action;
    assert_eq!(action("GPTBot/1.2"), GateAction::Allow);
    assert_eq!(action("ClaudeBot/1.0"), GateAction::Challenge);
    assert_eq!(action("AcmeAgent/2.0"), GateAction::Block);
    assert_eq!(action("Claude-User/1.0"), GateAction::Block);
}

#[test]
fn rate_violation_overrides_an_allow_policy() {
    let mut config = enforce();
    config
        .kind_actions
        .insert("crawler".into(), GateAction::Allow);
    config.rate.burst_limit = 2;
    let gate = engine(config);
    let f = facts("203.0.113.80", human_headers("GPTBot/1.2"), None);
    let start = Instant::now();
    let actions: Vec<GateAction> = (0..4)
        .map(|i| {
            gate.evaluate_at(&f, 1_800_000_000, start + Duration::from_millis(i))
                .action
        })
        .collect();
    assert_eq!(actions[0], GateAction::Allow);
    assert_eq!(actions[3], GateAction::Block);
}

#[test]
fn invalid_configs_are_rejected() {
    let bad = |mutate: fn(&mut GateConfig)| {
        let mut config = GateConfig::default();
        mutate(&mut config);
        GateEngine::new(config, catalog()).is_err()
    };
    assert!(bad(|c| c.host = "0.0.0.0".into()));
    assert!(bad(|c| c.token = "short".into()));
    assert!(bad(|c| {
        c.challenge_threshold = 0.9;
        c.block_threshold = 0.5;
    }));
    assert!(bad(|c| {
        c.agent_actions
            .insert("no_such_agent".into(), GateAction::Allow);
    }));
    assert!(bad(
        |c| c.allow_verified_agents = vec!["openai_chatgpt_agent".into()]
    ));
    assert!(bad(|c| {
        c.kind_actions.insert("robot".into(), GateAction::Allow);
    }));
    assert!(bad(|c| c.block_status = 200));
    assert!(bad(|c| c.trusted_proxies = vec!["not-an-ip".into()]));
    assert!(bad(|c| c.rate.action = GateAction::Allow));
    assert!(bad(|c| c.rate.penalty_secs = u64::MAX));
    assert!(bad(|c| c.web_bot_auth.clock_skew_secs = i64::MAX));
    assert!(bad(|c| {
        c.custom_agents = vec![AgentEntry {
            id: agentsniff::gate::UNIDENTIFIED_SIGNED_AGENT.into(),
            kind: "other".into(),
            ..AgentEntry::default()
        }];
    }));
    assert!(bad(|c| {
        c.custom_agents = vec![AgentEntry {
            id: "Bad Id".into(),
            kind: "crawler".into(),
            ..AgentEntry::default()
        }];
    }));
    // Non-loopback with a strong token is fine.
    let mut ok = GateConfig {
        host: "0.0.0.0".into(),
        token: TOKEN.into(),
        ..GateConfig::default()
    };
    ok.rate.burst_limit = 50;
    assert!(GateEngine::new(ok, catalog()).is_ok());
}

#[test]
fn a_claim_never_softens_the_behavior_score() {
    let mut config = enforce();
    config.default_agent_action = GateAction::Challenge;
    config
        .agent_actions
        .insert("meta_muse".into(), GateAction::Block);
    let gate = engine(config);

    // A self-declared Muse stays blocked whatever else it sends.
    let mut muse = human_headers("muse-agent/1.0");
    muse.insert("signature", HeaderValue::from_static("x"));
    let decision = decide(&gate, &facts("203.0.113.90", muse, None));
    assert_eq!(decision.agent.as_ref().unwrap().id, "meta_muse");
    assert_eq!(decision.action, GateAction::Block);

    // A score-blocked bot that adds a bogus Web Bot Auth claim gets the
    // stricter of policy (challenge) and score (block).
    let mut bot = headers(&[("user-agent", CHROME_139_MAC)]);
    bot.insert(
        "signature-input",
        HeaderValue::from_static(r#"sig1=("@authority");tag="web-bot-auth""#),
    );
    bot.insert("signature", HeaderValue::from_static("sig1=:AAAA:"));
    let decision = decide(&gate, &facts("84.37.98.194", bot, Some(9009)));
    assert_eq!(
        decision.agent.as_ref().unwrap().id,
        agentsniff::gate::UNIDENTIFIED_SIGNED_AGENT
    );
    assert!(decision.score >= 0.8, "{}", decision.score);
    assert_eq!(decision.action, GateAction::Block);

    // An allow policy for a claimable name still answers to behavior.
    let mut config = enforce();
    config
        .kind_actions
        .insert("crawler".into(), GateAction::Allow);
    let gate = engine(config);
    let spoof = headers(&[("user-agent", "GPTBot/1.2 python-requests/2.31")]);
    let decision = decide(&gate, &facts("92.112.92.120", spoof, Some(212238)));
    assert_eq!(decision.agent.as_ref().unwrap().id, "openai_crawlers");
    assert_eq!(decision.action, GateAction::Challenge);
}

#[test]
fn api_signature_schemes_are_not_agents() {
    let gate = engine(enforce());
    // PSD2 / draft-cavage request signing from a banking API client.
    let mut h = human_headers(CHROME_157);
    h.insert(
        "signature",
        HeaderValue::from_static(r#"keyId="tpp",algorithm="rsa-sha256",signature="AAAA""#),
    );
    h.insert("digest", HeaderValue::from_static("SHA-256=abc"));
    let decision = decide(&gate, &facts("198.51.100.91", h, None));
    assert!(decision.agent.is_none(), "{:?}", decision.agent);
    assert_eq!(decision.action, GateAction::Allow);
}

#[test]
fn unidentified_signed_agents_have_their_own_policy() {
    let mut config = enforce();
    config.agent_actions.insert(
        agentsniff::gate::UNIDENTIFIED_SIGNED_AGENT.into(),
        GateAction::Challenge,
    );
    let gate = engine(config);
    let mut h = human_headers(CHROME_157);
    h.insert(
        "signature-agent",
        HeaderValue::from_static(r#"a="https://unknown-agent.example""#),
    );
    let decision = decide(&gate, &facts("198.51.100.92", h, None));
    assert_eq!(
        decision.agent.as_ref().unwrap().id,
        agentsniff::gate::UNIDENTIFIED_SIGNED_AGENT
    );
    assert!(signal_ids(&decision).contains(&"unsigned_signature_agent"));
    assert_eq!(decision.action, GateAction::Challenge);
}

#[test]
fn bare_signature_agent_names_a_catalog_agent() {
    let gate = engine(enforce());
    let mut h = human_headers(CHROME_157);
    h.insert(
        "signature-agent",
        HeaderValue::from_static(r#""https://chatgpt.com""#),
    );
    let decision = decide(&gate, &facts("198.51.100.93", h, None));
    let agent = decision.agent.as_ref().unwrap();
    assert_eq!(agent.id, "openai_chatgpt_agent");
    assert_eq!(agent.assurance, Assurance::SelfDeclared);
    assert_eq!(decision.action, GateAction::Block);
}

#[test]
fn ipv6_rotation_inside_a_64_is_one_client() {
    let mut config = enforce();
    config.rate.burst_limit = 5;
    let gate = engine(config);
    let start = Instant::now();
    let mut blocked = false;
    for i in 0..10u64 {
        let ip = format!("2001:db8:aa:bb:{:x}::1", i + 1);
        let d = gate.evaluate_at(
            &facts(&ip, human_headers(CHROME_157), None),
            1_800_000_000,
            start + Duration::from_millis(i),
        );
        blocked |= d.action == GateAction::Block;
    }
    assert!(blocked, "fresh addresses in one /64 must share a counter");
}

#[test]
fn unresolved_client_address_skips_rate_limits() {
    let mut config = enforce();
    config.rate.burst_limit = 1;
    let gate = engine(config);
    let mut f = facts("127.0.0.1", human_headers(CHROME_157), None);
    f.client_ip_is_proxy = true;
    let start = Instant::now();
    for i in 0..5 {
        let d = gate.evaluate_at(&f, 1_800_000_000, start + Duration::from_millis(i));
        assert_eq!(d.action, GateAction::Allow);
        assert!(signal_ids(&d).contains(&"client_ip_unresolved"));
    }
}

#[test]
fn verified_agents_need_a_nonce_by_default() {
    let mut config = enforce();
    config.web_bot_auth.trusted_keys = vec![pinned_chatgpt_key()];
    config.allow_verified_agents = vec!["openai_chatgpt_agent".into()];
    let gate = engine(config);
    let now = 1_800_000_000;
    let decision = gate.evaluate_at(&signed_facts_without_nonce(now - 5), now, Instant::now());
    assert_eq!(
        decision.agent.as_ref().unwrap().assurance,
        Assurance::SelfDeclared
    );
    assert_eq!(decision.action, GateAction::Block);
}

// ── Forward-auth endpoint ───────────────────────────────────────────────

fn router(config: GateConfig, peer: &str) -> axum::Router {
    let state = Arc::new(GateState::new(engine(config), None).unwrap());
    let peer: SocketAddr = format!("{peer}:40000").parse().unwrap();
    create_gate_router(state).layer(MockConnectInfo(peer))
}

fn check(uri: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder().uri(uri);
    for (name, value) in pairs {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).unwrap()
}

fn header<'a>(response: &'a axum::response::Response, name: &str) -> Option<&'a str> {
    response.headers().get(name).and_then(|v| v.to_str().ok())
}

async fn recent(router: &axum::Router, pairs: &[(&str, &str)]) -> Vec<serde_json::Value> {
    let response = router
        .clone()
        .oneshot(check("/decisions?limit=10", pairs))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn endpoint_blocks_in_enforce_mode() {
    let app = router(enforce(), "127.0.0.1");
    let response = app
        .clone()
        .oneshot(check(
            "/check",
            &[
                ("user-agent", "Mozilla/5.0 (compatible; GrokAgent/1.0)"),
                ("x-forwarded-for", "203.0.113.9"),
                ("x-forwarded-uri", "/login?next=%2F"),
                ("x-forwarded-host", "bank.example"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(header(&response, "x-agentsniff-decision"), Some("block"));
    assert!(header(&response, "x-agentsniff-request-id").is_some());
    // Proxies relay a denial's headers to the client: no tuning signal there.
    for name in [
        "x-agentsniff-agent",
        "x-agentsniff-assurance",
        "x-agentsniff-reasons",
        "x-agentsniff-score",
    ] {
        assert!(header(&response, name).is_none(), "{name}");
    }

    let logged = recent(&app, &[]).await;
    assert_eq!(logged[0]["client_ip"], "203.0.113.9");
    assert_eq!(logged[0]["path"], "/login");
    assert_eq!(logged[0]["host"], "bank.example");
    assert_eq!(logged[0]["agent"]["id"], "xai_grok_agent");
}

#[tokio::test]
async fn deny_details_can_be_enabled() {
    let mut config = enforce();
    config.deny_details = true;
    let app = router(config, "127.0.0.1");
    let response = app
        .oneshot(check(
            "/check",
            &[
                ("user-agent", "Mozilla/5.0 (compatible; GrokAgent/1.0)"),
                ("x-forwarded-for", "203.0.113.9"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        header(&response, "x-agentsniff-agent"),
        Some("xai_grok_agent")
    );
    assert_eq!(
        header(&response, "x-agentsniff-assurance"),
        Some("self_declared")
    );
    assert!(header(&response, "x-agentsniff-reasons")
        .unwrap()
        .contains("known_agent_user_agent"));
}

#[tokio::test]
async fn endpoint_monitor_mode_allows_with_would_header() {
    let app = router(GateConfig::default(), "127.0.0.1");
    let response = app
        .oneshot(check("/check", &[("user-agent", "muse-agent/1.0")]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header(&response, "x-agentsniff-decision"), Some("allow"));
    assert_eq!(
        header(&response, "x-agentsniff-would-decision"),
        Some("block")
    );
}

#[tokio::test]
async fn endpoint_challenge_status_is_configurable() {
    let mut config = enforce();
    config.challenge_status = 429;
    config.deny_details = true;
    let app = router(config, "127.0.0.1");
    let response = app
        .oneshot(check(
            "/check",
            &[
                ("user-agent", CHROME_157),
                ("accept-language", "en"),
                ("x-asn", "AS32934"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(header(&response, "x-agentsniff-agent"), Some("meta_muse"));
    assert_eq!(
        header(&response, "x-agentsniff-assurance"),
        Some("suspected")
    );
}

#[tokio::test]
async fn forwarded_headers_from_untrusted_peers_are_ignored() {
    let app = router(enforce(), "198.51.100.7");
    let response = app
        .clone()
        .oneshot(check(
            "/check",
            &[
                ("user-agent", "muse-agent/1.0"),
                ("x-forwarded-for", "10.9.9.9"),
                ("x-forwarded-uri", "/spoofed"),
                ("x-asn", "7922"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let logged = recent(&app, &[]).await;
    assert_eq!(logged[0]["client_ip"], "198.51.100.7");
    assert_eq!(logged[0]["path"], "/");
}

#[tokio::test]
async fn xff_is_walked_past_trusted_hops() {
    let mut config = enforce();
    config.trusted_proxies.push("10.0.0.0/8".into());
    let app = router(config, "127.0.0.1");
    app.clone()
        .oneshot(check(
            "/check",
            &[
                ("user-agent", "muse-agent/1.0"),
                // The leftmost entry is client-controlled and must not win.
                ("x-forwarded-for", "1.1.1.1, 203.0.113.44, 10.0.0.5"),
            ],
        ))
        .await
        .unwrap();
    let logged = recent(&app, &[]).await;
    assert_eq!(logged[0]["client_ip"], "203.0.113.44");
}

#[tokio::test]
async fn xff_hops_with_ports_resolve() {
    let app = router(enforce(), "127.0.0.1");
    app.clone()
        .oneshot(check(
            "/check",
            &[
                ("user-agent", "muse-agent/1.0"),
                ("x-forwarded-for", "203.0.113.45:51234"),
            ],
        ))
        .await
        .unwrap();
    let logged = recent(&app, &[]).await;
    assert_eq!(logged[0]["client_ip"], "203.0.113.45");
}

#[tokio::test]
async fn missing_client_address_skips_rate_limits_and_is_counted() {
    let mut config = enforce();
    config.rate.burst_limit = 1;
    let app = router(config, "127.0.0.1");
    // No X-Forwarded-For: every client would share the proxy's bucket.
    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(check("/check", &human_pairs()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = app.oneshot(check("/stats", &[])).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let stats: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(stats["unresolved_client_ip"], 5);
}

fn human_pairs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("user-agent", CHROME_157),
        ("accept-language", "en-US"),
        ("sec-fetch-mode", "navigate"),
    ]
}

#[tokio::test]
async fn envoy_root_request() {
    let app = router(enforce(), "127.0.0.1");
    let response = app
        .clone()
        .oneshot(check("/check/", &human_pairs()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut pairs = human_pairs();
    pairs[0] = ("user-agent", "GPTBot/1.2");
    app.clone().oneshot(check("/check/", &pairs)).await.unwrap();
    let logged = recent(&app, &[]).await;
    assert_eq!(logged[0]["path"], "/");
}

#[tokio::test]
async fn envoy_style_path_prefix() {
    let app = router(enforce(), "127.0.0.1");
    app.clone()
        .oneshot(check(
            "/check/transfer?amount=10",
            &[("user-agent", "GPTBot/1.2")],
        ))
        .await
        .unwrap();
    let logged = recent(&app, &[]).await;
    assert_eq!(logged[0]["path"], "/transfer");
}

#[tokio::test]
async fn token_is_required_when_configured() {
    let config = GateConfig {
        mode: GateMode::Enforce,
        token: TOKEN.into(),
        ..GateConfig::default()
    };
    let app = router(config, "127.0.0.1");

    let missing = app
        .clone()
        .oneshot(check("/check", &[("user-agent", "muse-agent/1.0")]))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert!(header(&missing, "x-agentsniff-decision").is_none());

    let ok = app
        .clone()
        .oneshot(check(
            "/check",
            &[
                ("user-agent", "muse-agent/1.0"),
                ("x-agentsniff-gate-token", TOKEN),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::FORBIDDEN);

    let decisions = app.clone().oneshot(check("/decisions", &[])).await.unwrap();
    assert_eq!(decisions.status(), StatusCode::UNAUTHORIZED);
    let stats = app.clone().oneshot(check("/stats", &[])).await.unwrap();
    assert_eq!(stats.status(), StatusCode::UNAUTHORIZED);
    let health = app.oneshot(check("/healthz", &[])).await.unwrap();
    assert_eq!(health.status(), StatusCode::OK);
}

#[tokio::test]
async fn stats_count_decisions() {
    let app = router(GateConfig::default(), "127.0.0.1");
    for ua in ["muse-agent/1.0", CHROME_157] {
        app.clone()
            .oneshot(check(
                "/check",
                &[
                    ("user-agent", ua),
                    ("accept-language", "en"),
                    ("sec-fetch-mode", "navigate"),
                ],
            ))
            .await
            .unwrap();
    }
    let response = app.oneshot(check("/stats", &[])).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let stats: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(stats["mode"], "monitor");
    assert_eq!(stats["decisions"]["allow"], 2);
    assert_eq!(stats["would"]["block"], 1);
}

#[test]
fn client_ip_types_round_trip() {
    // IPv4-mapped IPv6 peers are treated as their IPv4 address.
    let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    assert_eq!(
        agentsniff::gate::server::canonical_ip(mapped),
        "127.0.0.1".parse::<IpAddr>().unwrap()
    );
}
