//! Forward-auth HTTP endpoint for the gate.
//!
//! Proxies call `/check` once per client request. 2xx means allow; the
//! configured challenge (default 401) and block (default 403) statuses mean
//! deny, which is the contract nginx `auth_request`, Traefik ForwardAuth,
//! Caddy `forward_auth` and Envoy `ext_authz` (HTTP service) all share.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, Query, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use super::{truncate, GateAction, GateDecision, GateEngine, RequestFacts};

/// Header the proxy uses to authenticate to the gate. The client's own
/// `Authorization` header is forwarded untouched, so it cannot be used here.
pub const GATE_TOKEN_HEADER: &str = "x-agentsniff-gate-token";
const RECENT_DECISIONS: usize = 1_000;
const LOG_QUEUE: usize = 10_000;

/// An IPv4 or IPv6 network in CIDR notation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

/// Collapse IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

impl IpCidr {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let (addr, prefix) = match text.trim().split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text.trim(), None),
        };
        let network = canonical_ip(
            addr.parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("invalid trusted proxy address {text:?}"))?,
        );
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| anyhow::anyhow!("invalid prefix in {text:?}"))?,
            None => max,
        };
        Ok(Self { network, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, canonical_ip(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

#[derive(Default)]
struct Counters {
    allow: AtomicU64,
    challenge: AtomicU64,
    block: AtomicU64,
    would_challenge: AtomicU64,
    would_block: AtomicU64,
    log_dropped: AtomicU64,
    unresolved_client_ip: AtomicU64,
}

pub struct GateState {
    engine: GateEngine,
    trusted: Vec<IpCidr>,
    recent: Mutex<VecDeque<GateDecision>>,
    counters: Counters,
    log_tx: Option<mpsc::Sender<String>>,
    warned_unresolved: AtomicBool,
}

impl GateState {
    /// Build state; `log_tx` receives one JSON line per logged decision.
    pub fn new(engine: GateEngine, log_tx: Option<mpsc::Sender<String>>) -> anyhow::Result<Self> {
        let trusted = engine
            .config()
            .trusted_proxies
            .iter()
            .map(|p| IpCidr::parse(p))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            engine,
            trusted,
            recent: Mutex::new(VecDeque::with_capacity(RECENT_DECISIONS)),
            counters: Counters::default(),
            log_tx,
            warned_unresolved: AtomicBool::new(false),
        })
    }

    pub fn engine(&self) -> &GateEngine {
        &self.engine
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|cidr| cidr.contains(ip))
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    if name.is_empty() {
        return None;
    }
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// Parse one forwarded address: `ip`, `ip:port`, `[ipv6]` or `[ipv6]:port`,
/// optionally quoted. Proxies such as Azure Application Gateway include ports.
pub fn parse_forwarded_ip(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim().trim_matches('"');
    if let Ok(ip) = hop.parse::<IpAddr>() {
        return Some(canonical_ip(ip));
    }
    if let Some(rest) = hop.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        let port_ok = tail.is_empty()
            || tail
                .strip_prefix(':')
                .is_some_and(|p| p.parse::<u16>().is_ok());
        if !port_ok {
            return None;
        }
        return addr
            .parse::<Ipv6Addr>()
            .ok()
            .map(|ip| canonical_ip(IpAddr::V6(ip)));
    }
    let (addr, port) = hop.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    addr.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// Resolve the client address. Forwarded headers count only when the direct
/// peer is a trusted proxy; X-Forwarded-For is walked right to left, skipping
/// trusted hops, so a client cannot spoof its address by prepending entries.
/// A hop that does not parse stops the walk at the last trusted proxy.
fn client_ip(state: &GateState, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    let peer = canonical_ip(peer);
    if !state.is_trusted(peer) {
        return peer;
    }
    let name = state.engine.config().client_ip_header.to_ascii_lowercase();
    if name.is_empty() {
        return peer;
    }
    // Lossy decoding, so one non-ASCII hop cannot hide the whole header.
    let values: Vec<String> = headers
        .get_all(name.as_str())
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect();
    if name == "x-forwarded-for" {
        let mut candidate = peer;
        for hop in values.iter().flat_map(|v| v.split(',')).rev().take(32) {
            match parse_forwarded_ip(hop) {
                Some(ip) => {
                    candidate = ip;
                    if !state.is_trusted(candidate) {
                        return candidate;
                    }
                }
                None => return candidate,
            }
        }
        return candidate;
    }
    // A proxy that appends instead of replacing leaves the client's own value
    // first, so the last value is the proxy's. Falling back to the proxy
    // address would switch rate limiting off for that request.
    values
        .last()
        .and_then(|value| parse_forwarded_ip(value))
        .unwrap_or(peer)
}

/// Rebuild the original request from forward-auth conventions:
/// X-Forwarded-Method/-Uri/-Host/-Proto (Traefik, Caddy, nginx snippets) and
/// X-Original-Method/-URI (nginx). Envoy appends the original path to the
/// `/check` prefix and keeps the original method and Host.
fn request_facts(
    state: &GateState,
    peer: IpAddr,
    uri: &Uri,
    method: &str,
    headers: &HeaderMap,
) -> RequestFacts {
    let trusted = state.is_trusted(canonical_ip(peer));
    let forwarded = |name: &str| {
        if trusted {
            header_str(headers, name)
        } else {
            None
        }
    };

    let method = forwarded("x-forwarded-method")
        .or_else(|| forwarded("x-original-method"))
        .unwrap_or(method)
        .to_ascii_uppercase();
    let original_uri = forwarded("x-forwarded-uri")
        .or_else(|| forwarded("x-original-uri"))
        .map(str::to_string)
        .unwrap_or_else(|| {
            let path = uri.path().strip_prefix("/check").unwrap_or(uri.path());
            match uri.query() {
                Some(q) => format!("{path}?{q}"),
                None => path.to_string(),
            }
        });
    let (path, query) = match original_uri.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (original_uri.clone(), None),
    };
    let authority = forwarded("x-forwarded-host")
        .or_else(|| header_str(headers, "host"))
        .unwrap_or("")
        .to_string();
    let scheme = forwarded("x-forwarded-proto")
        .unwrap_or("https")
        .to_ascii_lowercase();
    let config = state.engine.config();
    let ja4 =
        forwarded(&config.ja4_header.to_ascii_lowercase()).map(|v| truncate(v, 64).to_string());
    let asn = forwarded(&config.asn_header.to_ascii_lowercase()).and_then(|v| {
        v.trim_start_matches("AS")
            .trim_start_matches("as")
            .parse::<u32>()
            .ok()
    });

    let client_ip = client_ip(state, peer, headers);
    RequestFacts {
        client_ip,
        client_ip_is_proxy: state.is_trusted(client_ip),
        method,
        scheme,
        authority,
        path: if path.is_empty() { "/".into() } else { path },
        query,
        headers: headers.clone(),
        ja4,
        asn,
    }
}

fn authorized(state: &GateState, headers: &HeaderMap) -> bool {
    let expected = &state.engine.config().token;
    if expected.is_empty() {
        return true;
    }
    let mut values = headers.get_all(GATE_TOKEN_HEADER).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => {
            crate::server::constant_time_eq(value.as_bytes(), expected.as_bytes())
        }
        _ => false,
    }
}

/// On the credential-free loopback listener a browser page can reach the read
/// endpoints through DNS rebinding: the origin stays remote while the
/// connection lands on loopback. Browsers always send Host, so a non-loopback
/// authority is refused; local tools that omit Host are unaffected.
fn local_authority_or_token(state: &GateState, headers: &HeaderMap) -> bool {
    if !state.engine.config().token.is_empty() {
        return true;
    }
    let mut hosts = headers.get_all(axum::http::header::HOST).iter();
    match (hosts.next(), hosts.next()) {
        (None, _) => true,
        (Some(host), None) => host
            .to_str()
            .ok()
            .and_then(|host| host.parse::<axum::http::uri::Authority>().ok())
            .is_some_and(|authority| {
                crate::server::is_loopback_host(
                    authority
                        .host()
                        .trim_start_matches('[')
                        .trim_end_matches(']'),
                )
            }),
        _ => false,
    }
}

fn set_header(response: &mut Response, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(name), value);
    }
}

async fn check_handler(
    State(state): State<Arc<GateState>>,
    connect: Option<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    if !authorized(&state, request.headers()) {
        // 407, not 401: proxies read 401 as a client decision, while any
        // other status surfaces as a gate error in their logs (fail closed).
        return (
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "gate authentication required",
        )
            .into_response();
    }
    // A missing peer address is treated as untrusted, so forwarded headers are ignored.
    let peer = connect
        .map(|ConnectInfo(addr)| addr.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let facts = request_facts(
        &state,
        peer,
        request.uri(),
        request.method().as_str(),
        request.headers(),
    );
    if facts.client_ip_is_proxy {
        state
            .counters
            .unresolved_client_ip
            .fetch_add(1, Ordering::Relaxed);
        if !state.warned_unresolved.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "gate request from trusted proxy {} carried no client address in {}; \
                 rate limits are skipped for such requests. Set the header at the proxy.",
                facts.client_ip,
                config_header(&state)
            );
        }
    }
    let decision = state.engine.evaluate(&facts);
    record(&state, &decision);

    let config = state.engine.config();
    let status = match decision.action {
        GateAction::Allow => StatusCode::OK,
        GateAction::Challenge => {
            StatusCode::from_u16(config.challenge_status).unwrap_or(StatusCode::UNAUTHORIZED)
        }
        GateAction::Block => {
            StatusCode::from_u16(config.block_status).unwrap_or(StatusCode::FORBIDDEN)
        }
    };
    let mut response = (status, decision.action.as_str()).into_response();
    set_header(
        &mut response,
        "x-agentsniff-decision",
        decision.action.as_str(),
    );
    set_header(
        &mut response,
        "x-agentsniff-request-id",
        &decision.request_id,
    );
    // Proxies hand a denial's headers to the client. Keep the detail for the
    // upstream application (allow) and the decision log, not for an evader.
    if decision.action != GateAction::Allow && !config.deny_details {
        return response;
    }
    set_header(
        &mut response,
        "x-agentsniff-would-decision",
        decision.would_action.as_str(),
    );
    set_header(
        &mut response,
        "x-agentsniff-score",
        &format!("{:.3}", decision.score),
    );
    if let Some(agent) = &decision.agent {
        set_header(&mut response, "x-agentsniff-agent", &agent.id);
        set_header(
            &mut response,
            "x-agentsniff-assurance",
            match agent.assurance {
                super::Assurance::TrustedVerified => "trusted_verified",
                super::Assurance::SelfDeclared => "self_declared",
                super::Assurance::Suspected => "suspected",
            },
        );
    }
    let reasons: Vec<&str> = decision.signals.iter().map(|s| s.id).collect();
    if !reasons.is_empty() {
        set_header(&mut response, "x-agentsniff-reasons", &reasons.join(","));
    }
    response
}

fn config_header(state: &GateState) -> &str {
    &state.engine.config().client_ip_header
}

fn record(state: &GateState, decision: &GateDecision) {
    let counter = match decision.action {
        GateAction::Allow => &state.counters.allow,
        GateAction::Challenge => &state.counters.challenge,
        GateAction::Block => &state.counters.block,
    };
    counter.fetch_add(1, Ordering::Relaxed);
    match decision.would_action {
        GateAction::Challenge => state
            .counters
            .would_challenge
            .fetch_add(1, Ordering::Relaxed),
        GateAction::Block => state.counters.would_block.fetch_add(1, Ordering::Relaxed),
        GateAction::Allow => 0,
    };

    let notable = decision.would_action != GateAction::Allow || decision.agent.is_some();
    if !notable && !state.engine.config().log_allows {
        return;
    }
    if let Ok(mut recent) = state.recent.lock() {
        if recent.len() >= RECENT_DECISIONS {
            recent.pop_front();
        }
        recent.push_back(decision.clone());
    }
    if let Some(tx) = &state.log_tx {
        if let Ok(line) = serde_json::to_string(decision) {
            if tx.try_send(line).is_err() {
                state.counters.log_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Deserialize)]
struct DecisionsQuery {
    limit: Option<usize>,
}

async fn decisions_handler(
    State(state): State<Arc<GateState>>,
    Query(query): Query<DecisionsQuery>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "gate authentication required").into_response();
    }
    if !local_authority_or_token(&state, &headers) {
        return (StatusCode::FORBIDDEN, "unexpected host").into_response();
    }
    let limit = query.limit.unwrap_or(100).min(RECENT_DECISIONS);
    let recent: Vec<GateDecision> = state
        .recent
        .lock()
        .map(|r| r.iter().rev().take(limit).cloned().collect())
        .unwrap_or_default();
    Json(recent).into_response()
}

async fn stats_handler(State(state): State<Arc<GateState>>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "gate authentication required").into_response();
    }
    if !local_authority_or_token(&state, &headers) {
        return (StatusCode::FORBIDDEN, "unexpected host").into_response();
    }
    let c = &state.counters;
    let engine = &state.engine;
    Json(serde_json::json!({
        "mode": engine.config().mode,
        "decisions": {
            "allow": c.allow.load(Ordering::Relaxed),
            "challenge": c.challenge.load(Ordering::Relaxed),
            "block": c.block.load(Ordering::Relaxed),
        },
        "would": {
            "challenge": c.would_challenge.load(Ordering::Relaxed),
            "block": c.would_block.load(Ordering::Relaxed),
        },
        "log_dropped": c.log_dropped.load(Ordering::Relaxed),
        "unresolved_client_ip": c.unresolved_client_ip.load(Ordering::Relaxed),
        "catalog_agents": engine.catalog().len(),
        "trusted_keys": engine.trusted_key_count(),
    }))
    .into_response()
}

async fn health_handler() -> &'static str {
    "ok"
}

pub fn create_gate_router(state: Arc<GateState>) -> Router {
    Router::new()
        .route("/healthz", get(health_handler))
        .route("/check", any(check_handler))
        // Envoy sends `/check/` for a request to `/`.
        .route("/check/", any(check_handler))
        .route("/check/*rest", any(check_handler))
        .route("/decisions", get(decisions_handler))
        .route("/stats", get(stats_handler))
        .with_state(state)
}

/// Write decision lines to stdout or a file without blocking request handling.
pub fn spawn_decision_logger(destination: &str) -> anyhow::Result<Option<mpsc::Sender<String>>> {
    if destination.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    let (tx, mut rx) = mpsc::channel::<String>(LOG_QUEUE);
    let path = (!destination.is_empty() && destination != "-").then(|| destination.to_string());
    if let Some(path) = &path {
        // Fail at startup, not on the first decision.
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
    }
    tokio::spawn(async move {
        let mut file = match &path {
            Some(path) => match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
            {
                Ok(f) => Some(f),
                Err(e) => {
                    tracing::error!("cannot open gate decision log: {e}");
                    return;
                }
            },
            None => None,
        };
        let mut stdout = tokio::io::stdout();
        while let Some(mut line) = rx.recv().await {
            line.push('\n');
            let result = match file.as_mut() {
                Some(f) => f.write_all(line.as_bytes()).await,
                None => stdout.write_all(line.as_bytes()).await,
            };
            if let Err(e) = result {
                tracing::error!("gate decision log write failed: {e}");
            }
        }
    });
    Ok(Some(tx))
}

/// Run the gate until the process is stopped.
/// IP literals (including IPv6, which needs brackets in `host:port` form) bind
/// directly; hostnames go through the system resolver.
fn bind_addr(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address for {host}"))
}

pub async fn run_gate(engine: GateEngine) -> anyhow::Result<()> {
    let config = engine.config().clone();
    let log_tx = spawn_decision_logger(&config.decision_log)?;
    let state = Arc::new(GateState::new(engine, log_tx)?);
    let app = create_gate_router(state);
    let addr = bind_addr(&config.host, config.port)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("AgentSniff gate listening on {}", addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_literal_binds_with_brackets() {
        assert_eq!(bind_addr("::1", 9091).unwrap().to_string(), "[::1]:9091");
        assert_eq!(
            bind_addr("127.0.0.1", 9091).unwrap().to_string(),
            "127.0.0.1:9091"
        );
    }

    #[test]
    fn cidr_matching() {
        let v4 = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(v4.contains("10.1.2.3".parse().unwrap()));
        assert!(!v4.contains("11.0.0.1".parse().unwrap()));
        assert!(v4.contains("::ffff:10.0.0.1".parse().unwrap()));
        let host = IpCidr::parse("127.0.0.1").unwrap();
        assert!(host.contains("127.0.0.1".parse().unwrap()));
        assert!(!host.contains("127.0.0.2".parse().unwrap()));
        let v6 = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        assert!(IpCidr::parse("10.0.0.0/33").is_err());
        assert!(IpCidr::parse("nope").is_err());
        assert!(IpCidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn forwarded_hop_forms() {
        let ip = |s: &str| parse_forwarded_ip(s).map(|ip| ip.to_string());
        assert_eq!(ip(" 203.0.113.5 ").as_deref(), Some("203.0.113.5"));
        assert_eq!(ip("203.0.113.5:4711").as_deref(), Some("203.0.113.5"));
        assert_eq!(ip("[2001:db8::1]:443").as_deref(), Some("2001:db8::1"));
        assert_eq!(ip("[2001:db8::1]").as_deref(), Some("2001:db8::1"));
        assert_eq!(ip("\"[2001:db8::1]:443\"").as_deref(), Some("2001:db8::1"));
        assert_eq!(ip("2001:db8::1").as_deref(), Some("2001:db8::1"));
        assert_eq!(ip("::ffff:198.51.100.1").as_deref(), Some("198.51.100.1"));
        assert_eq!(ip("unknown"), None);
        assert_eq!(ip("203.0.113.5:http"), None);
        assert_eq!(ip("[2001:db8::1]junk"), None);
    }
}
