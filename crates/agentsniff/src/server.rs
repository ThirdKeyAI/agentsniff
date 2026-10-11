use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::baseline::apply_scan_diff;
use crate::config::ScanConfig;
use crate::ebpf::EbpfChannels;
use crate::models::{DetectedAgent, IdentityAssurance, ScanResult};
use crate::notifier::{send_alerts, Notifier};
use crate::scanner::{resolve_targets, run_scan};
use crate::storage::{SqliteBackend, StorageBackend};

// ─── Embedded dashboard assets ───────────────────────────────────────────────

#[derive(rust_embed::RustEmbed)]
#[folder = "assets/"]
#[include = "index.html"]
struct DashboardAssets;

// ─── Scan status ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ScanStatus {
    Idle,
    Running { scan_id: String },
    Completed { scan_id: String },
    Cancelled { scan_id: String },
}

// ─── SSE events ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SseEvent {
    ScanStarted {
        scan_id: String,
        network: String,
        host_count: usize,
        detectors: Vec<String>,
    },
    AgentDetected {
        agent: Box<DetectedAgent>,
    },
    ScanProgress {
        message: String,
    },
    ScanCompleted {
        scan_id: String,
        agent_count: usize,
        summary: ScanSummary,
    },
    ScanCancelled {
        scan_id: String,
        agent_count: usize,
        summary: ScanSummary,
    },
    ScanError {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_agents: usize,
    pub by_confidence: ConfidenceCounts,
    pub trusted_identities: usize,
    pub invalid_identities: usize,
    pub new_assets: usize,
    pub changed_assets: usize,
    pub removed_assets: usize,
    pub duration_seconds: Option<f64>,
    pub detectors_run: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceCounts {
    pub confirmed: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl ScanSummary {
    pub fn from_result(result: &ScanResult) -> Self {
        let mut counts = ConfidenceCounts {
            confirmed: 0,
            high: 0,
            medium: 0,
            low: 0,
        };
        for agent in &result.agents {
            match agent.confidence_level.as_str() {
                "confirmed" => counts.confirmed += 1,
                "high" => counts.high += 1,
                "medium" => counts.medium += 1,
                _ => counts.low += 1,
            }
        }
        ScanSummary {
            total_agents: result.agents.len(),
            by_confidence: counts,
            trusted_identities: result
                .agents
                .iter()
                .filter(|agent| agent.identity_assurance == IdentityAssurance::TrustedVerified)
                .count(),
            invalid_identities: result
                .agents
                .iter()
                .filter(|agent| agent.identity_assurance == IdentityAssurance::Invalid)
                .count(),
            new_assets: result.diff.new_assets.len(),
            changed_assets: result.diff.changed_assets.len(),
            removed_assets: result.diff.removed_assets.len(),
            duration_seconds: result.duration_seconds(),
            detectors_run: result
                .detectors_run
                .iter()
                .map(|d| format!("{:?}", d).to_lowercase())
                .collect(),
        }
    }
}

// ─── App state ──────────────────────────────────────────────────────────────

pub struct AppState {
    pub config: Mutex<ScanConfig>,
    pub storage: Box<dyn StorageBackend>,
    pub scan_status: Mutex<ScanStatus>,
    pub latest_result: Mutex<Option<ScanResult>>,
    pub notifier: Mutex<Notifier>,
    pub cancel_token: Mutex<Option<CancellationToken>>,
    pub sse_tx: broadcast::Sender<SseEvent>,
    pub ebpf_channels: Arc<EbpfChannels>,
}

// ─── Request / response types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub network: Option<String>,
    pub hosts: Option<Vec<String>>,
    pub detectors: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct ScanStartedResponse {
    scan_id: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct StopResponse {
    status: String,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

// ─── Route handlers ─────────────────────────────────────────────────────────

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Refuse remote API exposure unless a sufficiently strong shared secret is
/// configured. Loopback keeps its credential-free local workflow.
pub fn validate_api_security(config: &ScanConfig) -> anyhow::Result<()> {
    if !config.api_token.is_empty() && config.api_token.len() < 32 {
        anyhow::bail!("api_token must contain at least 32 bytes");
    }
    if !is_loopback_host(&config.api_host) && config.api_token.is_empty() {
        anyhow::bail!(
            "refusing to bind the management API to {} without AGENTSNIFF_API_TOKEN",
            config.api_host
        );
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

fn supplied_api_token(headers: &HeaderMap) -> Option<Vec<u8>> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }

    if let Some(token) = value.strip_prefix("Bearer ") {
        return (!token.is_empty()).then(|| token.as_bytes().to_vec());
    }

    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    (username == "agentsniff").then(|| password.as_bytes().to_vec())
}

fn unauthorized_response() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"AgentSniff\", charset=\"UTF-8\""),
    );
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"AgentSniff\""),
    );
    response
}

async fn require_api_auth(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let expected = state.config.lock().await.api_token.clone();
    if !expected.is_empty()
        && !matches!(
            supplied_api_token(request.headers()),
            Some(supplied) if constant_time_eq(&supplied, expected.as_bytes())
        )
    {
        return unauthorized_response();
    }

    // Loopback may run without a token, and browsers may cache Basic auth.
    // Requiring a non-simple content type on every mutation prevents ordinary
    // cross-origin forms from reaching handlers; hostile script requests are
    // stopped by the browser's failed CORS preflight.
    if matches!(
        *request.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) && !request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|media_type| {
                media_type.trim().eq_ignore_ascii_case("application/json")
            })
        })
    {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/json is required for state-changing requests",
        )
            .into_response();
    }

    next.run(request).await
}

/// Apply detector toggle overrides from a comma-separated list of detector names.
fn apply_detector_filter(config: &mut ScanConfig, detectors_csv: &str) {
    let enabled: Vec<&str> = detectors_csv.split(',').map(|s| s.trim()).collect();
    // Disable all, then re-enable only the listed ones
    config.enable_dns_monitor = false;
    config.enable_port_scanner = false;
    config.enable_agentpin_prober = false;
    config.enable_a2a_detector = false;
    config.enable_mcp_detector = false;
    config.enable_endpoint_prober = false;
    config.enable_tls_fingerprint = false;
    config.enable_traffic_analyzer = false;
    config.enable_sse_detector = false;
    for name in &enabled {
        match *name {
            "dns_monitor" => config.enable_dns_monitor = true,
            "port_scanner" => config.enable_port_scanner = true,
            "agentpin_prober" => config.enable_agentpin_prober = true,
            "a2a_detector" => config.enable_a2a_detector = true,
            "mcp_detector" => config.enable_mcp_detector = true,
            "endpoint_prober" => config.enable_endpoint_prober = true,
            "tls_fingerprint" => config.enable_tls_fingerprint = true,
            "traffic_analyzer" => config.enable_traffic_analyzer = true,
            "sse_detector" => config.enable_sse_detector = true,
            _ => tracing::warn!("Unknown detector: {}", name),
        }
    }
}

/// Collect names of enabled detectors from config.
fn enabled_detector_names(config: &ScanConfig) -> Vec<String> {
    let mut names = Vec::new();
    if config.enable_dns_monitor {
        names.push("dns_monitor".into());
    }
    if config.enable_port_scanner {
        names.push("port_scanner".into());
    }
    if config.enable_agentpin_prober {
        names.push("agentpin_prober".into());
    }
    if config.enable_a2a_detector {
        names.push("a2a_detector".into());
    }
    if config.enable_mcp_detector {
        names.push("mcp_detector".into());
    }
    if config.enable_endpoint_prober {
        names.push("endpoint_prober".into());
    }
    if config.enable_tls_fingerprint {
        names.push("tls_fingerprint".into());
    }
    if config.enable_traffic_analyzer {
        names.push("traffic_analyzer".into());
    }
    if config.enable_sse_detector {
        names.push("sse_detector".into());
    }
    names
}

/// Launch a scan in a background task, sending SSE events for progress.
fn spawn_scan(
    state: Arc<AppState>,
    scan_config: ScanConfig,
    scan_id: String,
    cancel_token: CancellationToken,
) {
    let sse_tx = state.sse_tx.clone();
    let cancel_clone = cancel_token.clone();

    // Resolve targets and enabled detectors for the start event
    let host_count = resolve_targets(&scan_config).map(|t| t.len()).unwrap_or(0);
    let detector_names = enabled_detector_names(&scan_config);
    let network = scan_config.target_network.clone();

    // Send scan started event with full info
    let _ = sse_tx.send(SseEvent::ScanStarted {
        scan_id: scan_id.clone(),
        network,
        host_count,
        detectors: detector_names,
    });

    let scan_id_clone = scan_id;

    let ebpf_channels = state.ebpf_channels.clone();

    tokio::spawn(async move {
        let on_agent_tx = sse_tx.clone();
        let on_agent: crate::scanner::OnAgentCallback = Box::new(move |agent: &DetectedAgent| {
            let _ = on_agent_tx.send(SseEvent::AgentDetected {
                agent: Box::new(agent.clone()),
            });
        });

        match run_scan(
            &scan_config,
            Some(ebpf_channels),
            Some(cancel_clone),
            Some(on_agent),
        )
        .await
        {
            Ok(mut result) => {
                // run_scan creates its own scan_id; overwrite so it matches
                // the one we returned to the API caller and announced via SSE.
                result.scan_id = scan_id_clone.clone();
                let was_cancelled = result.cancelled;
                if !was_cancelled {
                    let previous = match state.storage.get_latest_scan(&result.scope_id).await {
                        Ok(previous) => previous,
                        Err(error) => {
                            tracing::warn!("Failed to load persisted scan baseline: {}", error);
                            None
                        }
                    };
                    apply_scan_diff(&mut result, previous.as_ref());
                }
                let agent_count = result.agents.len();
                let summary = ScanSummary::from_result(&result);

                // Save to storage
                if let Err(e) = state.storage.save_scan(&result).await {
                    tracing::error!("Failed to save scan result: {}", e);
                }

                if !was_cancelled {
                    let alert_config = state.config.lock().await.clone();
                    let mut notifier = state.notifier.lock().await;
                    notifier.set_config(&alert_config);
                    if let Err(error) = notifier.check_and_notify(&result).await {
                        tracing::error!("Failed to dispatch scan alert: {}", error);
                    }
                }

                // Update state
                {
                    let mut latest = state.latest_result.lock().await;
                    *latest = Some(result);
                }
                {
                    let mut status = state.scan_status.lock().await;
                    *status = if was_cancelled {
                        ScanStatus::Cancelled {
                            scan_id: scan_id_clone.clone(),
                        }
                    } else {
                        ScanStatus::Completed {
                            scan_id: scan_id_clone.clone(),
                        }
                    };
                }
                {
                    let mut token = state.cancel_token.lock().await;
                    *token = None;
                }

                let event = if was_cancelled {
                    SseEvent::ScanCancelled {
                        scan_id: scan_id_clone,
                        agent_count,
                        summary,
                    }
                } else {
                    SseEvent::ScanCompleted {
                        scan_id: scan_id_clone,
                        agent_count,
                        summary,
                    }
                };
                let _ = sse_tx.send(event);
            }
            Err(e) => {
                let msg = format!("Scan failed: {}", e);
                tracing::error!("{}", msg);

                {
                    let mut status = state.scan_status.lock().await;
                    *status = ScanStatus::Idle;
                }
                {
                    let mut token = state.cancel_token.lock().await;
                    *token = None;
                }

                let _ = sse_tx.send(SseEvent::ScanError { message: msg });
            }
        }
    });
}

async fn start_scan_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanStartedResponse>, StatusCode> {
    // Build a config for this scan. JSON-only mutation keeps browser form and
    // query-string requests from becoming state-changing CSRF primitives.
    let mut scan_config = state.config.lock().await.clone();
    if let Some(network) = req.network {
        scan_config.target_network = network;
    }
    if let Some(detectors_csv) = req.detectors {
        apply_detector_filter(&mut scan_config, &detectors_csv);
    }
    if let Some(hosts) = req.hosts {
        scan_config.target_hosts = hosts;
    }

    let cancel_token = CancellationToken::new();
    let scan_result = ScanResult::new();
    let scan_id = scan_result.scan_id.clone();

    // Check and reserve the single scan slot atomically.
    {
        let mut status = state.scan_status.lock().await;
        if matches!(*status, ScanStatus::Running { .. }) {
            return Err(StatusCode::CONFLICT);
        }
        *status = ScanStatus::Running {
            scan_id: scan_id.clone(),
        };
    }
    {
        let mut token = state.cancel_token.lock().await;
        *token = Some(cancel_token.clone());
    }

    spawn_scan(
        Arc::clone(&state),
        scan_config,
        scan_id.clone(),
        cancel_token,
    );

    Ok(Json(ScanStartedResponse {
        scan_id,
        status: "started".to_string(),
    }))
}

async fn scan_status_handler(State(state): State<Arc<AppState>>) -> Json<ScanStatus> {
    let status = state.scan_status.lock().await;
    Json(status.clone())
}

async fn scan_results_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ScanResult>, StatusCode> {
    let latest = state.latest_result.lock().await;
    match latest.as_ref() {
        Some(result) => Ok(Json(result.clone())),
        None => Ok(Json(ScanResult::new())),
    }
}

async fn scan_sarif_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let latest = state.latest_result.lock().await;
    match latest.as_ref() {
        Some(result) => Ok(Json(crate::sarif_export::to_sarif(result))),
        None => Ok(Json(crate::sarif_export::to_sarif(&ScanResult::new()))),
    }
}

async fn stop_scan_handler(State(state): State<Arc<AppState>>) -> Json<StopResponse> {
    let token = state.cancel_token.lock().await;
    if let Some(ref cancel) = *token {
        cancel.cancel();
    }
    Json(StopResponse {
        status: "stopping".to_string(),
    })
}

async fn scan_stream_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    // SSE is read-only. Scans are started only by JSON POST /api/scan.
    let rx = state.sse_tx.subscribe();

    // Don't set SSE event type — dashboard uses onmessage (unnamed events)
    // and parses data.event from the JSON body directly.
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let json = serde_json::to_string(&event).unwrap_or_default();
            Some(Ok(Event::default().data(json)))
        }
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

async fn scan_history_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = query.limit.unwrap_or(10);
    let offset = query.offset.unwrap_or(0);

    match state.storage.list_scans(limit, offset).await {
        Ok(scans) => Ok(Json(serde_json::json!({ "scans": scans }))),
        Err(e) => {
            tracing::error!("Failed to list scans: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_scan_handler(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.storage.get_scan(&scan_id).await {
        Ok(Some(scan)) => {
            let summary = ScanSummary::from_result(&scan);
            Ok(Json(serde_json::json!({
                "scan_id": scan.scan_id,
                "scope_id": scan.scope_id,
                "target_network": scan.target_network,
                "agents": scan.agents,
                "diff": scan.diff,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "cancelled": scan.cancelled,
                "detectors_run": scan.detectors_run,
                "summary": summary,
            })))
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("Failed to load scan {}: {}", scan_id, e);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

async fn agents_handler(State(state): State<Arc<AppState>>) -> Json<Vec<DetectedAgent>> {
    let latest = state.latest_result.lock().await;
    match latest.as_ref() {
        Some(result) => Json(result.agents.clone()),
        None => Json(Vec::new()),
    }
}

// ─── Alert settings fields ─────────────────────────────────────────────────

/// The subset of ScanConfig fields exposed via /api/settings.
#[derive(Debug, Serialize, Deserialize)]
struct AlertSettings {
    alert_enabled: bool,
    alert_changes_only: bool,
    alert_min_agents: usize,
    alert_min_confidence: String,
    alert_cooldown: u64,
    webhook_url: String,
    smtp_host: String,
    smtp_port: u16,
    smtp_user: String,
    smtp_password: String,
    smtp_use_tls: bool,
    smtp_from: String,
    smtp_to: Vec<String>,
}

impl AlertSettings {
    fn from_config(config: &ScanConfig) -> Self {
        Self {
            alert_enabled: config.alert_enabled,
            alert_changes_only: config.alert_changes_only,
            alert_min_agents: config.alert_min_agents,
            alert_min_confidence: if config.alert_min_confidence >= 0.9 {
                "confirmed"
            } else if config.alert_min_confidence >= 0.7 {
                "high"
            } else if config.alert_min_confidence >= 0.4 {
                "medium"
            } else {
                "low"
            }
            .to_string(),
            alert_cooldown: config.alert_cooldown,
            webhook_url: config.webhook_url.clone(),
            smtp_host: config.smtp_host.clone(),
            smtp_port: config.smtp_port,
            smtp_user: config.smtp_user.clone(),
            // Never expose the actual password
            smtp_password: if config.smtp_password.is_empty() {
                String::new()
            } else {
                "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}".to_string()
            },
            smtp_use_tls: config.smtp_use_tls,
            smtp_from: config.smtp_from.clone(),
            smtp_to: config.smtp_to.clone(),
        }
    }
}

async fn get_settings_handler(State(state): State<Arc<AppState>>) -> Json<AlertSettings> {
    let config = state.config.lock().await;
    Json(AlertSettings::from_config(&config))
}

#[derive(Debug, Deserialize)]
struct UpdateSettingsRequest {
    alert_enabled: Option<bool>,
    alert_changes_only: Option<bool>,
    alert_min_agents: Option<usize>,
    alert_min_confidence: Option<String>,
    alert_cooldown: Option<u64>,
    webhook_url: Option<String>,
    smtp_host: Option<String>,
    smtp_port: Option<u16>,
    smtp_user: Option<String>,
    smtp_password: Option<String>,
    smtp_use_tls: Option<bool>,
    smtp_from: Option<String>,
    smtp_to: Option<Vec<String>>,
}

async fn update_settings_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateSettingsRequest>,
) -> Json<serde_json::Value> {
    let mut config = state.config.lock().await;
    let mut updated = Vec::new();

    let smtp_auth_endpoint_changed = body
        .smtp_host
        .as_ref()
        .is_some_and(|host| host != &config.smtp_host)
        || body.smtp_port.is_some_and(|port| port != config.smtp_port)
        || body
            .smtp_use_tls
            .is_some_and(|use_tls| use_tls != config.smtp_use_tls)
        || body
            .smtp_user
            .as_ref()
            .is_some_and(|user| user != &config.smtp_user);

    if smtp_auth_endpoint_changed {
        if !config.smtp_user.is_empty() {
            config.smtp_user.clear();
            updated.push("smtp_user_cleared");
        }
        if !config.smtp_password.is_empty() {
            config.smtp_password.clear();
            updated.push("smtp_password_cleared");
        }
    }

    if let Some(v) = body.alert_enabled {
        config.alert_enabled = v;
        updated.push("alert_enabled");
    }
    if let Some(v) = body.alert_changes_only {
        config.alert_changes_only = v;
        updated.push("alert_changes_only");
    }
    if let Some(v) = body.alert_min_agents {
        config.alert_min_agents = v;
        updated.push("alert_min_agents");
    }
    if let Some(ref v) = body.alert_min_confidence {
        // Dashboard sends string confidence levels; map to f64
        let score = match v.as_str() {
            "confirmed" => 0.9,
            "high" => 0.7,
            "medium" => 0.4,
            _ => 0.1, // "low"
        };
        config.alert_min_confidence = score;
        updated.push("alert_min_confidence");
    }
    if let Some(v) = body.alert_cooldown {
        config.alert_cooldown = v;
        updated.push("alert_cooldown");
    }
    if let Some(ref v) = body.webhook_url {
        if config.set_webhook_destination(v.clone()) {
            updated.push("webhook_headers_cleared");
        }
        updated.push("webhook_url");
    }
    if let Some(ref v) = body.smtp_host {
        config.smtp_host = v.clone();
        updated.push("smtp_host");
    }
    if let Some(v) = body.smtp_port {
        config.smtp_port = v;
        updated.push("smtp_port");
    }
    if let Some(ref v) = body.smtp_user {
        config.smtp_user = v.clone();
        updated.push("smtp_user");
    }
    if let Some(ref v) = body.smtp_password {
        // Skip masked password placeholder
        if v != "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}" {
            config.smtp_password = v.clone();
            updated.push("smtp_password");
        }
    }
    if let Some(v) = body.smtp_use_tls {
        config.smtp_use_tls = v;
        updated.push("smtp_use_tls");
    }
    if let Some(ref v) = body.smtp_from {
        config.smtp_from = v.clone();
        updated.push("smtp_from");
    }
    if let Some(ref v) = body.smtp_to {
        config.smtp_to = v.clone();
        updated.push("smtp_to");
    }

    let refreshed_config = config.clone();
    drop(config);
    state.notifier.lock().await.set_config(&refreshed_config);

    let count = updated.len();
    Json(serde_json::json!({
        "updated": updated,
        "count": count,
    }))
}

async fn test_alert_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let config = state.config.lock().await.clone();

    // Build a minimal fake result for testing
    let result = ScanResult {
        scan_id: "test-alert".to_string(),
        target_network: config.target_network.clone(),
        ..ScanResult::new()
    };

    let outcomes = send_alerts(&result, &config).await;
    Json(serde_json::json!({ "outcomes": outcomes }))
}

// ─── Database management ───────────────────────────────────────────────────

async fn db_backup_handler(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.storage.backup().await {
        Ok(data) => {
            let headers = [
                (
                    axum::http::header::CONTENT_TYPE,
                    "application/x-sqlite3".to_string(),
                ),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    "attachment; filename=\"agentsniff-backup.db\"".to_string(),
                ),
            ];
            Ok((headers, data))
        }
        Err(e) => {
            tracing::error!("Database backup failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn db_reset_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.storage.reset().await {
        Ok(()) => Ok(Json(serde_json::json!({ "status": "ok" }))),
        Err(e) => {
            tracing::error!("Database reset failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn dashboard_handler() -> impl IntoResponse {
    match DashboardAssets::get("index.html") {
        Some(content) => {
            let body = std::str::from_utf8(content.data.as_ref())
                .unwrap_or("<h1>Dashboard load error</h1>");
            Html(body.to_string())
        }
        None => Html("<h1>Dashboard not found</h1>".to_string()),
    }
}

async fn static_fallback_handler() -> StatusCode {
    StatusCode::NOT_FOUND
}

// ─── Router construction ────────────────────────────────────────────────────

/// Create the Axum router with all API routes and shared state.
///
/// This is exposed publicly so integration tests can call it without binding
/// to a real TCP port.
pub fn create_router(config: ScanConfig, ebpf_channels: Arc<EbpfChannels>) -> Router {
    let storage: Box<dyn StorageBackend> = Box::new(
        SqliteBackend::new(&config.storage.sqlite_path).expect("Failed to open SQLite database"),
    );
    create_router_with_storage(config, storage, ebpf_channels)
}

/// Create router with a custom storage backend (useful for testing with in-memory DB).
pub fn create_router_with_storage(
    config: ScanConfig,
    storage: Box<dyn StorageBackend>,
    ebpf_channels: Arc<EbpfChannels>,
) -> Router {
    let (sse_tx, _rx) = broadcast::channel::<SseEvent>(256);
    let notifier = Notifier::new(&config);

    let state = Arc::new(AppState {
        config: Mutex::new(config),
        storage,
        scan_status: Mutex::new(ScanStatus::Idle),
        latest_result: Mutex::new(None),
        notifier: Mutex::new(notifier),
        cancel_token: Mutex::new(None),
        sse_tx,
        ebpf_channels,
    });

    let protected_routes = Router::new()
        .route("/api/scan", post(start_scan_handler))
        .route("/api/scan/status", get(scan_status_handler))
        .route("/api/scan/results", get(scan_results_handler))
        .route("/api/scan/stop", post(stop_scan_handler))
        .route("/api/scan/stream", get(scan_stream_handler))
        .route("/api/scan/sarif", get(scan_sarif_handler))
        .route("/api/scan/history", get(scan_history_handler))
        .route("/api/scan/:scan_id", get(get_scan_handler))
        .route("/api/agents", get(agents_handler))
        .route(
            "/api/settings",
            get(get_settings_handler).put(update_settings_handler),
        )
        .route("/api/settings/test", post(test_alert_handler))
        .route("/api/db/backup", get(db_backup_handler))
        .route("/api/db/reset", post(db_reset_handler))
        .route("/", get(dashboard_handler))
        .fallback(get(static_fallback_handler))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_api_auth,
        ));

    Router::new()
        .route("/api/health", get(health_handler))
        .merge(protected_routes)
        .with_state(state)
}

/// Start the web server, binding to the configured host and port.
pub async fn run_server(
    config: ScanConfig,
    ebpf_channels: Arc<EbpfChannels>,
) -> anyhow::Result<()> {
    validate_api_security(&config)?;
    let host = config.api_host.clone();
    let port = config.api_port;

    let app = create_router(config, ebpf_channels);

    let addr = format!("{}:{}", host, port);
    tracing::info!("AgentSniff v2 server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
