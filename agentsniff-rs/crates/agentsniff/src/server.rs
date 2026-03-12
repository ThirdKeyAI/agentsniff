use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};

use crate::config::ScanConfig;
use crate::ebpf::EbpfChannels;
use crate::models::{DetectedAgent, ScanResult};
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
    ScanError {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_agents: usize,
    pub by_confidence: ConfidenceCounts,
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
    pub config: ScanConfig,
    pub storage: Box<dyn StorageBackend>,
    pub scan_status: Mutex<ScanStatus>,
    pub latest_result: Mutex<Option<ScanResult>>,
    pub cancel_token: Mutex<Option<CancellationToken>>,
    pub sse_tx: broadcast::Sender<SseEvent>,
    pub ebpf_channels: Arc<EbpfChannels>,
}

// ─── Request / response types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub network: Option<String>,
    pub hosts: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    pub network: Option<String>,
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
        version: "2.0.0".to_string(),
    })
}

/// Apply detector toggle overrides from a comma-separated list of detector names.
fn apply_detector_filter(config: &mut ScanConfig, detectors_csv: &str) {
    let enabled: Vec<&str> = detectors_csv.split(',').map(|s| s.trim()).collect();
    // Disable all, then re-enable only the listed ones
    config.enable_dns_monitor = false;
    config.enable_port_scanner = false;
    config.enable_agentpin_prober = false;
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
    if config.enable_dns_monitor { names.push("dns_monitor".into()); }
    if config.enable_port_scanner { names.push("port_scanner".into()); }
    if config.enable_agentpin_prober { names.push("agentpin_prober".into()); }
    if config.enable_mcp_detector { names.push("mcp_detector".into()); }
    if config.enable_endpoint_prober { names.push("endpoint_prober".into()); }
    if config.enable_tls_fingerprint { names.push("tls_fingerprint".into()); }
    if config.enable_traffic_analyzer { names.push("traffic_analyzer".into()); }
    if config.enable_sse_detector { names.push("sse_detector".into()); }
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
        let on_agent: crate::scanner::OnAgentCallback =
            Box::new(move |agent: &DetectedAgent| {
                let _ = on_agent_tx.send(SseEvent::AgentDetected {
                    agent: Box::new(agent.clone()),
                });
            });

        match run_scan(&scan_config, Some(ebpf_channels), Some(cancel_clone), Some(on_agent)).await {
            Ok(result) => {
                let agent_count = result.agents.len();
                let summary = ScanSummary::from_result(&result);

                // Save to storage
                if let Err(e) = state.storage.save_scan(&result).await {
                    tracing::error!("Failed to save scan result: {}", e);
                }

                // Update state
                {
                    let mut latest = state.latest_result.lock().await;
                    *latest = Some(result);
                }
                {
                    let mut status = state.scan_status.lock().await;
                    *status = ScanStatus::Completed {
                        scan_id: scan_id_clone.clone(),
                    };
                }
                {
                    let mut token = state.cancel_token.lock().await;
                    *token = None;
                }

                let _ = sse_tx.send(SseEvent::ScanCompleted {
                    scan_id: scan_id_clone,
                    agent_count,
                    summary,
                });
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
    Query(query): Query<StreamQuery>,
    body: axum::body::Bytes,
) -> Result<Json<ScanStartedResponse>, StatusCode> {
    // Check if already running
    {
        let status = state.scan_status.lock().await;
        if matches!(*status, ScanStatus::Running { .. }) {
            return Err(StatusCode::CONFLICT);
        }
    }

    // Build a config for this scan — accept both query params and JSON body
    let mut scan_config = state.config.clone();
    if let Some(network) = query.network {
        scan_config.target_network = network;
    }
    if let Some(detectors_csv) = query.detectors {
        apply_detector_filter(&mut scan_config, &detectors_csv);
    }
    // Try to parse JSON body (may be empty for query-param-only requests)
    if let Ok(req) = serde_json::from_slice::<ScanRequest>(&body) {
        if let Some(network) = req.network {
            scan_config.target_network = network;
        }
        if let Some(hosts) = req.hosts {
            scan_config.target_hosts = hosts;
        }
    }

    let cancel_token = CancellationToken::new();
    let scan_result = ScanResult::new();
    let scan_id = scan_result.scan_id.clone();

    // Update state
    {
        let mut status = state.scan_status.lock().await;
        *status = ScanStatus::Running {
            scan_id: scan_id.clone(),
        };
    }
    {
        let mut token = state.cancel_token.lock().await;
        *token = Some(cancel_token.clone());
    }

    spawn_scan(Arc::clone(&state), scan_config, scan_id.clone(), cancel_token);

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
    Query(query): Query<StreamQuery>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    // Subscribe to SSE BEFORE triggering the scan to avoid missing events
    let rx = state.sse_tx.subscribe();

    // If network query param is present, auto-trigger a scan
    if let Some(network) = query.network {
        let already_running = {
            let status = state.scan_status.lock().await;
            matches!(*status, ScanStatus::Running { .. })
        };

        if !already_running {
            let mut scan_config = state.config.clone();
            scan_config.target_network = network;

            if let Some(detectors_csv) = query.detectors {
                apply_detector_filter(&mut scan_config, &detectors_csv);
            }

            let cancel_token = CancellationToken::new();
            let scan_result = ScanResult::new();
            let scan_id = scan_result.scan_id.clone();

            {
                let mut status = state.scan_status.lock().await;
                *status = ScanStatus::Running {
                    scan_id: scan_id.clone(),
                };
            }
            {
                let mut token = state.cancel_token.lock().await;
                *token = Some(cancel_token.clone());
            }

            spawn_scan(Arc::clone(&state), scan_config, scan_id, cancel_token);
        }
    }

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
    match state.storage.get_agents(&scan_id).await {
        Ok(agents) => {
            let mut by_confidence = serde_json::Map::new();
            let (mut confirmed, mut high, mut medium, mut low) = (0usize, 0, 0, 0);
            for a in &agents {
                match a.confidence_level.as_str() {
                    "confirmed" => confirmed += 1,
                    "high" => high += 1,
                    "medium" => medium += 1,
                    _ => low += 1,
                }
            }
            by_confidence.insert("confirmed".into(), confirmed.into());
            by_confidence.insert("high".into(), high.into());
            by_confidence.insert("medium".into(), medium.into());
            by_confidence.insert("low".into(), low.into());

            Ok(Json(serde_json::json!({
                "scan_id": scan_id,
                "agents": agents,
                "summary": {
                    "total_agents": agents.len(),
                    "by_confidence": by_confidence,
                }
            })))
        }
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
        SqliteBackend::new(&config.storage.sqlite_path)
            .expect("Failed to open SQLite database"),
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

    let state = Arc::new(AppState {
        config,
        storage,
        scan_status: Mutex::new(ScanStatus::Idle),
        latest_result: Mutex::new(None),
        cancel_token: Mutex::new(None),
        sse_tx,
        ebpf_channels,
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/scan", post(start_scan_handler))
        .route("/api/scan/status", get(scan_status_handler))
        .route("/api/scan/results", get(scan_results_handler))
        .route("/api/scan/stop", post(stop_scan_handler))
        .route("/api/scan/stream", get(scan_stream_handler))
        .route("/api/scan/history", get(scan_history_handler))
        .route("/api/scan/{scan_id}", get(get_scan_handler))
        .route("/api/agents", get(agents_handler))
        .route("/", get(dashboard_handler))
        .fallback(get(static_fallback_handler))
        .layer(cors)
        .with_state(state)
}

/// Start the web server, binding to the configured host and port.
pub async fn run_server(config: ScanConfig, ebpf_channels: Arc<EbpfChannels>) -> anyhow::Result<()> {
    let host = config.api_host.clone();
    let port = config.api_port;

    let app = create_router(config, ebpf_channels);

    let addr = format!("{}:{}", host, port);
    tracing::info!("AgentSniff v2 server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
