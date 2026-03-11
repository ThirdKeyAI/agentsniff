use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
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
use crate::models::{DetectedAgent, ScanResult};
use crate::scanner::run_scan;
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
    },
    ScanError {
        message: String,
    },
}

// ─── App state ──────────────────────────────────────────────────────────────

pub struct AppState {
    pub config: ScanConfig,
    pub storage: Box<dyn StorageBackend>,
    pub scan_status: Mutex<ScanStatus>,
    pub latest_result: Mutex<Option<ScanResult>>,
    pub cancel_token: Mutex<Option<CancellationToken>>,
    pub sse_tx: broadcast::Sender<SseEvent>,
}

// ─── Request / response types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub network: Option<String>,
    pub hosts: Option<Vec<String>>,
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

async fn start_scan_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ScanRequest>,
) -> Result<Json<ScanStartedResponse>, StatusCode> {
    // Check if already running
    {
        let status = state.scan_status.lock().await;
        if matches!(*status, ScanStatus::Running { .. }) {
            return Err(StatusCode::CONFLICT);
        }
    }

    // Build a config for this scan
    let mut scan_config = state.config.clone();
    if let Some(network) = body.network {
        scan_config.target_network = network;
    }
    if let Some(hosts) = body.hosts {
        scan_config.target_hosts = hosts;
    }

    let cancel_token = CancellationToken::new();
    let cancel_clone = cancel_token.clone();

    // Create scan result to get the ID
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
        *token = Some(cancel_token);
    }

    let sse_tx = state.sse_tx.clone();

    // Send scan started event
    let _ = sse_tx.send(SseEvent::ScanStarted {
        scan_id: scan_id.clone(),
    });

    let state_clone = Arc::clone(&state);
    let scan_id_clone = scan_id.clone();

    // Spawn the scan as a background task
    tokio::spawn(async move {
        let on_agent_tx = sse_tx.clone();
        let on_agent: crate::scanner::OnAgentCallback =
            Box::new(move |agent: &DetectedAgent| {
                let _ = on_agent_tx.send(SseEvent::AgentDetected {
                    agent: Box::new(agent.clone()),
                });
            });

        match run_scan(&scan_config, Some(cancel_clone), Some(on_agent)).await {
            Ok(result) => {
                let agent_count = result.agents.len();

                // Save to storage
                if let Err(e) = state_clone.storage.save_scan(&result).await {
                    tracing::error!("Failed to save scan result: {}", e);
                }

                // Update state
                {
                    let mut latest = state_clone.latest_result.lock().await;
                    *latest = Some(result);
                }
                {
                    let mut status = state_clone.scan_status.lock().await;
                    *status = ScanStatus::Completed {
                        scan_id: scan_id_clone.clone(),
                    };
                }
                {
                    let mut token = state_clone.cancel_token.lock().await;
                    *token = None;
                }

                let _ = sse_tx.send(SseEvent::ScanCompleted {
                    scan_id: scan_id_clone,
                    agent_count,
                });
            }
            Err(e) => {
                let msg = format!("Scan failed: {}", e);
                tracing::error!("{}", msg);

                {
                    let mut status = state_clone.scan_status.lock().await;
                    *status = ScanStatus::Idle;
                }
                {
                    let mut token = state_clone.cancel_token.lock().await;
                    *token = None;
                }

                let _ = sse_tx.send(SseEvent::ScanError { message: msg });
            }
        }
    });

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
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.sse_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let json = serde_json::to_string(&event).unwrap_or_default();
            let event_name = match &event {
                SseEvent::ScanStarted { .. } => "scan_started",
                SseEvent::AgentDetected { .. } => "agent_detected",
                SseEvent::ScanProgress { .. } => "scan_progress",
                SseEvent::ScanCompleted { .. } => "scan_completed",
                SseEvent::ScanError { .. } => "scan_error",
            };
            Some(Ok(Event::default().event(event_name).data(json)))
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
        Ok(scans) => Ok(Json(scans)),
        Err(e) => {
            tracing::error!("Failed to list scans: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
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
pub fn create_router(config: ScanConfig) -> Router {
    let (sse_tx, _rx) = broadcast::channel::<SseEvent>(256);

    let storage: Box<dyn StorageBackend> = Box::new(
        SqliteBackend::in_memory().expect("Failed to create in-memory SQLite backend"),
    );

    let state = Arc::new(AppState {
        config,
        storage,
        scan_status: Mutex::new(ScanStatus::Idle),
        latest_result: Mutex::new(None),
        cancel_token: Mutex::new(None),
        sse_tx,
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
        .route("/api/agents", get(agents_handler))
        .route("/", get(dashboard_handler))
        .fallback(get(static_fallback_handler))
        .layer(cors)
        .with_state(state)
}

/// Start the web server, binding to the configured host and port.
pub async fn run_server(config: ScanConfig) -> anyhow::Result<()> {
    let host = config.api_host.clone();
    let port = config.api_port;

    let app = create_router(config);

    let addr = format!("{}:{}", host, port);
    tracing::info!("AgentSniff v2 server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
