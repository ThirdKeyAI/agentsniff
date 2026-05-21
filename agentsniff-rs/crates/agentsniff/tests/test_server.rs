use std::sync::Arc;

use agentsniff::config::ScanConfig;
use agentsniff::ebpf::EbpfChannels;
use agentsniff::server::create_router_with_storage;
use agentsniff::storage::SqliteBackend;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn test_router() -> axum::Router {
    let config = ScanConfig::default();
    let storage = Box::new(SqliteBackend::in_memory().unwrap());
    let channels = Arc::new(EbpfChannels::new());
    create_router_with_storage(config, storage, channels)
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = test_router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_scan_status_idle() {
    let app = test_router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/scan/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_scan_history_empty() {
    let app = test_router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/scan/history?limit=10&offset=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_agents_empty() {
    let app = test_router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/agents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_dashboard_serves() {
    let app = test_router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
