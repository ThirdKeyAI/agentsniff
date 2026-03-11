use agentsniff::config::ScanConfig;
use agentsniff::server::create_router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn test_health_endpoint() {
    let config = ScanConfig::default();
    let app = create_router(config);
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
    let config = ScanConfig::default();
    let app = create_router(config);
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
    let config = ScanConfig::default();
    let app = create_router(config);
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
    let config = ScanConfig::default();
    let app = create_router(config);
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
    let config = ScanConfig::default();
    let app = create_router(config);
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
