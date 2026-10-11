use agentsniff::models::*;
use agentsniff::storage::{SqliteBackend, StorageBackend};

#[tokio::test]
async fn test_sqlite_create_tables() {
    let backend = SqliteBackend::in_memory().unwrap();
    let count = backend.get_scan_count().await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_sqlite_save_and_list_scans() {
    let backend = SqliteBackend::in_memory().unwrap();
    let mut result = ScanResult::new();
    result.scan_id = "test-scan-1".to_string();
    result.completed_at = Some(chrono::Utc::now());
    result.detectors_run = vec![DetectorType::PortScanner];
    backend.save_scan(&result).await.unwrap();
    let scans = backend.list_scans(10, 0).await.unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].scan_id, "test-scan-1");
}

#[tokio::test]
async fn test_sqlite_save_and_get_agents() {
    let backend = SqliteBackend::in_memory().unwrap();
    let mut result = ScanResult::new();
    result.scan_id = "test-scan-2".to_string();
    let mut agent = DetectedAgent::new("host1".into(), "192.168.1.1".parse().unwrap());
    agent.port = Some(11434);
    agent.framework = Some("ollama".into());
    agent.add_signal(Signal::new(
        DetectorType::PortScanner,
        "open_port".into(),
        "Port 11434 open".into(),
        Confidence::Medium,
        serde_json::json!({"port": 11434}),
    ));
    agent.update_status();
    result.agents.push(agent);
    result.completed_at = Some(chrono::Utc::now());
    backend.save_scan(&result).await.unwrap();
    let agents = backend.get_agents("test-scan-2").await.unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].framework, Some("ollama".to_string()));
    assert_eq!(agents[0].port, Some(11434));
    assert_eq!(agents[0].signals.len(), 1);
}

#[tokio::test]
async fn test_sqlite_scan_count() {
    let backend = SqliteBackend::in_memory().unwrap();
    for i in 0..5 {
        let mut result = ScanResult::new();
        result.scan_id = format!("scan-{}", i);
        result.completed_at = Some(chrono::Utc::now());
        backend.save_scan(&result).await.unwrap();
    }
    let count = backend.get_scan_count().await.unwrap();
    assert_eq!(count, 5);
}

#[tokio::test]
async fn test_sqlite_list_scans_pagination() {
    let backend = SqliteBackend::in_memory().unwrap();
    for i in 0..10 {
        let mut result = ScanResult::new();
        result.scan_id = format!("scan-{:02}", i);
        result.completed_at = Some(chrono::Utc::now());
        backend.save_scan(&result).await.unwrap();
    }
    let page1 = backend.list_scans(3, 0).await.unwrap();
    assert_eq!(page1.len(), 3);
    let page2 = backend.list_scans(3, 3).await.unwrap();
    assert_eq!(page2.len(), 3);
    assert_ne!(page1[0].scan_id, page2[0].scan_id);
}

#[tokio::test]
async fn test_stable_asset_history_and_diff_survive_round_trip() {
    let backend = SqliteBackend::in_memory().unwrap();
    let started = chrono::Utc::now();
    let mut first = ScanResult::new();
    first.scan_id = "history-1".into();
    first.scope_id = "scope-test".into();
    first.target_network = "10.0.0.0/24".into();
    first.started_at = started;
    first.completed_at = Some(started + chrono::Duration::seconds(1));
    let mut first_agent = DetectedAgent::for_endpoint(
        "10.0.0.5".into(),
        "10.0.0.5".parse().unwrap(),
        Some(6274),
        "tcp",
    );
    first_agent.add_signal(Signal::new(
        DetectorType::McpDetector,
        "mcp_server_confirmed".into(),
        "MCP server".into(),
        Confidence::Confirmed,
        serde_json::json!({"port": 6274}),
    ));
    first.diff.new_assets.push(first_agent.id.clone());
    let stable_id = first_agent.id.clone();
    first.agents.push(first_agent);
    backend.save_scan(&first).await.unwrap();

    let mut second = first.clone();
    second.scan_id = "history-2".into();
    second.started_at = started + chrono::Duration::seconds(2);
    second.completed_at = Some(started + chrono::Duration::seconds(3));
    second.diff.baseline_scan_id = Some("history-1".into());
    second.diff.new_assets.clear();
    second.diff.unchanged_assets.push(stable_id.clone());
    second.agents[0].change_status = AssetChangeStatus::Unchanged;
    backend.save_scan(&second).await.unwrap();

    let mut cancelled = second.clone();
    cancelled.scan_id = "history-cancelled".into();
    cancelled.started_at = started + chrono::Duration::seconds(4);
    cancelled.completed_at = Some(started + chrono::Duration::seconds(5));
    cancelled.cancelled = true;
    backend.save_scan(&cancelled).await.unwrap();

    let mut degraded = second.clone();
    degraded.scan_id = "history-degraded".into();
    degraded.started_at = started + chrono::Duration::seconds(6);
    degraded.completed_at = Some(started + chrono::Duration::seconds(7));
    degraded.errors.push("detector failed".into());
    backend.save_scan(&degraded).await.unwrap();

    let first_agents = backend.get_agents("history-1").await.unwrap();
    let second_agents = backend.get_agents("history-2").await.unwrap();
    assert_eq!(first_agents.len(), 1);
    assert_eq!(second_agents.len(), 1);
    assert_eq!(first_agents[0].id, stable_id);
    assert_eq!(second_agents[0].id, stable_id);

    let latest = backend
        .get_latest_scan("scope-test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest.scan_id, "history-2");
    assert_eq!(latest.diff.baseline_scan_id.as_deref(), Some("history-1"));
    assert_eq!(latest.agents[0].change_status, AssetChangeStatus::Unchanged);

    let loaded = backend.get_scan("history-1").await.unwrap().unwrap();
    assert_eq!(loaded.diff.new_assets, vec![stable_id]);
    assert!(
        backend
            .get_scan("history-cancelled")
            .await
            .unwrap()
            .unwrap()
            .cancelled
    );
    let summaries = backend.list_scans(10, 0).await.unwrap();
    assert!(summaries
        .iter()
        .any(|scan| scan.scan_id == "history-degraded" && scan.status == "degraded"));
}
