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
