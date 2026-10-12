use agentsniff::config::StorageConfig;
use agentsniff::models::ScanResult;
use agentsniff::server::SseEvent;
use agentsniff::storage::{validate_storage_config, StorageBackend};
use agentsniff::storage_postgres::PostgresBackend;
use agentsniff::storage_redis::RedisEventBus;

#[test]
fn storage_config_rejects_unknown_backend() {
    let config = StorageConfig {
        backend: "mystery".into(),
        ..StorageConfig::default()
    };
    assert!(validate_storage_config(&config)
        .unwrap_err()
        .to_string()
        .contains("unsupported storage backend"));
}

#[test]
fn storage_config_requires_postgres_url() {
    let config = StorageConfig {
        backend: "postgres".into(),
        ..StorageConfig::default()
    };
    assert!(validate_storage_config(&config)
        .unwrap_err()
        .to_string()
        .contains("postgres_url"));
}

#[test]
fn redis_is_not_accepted_as_primary_storage() {
    let config = StorageConfig {
        backend: "redis".into(),
        redis_url: "redis://localhost".into(),
        ..StorageConfig::default()
    };
    assert!(validate_storage_config(&config)
        .unwrap_err()
        .to_string()
        .contains("event bus"));
}

#[tokio::test]
async fn postgres_rejects_empty_connection_url() {
    assert!(PostgresBackend::connect("").await.is_err());
}

#[tokio::test]
async fn postgres_storage_contract_when_test_database_is_configured() {
    let Ok(url) = std::env::var("AGENTSNIFF_TEST_POSTGRES_URL") else {
        return;
    };
    let backend = PostgresBackend::connect(&url).await.unwrap();
    backend.reset().await.unwrap();

    let mut result = ScanResult::new();
    result.scan_id = "postgres-contract".into();
    result.scope_id = "postgres-scope".into();
    result.target_network = "127.0.0.1/32".into();
    result.completed_at = Some(chrono::Utc::now());
    backend.save_scan(&result).await.unwrap();

    assert_eq!(backend.get_scan_count().await.unwrap(), 1);
    assert_eq!(
        backend
            .get_latest_scan("postgres-scope")
            .await
            .unwrap()
            .unwrap()
            .scan_id,
        "postgres-contract"
    );
    let backup = backend.backup().await.unwrap();
    assert_eq!(backup.content_type, "application/json");
    assert!(backup.data.starts_with(b"{"));
    backend.reset().await.unwrap();
}

#[tokio::test]
async fn redis_forwards_events_when_test_server_is_configured() {
    let Ok(url) = std::env::var("AGENTSNIFF_TEST_REDIS_URL") else {
        return;
    };
    let channel = format!("agentsniff:test:{}", uuid::Uuid::new_v4());
    let publisher = RedisEventBus::connect(&url, &channel).await.unwrap();
    let subscriber = RedisEventBus::connect(&url, &channel).await.unwrap();
    let (local, mut received) = tokio::sync::broadcast::channel(4);
    let task = subscriber.start_forwarder(local);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    publisher
        .publish(SseEvent::ScanProgress {
            message: "cross-instance".into(),
        })
        .await
        .unwrap();
    let event = tokio::time::timeout(std::time::Duration::from_secs(3), received.recv())
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(matches!(
        event,
        SseEvent::ScanProgress { message } if message == "cross-instance"
    ));
}
