use agentsniff::storage::{SqliteBackend, StorageBackend};
use agentsniff::storage_postgres::PostgresBackend;
use agentsniff::storage_redis::RedisOverlay;

#[test]
fn test_postgres_backend_creates() {
    let backend = PostgresBackend::new("postgresql://localhost/test");
    assert!(backend.is_ok());
}

#[tokio::test]
async fn test_postgres_backend_returns_not_implemented() {
    let backend = PostgresBackend::new("postgresql://localhost/test").unwrap();
    let result = backend.get_scan_count().await;
    assert!(result.is_err());
}

#[test]
fn test_redis_overlay_creates() {
    let sqlite = SqliteBackend::in_memory().unwrap();
    let overlay = RedisOverlay::new("redis://localhost", Box::new(sqlite));
    assert!(overlay.is_ok());
}

#[tokio::test]
async fn test_redis_overlay_delegates_to_inner() {
    let sqlite = SqliteBackend::in_memory().unwrap();
    let overlay = RedisOverlay::new("redis://localhost", Box::new(sqlite)).unwrap();
    let count = overlay.get_scan_count().await.unwrap();
    assert_eq!(count, 0);
}
