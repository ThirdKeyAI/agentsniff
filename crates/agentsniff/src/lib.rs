// async-trait expands async trait methods into must-use boxed futures, which
// triggers Clippy's redundant double_must_use lint on generated code.
#![allow(clippy::double_must_use)]

// AgentSniff library root
pub mod agentpin;
pub mod baseline;
pub mod config;
pub mod detectors;
pub mod ebpf;
pub mod fusion;
pub(crate) mod http;
pub mod integrations;
pub(crate) mod limits;
pub mod models;
pub mod notifier;
pub mod ratelimit;
pub mod sarif_export;
pub mod scanner;
pub mod server;
pub mod signatures;
pub mod storage;
pub mod storage_postgres;
pub mod storage_redis;
