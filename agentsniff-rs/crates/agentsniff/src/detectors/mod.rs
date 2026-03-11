use async_trait::async_trait;
use std::net::IpAddr;

use crate::config::ScanConfig;
use crate::models::{DetectorType, Signal};

/// Trait that all detectors implement.
#[async_trait]
pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn detector_type(&self) -> DetectorType;
    async fn setup(&mut self) -> anyhow::Result<()>;
    async fn scan(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>>;
    async fn teardown(&mut self) -> anyhow::Result<()>;
}

/// Passive detectors that consume eBPF events.
pub trait EbpfConsumer: Detector {
    type Event;
    fn handle_event(&self, event: Self::Event);
}

type DetectorFactory = Box<dyn Fn(&ScanConfig) -> Box<dyn Detector> + Send + Sync>;

/// Registry for detector factories.
pub struct DetectorRegistry {
    factories: Vec<(String, String, DetectorFactory)>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            factories: Vec::new(),
        }
    }

    pub fn register<F>(&mut self, name: &str, config_field: &str, factory: F)
    where
        F: Fn(&ScanConfig) -> Box<dyn Detector> + Send + Sync + 'static,
    {
        self.factories.push((
            name.to_string(),
            config_field.to_string(),
            Box::new(factory),
        ));
    }

    pub fn create_enabled(&self, config: &ScanConfig) -> Vec<Box<dyn Detector>> {
        let mut detectors = Vec::new();
        for (name, config_field, factory) in &self.factories {
            let enabled = match config_field.as_str() {
                "enable_dns_monitor" => config.enable_dns_monitor,
                "enable_port_scanner" => config.enable_port_scanner,
                "enable_agentpin_prober" => config.enable_agentpin_prober,
                "enable_mcp_detector" => config.enable_mcp_detector,
                "enable_endpoint_prober" => config.enable_endpoint_prober,
                "enable_tls_fingerprint" => config.enable_tls_fingerprint,
                "enable_traffic_analyzer" => config.enable_traffic_analyzer,
                "enable_sse_detector" => config.enable_sse_detector,
                _ => false,
            };
            if enabled {
                tracing::debug!("Enabling detector: {}", name);
                detectors.push(factory(config));
            }
        }
        detectors
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}
