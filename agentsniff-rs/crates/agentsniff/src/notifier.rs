use std::time::Instant;

use crate::config::ScanConfig;
use crate::models::{DetectedAgent, ScanResult};

/// Handles webhook and SMTP alerting when agents are detected.
pub struct Notifier {
    config: ScanConfig,
    last_alert: Option<Instant>,
}

impl Notifier {
    pub fn new(config: &ScanConfig) -> Self {
        Self {
            config: config.clone(),
            last_alert: None,
        }
    }

    /// Check if alert conditions are met and send notifications.
    pub async fn check_and_notify(&mut self, result: &ScanResult) -> anyhow::Result<()> {
        if !self.config.alert_enabled {
            return Ok(());
        }

        // Check cooldown
        if let Some(last) = self.last_alert {
            if last.elapsed().as_secs() < self.config.alert_cooldown {
                return Ok(());
            }
        }

        // Check min agents threshold
        let qualifying_agents: Vec<&DetectedAgent> = result
            .agents
            .iter()
            .filter(|a| a.confidence_score() >= self.config.alert_min_confidence)
            .collect();

        if qualifying_agents.len() < self.config.alert_min_agents {
            return Ok(());
        }

        // Send webhook
        if !self.config.webhook_url.is_empty() {
            self.send_webhook(&qualifying_agents).await?;
        }

        // Send email (stub - needs actual SMTP implementation)
        if !self.config.smtp_host.is_empty() {
            tracing::info!("SMTP alerting not yet fully implemented");
        }

        self.last_alert = Some(Instant::now());
        Ok(())
    }

    async fn send_webhook(&self, agents: &[&DetectedAgent]) -> anyhow::Result<()> {
        let payload = serde_json::json!({
            "event": "agents_detected",
            "agent_count": agents.len(),
            "agents": agents.iter().map(|a| serde_json::json!({
                "host": a.host,
                "ip": a.ip_address.to_string(),
                "status": a.status,
                "confidence": a.confidence_score(),
                "framework": a.framework,
            })).collect::<Vec<_>>(),
        });

        let client = reqwest::Client::new();
        let mut req = client.post(&self.config.webhook_url).json(&payload);

        for (key, value) in &self.config.webhook_headers {
            req = req.header(key.as_str(), value.as_str());
        }

        req.send().await?;
        tracing::info!("Webhook alert sent to {}", self.config.webhook_url);
        Ok(())
    }
}
