use std::time::{Duration, Instant};

use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::ScanConfig;
use crate::models::{AssetChangeStatus, DetectedAgent, ScanResult};

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

    /// Refresh destinations and thresholds without losing cooldown state.
    pub fn set_config(&mut self, config: &ScanConfig) {
        self.config = config.clone();
    }

    /// Return whether this result meets the configured alert threshold.
    pub fn should_notify(&self, result: &ScanResult) -> bool {
        !result.cancelled
            && result.errors.is_empty()
            && self.config.alert_enabled
            && actionable_count(result, &self.config) >= self.config.alert_min_agents
    }

    /// Check if alert conditions are met and send notifications.
    pub async fn check_and_notify(&mut self, result: &ScanResult) -> anyhow::Result<()> {
        if let Some(payload) = self.prepare(result) {
            send_payload(&payload, &self.config).await;
        }
        Ok(())
    }

    /// Reserve the cooldown before dispatch, so slow or failed destinations
    /// cannot create an unbounded queue of retries.
    pub(crate) fn prepare(&mut self, result: &ScanResult) -> Option<serde_json::Value> {
        if !self.should_notify(result) {
            return None;
        }

        // Check cooldown
        if let Some(last) = self.last_alert {
            if last.elapsed().as_secs() < self.config.alert_cooldown {
                return None;
            }
        }

        self.last_alert = Some(Instant::now());
        Some(build_payload(result, &self.config))
    }
}

/// Current assets included in an alert after confidence and change filters.
pub fn qualifying_agents<'a>(
    result: &'a ScanResult,
    config: &ScanConfig,
) -> Vec<&'a DetectedAgent> {
    result
        .agents
        .iter()
        .filter(|agent| agent.confidence_score >= config.alert_min_confidence)
        .filter(|agent| {
            !config.alert_changes_only
                || matches!(
                    agent.change_status,
                    AssetChangeStatus::New | AssetChangeStatus::Changed
                )
        })
        .collect()
}

fn actionable_count(result: &ScanResult, config: &ScanConfig) -> usize {
    qualifying_agents(result, config).len() + result.diff.removed_assets.len()
}

/// Build the JSON alert payload from a scan result.
fn build_payload(result: &ScanResult, config: &ScanConfig) -> serde_json::Value {
    let agents: Vec<serde_json::Value> = qualifying_agents(result, config)
        .into_iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id,
                "ip_address": a.ip_address.to_string(),
                "host": a.host,
                "port": a.port,
                "transport": a.transport,
                "agent_type": a.agent_type,
                "framework": a.framework,
                "confidence_score": a.confidence_score,
                "confidence_level": a.confidence_level,
                "status": a.status,
                "presence_status": a.presence_status,
                "identity_assurance": a.identity_assurance,
                "risk_level": a.risk_level,
                "change_status": a.change_status,
                "signal_count": a.signal_count,
            })
        })
        .collect();

    let alert_asset_count = agents.len() + result.diff.removed_assets.len();
    let diff = serde_json::json!({
        "baseline_scan_id": result.diff.baseline_scan_id,
        "new_assets": result.diff.new_assets,
        "changed_assets": result.diff.changed_assets,
        "unchanged_count": result.diff.unchanged_assets.len(),
        "removed_assets": result.diff.removed_assets,
    });

    serde_json::json!({
        "source": "agentsniff",
        "source_url": "https://agentsniff.org",
        "copyright": "\u{00a9} 2026 ThirdKey.AI (https://thirdkey.ai)",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "scan_id": result.scan_id,
        "target_network": result.target_network.clone(),
        "total_agents": result.agents.len(),
        "alert_asset_count": alert_asset_count,
        "duration_seconds": result.duration_seconds(),
        "changes_only": config.alert_changes_only,
        "diff": diff,
        "agents": agents,
    })
}

/// Dispatch alerts to all configured channels. Returns outcome strings.
pub async fn send_alerts(result: &ScanResult, config: &ScanConfig) -> Vec<String> {
    let payload = build_payload(result, config);
    send_payload(&payload, config).await
}

pub(crate) async fn send_payload(payload: &serde_json::Value, config: &ScanConfig) -> Vec<String> {
    let mut outcomes = Vec::new();

    if !config.webhook_url.is_empty() {
        outcomes.push(send_webhook(payload, config).await);
    }

    if !config.smtp_to.is_empty() {
        outcomes.push(
            tokio::time::timeout(Duration::from_secs(20), send_email(payload, config))
                .await
                .unwrap_or_else(|_| "email:failed:timeout".into()),
        );
    }

    outcomes
}

async fn send_webhook(payload: &serde_json::Value, config: &ScanConfig) -> String {
    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => return format!("webhook:failed:{error}"),
    };
    let mut req = client
        .post(&config.webhook_url)
        .header("Content-Type", "application/json")
        .json(payload);

    for (key, value) in &config.webhook_headers {
        req = req.header(key.as_str(), value.as_str());
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if resp.status().is_success() {
                tracing::info!("Webhook alert sent ({})", status);
                format!("webhook:ok:{}", status)
            } else {
                tracing::warn!("Webhook returned {}", status);
                format!("webhook:failed:{}", status)
            }
        }
        Err(e) => {
            tracing::error!("Webhook alert failed: {}", e);
            format!("webhook:failed:{}", e)
        }
    }
}

async fn send_email(payload: &serde_json::Value, config: &ScanConfig) -> String {
    if config.smtp_host.is_empty() {
        return "email:skipped:no_smtp_host".to_string();
    }

    let total = payload["alert_asset_count"].as_u64().unwrap_or(0);
    let network = payload["target_network"].as_str().unwrap_or("network");

    let subject = format!("[AgentSniff] {} asset change(s) on {}", total, network);

    // Build plain text body
    let mut lines = vec![
        "AgentSniff Alert".to_string(),
        String::new(),
        format!(
            "Scan ID:   {}",
            payload["scan_id"].as_str().unwrap_or("N/A")
        ),
        format!("Network:   {}", network),
        format!(
            "Timestamp: {}",
            payload["timestamp"].as_str().unwrap_or("N/A")
        ),
        format!("Duration:  {}s", payload["duration_seconds"]),
        String::new(),
        format!("Alerting Assets: {}", total),
        format!(
            "New / Changed / Removed: {} / {} / {}",
            payload["diff"]["new_assets"].as_array().map_or(0, Vec::len),
            payload["diff"]["changed_assets"]
                .as_array()
                .map_or(0, Vec::len),
            payload["diff"]["removed_assets"]
                .as_array()
                .map_or(0, Vec::len),
        ),
        String::new(),
    ];

    if let Some(agents) = payload["agents"].as_array() {
        for agent in agents {
            let ip = agent["ip_address"].as_str().unwrap_or("?");
            let port_str = agent["port"]
                .as_u64()
                .map(|p| format!(":{}", p))
                .unwrap_or_default();
            let atype = agent["agent_type"].as_str().unwrap_or("unknown");
            let fw = agent["framework"].as_str().unwrap_or("unknown");
            let level = agent["confidence_level"].as_str().unwrap_or("low");
            let score = agent["confidence_score"].as_f64().unwrap_or(0.0);
            lines.push(format!(
                "  {}{}  {}  {}  {} ({:.0}%)",
                ip,
                port_str,
                atype,
                fw,
                level,
                score * 100.0
            ));
        }
    }

    if let Some(removed) = payload["diff"]["removed_assets"].as_array() {
        for asset in removed {
            let ip = asset["ip_address"].as_str().unwrap_or("?");
            let port = asset["port"]
                .as_u64()
                .map(|port| format!(":{port}"))
                .unwrap_or_default();
            lines.push(format!("  REMOVED  {ip}{port}"));
        }
    }

    lines.push(String::new());
    lines.push("--".to_string());
    lines.push(
        "AgentSniff (https://agentsniff.org) \u{00a9} 2026 ThirdKey.AI (https://thirdkey.ai)"
            .to_string(),
    );

    let text_body = lines.join("\n");
    let json_attachment =
        serde_json::to_string_pretty(payload).unwrap_or_else(|_| "{}".to_string());

    let from_addr = if config.smtp_from.is_empty() {
        &config.smtp_user
    } else {
        &config.smtp_from
    };

    let from_mailbox: Mailbox = match from_addr.parse() {
        Ok(m) => m,
        Err(e) => return format!("email:failed:bad_from_address:{}", e),
    };

    let mut to_mailboxes = Vec::new();
    for addr in &config.smtp_to {
        match addr.trim().parse::<Mailbox>() {
            Ok(m) => to_mailboxes.push(m),
            Err(e) => {
                tracing::warn!("Skipping invalid recipient '{}': {}", addr, e);
            }
        }
    }

    if to_mailboxes.is_empty() {
        return "email:failed:no_valid_recipients".to_string();
    }

    let mut builder = Message::builder().from(from_mailbox).subject(subject);

    for mb in &to_mailboxes {
        builder = builder.to(mb.clone());
    }

    let email = match builder.multipart(
        MultiPart::mixed()
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_PLAIN)
                    .body(text_body),
            )
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::parse("application/json").unwrap())
                    .header(lettre::message::header::ContentDisposition::attachment(
                        "alert-payload.json",
                    ))
                    .body(json_attachment),
            ),
    ) {
        Ok(msg) => msg,
        Err(e) => return format!("email:failed:build:{}", e),
    };

    // Build SMTP transport
    let transport_result = if config.smtp_use_tls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
    };

    let transport = match transport_result {
        Ok(builder) => {
            let mut b = builder.port(config.smtp_port);
            if !config.smtp_user.is_empty() {
                b = b.credentials(Credentials::new(
                    config.smtp_user.clone(),
                    config.smtp_password.clone(),
                ));
            }
            b.build()
        }
        Err(e) => return format!("email:failed:transport:{}", e),
    };

    match transport.send(email).await {
        Ok(_) => {
            tracing::info!("Email alert sent to {}", config.smtp_to.join(", "));
            "email:ok".to_string()
        }
        Err(e) => {
            tracing::error!("Email alert failed: {}", e);
            format!("email:failed:{}", e)
        }
    }
}
