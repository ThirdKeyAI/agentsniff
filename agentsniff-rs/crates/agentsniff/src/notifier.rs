use std::time::Instant;

use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

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
            .filter(|a| a.confidence_score >= self.config.alert_min_confidence)
            .collect();

        if qualifying_agents.len() < self.config.alert_min_agents {
            return Ok(());
        }

        let outcomes = send_alerts(result, &self.config).await;
        if outcomes.iter().any(|o| o.contains("ok")) {
            self.last_alert = Some(Instant::now());
        }

        Ok(())
    }
}

/// Build the JSON alert payload from a scan result.
fn build_payload(result: &ScanResult, _config: &ScanConfig) -> serde_json::Value {
    let agents: Vec<serde_json::Value> = result
        .agents
        .iter()
        .map(|a| {
            serde_json::json!({
                "ip_address": a.ip_address.to_string(),
                "host": a.host,
                "port": a.port,
                "agent_type": a.agent_type,
                "framework": a.framework,
                "confidence_score": a.confidence_score,
                "confidence_level": a.confidence_level,
                "status": a.status,
                "signal_count": a.signal_count,
            })
        })
        .collect();

    serde_json::json!({
        "source": "agentsniff",
        "source_url": "https://agentsniff.org",
        "copyright": "\u{00a9} 2026 ThirdKey.AI (https://thirdkey.ai)",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "scan_id": result.scan_id,
        "target_network": result.target_network.clone(),
        "total_agents": result.agents.len(),
        "duration_seconds": result.duration_seconds(),
        "agents": agents,
    })
}

/// Dispatch alerts to all configured channels. Returns outcome strings.
pub async fn send_alerts(result: &ScanResult, config: &ScanConfig) -> Vec<String> {
    let mut outcomes = Vec::new();
    let payload = build_payload(result, config);

    if !config.webhook_url.is_empty() {
        outcomes.push(send_webhook(&payload, config).await);
    }

    if !config.smtp_to.is_empty() {
        outcomes.push(send_email(&payload, config).await);
    }

    outcomes
}

async fn send_webhook(payload: &serde_json::Value, config: &ScanConfig) -> String {
    let client = reqwest::Client::new();
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
            if status < 400 {
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

    let total = payload["total_agents"].as_u64().unwrap_or(0);
    let network = payload["target_network"].as_str().unwrap_or("network");

    let subject = format!("[AgentSniff] {} agent(s) detected on {}", total, network);

    // Build plain text body
    let mut lines = vec![
        "AgentSniff Alert".to_string(),
        String::new(),
        format!("Scan ID:   {}", payload["scan_id"].as_str().unwrap_or("N/A")),
        format!("Network:   {}", network),
        format!("Timestamp: {}", payload["timestamp"].as_str().unwrap_or("N/A")),
        format!("Duration:  {}s", payload["duration_seconds"]),
        String::new(),
        format!("Total Agents: {}", total),
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

    let mut builder = Message::builder()
        .from(from_mailbox)
        .subject(subject);

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
            tracing::info!(
                "Email alert sent to {}",
                config.smtp_to.join(", ")
            );
            "email:ok".to_string()
        }
        Err(e) => {
            tracing::error!("Email alert failed: {}", e);
            format!("email:failed:{}", e)
        }
    }
}
