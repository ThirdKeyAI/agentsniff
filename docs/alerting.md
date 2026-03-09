# Alerting

AgentSniff sends alerts when agents are detected during scans. Configure via YAML, environment variables, CLI flags, or the dashboard settings modal.

## Webhook

```bash
# CLI — auto-enables alerting
agentsniff scan 192.168.1.0/24 --webhook-url https://hooks.example.com/agentsniff

# Continuous monitoring with webhook
agentsniff scan 192.168.1.0/24 --continuous 300 \
  --webhook-url https://hooks.example.com/agentsniff
```

### Webhook Payload

POST JSON:

```json
{
  "source": "agentsniff",
  "source_url": "https://agentsniff.org",
  "timestamp": "2026-03-02T12:00:00Z",
  "scan_id": "scan-20260302-120000",
  "target_network": "192.168.1.0/24",
  "total_agents": 3,
  "by_confidence": {"confirmed": 1, "high": 1, "medium": 1},
  "duration_seconds": 4.2,
  "agents": [
    {
      "ip_address": "192.168.1.50",
      "host": "agent-server",
      "port": 8000,
      "agent_type": "framework",
      "framework": "langchain",
      "confidence_score": 0.95,
      "confidence_level": "confirmed",
      "status": "verified",
      "signal_count": 4
    }
  ]
}
```

### Custom Headers

```yaml
webhook_url: "https://hooks.example.com/agentsniff"
webhook_headers:
  Authorization: "Bearer YOUR_TOKEN"
  X-Custom-Header: "value"
```

## Email (SMTP)

```yaml
alert_enabled: true
alert_min_agents: 1
alert_min_confidence: medium
alert_cooldown: 600  # no more than one alert per 10 minutes

smtp_host: "smtp.example.com"
smtp_port: 587
smtp_user: "alerts@example.com"
smtp_password: "your-password"
smtp_use_tls: true
smtp_from: "agentsniff@example.com"
smtp_to:
  - "admin@example.com"
  - "security@example.com"
```

Or via CLI:

```bash
agentsniff scan 192.168.1.0/24 --smtp-to admin@example.com,security@example.com
```

## Alert Thresholds

| Setting | Description | Default |
|---------|-------------|---------|
| `alert_min_agents` | Minimum agents to trigger alert | `1` |
| `alert_min_confidence` | Minimum confidence level | `low` |
| `alert_cooldown` | Seconds between repeated alerts (0 = every scan) | `0` |

## Cron Job

Run periodic scans from cron with alerts and archived output:

```bash
# Scan every 10 minutes, alert via webhook, save results
*/10 * * * * agentsniff scan 192.168.1.0/24 \
  --webhook-url https://hooks.example.com/agentsniff \
  --format json \
  --output /var/log/agentsniff/scan-$(date +\%Y\%m\%d-\%H\%M).json \
  2>&1 | logger -t agentsniff
```

## Dashboard Settings

When running the web dashboard (`agentsniff serve`), click the gear icon to configure alert settings interactively — including webhook URL, SMTP credentials, thresholds, and a Test Alert button.
