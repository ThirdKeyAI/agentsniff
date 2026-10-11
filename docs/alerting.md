# Alerting

AgentSniff sends alerts after a scan is compared with its persisted baseline. By default, only new, changed, or removed assets are included. Configure via YAML, environment variables, CLI flags, or the dashboard settings modal.

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
  "alert_asset_count": 1,
  "changes_only": true,
  "duration_seconds": 4.2,
  "diff": {
    "baseline_scan_id": "previous-scan",
    "new_assets": ["asset-0123"],
    "changed_assets": [],
    "unchanged_count": 1,
    "removed_assets": []
  },
  "agents": [
    {
      "id": "asset-0123",
      "ip_address": "192.168.1.50",
      "host": "agent-server",
      "port": 8000,
      "agent_type": "framework",
      "framework": "langchain",
      "confidence_score": 0.95,
      "presence_status": "confirmed",
      "identity_assurance": "unknown",
      "risk_level": "unknown",
      "change_status": "new",
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
alert_changes_only: true
alert_min_agents: 1
alert_min_confidence: 0.5
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

SMTP supports `smtp_use_tls: true` (STARTTLS on the configured port, typically 587) and `smtp_use_tls: false` (plaintext relay). The JSON attachment contains the same change-focused payload sent to webhooks.

Or via CLI:

```bash
agentsniff scan 192.168.1.0/24 --smtp-to admin@example.com,security@example.com
```

## Alert Thresholds

| Setting | Description | Default |
|---------|-------------|---------|
| `alert_changes_only` | Include only new/changed assets plus removals | `true` |
| `alert_min_agents` | Minimum actionable assets to trigger alert | `1` |
| `alert_min_confidence` | Minimum presence confidence for current assets | `medium` (`0.5`) |
| `alert_cooldown` | Seconds between repeated alerts | `300` |

The first scan has no baseline, so every qualifying asset is `new`. Removed assets count toward `alert_min_agents`; the confidence threshold applies to current new or changed assets.

Databases created before scope-aware baselines do not contain a `scope_id`. The first scan after upgrading therefore establishes a fresh baseline and may notify on all qualifying assets as new.

If a scan is cancelled or any enabled detector reports an error, AgentSniff stores the partial result as cancelled or degraded but suppresses its diff and alerts. This prevents incomplete observations from generating false removals or replacing the last known-good baseline.

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

When running the web dashboard (`agentsniff serve`), click the gear icon to configure alert settings interactively — including change-only mode, webhook URL, SMTP credentials, thresholds, and a Test Alert button.
