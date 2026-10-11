# Dashboard

AgentSniff includes a web dashboard for real-time scan monitoring, history browsing, and settings management.

<p>
  <a href="https://raw.githubusercontent.com/ThirdKeyAI/agentsniff/main/AgentSniff-Dashboard-Main.png" target="_blank"><img src="https://raw.githubusercontent.com/ThirdKeyAI/agentsniff/main/AgentSniff-Dashboard-Main.png" alt="AgentSniff Dashboard - Main" width="48%"></a>
  <a href="https://raw.githubusercontent.com/ThirdKeyAI/agentsniff/main/AgentSniff-Dashboard-Settings.png" target="_blank"><img src="https://raw.githubusercontent.com/ThirdKeyAI/agentsniff/main/AgentSniff-Dashboard-Settings.png" alt="AgentSniff Dashboard - Settings" width="48%"></a>
</p>

## Starting the Dashboard

```bash
agentsniff serve --port 9090
# Open http://localhost:9090
```

Loopback use is credential-free. When `AGENTSNIFF_API_TOKEN` is configured, the dashboard is protected with HTTP Basic authentication: enter `agentsniff` as the username and the token as the password. AgentSniff refuses non-loopback binding without a token; use TLS for any remote listener.

## Features

### Live Scanning

- Select target network and detectors from the UI
- Real-time agent detection via Server-Sent Events (SSE)
- Presence and trusted-identity counters update as assets are found
- Stop button cancels the scan immediately

### Scan Results

- Service assets displayed with framework, host, port, presence, identity assurance, risk, and change state
- Expandable signal details for each detected agent
- Presence confirmation is visually separate from cryptographic identity verification

### Scan History

- Previous scans stored in SQLite database
- Browse past results with timestamps, asset counts, and new/changed/removed totals
- Stable service IDs and first-seen timestamps carry across scans of the same target
- Cancelled and incomplete scans are preserved

### Settings

Click the gear icon to configure:

- **Changes only** — Notify only for new, changed, or removed assets (enabled by default)
- **Alert thresholds** — Minimum assets and presence confidence needed to trigger alerts
- **Webhook URL** — HTTP POST endpoint for alert notifications
- **SMTP settings** — Email server configuration for alert emails
- **Test Alert** — Send a test notification to verify configuration

### Export & Database Management

The Export dropdown writes the latest scan in JSON, CSV, or SARIF 2.1.0 format.

On v2, the dashboard also exposes database administration controls backed by `GET /api/db/backup` and `POST /api/db/reset`:

- **Backup Database** — downloads a snapshot of the SQLite scan history
- **Reset Database** — wipes all stored scans (confirmation required)
