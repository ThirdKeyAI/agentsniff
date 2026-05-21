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

## Features

### Live Scanning

- Select target network and detectors from the UI
- Real-time agent detection via Server-Sent Events (SSE)
- Confidence counters update as agents are found
- Stop button cancels the scan immediately

### Scan Results

- Agents displayed with confidence level, framework, host, port, and signal count
- Expandable signal details for each detected agent
- Color-coded confidence levels: Confirmed, High, Medium, Low

### Scan History

- Previous scans stored in SQLite database
- Browse past results with timestamps, agent counts, and status
- Cancelled and incomplete scans are preserved

### Settings

Click the gear icon to configure:

- **Alert thresholds** — Minimum agents and confidence level to trigger alerts
- **Webhook URL** — HTTP POST endpoint for alert notifications
- **SMTP settings** — Email server configuration for alert emails
- **Test Alert** — Send a test notification to verify configuration

### Export & Database Management

The Export dropdown writes the latest scan in JSON, CSV, or SARIF 2.1.0 format.

On v2, the dashboard also exposes database administration controls backed by `GET /api/db/backup` and `POST /api/db/reset`:

- **Backup Database** — downloads a snapshot of the SQLite scan history
- **Reset Database** — wipes all stored scans (confirmation required)
