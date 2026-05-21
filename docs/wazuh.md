# Wazuh Integration

AgentSniff logs can be ingested by [Wazuh](https://wazuh.com/) for SIEM alerting and correlation. Example rules are provided in [`docs/wazuh-rules.xml`](https://github.com/ThirdKeyAI/agentsniff/blob/main/docs/wazuh-rules.xml).

The rules below match on log content, so they work identically against v1 (Python) and v2 (Rust) — same `--log-file` and `--format json --output` semantics.

## Setup

### 1. Configure AgentSniff Logging

Run AgentSniff with file logging:

```bash
agentsniff scan 192.168.1.0/24 --log-file /var/log/agentsniff/scan.log
```

For richer alerts, output JSON results:

```bash
agentsniff scan 192.168.1.0/24 --format json \
  --output /var/log/agentsniff/results.json
```

### 2. Configure Wazuh Agent

Add a log collector to the Wazuh agent's `ossec.conf`:

**Syslog format** (log file):

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/agentsniff/scan.log</location>
</localfile>
```

**JSON format** (recommended for richer alerts):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/agentsniff/results.json</location>
</localfile>
```

### 3. Install Rules

Copy the rules file to your Wazuh manager:

```bash
cp wazuh-rules.xml /var/ossec/etc/rules/agentsniff_rules.xml
systemctl restart wazuh-manager
```

## Rule Summary

Rules use IDs 100200-100271:

| Rule ID | Level | Description |
|---------|-------|-------------|
| 100200-100201 | 0 | Base rules — match any AgentSniff log event |
| 100210 | 3 | Scan completed |
| 100211 | 5 | Scan failed — no valid targets |
| 100212 | 4 | Scan failed — no detectors enabled |
| 100220 | 7 | Agents detected (syslog) |
| 100221 | 8 | Baseline anomaly — new or changed agents |
| 100230-100233 | 3-5 | Alert notification success/failure |
| 100240 | 7 | Agents found in JSON results |
| 100250 | 10 | Confirmed agent detected |
| 100251 | 9 | High confidence agent detected |
| 100252 | 7 | Medium confidence agent detected |
| 100253 | 5 | Low confidence agent detected |
| 100260 | 10 | MCP server found |
| 100261 | 10 | AgentPin identity verified |
| 100262 | 7 | LLM API DNS queries detected |
| 100263 | 8 | Agent framework endpoint found |
| 100264 | 7 | Agent traffic patterns detected |
| 100265 | 3 | nmap excluded non-agent service |
| 100270 | 12 | 5+ confirmed agents in 60s (cluster alert) |
| 100271 | 11 | 10+ high-confidence agents in 5 min |

## Continuous Monitoring

For ongoing monitoring, combine continuous scanning with Wazuh ingestion:

```bash
# Continuous scan every 5 minutes with JSON output
agentsniff scan 192.168.1.0/24 --continuous 300 \
  --format json --output /var/log/agentsniff/results.json \
  --log-file /var/log/agentsniff/scan.log
```

Both log files will be monitored by Wazuh — the syslog for operational events and the JSON for detection alerts.
