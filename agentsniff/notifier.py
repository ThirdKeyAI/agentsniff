"""
AgentSniff - Alert notifications (webhook + SMTP email).

Sends alerts when scans detect agents matching the configured thresholds.
Uses aiohttp (already a project dependency) for webhooks and stdlib smtplib
for email (via run_in_executor to avoid blocking the event loop).
"""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import aiohttp

from agentsniff.config import ScanConfig

logger = logging.getLogger("agentsniff.notifier")

# Confidence levels ordered for threshold comparison
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}

# Track last alert time for cooldown
_last_alert_time: float = 0.0


def should_alert(result: Any, config: ScanConfig) -> bool:
    """Check whether a scan result should trigger alerts."""
    global _last_alert_time

    if not config.alert_enabled:
        return False

    # Must have at least one alert channel configured
    if not config.webhook_url and not config.smtp_to:
        return False

    summary = result.summary
    total = summary.get("total_agents", 0)

    if total < config.alert_min_agents:
        return False

    # Check if any agent meets the minimum confidence threshold
    min_level = _CONFIDENCE_ORDER.get(config.alert_min_confidence, 0)
    by_conf = summary.get("by_confidence", {})
    qualifying = sum(
        count for level, count in by_conf.items()
        if _CONFIDENCE_ORDER.get(level, 0) >= min_level
    )
    if qualifying < config.alert_min_agents:
        return False

    # Cooldown check
    if config.alert_cooldown > 0:
        now = time.monotonic()
        if now - _last_alert_time < config.alert_cooldown:
            logger.debug("Alert suppressed by cooldown")
            return False

    return True


def _build_payload(result: Any, config: ScanConfig) -> dict:
    """Build a JSON-serialisable alert payload from a scan result."""
    summary = result.summary
    agents = []
    for agent in result.agents_detected:
        d = agent.to_dict()
        agents.append({
            "ip_address": d.get("ip_address", ""),
            "host": d.get("host", ""),
            "port": d.get("port"),
            "agent_type": d.get("agent_type", "unknown"),
            "framework": d.get("framework", "unknown"),
            "confidence_score": d.get("confidence_score", 0),
            "confidence_level": d.get("confidence_level", "low"),
            "status": d.get("status", "unknown"),
            "signal_count": d.get("signal_count", 0),
        })

    return {
        "source": "agentsniff",
        "source_url": "https://agentsniff.org",
        "copyright": "\u00a9 2026 ThirdKey.AI (https://thirdkey.ai)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_id": getattr(result, "scan_id", ""),
        "target_network": getattr(result, "target_network", config.target_network),
        "total_agents": summary.get("total_agents", 0),
        "by_confidence": summary.get("by_confidence", {}),
        "duration_seconds": summary.get("duration_seconds"),
        "agents": agents,
    }


async def send_alerts(result: Any, config: ScanConfig) -> list[str]:
    """Dispatch alerts to configured channels. Returns outcome strings."""
    global _last_alert_time

    outcomes: list[str] = []
    payload = _build_payload(result, config)

    if config.webhook_url:
        outcome = await _send_webhook(payload, config)
        outcomes.append(outcome)

    if config.smtp_to:
        outcome = await _send_email(payload, config)
        outcomes.append(outcome)

    if any("ok" in o for o in outcomes):
        _last_alert_time = time.monotonic()

    return outcomes


async def _send_webhook(payload: dict, config: ScanConfig) -> str:
    """POST alert payload to webhook URL."""
    headers = {"Content-Type": "application/json"}
    headers.update(config.webhook_headers)

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                config.webhook_url, json=payload, headers=headers
            ) as resp:
                if resp.status < 400:
                    logger.info(f"Webhook alert sent ({resp.status})")
                    return f"webhook:ok:{resp.status}"
                body = await resp.text()
                logger.warning(f"Webhook returned {resp.status}: {body[:200]}")
                return f"webhook:failed:{resp.status}"
    except Exception as e:
        logger.error(f"Webhook alert failed: {e}")
        return f"webhook:failed:{e}"


async def _send_email(payload: dict, config: ScanConfig) -> str:
    """Send alert email via SMTP (runs in executor to avoid blocking)."""
    if not config.smtp_host:
        return "email:skipped:no_smtp_host"

    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, _smtp_send, payload, config)
        logger.info(f"Email alert sent to {', '.join(config.smtp_to)}")
        return "email:ok"
    except Exception as e:
        logger.error(f"Email alert failed: {e}")
        return f"email:failed:{e}"


def _smtp_send(payload: dict, config: ScanConfig) -> None:
    """Blocking SMTP send — called via run_in_executor."""
    total = payload["total_agents"]
    by_conf = payload.get("by_confidence", {})
    conf_summary = ", ".join(f"{k}: {v}" for k, v in by_conf.items() if v)

    subject = f"[AgentSniff] {total} agent(s) detected on {payload.get('target_network', 'network')}"

    # Plain text body
    lines = [
        "AgentSniff Alert",
        "",
        f"Scan ID:   {payload.get('scan_id', 'N/A')}",
        f"Network:   {payload.get('target_network', 'N/A')}",
        f"Timestamp: {payload.get('timestamp', 'N/A')}",
        f"Duration:  {payload.get('duration_seconds', 'N/A')}s",
        "",
        f"Total Agents: {total}",
        f"By Confidence: {conf_summary}",
        "",
    ]

    for agent in payload.get("agents", []):
        lines.append(
            f"  {agent['ip_address']}"
            f"{':%s' % agent['port'] if agent.get('port') else ''}"
            f"  {agent['agent_type']}"
            f"  {agent['framework']}"
            f"  {agent['confidence_level']} ({agent['confidence_score']:.0%})"
        )

    lines.append("")
    lines.append("--")
    lines.append("AgentSniff (https://agentsniff.org) \u00a9 2026 ThirdKey.AI (https://thirdkey.ai)")

    text_body = "\n".join(lines)

    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"] = config.smtp_from or config.smtp_user
    msg["To"] = ", ".join(config.smtp_to)
    msg.attach(MIMEText(text_body, "plain"))

    # Attach JSON payload as a file
    json_part = MIMEText(json.dumps(payload, indent=2, default=str), "plain")
    json_part.add_header("Content-Disposition", "attachment", filename="alert-payload.json")
    msg.attach(json_part)

    if config.smtp_use_tls:
        server = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15)
        server.starttls()
    else:
        server = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15)

    try:
        if config.smtp_user and config.smtp_password:
            server.login(config.smtp_user, config.smtp_password)
        server.sendmail(
            config.smtp_from or config.smtp_user,
            config.smtp_to,
            msg.as_string(),
        )
    finally:
        server.quit()
