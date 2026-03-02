"""
AgentScan - CLI Interface

Rich terminal interface for running scans with table, JSON, and CSV output.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from agentscan.config import ScanConfig, default_config_yaml
from agentscan.scanner import run_scan


# ── Color codes for terminal output ──────────────────────────────────────
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


BANNER = f"""{Colors.CYAN}{Colors.BOLD}
    ___                    __  _____                 
   /   | ____ ____  ____  / /_/ ___/_________ _____ 
  / /| |/ __ `/ _ \\/ __ \\/ __/\\__ \\/ ___/ __ `/ __ \\
 / ___ / /_/ /  __/ / / / /_ ___/ / /__/ /_/ / / / /
/_/  |_\\__, /\\___/_/ /_/\\__//____/\\___/\\__,_/_/ /_/ 
      /____/                                         
{Colors.RESET}{Colors.DIM}  AI Agent Network Scanner v1.0.0
  Detect AI agents on your network{Colors.RESET}
"""

CONFIDENCE_COLORS = {
    "confirmed": Colors.GREEN,
    "high": Colors.YELLOW,
    "medium": Colors.BLUE,
    "low": Colors.DIM,
}

STATUS_ICONS = {
    "verified": "✓",
    "detected": "◉",
    "suspected": "◎",
    "unknown": "○",
}


def setup_logging(verbose: bool = False, quiet: bool = False):
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            f"{Colors.DIM}%(asctime)s{Colors.RESET} "
            f"%(levelname)-8s "
            f"{Colors.CYAN}%(name)s{Colors.RESET} %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    logging.root.handlers = [handler]
    logging.root.setLevel(level)


def print_table(result):
    """Print scan results as a formatted table."""
    agents = result.agents_detected
    summary = result.summary

    # Header
    print(f"\n{Colors.BOLD}{'═' * 78}{Colors.RESET}")
    print(f"{Colors.BOLD}  SCAN RESULTS  {Colors.RESET}{Colors.DIM}│  "
          f"ID: {result.scan_id[:8]}  │  "
          f"Duration: {result.duration_seconds:.1f}s  │  "
          f"Detectors: {len(result.detectors_run)}{Colors.RESET}")
    print(f"{Colors.BOLD}{'═' * 78}{Colors.RESET}")

    if not agents:
        print(f"\n  {Colors.DIM}No AI agents detected on {result.target_network}{Colors.RESET}\n")
        return

    # Summary bar
    total = summary["total_agents"]
    by_conf = summary.get("by_confidence", {})
    print(f"\n  {Colors.BOLD}{total} agent(s) detected{Colors.RESET}  ", end="")
    for level, count in by_conf.items():
        color = CONFIDENCE_COLORS.get(level, Colors.DIM)
        print(f" {color}■ {level}: {count}{Colors.RESET}", end="")
    print()

    # Table header
    print(f"\n  {'Host':<20} {'Port':<7} {'Type':<18} {'Framework':<14} "
          f"{'Confidence':<14} {'Signals':<8} {'Status'}")
    print(f"  {'─' * 20} {'─' * 7} {'─' * 18} {'─' * 14} "
          f"{'─' * 14} {'─' * 8} {'─' * 10}")

    for agent in agents:
        conf_level = agent.display_confidence.value
        color = CONFIDENCE_COLORS.get(conf_level, Colors.DIM)
        icon = STATUS_ICONS.get(agent.status.value, "○")

        conf_display = f"{agent.confidence_score:.0%} ({conf_level})"
        port_display = str(agent.port) if agent.port else "—"

        print(
            f"  {Colors.BOLD}{agent.ip_address:<20}{Colors.RESET} "
            f"{port_display:<7} "
            f"{agent.agent_type:<18} "
            f"{agent.framework:<14} "
            f"{color}{conf_display:<14}{Colors.RESET} "
            f"{len(agent.signals):<8} "
            f"{color}{icon} {agent.status.value}{Colors.RESET}"
        )

    # Detailed signals
    print(f"\n{Colors.BOLD}{'─' * 78}{Colors.RESET}")
    print(f"  {Colors.BOLD}DETECTION DETAILS{Colors.RESET}")
    print(f"{'─' * 78}")

    for agent in agents:
        conf_level = agent.display_confidence.value
        color = CONFIDENCE_COLORS.get(conf_level, Colors.DIM)
        print(
            f"\n  {color}{Colors.BOLD}▸ {agent.ip_address}"
            f"{f':{agent.port}' if agent.port else ''}{Colors.RESET}"
            f"  {Colors.DIM}({agent.agent_type}){Colors.RESET}"
        )

        # AgentPin identity
        if agent.agentpin_identity:
            ap = agent.agentpin_identity
            print(f"    {Colors.GREEN}⚿ AgentPin:{Colors.RESET} "
                  f"{ap.get('agent_id', 'unknown')} "
                  f"(issuer: {ap.get('issuer', 'unknown')})")
            caps = ap.get("capabilities", [])
            if caps:
                print(f"      Capabilities: {', '.join(caps[:5])}")

        # MCP capabilities
        if agent.mcp_capabilities:
            mcp = agent.mcp_capabilities
            si = mcp.get("server_info", {})
            print(f"    {Colors.MAGENTA}⚡ MCP Server:{Colors.RESET} "
                  f"{si.get('name', 'unknown')} v{si.get('version', '?')}")

        # Signals
        for signal in agent.signals[:6]:
            sig_color = CONFIDENCE_COLORS.get(signal.confidence.value, Colors.DIM)
            print(f"    {sig_color}● [{signal.detector.value}]{Colors.RESET} "
                  f"{signal.description}")

        remaining = len(agent.signals) - 6
        if remaining > 0:
            print(f"    {Colors.DIM}... and {remaining} more signal(s){Colors.RESET}")

    # Errors
    if result.errors:
        print(f"\n{Colors.YELLOW}  ⚠ {len(result.errors)} error(s) during scan:{Colors.RESET}")
        for err in result.errors[:5]:
            print(f"    {Colors.DIM}• {err}{Colors.RESET}")

    print(f"\n{Colors.BOLD}{'═' * 78}{Colors.RESET}\n")


def print_json(result):
    """Print scan results as JSON."""
    print(json.dumps(result.to_dict(), indent=2, default=str))


def print_csv(result):
    """Print scan results as CSV."""
    print("host,ip_address,port,agent_type,framework,confidence_score,"
          "confidence_level,status,signal_count,first_seen,last_seen")
    for agent in result.agents_detected:
        print(
            f"{agent.host},{agent.ip_address},{agent.port or ''},"
            f"{agent.agent_type},{agent.framework},"
            f"{agent.confidence_score},{agent.display_confidence.value},"
            f"{agent.status.value},{len(agent.signals)},"
            f"{agent.first_seen.isoformat()},{agent.last_seen.isoformat()}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentscan",
        description="AI Agent Network Scanner - Detect AI agents on your network",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  agentscan scan 192.168.1.0/24
  agentscan scan 10.0.0.0/16 --format json --output results.json
  agentscan scan 192.168.1.0/24 --detectors port_scanner,mcp_detector
  agentscan scan --hosts server1,server2,server3
  agentscan serve --port 9090
  agentscan init-config
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── scan command ─────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Run a network scan")
    scan_parser.add_argument(
        "network", nargs="?", default="192.168.1.0/24",
        help="Target network in CIDR notation (default: 192.168.1.0/24)",
    )
    scan_parser.add_argument(
        "--hosts", type=str, default="",
        help="Comma-separated list of specific hosts to scan",
    )
    scan_parser.add_argument(
        "--exclude", type=str, default="",
        help="Comma-separated list of hosts to exclude",
    )
    scan_parser.add_argument(
        "--config", type=str, default="",
        help="Path to YAML configuration file",
    )
    scan_parser.add_argument(
        "--format", "-f", choices=["table", "json", "csv"], default="table",
        help="Output format (default: table)",
    )
    scan_parser.add_argument(
        "--output", "-o", type=str, default="",
        help="Output file path (default: stdout)",
    )
    scan_parser.add_argument(
        "--detectors", type=str, default="",
        help="Comma-separated list of detectors to enable (default: all)",
    )
    scan_parser.add_argument(
        "--timeout", type=float, default=5.0,
        help="HTTP request timeout in seconds (default: 5.0)",
    )
    scan_parser.add_argument(
        "--concurrency", type=int, default=100,
        help="Maximum concurrent connections (default: 100)",
    )
    scan_parser.add_argument(
        "--continuous", type=int, default=0,
        help="Continuous scanning interval in seconds (0 = one-shot)",
    )
    scan_parser.add_argument("-v", "--verbose", action="store_true")
    scan_parser.add_argument("-q", "--quiet", action="store_true")

    # ── serve command ────────────────────────────────────────────────
    serve_parser = subparsers.add_parser("serve", help="Start web dashboard API server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    serve_parser.add_argument("--port", type=int, default=9090, help="Bind port")
    serve_parser.add_argument(
        "--network", default="192.168.1.0/24",
        help="Default scan target network",
    )
    serve_parser.add_argument("-v", "--verbose", action="store_true")

    # ── init-config command ──────────────────────────────────────────
    subparsers.add_parser("init-config", help="Generate default configuration file")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    if args.command == "init-config":
        config_path = Path("agentscan.yaml")
        config_path.write_text(default_config_yaml())
        print(f"Generated default config: {config_path}")
        sys.exit(0)

    if args.command == "serve":
        setup_logging(verbose=args.verbose)
        from agentscan.api.server import start_server
        start_server(
            host=args.host,
            port=args.port,
            default_network=args.network,
        )
        sys.exit(0)

    if args.command == "scan":
        setup_logging(verbose=args.verbose, quiet=args.quiet)

        if not args.quiet:
            print(BANNER)

        # Build config
        if args.config:
            config = ScanConfig.from_yaml(args.config)
        else:
            config = ScanConfig.from_env()

        # Apply CLI overrides
        config.target_network = args.network
        config.output_format = args.format
        config.output_file = args.output
        config.verbose = args.verbose
        config.quiet = args.quiet
        config.http_timeout = args.timeout
        config.port_scan_concurrency = args.concurrency
        config.scan_interval = args.continuous

        if args.hosts:
            config.target_hosts = [h.strip() for h in args.hosts.split(",")]

        if args.exclude:
            config.exclude_hosts = [h.strip() for h in args.exclude.split(",")]

        # Selective detector enabling
        if args.detectors:
            enabled = set(d.strip() for d in args.detectors.split(","))
            all_detector_names = [
                "dns_monitor", "port_scanner", "agentpin_prober",
                "mcp_detector", "endpoint_prober", "tls_fingerprint",
                "traffic_analyzer",
            ]
            for name in all_detector_names:
                setattr(config, f"enable_{name}", name in enabled)

        # Run scan
        if config.scan_interval > 0:
            asyncio.run(_continuous_scan(config))
        else:
            result = asyncio.run(run_scan(config))
            _output_result(result, config)


async def _continuous_scan(config: ScanConfig):
    """Run scans continuously at the configured interval."""
    scan_num = 0
    try:
        while True:
            scan_num += 1
            logger = logging.getLogger("agentscan")
            logger.info(f"Starting scan #{scan_num}")

            result = await run_scan(config)
            _output_result(result, config)

            logger.info(f"Next scan in {config.scan_interval}s...")
            await asyncio.sleep(config.scan_interval)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan stopped by user{Colors.RESET}")


def _output_result(result, config: ScanConfig):
    """Output scan result in the configured format."""
    # Route output
    if config.output_file:
        with open(config.output_file, "w") as f:
            if config.output_format == "json":
                json.dump(result.to_dict(), f, indent=2, default=str)
            elif config.output_format == "csv":
                # Redirect stdout temporarily
                import io
                buf = io.StringIO()
                sys.stdout = buf
                print_csv(result)
                sys.stdout = sys.__stdout__
                f.write(buf.getvalue())
            else:
                import io
                buf = io.StringIO()
                sys.stdout = buf
                print_table(result)
                sys.stdout = sys.__stdout__
                f.write(buf.getvalue())
        if not config.quiet:
            print(f"{Colors.GREEN}Results saved to {config.output_file}{Colors.RESET}")
    else:
        if config.output_format == "json":
            print_json(result)
        elif config.output_format == "csv":
            print_csv(result)
        else:
            print_table(result)


if __name__ == "__main__":
    main()
