import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import httpx

from .checks import encoding, permissions, poisoning, provenance, shadowing
from .drift import snapshot_and_diff
from .report import print_console, to_json, to_markdown, to_sarif
from .severity import Severity
from .transport import MCPError, make_client


def scan(target: str, headers: dict[str, str] | None = None,
         no_drift: bool = False, update_snapshot: bool = True):
    findings = []
    client = make_client(target, headers=headers)
    try:
        # Turn httpx network errors into MCPError so main() can print something
        # readable instead of a raw traceback.
        try:
            init_result = client.initialize() or {}
            tools = client.list_tools()
            resources = client.list_resources()
            prompts = client.list_prompts()
        except httpx.HTTPError as exc:
            raise MCPError(f"{type(exc).__name__}: {exc}") from exc

        findings += provenance.check_server_metadata(init_result, target)

        for tool in tools:
            findings += poisoning.check_tool_poisoning(tool)
            findings += permissions.check_permissions(tool)
            findings += encoding.check_encoded_payloads(tool)

        findings += permissions.check_scope(tools)
        findings += shadowing.check_shadowing(tools)

        # Resources and prompts carry descriptions too, so run the poisoning
        # checks over them as well.
        for item in resources + prompts:
            findings += poisoning.check_tool_poisoning(item)

        if not no_drift:
            findings += snapshot_and_diff(target, tools, update=update_snapshot)

        meta = {
            "tool_count": len(tools),
            "resource_count": len(resources),
            "prompt_count": len(prompts),
            "server_info": init_result.get("serverInfo", {}),
            "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        return findings, tools, meta
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-scan",
        description="Security scanner for MCP servers: tool poisoning, rug pull, "
                    "shadowing, excessive permissions.",
        epilog="Examples:\n"
               "  mcp-scan https://example.com/mcp\n"
               "  mcp-scan 'npx -y @some/mcp-server'\n"
               "  mcp-scan https://example.com/mcp --header 'Authorization: Bearer X'\n"
               "  mcp-scan 'python3 tests/fixtures/malicious_server.py' --markdown report.md\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="URL (http/https) or the command that starts the server")
    parser.add_argument("--header", action="append", default=[],
                        help="HTTP header as 'Name: Value' (repeatable)")
    parser.add_argument("--json", metavar="PATH", help="write a JSON report")
    parser.add_argument("--markdown", metavar="PATH", help="write a Markdown report")
    parser.add_argument("--sarif", metavar="PATH", help="write SARIF, for GitHub Code Scanning")
    parser.add_argument("--no-drift", action="store_true",
                        help="do not create or compare a snapshot")
    parser.add_argument("--no-update-snapshot", action="store_true",
                        help="compare against the snapshot but do not update it")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                        default="high",
                        help="exit 1 if any finding is at this level or above (for CI)")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    headers = {}
    for raw in args.header:
        if ":" not in raw:
            print(f"malformed header: {raw}", file=sys.stderr)
            return 2
        key, value = raw.split(":", 1)
        headers[key.strip()] = value.strip()

    try:
        findings, tools, meta = scan(
            args.target,
            headers=headers or None,
            no_drift=args.no_drift,
            update_snapshot=not args.no_update_snapshot,
        )
    except MCPError as exc:
        print(f"could not reach the server: {exc}", file=sys.stderr)
        print("Check that it speaks MCP over the transport you selected.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130

    if not args.quiet:
        print_console(findings, args.target, len(tools))

    if args.json:
        Path(args.json).write_text(to_json(findings, args.target, meta), encoding="utf-8")
    if args.markdown:
        Path(args.markdown).write_text(to_markdown(findings, args.target, meta), encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(
            json.dumps(to_sarif(findings, args.target), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    threshold = {
        "low": Severity.LOW, "medium": Severity.MEDIUM,
        "high": Severity.HIGH, "critical": Severity.CRITICAL,
    }[args.fail_on]
    return 1 if any(f.severity >= threshold for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
