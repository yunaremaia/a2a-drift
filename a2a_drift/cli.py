"""CLI for a2a-drift."""

import argparse
import json
import sys

from a2a_drift import (
    AgentCardChecker,
    EndpointProber,
    ValidationResult,
    __version__,
)

SARIF_LEVELS = {"error": "error", "warning": "warning", "info": "note"}


def to_sarif(result: ValidationResult) -> dict:
    """Render a single ValidationResult as a SARIF 2.1.0 document."""
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "a2a-drift", "version": __version__}},
                "results": [
                    {
                        "level": SARIF_LEVELS.get(finding.severity, "warning"),
                        "message": {"text": finding.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": result.url}
                                }
                            }
                        ],
                        "ruleId": finding.drift_type,
                    }
                    for finding in result.drift
                ],
            }
        ],
    }


def _positive_int(value: str) -> int:
    """argparse type for counts that must be at least 1 (e.g. --retries)."""
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def _render(result: ValidationResult, output_format: str) -> str:
    """Render a validation result in the requested output format."""
    if output_format == "json":
        return json.dumps(
            {
                "url": result.url,
                "is_compliant": result.is_compliant,
                "spec_version": result.spec_version,
                "target_spec_version": result.spec_version_target,
                "jsonrpc_compliant": result.jsonrpc_compliant,
                "drift_count": len(result.drift),
                "attempts": result.attempts,
                "response_time_ms": result.response_time_ms,
                "drift": [
                    {
                        "type": d.drift_type,
                        "severity": d.severity,
                        "message": d.message,
                        "path": d.path,
                    }
                    for d in result.drift
                ],
                "error": result.error,
            },
            indent=2,
        )

    if output_format == "sarif":
        return json.dumps(to_sarif(result), indent=2)

    lines = []
    status = "✓ COMPLIANT" if result.is_compliant else "✗ NON-COMPLIANT"
    lines.append(f"[{status}] {result.url}")
    if result.spec_version:
        lines.append(f"  Spec version: {result.spec_version}")
    if result.jsonrpc_compliant is not None:
        lines.append(f"  JSON-RPC compliant: {result.jsonrpc_compliant}")
    if result.response_time_ms is not None:
        lines.append(f"  Response time: {result.response_time_ms}ms")
    if result.error:
        lines.append(f"  Error: {result.error}")
    lines.append(f"  Attempts: {result.attempts}")
    if result.drift:
        lines.append(f"  Drift findings ({len(result.drift)}):")
        for d in result.drift:
            lines.append(f"    [{d.severity.upper()}] {d.drift_type}: {d.message}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="a2a-drift", description="Detect A2A protocol compliance drift"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_network_args(subparser: argparse.ArgumentParser) -> None:
        """Add the retry and timeout options shared by every subcommand."""
        subparser.add_argument(
            "--retries",
            type=_positive_int,
            default=3,
            help="Max attempts on transient failures, must be >= 1 (default: 3)",
        )
        subparser.add_argument(
            "--timeout",
            type=float,
            default=10.0,
            help="HTTP timeout in seconds (default: 10.0)",
        )
        subparser.add_argument(
            "--allow-internal",
            action="store_true",
            help=(
                "Allow fetching internal/loopback addresses (e.g. "
                "http://127.0.0.1:8080). Off by default in --deny-internal mode."
            ),
        )
        subparser.add_argument(
            "--deny-internal",
            action="store_true",
            help=(
                "Refuse to fetch internal, loopback, link-local or reserved "
                "addresses (CWE-918). Use when the URL comes from untrusted input."
            ),
        )

    # check command
    check_parser = subparsers.add_parser("check", help="Validate an agent card")
    check_parser.add_argument("url", help="URL of the agent card")
    check_parser.add_argument(
        "--spec-version", default="1.0", help="Target spec version (default: 1.0)"
    )
    check_parser.add_argument(
        "--format", choices=["text", "json", "sarif"], default="text"
    )
    check_parser.add_argument("--output", "-o", help="Output file")
    add_network_args(check_parser)

    # probe command
    probe_parser = subparsers.add_parser("probe", help="Probe a live endpoint")
    probe_parser.add_argument("url", help="Endpoint URL")
    probe_parser.add_argument(
        "--method", default="message/send", help="JSON-RPC method"
    )
    probe_parser.add_argument("--params", default="{}", help="JSON params")
    probe_parser.add_argument(
        "--format", choices=["text", "json", "sarif"], default="text"
    )
    probe_parser.add_argument("--output", "-o", help="Output file")
    add_network_args(probe_parser)

    # batch command
    batch_parser = subparsers.add_parser("batch", help="Batch check multiple agents")
    batch_parser.add_argument("--file", required=True, help="File with agent card URLs")
    batch_parser.add_argument(
        "--format", choices=["text", "json", "sarif"], default="text"
    )
    batch_parser.add_argument("--output", "-o", help="Output file")
    add_network_args(batch_parser)

    args = parser.parse_args()

    allow_internal = args.allow_internal or not args.deny_internal

    if args.command == "check":
        checker = AgentCardChecker(
            args.url,
            timeout=args.timeout,
            max_retries=args.retries,
            target_spec_version=args.spec_version,
            allow_internal=allow_internal,
        )
        result = checker.validate()
        out_str = _render(result, args.format)

        if args.output:
            with open(args.output, "w") as f:
                f.write(out_str + "\n")
        else:
            print(out_str)

        sys.exit(0 if result.is_compliant else 1)

    elif args.command == "probe":
        try:
            params = json.loads(args.params) if args.params else {}
        except json.JSONDecodeError as e:
            parser.error(f"--params is not valid JSON: {e}")
        prober = EndpointProber(
            args.url,
            timeout=args.timeout,
            max_retries=args.retries,
            allow_internal=allow_internal,
        )
        result = prober.probe(args.method, params)
        out_str = _render(result, args.format)

        if args.output:
            with open(args.output, "w") as f:
                f.write(out_str + "\n")
        else:
            print(out_str)

        sys.exit(0 if result.is_compliant else 1)

    elif args.command == "batch":
        try:
            with open(args.file) as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"error: no such file: {args.file}", file=sys.stderr)
            sys.exit(1)
        except OSError as e:
            print(f"error: could not read {args.file}: {e}", file=sys.stderr)
            sys.exit(1)

        if not urls:
            # all([]) is True, so an empty list would report vacuous success.
            print(f"error: no agent card URLs found in {args.file}", file=sys.stderr)
            sys.exit(1)

        results = []
        for url in urls:
            # One broken card must never discard the rest of the run.
            try:
                checker = AgentCardChecker(
                    url,
                    timeout=args.timeout,
                    max_retries=args.retries,
                    allow_internal=allow_internal,
                )
                result = checker.validate()
            except Exception as e:  # noqa: BLE001 - isolate per-item failures
                result = ValidationResult(url=url)
                result.error = f"{type(e).__name__}: {e}"
                result.add_drift("internal-error", "error", result.error)
            results.append(result)

        if args.format == "json":
            out_str = json.dumps(
                [
                    {
                        "url": r.url,
                        "is_compliant": r.is_compliant,
                        "spec_version": r.spec_version,
                        "drift_count": len(r.drift),
                        "error": r.error,
                    }
                    for r in results
                ],
                indent=2,
            )
        elif args.format == "sarif":
            runs = []
            for r in results:
                runs.extend(to_sarif(r)["runs"])
            out_str = json.dumps(
                {
                    "version": "2.1.0",
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "runs": runs,
                },
                indent=2,
            )
        else:
            out_str = "\n".join(
                f"[{'✓ COMPLIANT' if r.is_compliant else '✗ NON-COMPLIANT'}] "
                f"{r.url} ({len(r.drift)} findings)"
                + (f" — {r.error}" if r.error else "")
                for r in results
            )

        if args.output:
            with open(args.output, "w") as f:
                f.write(out_str + "\n")
        else:
            print(out_str)

        sys.exit(0 if all(r.is_compliant for r in results) else 1)


if __name__ == "__main__":
    main()
