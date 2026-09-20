"""CLI for a2a-drift."""

import argparse
import json
import sys
from a2a_drift import AgentCardChecker, EndpointProber


def main():
    parser = argparse.ArgumentParser(
        prog="a2a-drift",
        description="Detect A2A protocol compliance drift"
    )
    subparsers = parser.add_subparsers(dest="command")
    
    # check command
    check_parser = subparsers.add_parser("check", help="Validate an agent card")
    check_parser.add_argument("url", help="URL of the agent card")
    check_parser.add_argument("--spec-version", default="1.0", help="Target spec version")
    check_parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    check_parser.add_argument("--output", "-o", help="Output file")
    check_parser.add_argument("--retries", type=int, default=3, help="Max retries on transient failures (default: 3)")
    check_parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10.0)")
    
    # probe command
    probe_parser = subparsers.add_parser("probe", help="Probe a live endpoint")
    probe_parser.add_argument("url", help="Endpoint URL")
    probe_parser.add_argument("--method", default="message/send", help="JSON-RPC method")
    probe_parser.add_argument("--params", default="{}", help="JSON params")
    probe_parser.add_argument("--format", choices=["text", "json"], default="text")
    probe_parser.add_argument("--retries", type=int, default=3, help="Max retries on transient failures (default: 3)")
    probe_parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10.0)")
    
    # batch command
    batch_parser = subparsers.add_parser("batch", help="Batch check multiple agents")
    batch_parser.add_argument("--file", required=True, help="File with agent card URLs")
    batch_parser.add_argument("--format", choices=["text", "json"], default="text")
    batch_parser.add_argument("--retries", type=int, default=3, help="Max retries on transient failures (default: 3)")
    batch_parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10.0)")
    
    args = parser.parse_args()
    
    if args.command == "check":
        checker = AgentCardChecker(args.url, timeout=args.timeout, max_retries=args.retries)
        result = checker.validate()
        
        if args.format == "json":
            output = {
                "url": result.url,
                "is_compliant": result.is_compliant,
                "spec_version": result.spec_version,
                "drift_count": len(result.drift),
                "attempts": result.attempts,
                "drift": [
                    {
                        "type": d.drift_type,
                        "severity": d.severity,
                        "message": d.message,
                        "path": d.path
                    }
                    for d in result.drift
                ],
                "error": result.error
            }
            out_str = json.dumps(output, indent=2)
        else:
            lines = []
            status = "✓ COMPLIANT" if result.is_compliant else "✗ NON-COMPLIANT"
            lines.append(f"[{status}] {result.url}")
            if result.spec_version:
                lines.append(f"  Spec version: {result.spec_version}")
            if result.error:
                lines.append(f"  Error: {result.error}")
            lines.append(f"  Attempts: {result.attempts}")
            if result.drift:
                lines.append(f"  Drift findings ({len(result.drift)}):")
                for d in result.drift:
                    lines.append(f"    [{d.severity.upper()}] {d.drift_type}: {d.message}")
            out_str = "\n".join(lines)
        
        if args.output:
            with open(args.output, "w") as f:
                f.write(out_str + "\n")
        else:
            print(out_str)
        
        sys.exit(0 if result.is_compliant else 1)
    
    elif args.command == "probe":
        prober = EndpointProber(args.url, timeout=args.timeout, max_retries=args.retries)
        result = prober.probe(args.method, json.loads(args.params) if args.params else {})
        
        if args.format == "json":
            output = {
                "url": result.url,
                "is_compliant": result.is_compliant,
                "jsonrpc_compliant": result.jsonrpc_compliant,
                "drift_count": len(result.drift),
                "attempts": result.attempts,
                "response_time_ms": result.response_time_ms,
                "drift": [
                    {
                        "type": d.drift_type,
                        "severity": d.severity,
                        "message": d.message
                    }
                    for d in result.drift
                ],
                "error": result.error
            }
            out_str = json.dumps(output, indent=2)
        else:
            lines = []
            status = "✓ COMPLIANT" if result.is_compliant else "✗ NON-COMPLIANT"
            lines.append(f"[{status}] {result.url}")
            lines.append(f"  Response time: {result.response_time_ms}ms")
            lines.append(f"  Attempts: {result.attempts}")
            if result.error:
                lines.append(f"  Error: {result.error}")
            if result.drift:
                lines.append(f"  Drift findings ({len(result.drift)}):")
                for d in result.drift:
                    lines.append(f"    [{d.severity.upper()}] {d.drift_type}: {d.message}")
            out_str = "\n".join(lines)
        
        print(out_str)
        sys.exit(0 if result.is_compliant else 1)
    
    elif args.command == "batch":
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]
        
        results = []
        for url in urls:
            checker = AgentCardChecker(url, timeout=args.timeout, max_retries=args.retries)
            result = checker.validate()
            results.append({
                "url": result.url,
                "is_compliant": result.is_compliant,
                "drift_count": len(result.drift),
                "error": result.error
            })
        
        if args.format == "json":
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                status = "✓ COMPLIANT" if r["is_compliant"] else "✗ NON-COMPLIANT"
                print(f"[{status}] {r['url']} ({r['drift_count']} findings)")
        
        sys.exit(0 if all(r["is_compliant"] for r in results) else 1)


if __name__ == "__main__":
    main()

