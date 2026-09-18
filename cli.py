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
    
    # probe command
    probe_parser = subparsers.add_parser("probe", help="Probe a live endpoint")
    probe_parser.add_argument("url", help="Endpoint URL")
    probe_parser.add_argument("--method", default="message/send", help="JSON-RPC method")
    probe_parser.add_argument("--params", default="{}", help="JSON params")
    probe_parser.add_argument("--format", choices=["text", "json"], default="text")
    
    # batch command
    batch_parser = subparsers.add_parser("batch", help="Batch check multiple agents")
    batch_parser.add_argument("--file", required=True, help="File with agent card URLs")
    batch_parser.add_argument("--format", choices=["text", "json"], default="text")
    
    args = parser.parse_args()
    
    if args.command == "check":
        checker = AgentCardChecker(args.url)
        result = checker.validate()
        
        if args.format == "json":
            output = {
                "url": result.url,
                "is_compliant": result.is_compliant,
                "spec_version": result.spec_version,
                "drift_count": len(result.drift),
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
            if result.drift:
                lines.append(f"  Drift findings ({len(result.drift)}):")
                for d in result.drift:
                    lines.append(f"    [{d.severity.upper()}] {d.drift_type}: {d.message}")
            out_str = "\n".join(lines)
        
        if args.output:
            with open(args.output, "w") as f:
                f.write(out_str)
        else:
            print(out_str)
        
        sys.exit(0 if result.is_compliant else 1)
    
    elif args.command == "probe":
        import json as json_mod
        params = json_mod.loads(args.params)
        prober = EndpointProber(args.url)
        result = prober.probe(args.method, params)
        
        if args.format == "json":
            output = {
                "url": result.url,
                "jsonrpc_compliant": result.jsonrpc_compliant,
                "response_time_ms": result.response_time_ms,
                "drift_count": len(result.drift),
                "drift": [{"type": d.drift_type, "severity": d.severity, "message": d.message} for d in result.drift],
                "error": result.error
            }
            print(json.dumps(output, indent=2))
        else:
            status = "✓ JSON-RPC COMPLIANT" if result.jsonrpc_compliant else "✗ NON-COMPLIANT"
            print(f"[{status}] {args.url}")
            print(f"  Method: {args.method}")
            if result.response_time_ms:
                print(f"  Response time: {result.response_time_ms:.2f}ms")
            if result.error:
                print(f"  Error: {result.error}")
            for d in result.drift:
                print(f"  [{d.severity.upper()}] {d.drift_type}: {d.message}")
        
        sys.exit(0 if result.jsonrpc_compliant else 1)
    
    elif args.command == "batch":
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        
        results = []
        for url in urls:
            checker = AgentCardChecker(url)
            result = checker.validate()
            results.append(result)
            status = "✓" if result.is_compliant else "✗"
            print(f"{status} {url}")
        
        compliant_count = sum(1 for r in results if r.is_compliant)
        print(f"\n{compliant_count}/{len(results)} compliant")
        
        sys.exit(0 if compliant_count == len(results) else 1)
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
