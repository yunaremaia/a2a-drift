# a2a-drift

Detect [A2A (Agent2Agent)](https://a2a-protocol.org) protocol compliance drift — agent cards, endpoints, spec versions, JSON-RPC conformance.

## Problem

The A2A protocol (25k+ stars, v1.0 since March 2026) is the Linux Foundation standard for agent-to-agent communication. But:

- **Agent cards rot** — capabilities advertised in the card drift from what the endpoint actually serves.
- **Spec versions diverge** — agents still on v0.3 while the ecosystem moves to v1.0.
- **JSON-RPC conformance decays** — endpoints silently break protocol contracts.
- **No drift detection exists** — `a2a-inspector` is a web debugger, `a2a-lint` validates cards statically, but nothing tracks drift over time or compares advertised vs actual behavior.

## Solution

`a2a-drift` is a CLI + library that:

1. **Fetches** an agent card from any URL.
2. **Validates** it against the A2A v1.0 spec (proto + JSON schema).
3. **Probes** live endpoints for JSON-RPC conformance (`message/send`, `tasks/get`, `tasks/cancel`).
4. **Detects drift** between advertised capabilities and actual endpoint behavior.
5. **Tracks spec version drift** (v0.3 → v1.0 migration status).
6. **Outputs SARIF** for GitHub Advanced Security integration.
7. **CI-friendly** — exit codes, JSON output, GitHub Actions support.

## Install

```bash
pip install a2a-drift
```

## Usage

### CLI

```bash
# Check an A2A agent for drift
a2a-drift check https://example.com/.well-known/agent-card.json

# Output as JSON
a2a-drift check https://example.com/.well-known/agent-card.json --format json

# Output as SARIF (for GitHub Advanced Security)
a2a-drift check https://example.com/.well-known/agent-card.json --format sarif --output results.sarif

# Validate against a specific spec version
a2a-drift check https://example.com/.well-known/agent-card.json --spec-version 1.0

# Probe live endpoints
a2a-drift probe https://example.com/a2a --method message/send --params '{"message": {"role": "user", "parts": [{"type": "text", "text": "hello"}]}}'

# Batch check multiple agents
a2a-drift batch --file agents.txt
```

### Library

```python
from a2a_drift import AgentCardChecker, EndpointProber

# Check agent card
checker = AgentCardChecker("https://example.com/.well-known/agent-card.json")
result = checker.validate()
print(result.drift)  # list of drift findings
print(result.spec_version)  # "1.0" or "0.3"
print(result.is_compliant)  # bool

# Probe endpoint
prober = EndpointProber("https://example.com/a2a")
result = prober.probe("message/send", {"message": {...}})
print(result.is_jsonrpc_compliant)
print(result.response_time_ms)
```

### GitHub Action

```yaml
- uses: yunaremaia/a2a-drift@v1
  with:
    url: https://your-agent.com/.well-known/agent-card.json
    spec-version: '1.0'
    fail-on-drift: true
```

## Drift Detection

| Drift Type | Description | Severity |
|---|---|---|
| `spec-version` | Agent card uses outdated spec version (e.g., v0.3 when v1.0 is current) | warning |
| `capability-advertised-but-unsupported` | Card advertises skill/endpoint that returns error on probe | error |
| `capability-supported-but-unadvertised` | Endpoint works but not listed in agent card | info |
| `jsonrpc-conformance` | Response violates JSON-RPC 2.0 spec | error |
| `schema-violation` | Agent card fails schema validation against A2A spec | error |
| `security-transport` | Missing HTTPS or authentication | warning |
| `streaming-drift` | Streaming capability advertised but SSE fails | error |

## Spec Coverage

- [A2A v1.0](https://a2a-protocol.org/latest/) — full agent card schema, JSON-RPC methods, task lifecycle
- [A2A v0.3](https://a2a-protocol.org/v0.3/) — legacy support with migration warnings
- [A2A Proto](https://github.com/a2aproject/A2A/tree/main/specification) — protocol buffer definitions

## Roadmap

- [ ] Agent card schema validation (v1.0 + v0.3)
- [ ] Live endpoint probing (message/send, tasks/get, tasks/cancel)
- [ ] JSON-RPC 2.0 conformance checks
- [ ] Spec version drift detection
- [ ] SARIF output
- [ ] GitHub Action
- [ ] CI/CD integration (exit codes, JSON output)
- [ ] Streaming (SSE) capability verification
- [ ] Authentication/transport security checks
- [ ] Historical drift tracking (compare snapshots over time)
- [ ] MCP ↔ A2A bridge drift detection

## License

MIT

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
