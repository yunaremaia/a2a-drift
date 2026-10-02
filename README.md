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

Not published to PyPI yet. Install from source:

```bash
pip install git+https://github.com/yunaremaia/a2a-drift.git
```

or, for development:

```bash
git clone https://github.com/yunaremaia/a2a-drift.git
cd a2a-drift
pip install -e .
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

# Validate against a specific spec version (drift is measured against this target)
a2a-drift check https://example.com/.well-known/agent-card.json --spec-version 0.3

# Refuse internal/loopback targets (use when the URL comes from untrusted input)
a2a-drift check "$AGENT_CARD_URL" --deny-internal

# Probe live endpoints
a2a-drift probe https://example.com/a2a --method message/send --params '{"message": {"messageId": "msg-1", "role": "user", "parts": [{"type": "text", "text": "hello"}]}}'

# Send a notification (no 'id') and assert the endpoint sends no response body
a2a-drift probe https://example.com/a2a --method tasks/cancel --params '{"id": "task-1"}' --notification

# Batch check multiple agents
a2a-drift batch --file agents.txt
```

`check`, `probe` and `batch` all accept `--format text|json|sarif`,
`--output FILE`, `--retries N` (N >= 1), `--timeout SECONDS`,
`--deny-internal` and `--allow-internal`. Exit code is `0` when the target is
compliant, `1` when any error-severity drift is found, `2` on a usage error.

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
print(result.jsonrpc_compliant)
print(result.response_time_ms)

# Send a notification: no 'id' is sent, and a response body is a violation
result = prober.probe("tasks/cancel", {"id": "task-1"}, notification=True)
```

### CI

Run the CLI in a workflow and upload the SARIF report to GitHub Code Scanning:

```yaml
- run: pip install git+https://github.com/yunaremaia/a2a-drift.git
- run: a2a-drift check "$AGENT_CARD_URL" --deny-internal --format sarif --output a2a-drift.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: a2a-drift.sarif
```

The CLI exits 1 when any error-severity drift is found, so it works as a
pass/fail gate directly. A prebuilt `action.yml` is on the roadmap but does
not exist yet.

## Drift Detection

| Drift Type | Description | Severity |
|---|---|---|
| `spec-version` | Agent card uses outdated spec version (e.g., v0.3 when v1.0 is current) | warning |
| `capability-advertised-but-unsupported` | Card advertises skill/endpoint that returns error on probe | error |
| `capability-supported-but-unadvertised` | Endpoint works but not listed in agent card | info |
| `jsonrpc-conformance` | Response violates JSON-RPC 2.0 spec | error |
| `jsonrpc-request` | Request params do not satisfy the method's A2A schema | warning |
| `schema-violation` | Agent card fails schema validation against A2A spec | error |
| `security-transport` | Missing HTTPS or authentication | warning |
| `streaming-drift` | Streaming capability advertised but SSE fails | error |

## Spec Coverage

- [A2A v1.0](https://a2a-protocol.org/latest/) — full agent card schema, JSON-RPC methods, task lifecycle
- [A2A v0.3](https://a2a-protocol.org/v0.3/) — legacy support with migration warnings
- [A2A Proto](https://github.com/a2aproject/A2A/tree/main/specification) — protocol buffer definitions

## Security

`a2a-drift` fetches URLs supplied on the command line. When those URLs come from
untrusted input (a CI job, a webhook, a shared config file), pass
`--deny-internal` to refuse loopback, private, link-local (including cloud
metadata at `169.254.169.254`), reserved and multicast addresses -- the SSRF
class of attack tracked as CWE-918. Internal checks stay allowed by default, so
local development against `http://127.0.0.1:8080` keeps working; `--deny-internal`
is the hardening switch and `--allow-internal` overrides it explicitly.

For the library API, `validate_url(url, allow_internal=False)` returns an error
message or `None`, and `AgentCardChecker` / `EndpointProber` accept
`allow_internal=`.

To report a vulnerability, please see [SECURITY.md](SECURITY.md).

## Roadmap

- [x] Agent card schema validation (v1.0 + v0.3)
- [x] Live endpoint probing (message/send, tasks/get, tasks/cancel)
- [x] JSON-RPC 2.0 conformance checks
- [x] Spec version drift detection
- [x] SARIF output
- [ ] Custom conformance profiles (issue #5)
- [ ] Prebuilt GitHub Action (`action.yml`) — not yet available
- [ ] CI/CD integration (exit codes, JSON output)
- [ ] Streaming (SSE) capability verification
- [ ] Authentication/transport security checks
- [ ] Historical drift tracking (compare snapshots over time)
- [ ] MCP ↔ A2A bridge drift detection

## License

MIT

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
