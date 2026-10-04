# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- `a2a_drift.jsonrpc.validate_method_request()`: A2A method request-schema
  validation for `message/send`, `tasks/get` and `tasks/cancel`, reported by
  `probe()` as `jsonrpc-request` drift. Field names follow the A2A payloads
  (`TaskIdParams.id`, `Message.messageId`/`role`/`parts`); methods without a
  schema are never reported on.
- `probe(..., notification=True)` and `a2a-drift probe --notification` send a
  request with no `id` and assert the endpoint returns no response body, per
  JSON-RPC 2.0 §4.1.
- `validate_url()` helper plus `--deny-internal` / `--allow-internal` CLI flags to
  refuse internal, loopback, link-local and reserved addresses (CWE-918).
- `--spec-version` is now honored: the target version is threaded through to
  `AgentCardChecker` and reported as `target_spec_version` in JSON output.
- `ValidationResult.spec_version_target` records the version drift was measured against.
- `to_sarif()` in `a2a_drift/cli.py`; `check`, `probe` and `batch` accept `--format sarif`.
- `--output` is now honored by the `probe` subcommand.
- CI now tests Python 3.9, the floor declared in `pyproject.toml`.
- A `[dev]` extra in `pyproject.toml`, so `pip install -e ".[dev]"` installs
  the tools this project is developed with instead of silently installing
  nothing. Before it existed the documented setup command installed only the
  package: pip *warns* on an unknown extra and still exits 0, so the gap was
  invisible, and CI hid it by naming `pytest`, `pytest-cov`, `ruff` and `mypy`
  in its own install steps. `test_packaging.py` now fails if CI installs a tool
  the extra does not declare, so the two cannot drift apart.
- `test_packaging.py` fails if `requires-python` and the CI matrix drift apart, or
  if 3.10+-only syntax (PEP 604 `X | None` unions) sneaks into the package.
- A coverage floor of 100% is enforced from `pyproject.toml`
  (`[tool.coverage.report] fail_under`), so the CI test job now fails when
  coverage regresses instead of only reporting it.

### Changed

- Non-positive `--retries` values are rejected by argparse (exit 2) instead of
  crashing with `UnboundLocalError`; the library constructors clamp to 1 attempt.
- `batch` isolates per-URL failures, reports every entry, and treats an empty
  URL file as an error rather than a vacuous success.

### Fixed

- `probe` sends the `params` the operator typed, and says so in its findings.
  The payload was built with `params or {}`, which tested *truthiness* instead
  of absence, so every falsy JSON value -- `[]`, `0`, `false`, `""` -- was
  replaced by an empty object on the wire, while `validate_method_request()`
  was handed the original and named its type. `--params '[]'` reported "params
  must be a JSON object, got list" for a request the endpoint never received:
  the report described a probe that was not performed, and the run's
  JSON-RPC verdict was attributed to the wrong payload. `params` is now
  forwarded verbatim, and an *absent* value omits the member entirely instead
  of inventing an empty object, which is what "not supplied" means to
  `--params`. `--params null` also sends no member: JSON-RPC 2.0 requires
  `params` to be a Structured value when present, and the validator already
  read `None` as "no params".
- A JSON-RPC response whose `id` has the right value but the wrong type is now
  reported as drift. `probe()` sends `"id": 1` and verified the answer with a
  bare `!=`, and Python has `True == 1` and `1.0 == 1`, so an endpoint replying
  with a boolean or float id took the conforming branch and was reported
  compliant with an empty drift list and exit 0 -- a false green in CI. The id
  is now compared by value *and* type. The predicate only adds branches, so no
  response that was previously flagged becomes silent. Contributed by
  [@Jah-yee](https://github.com/Jah-yee) in #46.
- An unwritable `--output` path exits 2 with the path on stderr, on `check`,
  `probe` and `batch`. It previously raised an unhandled `OSError` out of
  `main()` and exited 1 -- the same code used for a genuine NON-COMPLIANT
  result, so a crash was indistinguishable from a real finding. Contributed by
  [@Jah-yee](https://github.com/Jah-yee) in #46.
- `--spec-version` normalises the target the same way the detected
  `protocolVersion` is normalised, instead of comparing a normalised value
  against a raw command-line string. `1.0.0`, `1.0-rc.1`, `1.0+build.7` and a
  leading `v` (`v1.0`) now measure as `1.0`, so an equivalent spelling no
  longer reports phantom drift against a conformant agent. A target that names
  no known spec version (`banana`, `9.9`, `1`) is now rejected by argparse with
  exit code 2, before any request is issued, instead of being accepted silently
  and exiting 0; an empty or whitespace-only `--spec-version` is rejected too,
  where `target_spec_version or CURRENT_SPEC` had folded it into the default
  and made a typo indistinguishable from an omitted flag.
  `AgentCardChecker(target_spec_version=...)` raises `ValueError` on the same
  unusable values rather than quietly measuring against the current spec.
  Unchanged on purpose: a genuine mismatch (a 0.3 agent against a 1.0 target)
  is still reported, with the same severity and message.
- A non-UTF-8 agent card body is reported as a `json-decode-error` finding with
  a non-zero exit code, instead of raising an uncaught `UnicodeDecodeError` out
  of `validate()`. `issubclass(UnicodeDecodeError, json.JSONDecodeError)` is
  False (it inherits `ValueError`), so the `except json.JSONDecodeError` around
  the parse never fired; the CLI printed no report and a traceback aborted a
  whole `batch` run. Decoding is named apart from JSON syntax on purpose: a
  body that never decoded was never parsed, and the two need different fixes.
- `check` isolates an unexpected checker failure the way `batch` already did
  per URL, so a caller-supplied URL can no longer cost the operator the report.
- Required agent-card fields are validated by *value*, not by key presence. A
  card whose `name`, `description`, `url`, `version` or `capabilities` was
  `null`, held a wrong type (a number where a string belongs), or held a blank
  string now reports a `schema-violation` and exits 1; it previously reported
  `is_compliant=true`, `drift_count=0` and exit 0. The finding distinguishes
  *absent*, *present but null*, *present but wrong type* and *present but
  empty*, and reads with `.get` so a stored null is not read as an absent key.
  Unchanged on purpose: `capabilities={}` stays a warning.
- A JSON array, `null`, string or number agent card is reported as a
  `schema-violation` finding instead of raising `AttributeError`/`TypeError`.
- `--format sarif` emits a real SARIF 2.1.0 document; it previously accepted the
  flag and printed the human-readable text report.
- A missing `--file` for `batch` reports a clean error instead of a traceback.
- Running the CLI with no subcommand (`python -m a2a_drift`, `a2a-drift`) no
  longer crashes with `AttributeError: 'Namespace' object has no attribute
  'allow_internal'`; it now prints usage and exits 2, like any other argument
  error.
- A malformed bracketed IPv6 URL (for example `http://[::1`) is reported as an
  `invalid URL` validation message instead of raising `ValueError` out of
  `validate_url` as an unhandled traceback.
- `--deny-internal` is enforced on the destination actually contacted, not only
  on the URL as written. A public URL answering `302 Location:
  http://127.0.0.1:PORT/` had its redirect followed with `follow_redirects=True`
  while the guard had only ever inspected the first URL, so the internal card was
  fetched and reported compliant with exit code 0 (CWE-918, the standard SSRF
  pivot). Redirects are now followed one hop at a time and each destination is
  validated before it is requested, so a refused hop is reported as a
  `security-transport` error and its address is never contacted. Chains are
  bounded at `MAX_REDIRECTS` hops; `--allow-internal` is unchanged.

## [Initial Release]

- Initial project release
