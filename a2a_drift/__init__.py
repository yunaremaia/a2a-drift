"""A2A Drift — Detect A2A protocol compliance drift."""

__version__ = "0.1.0"

import ipaddress
import json
import logging
import socket
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Union

import httpx

logger = logging.getLogger(__name__)


@dataclass
class DriftFinding:
    drift_type: str
    severity: str  # error, warning, info
    message: str
    path: Optional[str] = None


@dataclass
class ValidationResult:
    url: str
    spec_version: Optional[str] = None
    is_compliant: bool = True
    drift: list[DriftFinding] = field(default_factory=list)
    jsonrpc_compliant: Optional[bool] = None
    response_time_ms: Optional[float] = None
    error: Optional[str] = None
    attempts: int = 0
    # The spec version the check was measured against (the --spec-version target).
    spec_version_target: Optional[str] = None

    def add_drift(
        self,
        drift_type: str,
        severity: str,
        message: str,
        path: Optional[str] = None,
    ):
        self.drift.append(DriftFinding(drift_type, severity, message, path))
        if severity == "error":
            self.is_compliant = False


def _normalize_spec_version(raw: object) -> Optional[str]:
    """Return the A2A spec version a raw ``protocolVersion`` value declares.

    Matching is on the leading ``major.minor`` component, never a substring:
    ``"0.1.0"`` must not be read as ``"1.0"`` just because the digits appear in
    order. A value whose leading ``major.minor`` is not one of the known spec
    versions returns ``None`` so the caller reports it as undetermined.
    """
    text = str(raw or "").strip()
    if not text:
        return None
    # Drop any pre-release/build suffix (e.g. "1.0-rc.1") before splitting.
    text = text.split("-", 1)[0].split("+", 1)[0]
    parts = text.split(".")
    if len(parts) < 2:
        return None
    candidate = f"{parts[0]}.{parts[1]}"
    return candidate if candidate in AgentCardChecker.SPEC_VERSIONS else None


def _should_retry(exc: Exception) -> bool:
    """Determine if an HTTP exception is retryable."""
    if isinstance(exc, httpx.TimeoutException):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    if isinstance(exc, (httpx.ConnectError, httpx.RemoteProtocolError)):
        return True
    return False


def _is_internal_ip(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Return True for addresses that must not be reached from an untrusted URL."""
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_url(url: str, allow_internal: bool = False) -> Optional[str]:
    """Check that ``url`` is well formed and, unless allowed, not internal.

    Returns an error message describing the problem, or ``None`` when the URL is
    acceptable. When internal addresses are allowed no name resolution happens at
    all, so the common case stays offline and cheap; the resolution pass only
    runs when the caller has opted into blocking internal targets, which is the
    SSRF hardening described in CWE-918.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as e:
        # urlparse raises on a malformed bracketed IPv6 host (e.g. "http://[::1").
        # Untrusted input must produce a validation message, never a traceback.
        return f"invalid URL: {e}"
    if parsed.scheme not in ("http", "https"):
        return f"invalid URL scheme: {parsed.scheme or '(none)'}"
    hostname = parsed.hostname
    if not hostname:
        return "invalid URL: no hostname"
    if allow_internal:
        return None

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return f"could not resolve hostname: {hostname}"

    for entry in addresses:
        ip = ipaddress.ip_address(entry[4][0])
        if _is_internal_ip(ip):
            return f"internal URL blocked ({ip}); pass --allow-internal to override"
    return None


class AgentCardChecker:
    """Validate an A2A agent card against the spec and detect drift."""

    REQUIRED_FIELDS = ["name", "description", "url", "version", "capabilities"]
    SPEC_VERSIONS = ["0.3", "1.0"]
    CURRENT_SPEC = "1.0"

    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        max_retries: int = 3,
        target_spec_version: Optional[str] = None,
        allow_internal: bool = False,
    ):
        self.url = url
        self.timeout = timeout
        # max_retries is an attempt count, so it must never drop below 1: a range
        # of zero iterations leaves `response` unbound and crashes further down.
        self.max_retries = max(1, int(max_retries))
        self.target_spec_version = target_spec_version or self.CURRENT_SPEC
        self.allow_internal = allow_internal

    def validate(self) -> ValidationResult:
        result = ValidationResult(url=self.url)
        result.spec_version_target = self.target_spec_version

        blocked = validate_url(self.url, allow_internal=self.allow_internal)
        if blocked:
            result.error = blocked
            result.add_drift("security-transport", "error", blocked)
            return result

        last_error = None
        response = None
        for attempt in range(self.max_retries):
            try:
                response = httpx.get(
                    self.url, timeout=self.timeout, follow_redirects=True
                )
                response.raise_for_status()
                result.attempts = attempt + 1
                break
            except (httpx.HTTPError, Exception) as e:
                last_error = e
                if _should_retry(e) and attempt < self.max_retries - 1:
                    delay = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                    logger.warning(
                        f"Attempt {attempt + 1}/{self.max_retries} failed: {e}. "
                        f"Retrying in {delay}s..."
                    )
                    time.sleep(delay)
                    continue
                else:
                    result.error = f"Failed to fetch agent card: {e}"
                    result.add_drift("fetch-error", "error", result.error)
                    result.attempts = attempt + 1
                    return result

        if response is None:
            # Defensive: no attempt produced a response, so there is nothing to
            # parse. Report it instead of dereferencing an unbound name.
            if last_error is not None and result.error is None:
                result.error = f"Failed to fetch agent card: {last_error}"
                result.add_drift("fetch-error", "error", result.error)
            else:
                result.error = "No attempt was made (max_retries must be >= 1)"
                result.add_drift("fetch-error", "error", result.error)
            result.attempts = max(self.max_retries, result.attempts)
            return result

        try:
            card = response.json()
        except json.JSONDecodeError as e:
            result.error = f"Agent card is not valid JSON: {e}"
            result.add_drift("json-parse-error", "error", result.error)
            return result

        # A well-formed JSON body of the wrong shape is a schema violation, not a
        # crash: `in` and `.get` below only work on a mapping.
        if not isinstance(card, dict):
            result.error = (
                f"Agent card must be a JSON object, got {type(card).__name__}"
            )
            result.add_drift("schema-violation", "error", result.error, path="$")
            return result

        # Check required fields
        for field_name in self.REQUIRED_FIELDS:
            if field_name not in card:
                result.add_drift(
                    "schema-violation",
                    "error",
                    f"Missing required field: {field_name}",
                    path=f"$.{field_name}"
                )

        # Check spec version. Match the leading major.minor component only:
        # a substring test would read protocolVersion "0.1.0" as spec 1.0.
        proto_version = card.get("protocolVersion", "")
        detected = _normalize_spec_version(proto_version)
        target = self.target_spec_version
        if detected == target:
            result.spec_version = detected
        elif detected is not None:
            result.spec_version = detected
            result.add_drift(
                "spec-version",
                "warning",
                f"Agent uses spec v{detected}; v{target} is the expected version"
            )
        else:
            result.add_drift(
                "spec-version",
                "warning",
                f"Could not determine A2A spec version (got: {proto_version})"
            )
        
        # Check capabilities
        capabilities = card.get("capabilities", {})
        if not capabilities:
            result.add_drift(
                "capability-advertised-but-unsupported",
                "warning",
                "No capabilities declared in agent card"
            )
        
        # If no errors, mark as compliant
        if not any(d.severity == "error" for d in result.drift):
            result.is_compliant = True
        
        return result


class EndpointProber:
    """Probe a live A2A endpoint for JSON-RPC conformance."""

    def __init__(
        self,
        endpoint_url: str,
        timeout: float = 10.0,
        max_retries: int = 3,
        allow_internal: bool = False,
    ):
        self.endpoint_url = endpoint_url
        self.timeout = timeout
        # At least one attempt, for the same reason as AgentCardChecker.
        self.max_retries = max(1, int(max_retries))
        self.allow_internal = allow_internal

    def probe(self, method: str, params: Optional[dict] = None) -> ValidationResult:
        result = ValidationResult(url=self.endpoint_url)

        blocked = validate_url(
            self.endpoint_url, allow_internal=self.allow_internal
        )
        if blocked:
            result.error = blocked
            result.add_drift("security-transport", "error", blocked)
            return result

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": 1
        }

        last_error = None
        response = None
        for attempt in range(self.max_retries):
            try:
                start = time.time()
                response = httpx.post(
                    self.endpoint_url,
                    json=payload,
                    timeout=self.timeout,
                    headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()
                elapsed = (time.time() - start) * 1000
                result.response_time_ms = round(elapsed, 2)
                result.attempts = attempt + 1
                break
            except (httpx.HTTPError, Exception) as e:
                last_error = e
                if _should_retry(e) and attempt < self.max_retries - 1:
                    delay = 2 ** attempt
                    logger.warning(
                        f"Attempt {attempt + 1}/{self.max_retries} failed: {e}. "
                        f"Retrying in {delay}s..."
                    )
                    time.sleep(delay)
                    continue
                else:
                    result.error = f"Failed to probe endpoint: {e}"
                    result.add_drift("probe-error", "error", result.error)
                    result.attempts = attempt + 1
                    return result

        if response is None:
            if last_error is not None and result.error is None:
                result.error = f"Failed to probe endpoint: {last_error}"
                result.add_drift("probe-error", "error", result.error)
            else:
                result.error = "No attempt was made (max_retries must be >= 1)"
                result.add_drift("probe-error", "error", result.error)
            result.attempts = max(self.max_retries, result.attempts)
            return result
        
        if response.status_code not in (200, 202, 204):
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                f"Non-success HTTP status: {response.status_code}"
            )
            # A response was obtained and rejected: conformance is decided.
            result.jsonrpc_compliant = False
            return result

        try:
            resp_json = response.json()
        except (json.JSONDecodeError, Exception):
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                "Response is not valid JSON (body is not JSON)"
            )
            result.jsonrpc_compliant = False
            return result

        # A JSON-RPC response must be an object; arrays and scalars are invalid.
        if not isinstance(resp_json, dict):
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                f"Response must be a JSON object, got {type(resp_json).__name__}"
            )
            result.jsonrpc_compliant = False
            return result

        # Check JSON-RPC 2.0 required fields
        if "jsonrpc" not in resp_json:
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                "Missing 'jsonrpc' field in response"
            )
        elif resp_json["jsonrpc"] != "2.0":
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                f"Expected jsonrpc='2.0', got '{resp_json['jsonrpc']}'"
            )

        if "id" not in resp_json:
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                "Missing 'id' field in response"
            )
        elif resp_json["id"] != payload["id"]:
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                f"Response 'id' mismatch: expected {payload['id']}, "
                f"got {resp_json['id']}"
            )

        # Exactly one of result/error must be present (JSON-RPC 2.0 §5.1).
        has_result = "result" in resp_json
        has_error = "error" in resp_json
        if not has_result and not has_error:
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                "Response must contain either 'result' or 'error'"
            )
        elif has_result and has_error:
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                "Response must not contain both 'result' and 'error'"
            )
        elif has_error:
            error = resp_json["error"]
            if not isinstance(error, dict):
                result.add_drift(
                    "jsonrpc-conformance",
                    "error",
                    f"error must be an object, got {type(error).__name__}"
                )
            else:
                code = error.get("code")
                if "code" not in error:
                    result.add_drift(
                        "jsonrpc-conformance",
                        "error",
                        "error.code is required and must be an integer"
                    )
                elif isinstance(code, bool) or not isinstance(code, int):
                    result.add_drift(
                        "jsonrpc-conformance",
                        "error",
                        f"error.code must be an integer, got {code!r}"
                    )
                if not isinstance(error.get("message"), str):
                    result.add_drift(
                        "jsonrpc-conformance",
                        "error",
                        "error.message is required and must be a string"
                    )

        # Set jsonrpc_compliant based on conformance checks
        if any(
            d.drift_type == "jsonrpc-conformance" and d.severity == "error"
            for d in result.drift
        ):
            result.jsonrpc_compliant = False
        else:
            result.jsonrpc_compliant = True

        return result
