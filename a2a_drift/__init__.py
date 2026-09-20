"""A2A Drift — Detect A2A protocol compliance drift."""

__version__ = "0.1.0"

from typing import Optional
from dataclasses import dataclass, field
import httpx
import json
import time
import logging

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

    def add_drift(self, drift_type: str, severity: str, message: str, path: Optional[str] = None):
        self.drift.append(DriftFinding(drift_type, severity, message, path))
        if severity == "error":
            self.is_compliant = False


def _should_retry(exc: Exception) -> bool:
    """Determine if an HTTP exception is retryable."""
    if isinstance(exc, httpx.TimeoutException):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    if isinstance(exc, (httpx.ConnectError, httpx.RemoteProtocolError)):
        return True
    return False


class AgentCardChecker:
    """Validate an A2A agent card against the spec and detect drift."""

    REQUIRED_FIELDS = ["name", "description", "url", "version", "capabilities"]
    SPEC_VERSIONS = ["0.3", "1.0"]
    CURRENT_SPEC = "1.0"

    def __init__(self, url: str, timeout: float = 10.0, max_retries: int = 3):
        self.url = url
        self.timeout = timeout
        self.max_retries = max_retries

    def validate(self) -> ValidationResult:
        result = ValidationResult(url=self.url)
        
        last_error = None
        for attempt in range(self.max_retries):
            try:
                response = httpx.get(self.url, timeout=self.timeout, follow_redirects=True)
                response.raise_for_status()
                result.attempts = attempt + 1
                break
            except (httpx.HTTPError, Exception) as e:
                last_error = e
                if _should_retry(e) and attempt < self.max_retries - 1:
                    delay = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                    logger.warning(f"Attempt {attempt + 1}/{self.max_retries} failed: {e}. Retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                else:
                    result.error = f"Failed to fetch agent card: {e}"
                    result.add_drift("fetch-error", "error", result.error)
                    result.attempts = attempt + 1
                    return result
        
        if last_error and result.error:
            result.attempts = self.max_retries
            return result
        
        try:
            card = response.json()
        except json.JSONDecodeError as e:
            result.error = f"Agent card is not valid JSON: {e}"
            result.add_drift("json-parse-error", "error", result.error)
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
        
        # Check spec version
        proto_version = card.get("protocolVersion", "")
        if proto_version == "1.0" or "1.0" in str(proto_version):
            result.spec_version = "1.0"
        elif proto_version == "0.3" or "0.3" in str(proto_version):
            result.spec_version = "0.3"
            result.add_drift(
                "spec-version",
                "warning",
                f"Agent uses spec v0.3; v{self.CURRENT_SPEC} is current"
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

    def __init__(self, endpoint_url: str, timeout: float = 10.0, max_retries: int = 3):
        self.endpoint_url = endpoint_url
        self.timeout = timeout
        self.max_retries = max_retries

    def probe(self, method: str, params: Optional[dict] = None) -> ValidationResult:
        result = ValidationResult(url=self.endpoint_url)
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": 1
        }
        
        last_error = None
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
                    logger.warning(f"Attempt {attempt + 1}/{self.max_retries} failed: {e}. Retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                else:
                    result.error = f"Failed to probe endpoint: {e}"
                    result.add_drift("probe-error", "error", result.error)
                    result.attempts = attempt + 1
                    return result
        
        if last_error and result.error:
            result.attempts = self.max_retries
            return result
        
        if response.status_code not in (200, 202, 204):
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                f"Non-success HTTP status: {response.status_code}"
            )
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
                f"Response 'id' mismatch: expected {payload['id']}, got {resp_json['id']}"
            )

        if "result" not in resp_json and "error" not in resp_json:
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                "Response must contain either 'result' or 'error'"
            )
        
        # Set jsonrpc_compliant based on conformance checks
        if any(d.drift_type == "jsonrpc-conformance" and d.severity == "error" for d in result.drift):
            result.jsonrpc_compliant = False
        else:
            result.jsonrpc_compliant = True
        
        return result
