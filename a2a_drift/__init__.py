"""A2A Drift — Detect A2A protocol compliance drift."""

__version__ = "0.1.0"

from typing import Optional
from dataclasses import dataclass, field
import httpx
import json


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
    is_compliant: bool = False
    drift: list[DriftFinding] = field(default_factory=list)
    jsonrpc_compliant: Optional[bool] = None
    response_time_ms: Optional[float] = None
    error: Optional[str] = None

    def add_drift(self, drift_type: str, severity: str, message: str, path: Optional[str] = None):
        self.drift.append(DriftFinding(drift_type, severity, message, path))
        if severity == "error":
            self.is_compliant = False


class AgentCardChecker:
    """Validate an A2A agent card against the spec and detect drift."""

    REQUIRED_FIELDS = ["name", "description", "url", "version", "capabilities"]
    SPEC_VERSIONS = ["0.3", "1.0"]
    CURRENT_SPEC = "1.0"

    def __init__(self, url: str, timeout: float = 10.0):
        self.url = url
        self.timeout = timeout

    def validate(self) -> ValidationResult:
        result = ValidationResult(url=self.url)
        
        try:
            response = httpx.get(self.url, timeout=self.timeout, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as e:
            result.error = f"Failed to fetch agent card: {e}"
            result.add_drift("fetch-error", "error", result.error)
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

    def __init__(self, endpoint_url: str, timeout: float = 10.0):
        self.endpoint_url = endpoint_url
        self.timeout = timeout

    def probe(self, method: str, params: Optional[dict] = None) -> ValidationResult:
        result = ValidationResult(url=self.endpoint_url)
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": 1
        }
        
        try:
            import time
            start = time.time()
            response = httpx.post(
                self.endpoint_url,
                json=payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"}
            )
            elapsed = (time.time() - start) * 1000
            result.response_time_ms = round(elapsed, 2)
            
            if response.status_code not in (200, 202, 204):
                result.add_drift(
                    "jsonrpc-conformance",
                    "error",
                    f"Non-success HTTP status: {response.status_code}"
                )
                return result
            
            try:
                resp_json = response.json()
            except json.JSONDecodeError:
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
            
            if "result" not in resp_json and "error" not in resp_json:
                result.add_drift(
                    "jsonrpc-conformance",
                    "error",
                    "Response must contain either 'result' or 'error'"
                )
            
            result.jsonrpc_compliant = not any(
                d.severity == "error" and d.drift_type == "jsonrpc-conformance"
                for d in result.drift
            )
            
        except httpx.TimeoutException:
            result.error = "Endpoint probe timed out"
            result.add_drift("endpoint-timeout", "error", result.error)
        except httpx.HTTPError as e:
            result.error = f"HTTP error: {e}"
            result.add_drift("endpoint-error", "error", result.error)
        
        return result
