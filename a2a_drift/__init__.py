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

from a2a_drift.jsonrpc import validate_method_request

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
    ) -> None:
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


def _normalize_target_spec_version(raw: object) -> Optional[str]:
    """Return the spec version a ``--spec-version`` target names, or ``None``.

    The target is normalised through the same helper as the detected
    ``protocolVersion`` so both sides of the comparison live in one space. That
    symmetry is the whole point: comparing a normalised ``"1.0"`` against a raw
    ``"1.0.0"`` reported drift against an agent that is perfectly conformant.

    A leading ``v`` is accepted (``v1.0`` -> ``1.0``) because it is how the
    version is conventionally written, and it is not part of the version.
    ``None`` means the target names no known version -- empty, whitespace, or
    nonsense -- and the caller must decide what to do about it.
    """
    text = str(raw or "").strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    return _normalize_spec_version(text)


def _should_retry(exc: Exception) -> bool:
    """Determine if an HTTP exception is retryable."""
    if isinstance(exc, httpx.TimeoutException):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    return isinstance(exc, (httpx.ConnectError, httpx.RemoteProtocolError))


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


# A redirect chain is walked by hand (see ``_fetch_following_redirects``), so
# this bounds how many hops one check will follow. httpx defaults to 20; the
# value only has to stop an unbounded loop against a host the caller does not
# control, so it matches httpx's own default rather than inventing a new one.
MAX_REDIRECTS = 20

# Distinguishes "this key is absent" from "this key holds null". A bare
# ``card.get(key)`` collapses the two into None, which is exactly what made a
# stored ``capabilities: null`` indistinguishable from an absent key.
_MISSING = object()


def _is_empty_value(value: object, allow_empty: bool) -> bool:
    """Return True when ``value`` is unusable for a required field.

    ``allow_empty`` carries the per-field decision recorded in
    ``AgentCardChecker.REQUIRED_FIELD_EXPECTATIONS``: an empty capabilities
    object is a real (if minimal) declaration, while an empty string is not.
    Strings are stripped before the test, because ``"   "`` is truthy in
    Python and would otherwise pass as a name or a url.
    """
    if isinstance(value, str):
        return not value.strip()
    return not value and not allow_empty


# Statuses whose Location header names a request to make, as opposed to 304
# Not Modified, which is a cache answer with no target to follow.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class _RedirectBlocked(Exception):
    """A redirect destination was refused by the same policy as the first URL.

    Distinct from a fetch error because it is a verdict on the address the
    request *would* have reached, not a failure to get there. Reporting it as
    ``fetch-error`` would retry it and lose the security meaning.
    """


def _next_hop(url: str, response: httpx.Response) -> Optional[str]:
    """Return the absolute URL a redirect response points at, or ``None``.

    ``None`` means this response is final: either not a redirect at all, or a
    redirect with no usable ``Location``. A relative ``Location`` is resolved
    against the URL that produced it, so the next hop is always an absolute
    URL the guard can check as written.
    """
    if response.status_code not in _REDIRECT_STATUSES:
        return None
    location = response.headers.get("location")
    if not location:
        return None
    return urllib.parse.urljoin(url, location)


def _fetch_following_redirects(
    url: str, timeout: float, allow_internal: bool
) -> httpx.Response:
    """GET ``url``, applying the deny-internal policy to every hop.

    ``httpx.get(..., follow_redirects=True)`` hands the choice of final
    destination to the remote party: a public URL answering
    ``302 Location: http://127.0.0.1:PORT/`` was fetched anyway and reported
    compliant, because the guard had only ever seen the URL as written. That is
    the standard SSRF pivot, and it defeats a blocklist that inspects one URL.

    So redirects are followed here one hop at a time, and each destination is
    validated *before* the request to it is issued. The policy therefore holds
    for the address actually contacted rather than the address asked for.

    Raises ``_RedirectBlocked`` if any hop is refused, and
    ``httpx.TooManyRedirects`` if the chain never terminates.
    """
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        response = httpx.get(current, timeout=timeout, follow_redirects=False)
        target = _next_hop(current, response)
        if target is None:
            return response
        # Checked before the request, not after: once the hop is issued the
        # internal address has already been contacted.
        blocked = validate_url(target, allow_internal=allow_internal)
        if blocked:
            raise _RedirectBlocked(f"redirect to {target} blocked: {blocked}")
        current = target
    raise httpx.TooManyRedirects(f"more than {MAX_REDIRECTS} redirects: {url}")


class AgentCardChecker:
    """Validate an A2A agent card against the spec and detect drift."""

    REQUIRED_FIELDS = ["name", "description", "url", "version", "capabilities"]

    # What each required field must actually *contain*, not merely have a key
    # for. `field_name in card` proved presence and nothing else, so a card
    # whose required fields were all null, wrong-typed or empty strings
    # reported zero drift and exited 0.
    #
    # The value is (expected type, empty value allowed?). An empty *object* is
    # a legitimate capabilities declaration -- the card still says something --
    # so it is allowed here and reported separately as a warning, exactly as
    # before. An empty *string* is not: a blank name or url tells a peer agent
    # nothing, so it is an error like any other unusable value.
    REQUIRED_FIELD_EXPECTATIONS = {
        "name": (str, False),
        "description": (str, False),
        "url": (str, False),
        "version": (str, False),
        "capabilities": (dict, True),
    }

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
        self.target_spec_version = self._resolve_target(target_spec_version)
        self.allow_internal = allow_internal

    @classmethod
    def _resolve_target(cls, target_spec_version: Optional[str]) -> str:
        """Return the normalised spec version to measure drift against.

        ``None`` means the caller expressed no preference, so the current spec is
        the target. Anything else is an explicit choice and must name a spec we
        know: `target_spec_version or CURRENT_SPEC` folded an empty or blank
        string into the default, so `--spec-version ''` in a CI matrix ran
        exactly as if the flag had been omitted. Raising here keeps the typo
        visible at the boundary instead of producing a check that quietly
        measures the wrong thing and exits 0.
        """
        if target_spec_version is None:
            return cls.CURRENT_SPEC
        normalized = _normalize_target_spec_version(target_spec_version)
        if normalized is None:
            accepted = ", ".join(cls.SPEC_VERSIONS)
            raise ValueError(
                f"invalid spec version {str(target_spec_version)!r}; "
                f"expected one of: {accepted}"
            )
        return normalized

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
                response = _fetch_following_redirects(
                    self.url, self.timeout, self.allow_internal
                )
                response.raise_for_status()
                result.attempts = attempt + 1
                break
            except _RedirectBlocked as e:
                # The chain reached an address the policy refuses. That is a
                # security finding, not a transient failure: retrying would
                # re-run the same refused check, so it is reported at once.
                result.error = str(e)
                result.add_drift("security-transport", "error", result.error)
                result.attempts = attempt + 1
                return result
            except (httpx.HTTPError, Exception) as e:
                last_error = e
                if _should_retry(e) and attempt < self.max_retries - 1:
                    delay = 2**attempt  # Exponential backoff: 1s, 2s, 4s
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
        except UnicodeDecodeError as e:
            # A body that is not valid UTF-8 never reached the JSON parser, so
            # this is NOT "not valid JSON": the bytes are attacker-controlled on
            # the untrusted-URL fetch path that --deny-internal exists to guard,
            # and `issubclass(UnicodeDecodeError, json.JSONDecodeError)` is False
            # (it inherits ValueError), so the except below never caught it and
            # the exception escaped validate() as a traceback. Named apart so the
            # operator can tell an encoding failure from a syntax failure.
            result.error = (
                f"Agent card is not valid UTF-8 and could not be decoded: {e}"
            )
            result.add_drift("json-decode-error", "error", result.error)
            return result
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

        # Check required fields, by value rather than by key presence.
        for field_name in self.REQUIRED_FIELDS:
            expected_type, allow_empty = self.REQUIRED_FIELD_EXPECTATIONS[field_name]
            path = f"$.{field_name}"
            # `.get` with the sentinel, never indexing: `in` plus `[key]` cannot
            # tell "absent" from "present but null", and both need naming.
            value = card.get(field_name, _MISSING)
            if value is _MISSING:
                result.add_drift(
                    "schema-violation",
                    "error",
                    f"Missing required field: {field_name}",
                    path=path,
                )
            elif value is None:
                result.add_drift(
                    "schema-violation",
                    "error",
                    f"Required field {field_name} is null",
                    path=path,
                )
            elif not isinstance(value, expected_type):
                result.add_drift(
                    "schema-violation",
                    "error",
                    f"Required field {field_name} must be "
                    f"{expected_type.__name__}, got {type(value).__name__}",
                    path=path,
                )
            elif _is_empty_value(value, allow_empty):
                # An empty object is a real capabilities declaration and stays a
                # warning below; a blank string is an unusable value. Whitespace
                # counts as blank: `"   "` is truthy in Python but names nothing.
                result.add_drift(
                    "schema-violation",
                    "error",
                    f"Required field {field_name} is empty",
                    path=path,
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
                f"Agent uses spec v{detected}; v{target} is the expected version",
            )
        else:
            result.add_drift(
                "spec-version",
                "warning",
                f"Could not determine A2A spec version (got: {proto_version})",
            )

        # Check capabilities. A stored null is already reported above as
        # "Required field capabilities is null"; `card.get(..., {})` returned
        # that None and `if not capabilities` then reported "No capabilities
        # declared", so null and {} produced byte-identical output. Now only a
        # dict that is genuinely empty earns the warning.
        capabilities = card.get("capabilities", _MISSING)
        if isinstance(capabilities, dict) and not capabilities:
            result.add_drift(
                "capability-advertised-but-unsupported",
                "warning",
                "No capabilities declared in agent card",
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

    def probe(
        self,
        method: str,
        params: Optional[dict] = None,
        notification: bool = False,
    ) -> ValidationResult:
        """Send one JSON-RPC request and validate what comes back.

        With ``notification=True`` the request omits ``id``, which JSON-RPC 2.0
        defines as a notification: the server must not reply, so an empty body
        is the compliant outcome and any body at all is the finding.
        """
        result = ValidationResult(url=self.endpoint_url)

        blocked = validate_url(self.endpoint_url, allow_internal=self.allow_internal)
        if blocked:
            result.error = blocked
            result.add_drift("security-transport", "error", blocked)
            return result

        # A notification is identified by the *absence* of 'id'. It must not be
        # sent as null: null is a request whose id happens to be null, which the
        # server is required to answer.
        payload: dict = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notification:
            payload["id"] = 1

        # Report what we are about to send before deciding anything about the
        # response: a request the method schema rejects makes the endpoint's
        # answer uninterpretable, and saying so is the point of a drift tool.
        # Severity is warning because the finding is about the request, not the
        # endpoint -- an endpoint that answers a malformed request correctly is
        # still compliant, and the exit code must keep saying so.
        for message in validate_method_request(method, params):
            result.add_drift("jsonrpc-request", "warning", message)

        last_error = None
        response = None
        for attempt in range(self.max_retries):
            try:
                start = time.time()
                response = httpx.post(
                    self.endpoint_url,
                    json=payload,
                    timeout=self.timeout,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                elapsed = (time.time() - start) * 1000
                result.response_time_ms = round(elapsed, 2)
                result.attempts = attempt + 1
                break
            except (httpx.HTTPError, Exception) as e:
                last_error = e
                if _should_retry(e) and attempt < self.max_retries - 1:
                    delay = 2**attempt
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
                f"Non-success HTTP status: {response.status_code}",
            )
            # A response was obtained and rejected: conformance is decided.
            result.jsonrpc_compliant = False
            return result

        if notification:
            # JSON-RPC 2.0 §4.1: the server MUST NOT reply to a notification.
            # Silence is therefore the compliant outcome, and any body at all is
            # a violation -- including a well-formed response, which is worse
            # than no reply because it looks correct to a human reader.
            body = response.text or ""
            if body.strip():
                result.add_drift(
                    "jsonrpc-conformance",
                    "error",
                    "A JSON-RPC notification must not send a response body, "
                    f"got {len(body)} bytes",
                )
                result.jsonrpc_compliant = False
                return result
            result.jsonrpc_compliant = True
            return result

        try:
            resp_json = response.json()
        except (json.JSONDecodeError, Exception):
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                "Response is not valid JSON (body is not JSON)",
            )
            result.jsonrpc_compliant = False
            return result

        # A JSON-RPC response must be an object; arrays and scalars are invalid.
        if not isinstance(resp_json, dict):
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                f"Response must be a JSON object, got {type(resp_json).__name__}",
            )
            result.jsonrpc_compliant = False
            return result

        # Check JSON-RPC 2.0 required fields
        if "jsonrpc" not in resp_json:
            result.add_drift(
                "jsonrpc-conformance", "error", "Missing 'jsonrpc' field in response"
            )
        elif resp_json["jsonrpc"] != "2.0":
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                f"Expected jsonrpc='2.0', got '{resp_json['jsonrpc']}'",
            )

        if "id" not in resp_json:
            result.add_drift(
                "jsonrpc-conformance", "error", "Missing 'id' field in response"
            )
        elif resp_json["id"] != payload["id"]:
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                f"Response 'id' mismatch: expected {payload['id']}, "
                f"got {resp_json['id']}",
            )

        # Exactly one of result/error must be present (JSON-RPC 2.0 §5.1).
        has_result = "result" in resp_json
        has_error = "error" in resp_json
        if not has_result and not has_error:
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                "Response must contain either 'result' or 'error'",
            )
        elif has_result and has_error:
            result.add_drift(
                "jsonrpc-conformance",
                "error",
                "Response must not contain both 'result' and 'error'",
            )
        elif has_error:
            error = resp_json["error"]
            if not isinstance(error, dict):
                result.add_drift(
                    "jsonrpc-conformance",
                    "error",
                    f"error must be an object, got {type(error).__name__}",
                )
            else:
                code = error.get("code")
                if "code" not in error:
                    result.add_drift(
                        "jsonrpc-conformance",
                        "error",
                        "error.code is required and must be an integer",
                    )
                elif isinstance(code, bool) or not isinstance(code, int):
                    result.add_drift(
                        "jsonrpc-conformance",
                        "error",
                        f"error.code must be an integer, got {code!r}",
                    )
                if not isinstance(error.get("message"), str):
                    result.add_drift(
                        "jsonrpc-conformance",
                        "error",
                        "error.message is required and must be a string",
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
