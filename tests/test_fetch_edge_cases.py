"""Tests for the defensive and edge branches of the fetch/retry loops.

These paths exist so a violated invariant produces a reported drift finding
instead of an ``UnboundLocalError`` or a silently wrong verdict. They are hard
to reach through normal use, which is exactly why they need explicit tests:
nothing else in the suite would notice if they stopped working.
"""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from a2a_drift import AgentCardChecker, EndpointProber, ValidationResult

pytestmark = pytest.mark.unit

VALID_RPC = {"jsonrpc": "2.0", "id": 1, "result": {}}


def rpc_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


class TestNoAttemptMade:
    """A zero attempt budget must be reported, never dereferenced."""

    def test_checker_reports_zero_attempt_budget(self):
        """max_retries is clamped to >= 1 on construction.

        Zeroing the attribute afterwards is the only way to observe this
        branch. It must still yield a drift finding rather than crashing on an
        unbound response.
        """
        checker = AgentCardChecker("https://example.com/card.json")
        checker.max_retries = 0

        with patch("a2a_drift.httpx.get") as mock_get:
            result = checker.validate()

        assert mock_get.call_count == 0
        assert result.is_compliant is False
        assert result.error == "No attempt was made (max_retries must be >= 1)"
        assert "fetch-error" in [d.drift_type for d in result.drift]

    def test_prober_reports_zero_attempt_budget(self):
        prober = EndpointProber("https://example.com/a2a")
        prober.max_retries = 0

        with patch("a2a_drift.httpx.post") as mock_post:
            result = prober.probe("message/send")

        assert mock_post.call_count == 0
        assert result.is_compliant is False
        assert result.error == "No attempt was made (max_retries must be >= 1)"
        assert "probe-error" in [d.drift_type for d in result.drift]

    @pytest.mark.parametrize("zeroed", [0, -1, -5])
    def test_constructor_clamps_a_non_positive_budget(self, zeroed):
        """The clamp is what keeps the zero-attempt branch reachable-but-safe."""
        checker = AgentCardChecker("https://example.com/card.json", max_retries=zeroed)
        prober = EndpointProber("https://example.com/a2a", max_retries=zeroed)

        assert checker.max_retries == 1
        assert prober.max_retries == 1


class TestLoopEndsWithoutAResponse:
    """The attempt loop can finish without ever producing a response.

    ``range()`` is fixed when the loop starts, but the retry decision reads
    ``self.max_retries`` on every attempt. Raising the budget while an attempt
    is in flight therefore lets the loop run out with ``response`` still None.
    The defensive branch must report that instead of parsing None.
    """

    def test_checker_reports_the_exhausted_loop_as_a_fetch_error(self):
        checker = AgentCardChecker("https://example.com/card.json", max_retries=2)

        def raise_budget(*args, **kwargs):
            checker.max_retries = 9
            raise httpx.ConnectError("refused")

        with patch("a2a_drift.time.sleep"):
            with patch("a2a_drift.httpx.get", side_effect=raise_budget) as mock_get:
                result = checker.validate()

        assert mock_get.call_count == 2
        assert result.is_compliant is False
        assert result.error is not None
        assert "Failed to fetch agent card" in result.error
        assert "fetch-error" in [d.drift_type for d in result.drift]
        assert result.response_time_ms is None

    def test_prober_reports_the_exhausted_loop_as_a_probe_error(self):
        prober = EndpointProber("https://example.com/a2a", max_retries=2)

        def raise_budget(*args, **kwargs):
            prober.max_retries = 9
            raise httpx.ConnectError("refused")

        with patch("a2a_drift.time.sleep"):
            with patch("a2a_drift.httpx.post", side_effect=raise_budget) as mock_post:
                result = prober.probe("message/send")

        assert mock_post.call_count == 2
        assert result.is_compliant is False
        assert result.error is not None
        assert "Failed to probe endpoint" in result.error
        assert "probe-error" in [d.drift_type for d in result.drift]


class TestUnexpectedSuccessStatus:
    """A non-2xx that raise_for_status tolerates must not read as compliant."""

    @pytest.mark.parametrize("status_code", [201, 205, 302])
    def test_non_success_status_decides_conformance_as_false(self, status_code):
        """raise_for_status only rejects 4xx/5xx, so 2xx-other and 3xx get here.

        Treating such a response as conformant would report an endpoint as
        healthy on the strength of a body that is not a JSON-RPC response.
        """
        with patch(
            "a2a_drift.httpx.post",
            return_value=rpc_response(VALID_RPC, status_code),
        ):
            result = EndpointProber("https://example.com/a2a").probe("message/send")

        assert result.jsonrpc_compliant is False
        assert result.is_compliant is False
        assert f"Non-success HTTP status: {status_code}" in [
            d.message for d in result.drift
        ]

    @pytest.mark.parametrize("status_code", [202, 204])
    def test_accepted_success_statuses_still_report_compliance(self, status_code):
        """202 and 204 are explicitly accepted, so 204 stays conformant."""
        with patch(
            "a2a_drift.httpx.post",
            return_value=rpc_response(VALID_RPC, status_code),
        ):
            result = EndpointProber("https://example.com/a2a").probe("message/send")

        assert result.jsonrpc_compliant is True


class TestResultOrErrorExclusivity:
    """JSON-RPC 2.0 section 5.1: exactly one of result/error must be present."""

    def test_response_with_neither_is_not_compliant(self):
        with patch(
            "a2a_drift.httpx.post",
            return_value=rpc_response({"jsonrpc": "2.0", "id": 1}),
        ):
            result = EndpointProber("https://example.com/a2a").probe("message/send")

        assert result.jsonrpc_compliant is False
        assert "Response must contain either 'result' or 'error'" in [
            d.message for d in result.drift
        ]

    def test_response_with_both_names_the_both_finding(self):
        """Both present is a distinct violation, not a generic one."""
        with patch(
            "a2a_drift.httpx.post",
            return_value=rpc_response(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {},
                    "error": {"code": -1, "message": "x"},
                }
            ),
        ):
            result = EndpointProber("https://example.com/a2a").probe("message/send")

        assert result.jsonrpc_compliant is False
        assert "Response must not contain both 'result' and 'error'" in [
            d.message for d in result.drift
        ]


class TestBlockedUrlDriftTypes:
    """A blocked URL is a security finding on both entrypoints."""

    def test_prober_reports_a_security_transport_finding(self):
        with patch("a2a_drift.socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (__import__("socket").AF_INET, 1, 6, "", ("10.0.0.1", 0, 0, 0))
            ]
            result = EndpointProber("http://internal.example/a2a").probe("m")

        assert result.is_compliant is False
        assert "security-transport" in [d.drift_type for d in result.drift]

    @patch("a2a_drift.httpx.get")
    def test_checker_reports_a_security_transport_finding(self, mock_get):
        with patch("a2a_drift.socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (__import__("socket").AF_INET, 1, 6, "", ("10.0.0.1", 0, 0, 0))
            ]
            result = AgentCardChecker("http://internal.example/card.json").validate()

        assert mock_get.call_count == 0
        assert result.is_compliant is False
        assert "security-transport" in [d.drift_type for d in result.drift]


class TestJsonDecodeFallbacks:
    """A response body that is not JSON is a conformance failure, not a crash."""

    def test_probe_json_call_raising_a_non_json_error_is_handled(self):
        """httpx raises JSONDecodeError, but any decode-time error is caught.

        Pinned so a future decoder change cannot turn a malformed body into an
        unhandled traceback.
        """
        response = MagicMock()
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.json.side_effect = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")

        with patch("a2a_drift.httpx.post", return_value=response):
            result = EndpointProber("https://example.com/a2a").probe("message/send")

        assert result.jsonrpc_compliant is False
        assert "not valid JSON" in " ".join(d.message for d in result.drift)


class TestValidationResultDefaults:
    """The dataclass defaults the CLI and SARIF rendering both rely on."""

    def test_a_fresh_result_defaults_to_compliant_with_no_findings(self):
        result = ValidationResult(url="https://example.com")

        assert result.is_compliant is True
        assert result.drift == []
        assert result.spec_version is None
        assert result.spec_version_target is None
        assert result.jsonrpc_compliant is None
        assert result.response_time_ms is None
        assert result.error is None
        assert result.attempts == 0

    def test_each_result_gets_its_own_drift_list(self):
        """A shared default list would leak findings between results."""
        first = ValidationResult(url="https://example.com/one")
        second = ValidationResult(url="https://example.com/two")

        first.add_drift("schema-violation", "error", "boom")

        assert len(first.drift) == 1
        assert second.drift == []