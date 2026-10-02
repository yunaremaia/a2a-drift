"""Tests for JSON-RPC 2.0 transport conformance checks (issue #4).

A compliance tool that reports a malformed JSON-RPC response as compliant is
worse than one that stays silent, so these tests pin the negative cases.
"""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from a2a_drift import EndpointProber

pytestmark = pytest.mark.unit


def json_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


def probe(payload, status_code=200, method="message/send"):
    with patch("a2a_drift.httpx.post") as mock_post:
        mock_post.return_value = json_response(payload, status_code)
        return EndpointProber("https://example.com/a2a").probe(method)


class TestErrorObjectStructure:
    """error must be an object carrying an int code and a string message."""

    def test_error_object_with_code_and_message_is_compliant(self):
        result = probe(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "Invalid"}}
        )
        assert result.jsonrpc_compliant is True

    def test_error_as_bare_string_is_not_compliant(self):
        result = probe({"jsonrpc": "2.0", "id": 1, "error": "boom"})
        assert result.jsonrpc_compliant is False
        assert any("must be an object" in d.message for d in result.drift)

    def test_error_missing_code_is_not_compliant(self):
        result = probe({"jsonrpc": "2.0", "id": 1, "error": {"message": "no code"}})
        assert result.jsonrpc_compliant is False
        assert any("error.code" in d.message for d in result.drift)

    def test_error_with_non_integer_code_is_not_compliant(self):
        result = probe(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": "-32600", "message": "x"}}
        )
        assert result.jsonrpc_compliant is False
        assert any("error.code" in d.message for d in result.drift)

    def test_error_with_non_string_message_is_not_compliant(self):
        result = probe(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": 42}}
        )
        assert result.jsonrpc_compliant is False
        assert any("error.message" in d.message for d in result.drift)

    def test_error_with_optional_data_stays_compliant(self):
        result = probe(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -32602,
                    "message": "Invalid params",
                    "data": {"f": 1},
                },
            }
        )
        assert result.jsonrpc_compliant is True


class TestResponseShape:
    """A response must carry exactly one of result/error, and a real id."""

    def test_both_result_and_error_is_not_compliant(self):
        result = probe(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {},
                "error": {"code": -1, "message": "x"},
            }
        )
        assert result.jsonrpc_compliant is False

    def test_missing_id_is_not_compliant(self):
        result = probe({"jsonrpc": "2.0", "result": {}})
        assert result.jsonrpc_compliant is False

    def test_wrong_jsonrpc_version_is_not_compliant(self):
        result = probe({"jsonrpc": "1.0", "id": 1, "result": {}})
        assert result.jsonrpc_compliant is False

    def test_non_object_response_body_is_not_compliant(self):
        result = probe([1, 2, 3])
        assert result.jsonrpc_compliant is False
        assert any("must be a JSON object" in d.message for d in result.drift)


class TestComplianceIsAlwaysDecided:
    """jsonrpc_compliant must be True/False whenever a response was obtained."""

    def test_http_error_status_never_reached_a_jsonrpc_body(self):
        """A 5xx means no JSON-RPC response was ever seen.

        Conformance is therefore unknown rather than false: claiming the
        endpoint is non-conformant would over-report what we actually observed.
        The run still fails, via a probe-error finding.
        """
        with patch("a2a_drift.httpx.post") as mock_post:
            response = MagicMock()
            response.status_code = 500
            response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Server Error", request=MagicMock(), response=response
            )
            mock_post.return_value = response
            result = EndpointProber("https://example.com/a2a", max_retries=1).probe(
                "message/send"
            )

        assert result.jsonrpc_compliant is None
        assert result.is_compliant is False
        assert "probe-error" in [d.drift_type for d in result.drift]

    def test_unexpected_success_status_with_bad_body_is_decided(self):
        """A 200 body that breaks the spec decides conformance as False."""
        with patch("a2a_drift.httpx.post") as mock_post:
            # raise_for_status passes (status 200) but the body is malformed.
            response = MagicMock()
            response.status_code = 200
            response.raise_for_status.return_value = None
            response.json.return_value = {"result": {}}  # no jsonrpc, no id
            mock_post.return_value = response
            result = EndpointProber("https://example.com/a2a").probe("message/send")

        assert result.jsonrpc_compliant is False

    def test_fetch_failure_leaves_conformance_unknown(self):
        with patch("a2a_drift.httpx.post") as mock_post:
            mock_post.side_effect = httpx.ConnectError("refused")
            result = EndpointProber("https://example.com/a2a", max_retries=1).probe(
                "message/send"
            )

        # No response was obtained, so conformance genuinely is unknown.
        assert result.jsonrpc_compliant is None
        assert result.is_compliant is False
        assert result.error is not None
