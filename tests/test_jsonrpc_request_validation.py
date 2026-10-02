"""Request-side JSON-RPC checks for issue #4: method schema and notifications.

``test_jsonrpc_conformance.py`` covers what came back. These cover what we sent
and what coming back nothing means: the params a method requires, and the fact
that a request without an ``id`` is a notification that must not be answered.

Field names come from the A2A JSON-RPC payloads (``TaskIdParams``,
``MessageSendParams``/``Message``). A validator built from guessed names would
report compliant endpoints as broken, which is worse than not checking.
"""

import contextlib
import io
import sys
from unittest.mock import MagicMock, patch

import pytest

from a2a_drift import EndpointProber, cli
from a2a_drift.jsonrpc import validate_method_request

pytestmark = pytest.mark.unit


def run_cli(argv):
    """Run cli.main() with argv, returning (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with patch.object(sys, "argv", ["a2a-drift"] + argv):
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                cli.main()
        except SystemExit as exc:
            code = exc.code if exc.code is not None else 0
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def mock_post():
    """Patch the transport for CLI-level tests and yield the mock."""
    with patch("a2a_drift.httpx.post") as mocked:
        mocked.return_value = rpc_response(text="")
        yield mocked


class TestMethodSchema:
    """A method's params must carry the fields its payload type declares."""

    def test_message_send_with_no_params_reports_the_missing_message(self):
        errors = validate_method_request("message/send", {})

        assert errors == ["params.message is required by method 'message/send'"]

    def test_message_send_requires_message_id_role_and_parts(self):
        errors = validate_method_request("message/send", {"message": {}})

        assert errors == [
            "params.message.messageId is required by method 'message/send'",
            "params.message.role is required by method 'message/send'",
            "params.message.parts is required by method 'message/send'",
        ]

    def test_message_send_accepts_a_complete_message(self):
        errors = validate_method_request(
            "message/send",
            {
                "message": {
                    "messageId": "msg-1",
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}],
                }
            },
        )

        assert errors == []

    def test_message_send_rejects_a_role_outside_the_enum(self):
        errors = validate_method_request(
            "message/send",
            {
                "message": {
                    "messageId": "msg-1",
                    "role": "system",
                    "parts": [{"type": "text", "text": "hi"}],
                }
            },
        )

        assert errors == ["params.message.role must be 'user' or 'agent', got 'system'"]

    def test_message_send_rejects_empty_parts(self):
        errors = validate_method_request(
            "message/send",
            {"message": {"messageId": "msg-1", "role": "user", "parts": []}},
        )

        assert errors == ["params.message.parts must be a non-empty array"]

    def test_message_send_rejects_parts_that_is_not_an_array(self):
        errors = validate_method_request(
            "message/send",
            {
                "message": {
                    "messageId": "msg-1",
                    "role": "user",
                    "parts": {"type": "text", "text": "hi"},
                }
            },
        )

        assert errors == ["params.message.parts must be a non-empty array"]

    def test_message_send_rejects_a_message_that_is_not_an_object(self):
        errors = validate_method_request("message/send", {"message": "hello"})

        assert errors == [
            "params.message must be a JSON object, got str",
        ]

    def test_message_send_does_not_report_nested_fields_when_message_is_absent(
        self,
    ):
        """One missing field, one finding: three complaints about an absent
        message would bury the actual problem in noise."""
        errors = validate_method_request("message/send", {"metadata": {}})

        assert errors == ["params.message is required by method 'message/send'"]

    @pytest.mark.parametrize("method", ["tasks/get", "tasks/cancel"])
    def test_task_methods_require_an_id(self, method):
        errors = validate_method_request(method, {})

        assert errors == [f"params.id is required by method '{method}'"]

    @pytest.mark.parametrize("method", ["tasks/get", "tasks/cancel"])
    def test_task_methods_accept_an_id(self, method):
        assert validate_method_request(method, {"id": "task-1"}) == []

    def test_task_methods_reject_a_non_string_id(self):
        errors = validate_method_request("tasks/get", {"id": 7})

        assert errors == ["params.id must be a non-empty string, got 7"]

    def test_task_methods_reject_an_empty_id(self):
        errors = validate_method_request("tasks/cancel", {"id": ""})

        assert errors == ["params.id must be a non-empty string, got ''"]

    def test_none_params_is_treated_as_no_params(self):
        assert validate_method_request("tasks/get", None) == [
            "params.id is required by method 'tasks/get'"
        ]

    def test_params_that_is_not_an_object_is_reported_once(self):
        """--params '[1, 2]' parses as a JSON array; reporting it as though
        every field were missing would be technically true and useless."""
        errors = validate_method_request("tasks/get", [1, 2])

        assert errors == ["params must be a JSON object, got list"]

    def test_an_unmodelled_method_is_never_reported(self):
        """This tool probes any JSON-RPC method. Inventing requirements for one
        it has no schema for would be a guess reported as a finding."""
        assert validate_method_request("tasks/resubscribe", {}) == []
        assert validate_method_request("vendor/doesWhatever", {}) == []


def rpc_response(payload=None, status_code=200, text=""):
    response = MagicMock()
    response.status_code = status_code
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    response.text = text
    return response


def probe(method="message/send", params=None, notification=False, response=None):
    with patch("a2a_drift.httpx.post") as mock_post:
        mock_post.return_value = response or rpc_response(
            {"jsonrpc": "2.0", "id": 1, "result": {}}
        )
        return EndpointProber("https://example.com/a2a").probe(
            method, params, notification=notification
        )


class TestProbeReportsMethodSchema:
    def test_incomplete_params_are_reported_as_a_drift_finding(self):
        result = probe("tasks/get", {})

        schema_drift = [d for d in result.drift if d.drift_type == "jsonrpc-request"]
        assert len(schema_drift) == 1
        assert schema_drift[0].severity == "warning"
        assert "params.id is required" in schema_drift[0].message

    def test_request_schema_drift_does_not_break_compliance(self):
        """The finding describes the request we sent, not the endpoint. An
        endpoint that answers a malformed request correctly is still
        compliant, and the exit code must keep saying so."""
        result = probe("tasks/get", {})

        assert result.is_compliant is True
        assert result.jsonrpc_compliant is True

    def test_a_complete_request_reports_no_schema_drift(self):
        result = probe(
            "message/send",
            {
                "message": {
                    "messageId": "msg-1",
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}],
                }
            },
        )

        assert [d for d in result.drift if d.drift_type == "jsonrpc-request"] == []

    def test_the_request_is_still_sent_when_the_schema_is_incomplete(self):
        """Reporting the bad request and then observing how the endpoint
        handles it is more useful than refusing to send it."""
        with patch("a2a_drift.httpx.post") as mock_post:
            mock_post.return_value = rpc_response(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32602, "message": "Invalid parameters"},
                }
            )
            result = EndpointProber("https://example.com/a2a").probe("tasks/get", {})

        assert mock_post.call_count == 1
        assert result.jsonrpc_compliant is True
        assert any(d.drift_type == "jsonrpc-request" for d in result.drift)


class TestProbeSendsARequestIdByDefault:
    def test_an_ordinary_probe_carries_an_id(self):
        with patch("a2a_drift.httpx.post") as mock_post:
            mock_post.return_value = rpc_response(
                {"jsonrpc": "2.0", "id": 1, "result": {}}
            )
            EndpointProber("https://example.com/a2a").probe("tasks/get", {"id": "t"})

        payload = mock_post.call_args.kwargs["json"]
        assert payload["id"] == 1
        assert payload["method"] == "tasks/get"


class TestNotifications:
    """A request without an id is a notification: JSON-RPC 2.0 says the server
    must not reply to one, so an empty body is the compliant outcome and any
    body at all is the finding."""

    def test_a_notification_is_sent_without_an_id(self):
        with patch("a2a_drift.httpx.post") as mock_post:
            mock_post.return_value = rpc_response(text="")
            EndpointProber("https://example.com/a2a").probe(
                "tasks/cancel", {"id": "t"}, notification=True
            )

        assert "id" not in mock_post.call_args.kwargs["json"]

    def test_an_empty_body_is_a_compliant_notification(self):
        with patch("a2a_drift.httpx.post") as mock_post:
            mock_post.return_value = rpc_response(status_code=204, text="")
            result = EndpointProber("https://example.com/a2a").probe(
                "tasks/cancel", {"id": "t"}, notification=True
            )

        assert result.jsonrpc_compliant is True
        assert result.is_compliant is True
        assert result.drift == []

    def test_a_whitespace_only_body_still_counts_as_no_response(self):
        with patch("a2a_drift.httpx.post") as mock_post:
            mock_post.return_value = rpc_response(text="  \n")
            result = EndpointProber("https://example.com/a2a").probe(
                "tasks/cancel", {"id": "t"}, notification=True
            )

        assert result.jsonrpc_compliant is True
        assert result.drift == []

    def test_answering_a_notification_is_not_compliant(self):
        with patch("a2a_drift.httpx.post") as mock_post:
            mock_post.return_value = rpc_response(
                text='{"jsonrpc": "2.0", "id": 1, "result": {}}'
            )
            result = EndpointProber("https://example.com/a2a").probe(
                "tasks/cancel", {"id": "t"}, notification=True
            )

        assert result.jsonrpc_compliant is False
        assert any("must not send a response" in d.message for d in result.drift), [
            d.message for d in result.drift
        ]

    def test_a_notification_with_a_broken_url_never_reaches_the_network(self):
        with patch("a2a_drift.httpx.post") as mock_post:
            result = EndpointProber("http://internal.example/a2a").probe(
                "m", notification=True
            )

        assert mock_post.call_count == 0
        assert result.jsonrpc_compliant is None


class TestCliNotificationFlag:
    def test_the_notification_flag_omits_the_id(self, mock_post):
        code, _out, _err = run_cli(
            ["probe", "https://example.com/a2a", "--notification"]
        )

        assert code == 0
        assert "id" not in mock_post.call_args.kwargs["json"]

    def test_without_the_flag_the_request_carries_an_id(self, mock_post):
        run_cli(["probe", "https://example.com/a2a"])

        assert mock_post.call_args.kwargs["json"]["id"] == 1
