"""An agent-card body that cannot be decoded is a finding, not a crash.

The bytes of a card fetched from an untrusted URL are attacker-controlled, and
``--deny-internal`` exists precisely because that fetch path is a security
boundary. A body that is not valid UTF-8 therefore has to come back as a report
with a non-zero exit code. It used to escape as an uncaught
``UnicodeDecodeError``: ``issubclass(UnicodeDecodeError, json.JSONDecodeError)``
is False (it inherits from ``ValueError``), so the ``except json.JSONDecodeError``
around the parse never fired, the library call raised, and the CLI's ``main()``
had no handler either -- so the process died with a traceback, printed no
report, and aborted a whole batch.
"""

import contextlib
import io
import sys
from unittest.mock import MagicMock, patch

import httpx

from a2a_drift import AgentCardChecker, cli

# A second, fully valid card, used to prove a broken URL does not discard the
# rest of a batch run.
GOOD_CARD = {
    "name": "Good Agent",
    "description": "Fine",
    "url": "https://example.com/a2a",
    "version": "1.0.0",
    "protocolVersion": "1.0",
    "capabilities": {"streaming": True},
}


def good_card_response():
    """A 200 response whose body is the valid card above."""
    response = MagicMock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.return_value = GOOD_CARD
    return response


# A JSON document whose string values contain bytes that are not valid UTF-8.
# 0xff is never a legal UTF-8 lead byte, so the decode fails inside json.loads.
NON_UTF8_BODY = b'{"name": "Agent \xff\xfe", "protocolVersion": "1.0"}'

# Valid UTF-8 that is nonetheless not JSON: the *syntax* failure case.
NOT_JSON_BODY = b"this is not json"


def run_cli(argv):
    """Run cli.main() with argv; return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with patch.object(sys, "argv", ["a2a-drift"] + argv):
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                cli.main()
        except SystemExit as exc:
            code = exc.code if exc.code is not None else 0
    return code, out.getvalue(), err.getvalue()


CARD_URL = "https://example.com/card.json"


def card_response(body: bytes):
    """A real httpx 200 response carrying ``body``.

    ``request=`` is required: ``raise_for_status()`` refuses to run on a
    response with no request instance, which would send every test down the
    fetch-error path instead of the JSON parse under test.
    """
    return httpx.Response(200, content=body, request=httpx.Request("GET", CARD_URL))


def fetch_body(body: bytes):
    """Validate a card whose HTTP response carries exactly ``body``."""
    with patch("a2a_drift.httpx.get", return_value=card_response(body)):
        return AgentCardChecker(CARD_URL).validate()


class TestUndecodableCardBody:
    """validate() must report an undecodable body instead of raising."""

    def test_non_utf8_body_returns_a_result_instead_of_raising(self):
        result = fetch_body(NON_UTF8_BODY)

        assert result.is_compliant is False
        assert result.drift

    def test_non_utf8_body_is_reported_as_an_error_severity_finding(self):
        result = fetch_body(NON_UTF8_BODY)

        errors = [d for d in result.drift if d.severity == "error"]
        assert errors, "an undecodable card must be an error-severity finding"

    def test_decode_failure_is_named_distinctly_from_a_json_syntax_failure(self):
        """Two different conditions must not be reported under one name.

        A body that is not UTF-8 never reached the JSON parser at all, so
        blaming "not valid JSON" for it is a misdiagnosis the operator cannot
        act on. The drift type and the message must both tell the two apart.
        """
        decoded = fetch_body(NON_UTF8_BODY)
        syntax = fetch_body(NOT_JSON_BODY)

        decode_message = " ".join(d.message for d in decoded.drift)
        syntax_message = " ".join(d.message for d in syntax.drift)

        assert decode_message != syntax_message
        assert "utf-8" in decode_message.lower()
        assert "decode" in decode_message.lower()
        assert "not valid json" not in decode_message.lower()

        assert "not valid json" in syntax_message.lower()

        decode_types = {d.drift_type for d in decoded.drift}
        syntax_types = {d.drift_type for d in syntax.drift}
        assert not (decode_types & syntax_types), (
            f"decode and syntax failures must not share a drift type: "
            f"{decode_types & syntax_types}"
        )

    def test_error_is_set_on_the_result(self):
        result = fetch_body(NON_UTF8_BODY)

        assert result.error is not None
        assert result.error in [d.message for d in result.drift]


class TestCliOnUndecodableCardBody:
    """The CLI contract is a report on stdout plus a non-zero exit code."""

    def test_check_exits_non_zero_on_an_undecodable_card(self):
        with patch("a2a_drift.httpx.get", return_value=card_response(NON_UTF8_BODY)):
            code, out, err = run_cli(["check", CARD_URL])

        assert code == 1
        assert "Traceback" not in out
        assert "Traceback" not in err

    def test_check_still_renders_a_report_on_stdout(self):
        with patch("a2a_drift.httpx.get", return_value=card_response(NON_UTF8_BODY)):
            code, out, _err = run_cli(["check", CARD_URL])

        assert "NON-COMPLIANT" in out
        assert "Drift findings" in out

    def test_check_json_format_still_renders_a_document(self):
        with patch("a2a_drift.httpx.get", return_value=card_response(NON_UTF8_BODY)):
            code, out, _err = run_cli(["check", CARD_URL, "--format", "json"])

        assert code == 1
        assert '"drift":' in out
        assert '"drift_count":' in out

    def test_batch_reports_the_decode_failure_instead_of_dying(self, tmp_path):
        """One broken card must never discard the rest of a batch."""
        url_file = tmp_path / "urls.txt"
        url_file.write_text(
            "https://broken.example/card.json\nhttps://good.example/card.json\n"
        )

        broken = card_response(NON_UTF8_BODY)

        def fake_get(url, **_kwargs):
            return broken if "broken" in url else good_card_response()

        with patch("a2a_drift.httpx.get", side_effect=fake_get):
            code, out, err = run_cli(["batch", "--file", str(url_file)])

        assert "Traceback" not in out
        assert "Traceback" not in err
        # Both URLs are accounted for: the broken one is a finding, not a crash.
        assert "broken.example" in out
        assert "good.example" in out
        assert code == 1


class TestCliNeverCrashesOnACallerUrl:
    """`check` must isolate an unexpected failure the way `batch` already does.

    This is the safety net behind the decode fix: the bytes of the card come
    from whatever host the operator pointed the tool at, and a traceback costs
    them the report the tool exists to produce.
    """

    def test_an_unexpected_checker_failure_is_reported_not_raised(self):
        with patch.object(
            cli.AgentCardChecker, "validate", side_effect=RuntimeError("boom")
        ):
            code, out, err = run_cli(["check", CARD_URL])

        assert "Traceback" not in out
        assert "Traceback" not in err
        assert code == 1
        assert "boom" in out

    def test_the_finding_names_the_exception_type(self):
        """Catching it must not hide it: the operator has to see what happened."""
        with patch.object(
            cli.AgentCardChecker, "validate", side_effect=RuntimeError("boom")
        ):
            _code, out, _err = run_cli(["check", CARD_URL])

        assert "RuntimeError: boom" in out
        assert "internal-error" in out


class TestDecodeControlCards:
    """Positive controls: the fix must not reject every body it is given."""

    def test_a_well_formed_utf8_card_still_validates(self):
        body = (
            '{"name": "Agente Ação ✅", "description": "d", '
            '"url": "https://example.com/a2a", "version": "1.0.0", '
            '"protocolVersion": "1.0", "capabilities": {"streaming": true}}'
        ).encode()

        result = fetch_body(body)

        assert result.is_compliant is True
        assert result.drift == []
        assert result.spec_version == "1.0"

    def test_a_utf8_card_with_multibyte_characters_is_not_a_decode_failure(self):
        """Multi-byte UTF-8 must still parse: the control for over-rejection."""
        body = '{"name": "café — naïve ☃", "protocolVersion": "1.0"}'.encode()

        result = fetch_body(body)

        decode_types = {
            d.drift_type
            for d in result.drift
            if "decode" in d.drift_type.lower() or "utf-8" in d.message.lower()
        }
        assert not decode_types

    def test_a_json_syntax_error_still_uses_the_original_drift_type(self):
        """The pre-existing 'not valid JSON' path must keep its name."""
        result = fetch_body(NOT_JSON_BODY)

        assert "json-parse-error" in [d.drift_type for d in result.drift]
