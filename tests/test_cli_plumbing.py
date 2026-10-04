"""Tests for CLI plumbing that the higher-level CLI tests do not reach.

Covers ``--output`` file writes, ``--params`` parsing, batch read failures, the
per-item exception guard, and the ``python -m`` / ``cli.py`` entrypoints. The
HTTP layer is mocked exactly as elsewhere in the suite, so nothing here needs a
network.
"""

import contextlib
import io
import json
import runpy
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from a2a_drift import AgentCardChecker, cli

LEGACY_CARD = {
    "name": "Legacy Agent",
    "description": "Old spec",
    "url": "https://example.com/a2a",
    "version": "0.3.0",
    "protocolVersion": "0.3",
    "capabilities": {},
}


def run_cli(argv):
    """Run cli.main() with argv.

    Returns (exit_code, stdout, stderr).
    """
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with patch.object(sys, "argv", ["a2a-drift"] + argv):
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                cli.main()
        except SystemExit as exc:
            code = exc.code if exc.code is not None else 0
    return code, out.getvalue(), err.getvalue()


def card_response(payload):
    response = MagicMock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


def rpc_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


VALID_RPC = {"jsonrpc": "2.0", "id": 1, "result": {}}


class TestPositiveIntParsing:
    """--retries rejects anything that is not an integer of at least 1."""

    @pytest.mark.parametrize("value", ["abc", "1.5", "", " ", "0x3", "1e3"])
    def test_non_integer_retries_is_an_argument_error(self, value):
        code, out, err = run_cli(
            ["check", "https://example.com/card.json", "--retries", value]
        )

        assert code == 2
        assert "is not an integer" in err
        assert out == ""

    def test_integer_retries_is_accepted(self):
        with patch("a2a_drift.httpx.get", return_value=card_response(LEGACY_CARD)):
            code, out, _err = run_cli(
                [
                    "check",
                    "https://example.com/card.json",
                    "--retries",
                    "2",
                    "--format",
                    "json",
                ]
            )

        # Only a spec-version warning, which does not break compliance.
        assert code == 0
        assert json.loads(out)["attempts"] == 1


class TestOutputFileWrites:
    """--output writes the rendered report to a file instead of stdout."""

    @patch("a2a_drift.httpx.get")
    def test_check_writes_report_to_file(self, mock_get, tmp_path, valid_agent_card):
        mock_get.return_value = card_response(valid_agent_card)
        target = tmp_path / "report.json"

        code, out, _err = run_cli(
            [
                "check",
                "https://example.com/card.json",
                "--format",
                "json",
                "--output",
                str(target),
            ]
        )

        assert out == ""
        report = json.loads(target.read_text())
        assert report["is_compliant"] is True
        assert target.read_text().endswith("\n")
        assert code == 0

    @patch("a2a_drift.httpx.get")
    def test_check_writes_non_compliant_report_too(self, mock_get, tmp_path):
        mock_get.return_value = card_response({"name": "Incomplete"})
        target = tmp_path / "report.txt"

        code, out, _err = run_cli(
            ["check", "https://example.com/card.json", "--output", str(target)]
        )

        assert out == ""
        assert "NON-COMPLIANT" in target.read_text()
        assert code == 1

    @patch("a2a_drift.httpx.post")
    def test_probe_writes_report_to_file(self, mock_post, tmp_path):
        mock_post.return_value = rpc_response(VALID_RPC)
        target = tmp_path / "probe.json"

        code, out, _err = run_cli(
            [
                "probe",
                "https://example.com/a2a",
                "--format",
                "json",
                "--output",
                str(target),
            ]
        )

        assert out == ""
        report = json.loads(target.read_text())
        assert report["jsonrpc_compliant"] is True
        assert code == 0

    @patch("a2a_drift.httpx.post")
    def test_probe_writes_sarif_to_file(self, mock_post, tmp_path):
        mock_post.return_value = rpc_response({"jsonrpc": "1.0", "id": 1, "result": {}})
        target = tmp_path / "probe.sarif"

        code, out, _err = run_cli(
            [
                "probe",
                "https://example.com/a2a",
                "--format",
                "sarif",
                "--output",
                str(target),
            ]
        )

        assert out == ""
        doc = json.loads(target.read_text())
        assert doc["version"] == "2.1.0"
        # Asserted by membership, not by index: a probe also reports what it
        # sent, so results[0] is the request-schema finding, not this one.
        rule_ids = [r["ruleId"] for r in doc["runs"][0]["results"]]
        assert "jsonrpc-conformance" in rule_ids
        assert set(rule_ids) == {"jsonrpc-request", "jsonrpc-conformance"}
        assert code == 1

    @patch("a2a_drift.httpx.get")
    def test_batch_writes_report_to_file(self, mock_get, tmp_path, valid_agent_card):
        mock_get.side_effect = [
            card_response(valid_agent_card),
            card_response(LEGACY_CARD),
        ]
        urls = tmp_path / "agents.txt"
        urls.write_text("https://example.com/one.json\nhttps://example.com/two.json\n")
        target = tmp_path / "batch.json"

        code, out, _err = run_cli(
            [
                "batch",
                "--file",
                str(urls),
                "--format",
                "json",
                "--output",
                str(target),
            ]
        )

        assert out == ""
        results = json.loads(target.read_text())
        assert [r["is_compliant"] for r in results] == [True, True]
        assert code == 0


class TestProbeParamsParsing:
    """--params must be JSON; a bad value is an argument error, not a traceback."""

    @patch("a2a_drift.httpx.post")
    def test_params_are_forwarded_verbatim(self, mock_post):
        mock_post.return_value = rpc_response(VALID_RPC)

        run_cli(
            [
                "probe",
                "https://example.com/a2a",
                "--params",
                '{"message": {"role": "user"}}',
            ]
        )

        payload = mock_post.call_args.kwargs["json"]
        assert payload["params"] == {"message": {"role": "user"}}
        assert payload["method"] == "message/send"
        assert payload["jsonrpc"] == "2.0"

    def test_invalid_params_json_is_an_argument_error(self):
        code, out, err = run_cli(
            ["probe", "https://example.com/a2a", "--params", "{not json}"]
        )

        assert code == 2
        assert "--params is not valid JSON" in err
        assert out == ""

    @patch("a2a_drift.httpx.post")
    def test_empty_params_string_falls_back_to_no_params(self, mock_post):
        mock_post.return_value = rpc_response(VALID_RPC)

        run_cli(["probe", "https://example.com/a2a", "--params", ""])

        assert mock_post.call_args.kwargs["json"]["params"] == {}

    @patch("a2a_drift.httpx.post")
    def test_custom_method_is_used(self, mock_post):
        mock_post.return_value = rpc_response(VALID_RPC)

        run_cli(["probe", "https://example.com/a2a", "--method", "tasks/get"])

        assert mock_post.call_args.kwargs["json"]["method"] == "tasks/get"


# Falsy JSON values that are still real values: each parses to a non-None
# object that a user deliberately typed, so each has to reach the wire.
FALSY_PARAMS = [
    ("[]", []),
    ("0", 0),
    ('""', ""),
    ("false", False),
]


class TestProbeParamsReachTheWireUnchanged:
    """The `params` member must carry exactly the value that was typed.

    ``probe()`` built its payload with ``params or {}``, so every falsy JSON
    value -- ``[]``, ``0``, ``false``, ``""`` -- was swapped for an empty
    object *before* the request was issued, while ``validate_method_request()``
    was handed the original and named its type. The finding then described a
    request the endpoint never received, and the JSON-RPC verdict for the run
    was attributed to the wrong payload (issue #44).

    "Not supplied" is a different thing from "supplied a falsy value", and the
    payload is where the two are told apart: an omitted ``--params`` sends no
    ``params`` member at all, because JSON-RPC 2.0 allows it to be absent,
    while ``--params 0`` sends ``0``.
    """

    @patch("a2a_drift.httpx.post")
    def test_an_omitted_flag_sends_no_params_member(self, mock_post):
        mock_post.return_value = rpc_response(VALID_RPC)

        run_cli(["probe", "https://example.com/a2a", "--method", "tasks/get"])

        payload = mock_post.call_args.kwargs["json"]
        assert "params" not in payload
        # Positive control: only `params` is absent. The request is still a
        # well-formed JSON-RPC request, so this is not "nothing was sent".
        assert payload == {"jsonrpc": "2.0", "method": "tasks/get", "id": 1}

    @pytest.mark.parametrize(
        ("raw", "expected"),
        FALSY_PARAMS,
        ids=["array", "zero", "empty-string", "false"],
    )
    @patch("a2a_drift.httpx.post")
    def test_falsy_params_are_sent_verbatim(self, mock_post, raw, expected):
        mock_post.return_value = rpc_response(VALID_RPC)

        run_cli(["probe", "https://example.com/a2a", "--params", raw])

        sent = mock_post.call_args.kwargs["json"]["params"]
        assert sent == expected
        # `0 == False` and `False == []` is False, so equality alone cannot
        # tell an integer zero from a boolean false on the wire.
        assert type(sent) is type(expected)

    @patch("a2a_drift.httpx.post")
    def test_an_explicit_empty_object_is_still_sent(self, mock_post):
        """The control from the issue: a non-empty object is already verbatim."""
        mock_post.return_value = rpc_response(VALID_RPC)

        run_cli(["probe", "https://example.com/a2a", "--params", '{"id": "t-1"}'])

        assert mock_post.call_args.kwargs["json"]["params"] == {"id": "t-1"}

    @patch("a2a_drift.httpx.post")
    def test_the_finding_names_the_value_that_reached_the_wire(self, mock_post):
        """The report and the request must describe the same payload."""
        mock_post.return_value = rpc_response(VALID_RPC)

        code, out, _err = run_cli(
            [
                "probe",
                "https://example.com/a2a",
                "--method",
                "tasks/get",
                "--params",
                "[]",
            ]
        )

        sent = mock_post.call_args.kwargs["json"]["params"]
        assert sent == [], f"the wire carried {sent!r}, not the typed []"
        assert "params must be a JSON object, got list" in out
        # The finding is about the request, not the endpoint, so an endpoint
        # that answers it correctly is still compliant.
        assert code == 0

    @patch("a2a_drift.httpx.post")
    def test_an_explicit_null_is_sent_as_no_params(self, mock_post):
        """``null`` is not a Structured value, so it is sent as no params.

        Pinned because it is the one falsy JSON value that *is* Python's
        ``None``: JSON-RPC 2.0 requires ``params`` to be an object or array
        when present, and ``validate_method_request`` already reads ``None`` as
        "no params". The alternative -- transmitting ``params: null`` -- would
        put a value the spec disallows on the wire.
        """
        mock_post.return_value = rpc_response(VALID_RPC)

        code, out, _err = run_cli(
            [
                "probe",
                "https://example.com/a2a",
                "--method",
                "tasks/get",
                "--params",
                "null",
            ]
        )

        payload = mock_post.call_args.kwargs["json"]
        assert "params" not in payload
        assert "params.id is required by method 'tasks/get'" in out
        assert code == 0


class TestBatchFileErrors:
    """A batch file that cannot be read must be reported, not raised."""

    def test_directory_instead_of_file_reports_read_error(self, tmp_path):
        code, out, err = run_cli(["batch", "--file", str(tmp_path)])

        assert code == 1
        assert "could not read" in err
        assert out == ""

    @patch("a2a_drift.httpx.get")
    def test_batch_sarif_merges_one_run_per_agent(
        self, mock_get, tmp_path, valid_agent_card
    ):
        mock_get.side_effect = [
            card_response(valid_agent_card),
            card_response(LEGACY_CARD),
        ]
        urls = tmp_path / "agents.txt"
        urls.write_text("https://example.com/one.json\nhttps://example.com/two.json\n")

        code, out, _err = run_cli(["batch", "--file", str(urls), "--format", "sarif"])

        doc = json.loads(out)
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 2
        # The compliant agent contributes an empty run, the legacy one a finding.
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][1]["results"][0]["ruleId"] == "spec-version"
        assert code == 0

    def test_batch_skips_blank_lines(self, tmp_path, valid_agent_card):
        urls = tmp_path / "agents.txt"
        urls.write_text(
            "\nhttps://example.com/one.json\n\n   \nhttps://example.com/two.json\n"
        )
        with patch("a2a_drift.httpx.get", return_value=card_response(valid_agent_card)):
            code, out, _err = run_cli(
                ["batch", "--file", str(urls), "--format", "json"]
            )

        assert code == 0
        assert len(json.loads(out)) == 2


class TestBatchPerItemException:
    """An unexpected exception on one agent must not abort the batch."""

    def test_unexpected_checker_exception_is_isolated(self, tmp_path, valid_agent_card):
        urls = tmp_path / "agents.txt"
        urls.write_text("https://example.com/boom.json\nhttps://example.com/ok.json\n")
        real_checker = AgentCardChecker

        def build(url, **kwargs):
            if "boom" in url:
                raise RuntimeError("checker exploded")
            return real_checker(url, **kwargs)

        with patch("a2a_drift.httpx.get", return_value=card_response(valid_agent_card)):
            with patch("a2a_drift.cli.AgentCardChecker", side_effect=build):
                code, out, _err = run_cli(
                    ["batch", "--file", str(urls), "--format", "json"]
                )

        results = json.loads(out)
        assert results[0]["is_compliant"] is False
        assert results[0]["error"] == "RuntimeError: checker exploded"
        assert results[0]["drift_count"] == 1
        assert results[1]["is_compliant"] is True
        assert code == 1

    def test_text_batch_surfaces_the_per_item_error(self, tmp_path):
        urls = tmp_path / "agents.txt"
        urls.write_text("https://example.com/boom.json\n")

        with patch(
            "a2a_drift.cli.AgentCardChecker",
            side_effect=ValueError("bad url"),
        ):
            code, out, _err = run_cli(["batch", "--file", str(urls)])

        assert "ValueError: bad url" in out
        assert "NON-COMPLIANT" in out
        assert code == 1


class TestUnwritableOutputPath:
    """An unwritable --output is a usage error, not a traceback (issue #43).

    All three subcommands wrote the report with a bare ``open()``. A missing
    parent directory or a read-only mount raised out of ``main()``, and the
    process died with a traceback and exit 1 -- the same code that means
    NON-COMPLIANT, so a CI gate could not tell "the checker broke" from "the
    agent drifted". These tests pin the distinct exit code and the message.

    Every case here raises a real ``OSError`` from the real ``open()``: the
    point of the fix is which exception the handler catches, so mocking
    ``open`` would test the mock rather than the contract. ``FileNotFoundError``
    is an ``OSError`` subclass, so the missing-parent case covers the handler.
    """

    @patch("a2a_drift.httpx.get")
    def test_check_exits_2_when_output_dir_is_missing(self, mock_get, tmp_path):
        mock_get.return_value = card_response(LEGACY_CARD)
        target = tmp_path / "no-such-dir" / "report.json"

        code, out, err = run_cli(
            ["check", "https://example.com/card.json", "--output", str(target)]
        )

        assert code == 2
        # No traceback, and nothing on stdout pretending a report was produced.
        assert "Traceback" not in err
        assert out == ""
        assert str(target) in err
        assert "cannot write" in err

    @patch("a2a_drift.httpx.post")
    def test_probe_exits_2_when_output_dir_is_missing(self, mock_post, tmp_path):
        mock_post.return_value = rpc_response(VALID_RPC)
        target = tmp_path / "no-such-dir" / "probe.json"

        code, out, err = run_cli(
            ["probe", "https://example.com/a2a", "--output", str(target)]
        )

        assert code == 2
        assert "Traceback" not in err
        assert out == ""
        assert str(target) in err
        assert "cannot write" in err

    @patch("a2a_drift.httpx.get")
    def test_batch_exits_2_when_output_dir_is_missing(self, mock_get, tmp_path):
        mock_get.return_value = card_response(LEGACY_CARD)
        urls = tmp_path / "agents.txt"
        urls.write_text("https://example.com/one.json\n")
        target = tmp_path / "no-such-dir" / "batch.json"

        code, out, err = run_cli(
            ["batch", "--file", str(urls), "--output", str(target)]
        )

        assert code == 2
        assert "Traceback" not in err
        assert out == ""
        assert str(target) in err
        assert "cannot write" in err

    @patch("a2a_drift.httpx.get")
    def test_check_exits_2_when_output_path_is_a_directory(self, mock_get, tmp_path):
        """A path that is a directory raises IsADirectoryError, also an OSError."""
        mock_get.return_value = card_response(LEGACY_CARD)
        target = tmp_path / "a-directory"
        target.mkdir()

        code, _out, err = run_cli(
            ["check", "https://example.com/card.json", "--output", str(target)]
        )

        assert code == 2
        assert "Traceback" not in err
        assert "cannot write" in err

    @patch("a2a_drift.httpx.get")
    def test_write_failure_is_distinguishable_from_drift(self, mock_get, tmp_path):
        """The whole point of exit 2: it must not collide with exit 1.

        A NON-COMPLIANT agent reports drift and exits 1; the same run with an
        unwritable output path exits 2. A CI gate keys on those two numbers, so
        a regression here silently turns a crash into a drift verdict.
        """
        mock_get.return_value = card_response({"name": "Incomplete"})

        drifted, _out, _err = run_cli(
            [
                "check",
                "https://example.com/card.json",
                "--output",
                str(tmp_path / "ok.json"),
            ]
        )
        broken, _out2, _err2 = run_cli(
            [
                "check",
                "https://example.com/card.json",
                "--output",
                str(tmp_path / "no-such-dir" / "ok.json"),
            ]
        )

        assert drifted == 1
        assert broken == 2
        assert drifted != broken


class TestTextReportSections:
    """The text report only prints the detail lines it actually has data for."""

    @patch("a2a_drift.httpx.post")
    def test_probe_text_report_includes_measured_details(self, mock_post):
        mock_post.return_value = rpc_response(VALID_RPC)

        _code, out, _err = run_cli(["probe", "https://example.com/a2a"])

        assert "JSON-RPC compliant: True" in out
        assert "Response time:" in out
        assert "Attempts: 1" in out

    @patch("a2a_drift.httpx.get")
    def test_check_text_report_omits_lines_without_data(self, mock_get):
        mock_get.return_value = card_response({"name": "Incomplete"})

        _code, out, _err = run_cli(["check", "https://example.com/card.json"])

        # A fetch never ran, so there is no timing and no JSON-RPC verdict.
        assert "Response time:" not in out
        assert "JSON-RPC compliant:" not in out
        # An undetermined spec version must not be invented.
        assert "Spec version:" not in out
        assert "Could not determine A2A spec version" in out

    @patch("a2a_drift.httpx.get")
    def test_check_text_report_includes_error_and_findings(self, mock_get):
        mock_get.return_value = card_response(LEGACY_CARD)

        _code, out, _err = run_cli(["check", "https://example.com/card.json"])

        assert "Spec version: 0.3" in out
        assert "Drift findings (" in out
        assert "[WARNING] spec-version:" in out

    @patch("a2a_drift.httpx.get")
    def test_check_text_report_includes_transport_error(self, mock_get):
        mock_get.side_effect = __import__("httpx").ConnectError("refused")

        _code, out, _err = run_cli(
            ["check", "https://example.com/card.json", "--retries", "1"]
        )

        assert "Error: Failed to fetch agent card" in out
        assert "[ERROR] fetch-error:" in out


class TestModuleEntrypoints:
    """Both module entrypoints must dispatch to the CLI."""

    def test_running_the_package_with_no_arguments_is_not_a_crash(self):
        """``python -m a2a_drift`` must print usage, not raise AttributeError.

        With no subcommand the parsed namespace has no ``allow_internal``, so
        reading it unconditionally crashed with a traceback and exit code 1.
        """
        completed = subprocess.run(
            [sys.executable, "-m", "a2a_drift"],
            capture_output=True,
            text=True,
        )

        assert "AttributeError" not in completed.stderr
        assert "Traceback" not in completed.stderr
        assert completed.returncode != 0
        assert "usage: a2a-drift" in (completed.stderr + completed.stdout)

    def test_running_the_package_with_no_arguments_inside_the_cli(self):
        """The same no-subcommand path, exercised in-process via run_cli."""
        code, out, err = run_cli([])

        assert code != 0
        assert "Traceback" not in err
        assert "AttributeError" not in err
        assert "usage: a2a-drift" in (out + err)

    def test_cli_module_is_runnable_as_a_script(self):
        """``python -m a2a_drift.cli`` reaches the same ``__main__`` guard."""
        completed = subprocess.run(
            [sys.executable, "-m", "a2a_drift.cli", "--help"],
            capture_output=True,
            text=True,
        )

        assert completed.returncode == 0
        assert "Detect A2A protocol compliance drift" in completed.stdout

    def test_runpy_executes_the_package_main_guard(self):
        """runpy covers the ``if __name__ == '__main__'`` line under coverage."""
        import a2a_drift.__main__ as entry

        with patch.object(sys, "argv", ["a2a-drift", "--help"]):
            with contextlib.redirect_stdout(io.StringIO()):
                with pytest.raises(SystemExit) as excinfo:
                    runpy.run_path(entry.__file__, run_name="__main__")

        assert excinfo.value.code == 0

    def test_runpy_executes_the_cli_main_guard(self):
        with patch.object(sys, "argv", ["a2a-drift", "--help"]):
            with contextlib.redirect_stdout(io.StringIO()):
                with pytest.raises(SystemExit) as excinfo:
                    runpy.run_path(cli.__file__, run_name="__main__")

        assert excinfo.value.code == 0
