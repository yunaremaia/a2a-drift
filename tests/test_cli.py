"""Tests for the a2a-drift CLI: output formats, batch isolation, flags."""

import contextlib
import io
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from a2a_drift import cli

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


class TestSarifOutput:
    """--format sarif must emit SARIF 2.1.0, not the human-readable text report."""

    @patch("a2a_drift.httpx.get")
    def test_sarif_document_structure(self, mock_get):
        mock_get.return_value = card_response(LEGACY_CARD)

        code, out, _err = run_cli(
            ["check", "https://example.com/card.json", "--format", "sarif"]
        )

        doc = json.loads(out)
        assert doc["version"] == "2.1.0"
        assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "a2a-drift"
        assert driver["version"]

    @patch("a2a_drift.httpx.get")
    def test_sarif_results_match_drift_findings(self, mock_get):
        mock_get.return_value = card_response(LEGACY_CARD)

        _, out, _err = run_cli(
            ["check", "https://example.com/card.json", "--format", "sarif"]
        )
        doc = json.loads(out)
        results = doc["runs"][0]["results"]

        _, json_out, _err = run_cli(
            ["check", "https://example.com/card.json", "--format", "json"]
        )
        expected = json.loads(json_out)["drift"]

        assert len(results) == len(expected)
        assert [r["ruleId"] for r in results] == [d["type"] for d in expected]
        assert [r["level"] for r in results] == [
            {"error": "error", "warning": "warning", "info": "note"}[d["severity"]]
            for d in expected
        ]
        for result in results:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert uri == "https://example.com/card.json"

    @patch("a2a_drift.httpx.get")
    def test_sarif_empty_results_when_compliant(self, mock_get, valid_agent_card):
        mock_get.return_value = card_response(valid_agent_card)

        code, out, _err = run_cli(
            ["check", "https://example.com/card.json", "--format", "sarif"]
        )

        doc = json.loads(out)
        assert doc["runs"][0]["results"] == []
        assert code == 0

    @patch("a2a_drift.httpx.get")
    def test_sarif_exits_nonzero_on_error_drift(self, mock_get):
        mock_get.return_value = card_response({"name": "Incomplete"})

        code, out, _err = run_cli(
            ["check", "https://example.com/card.json", "--format", "sarif"]
        )

        assert code == 1
        assert json.loads(out)["runs"][0]["results"]

    def test_to_sarif_maps_severities(self):
        from a2a_drift import DriftFinding, ValidationResult

        result = ValidationResult(url="https://example.com/card.json")
        result.drift = [
            DriftFinding("schema-violation", "error", "boom", "$"),
            DriftFinding("spec-version", "warning", "old spec"),
            DriftFinding("capability-drift", "info", "note"),
        ]

        doc = cli.to_sarif(result)
        assert [r["level"] for r in doc["runs"][0]["results"]] == [
            "error",
            "warning",
            "note",
        ]


class TestBatchIsolation:
    """One broken agent card must not discard the rest of the batch."""

    @patch("a2a_drift.httpx.get")
    def test_non_object_card_does_not_abort_batch(
        self, mock_get, tmp_path, valid_agent_card
    ):
        good = card_response(valid_agent_card)
        bad = card_response([1, 2, 3])
        mock_get.side_effect = [good, bad, good]

        urls = tmp_path / "agents.txt"
        urls.write_text(
            "https://example.com/one.json\n"
            "https://example.com/bad.json\n"
            "https://example.com/two.json\n"
        )
        code, out, _err = run_cli(
            ["batch", "--file", str(urls), "--format", "json", "--retries", "1"]
        )

        results = json.loads(out)
        assert len(results) == 3
        assert results[0]["is_compliant"] is True
        assert results[1]["is_compliant"] is False
        assert results[2]["is_compliant"] is True
        assert "must be a JSON object" in results[1]["error"]
        assert code == 1

    @patch("a2a_drift.httpx.get")
    def test_text_batch_reports_every_entry(
        self, mock_get, tmp_path, valid_agent_card
    ):
        mock_get.side_effect = [
            card_response([1, 2, 3]),
            card_response(valid_agent_card),
        ]

        urls = tmp_path / "agents.txt"
        urls.write_text(
            "https://example.com/bad.json\nhttps://example.com/good.json\n"
        )
        code, out, _err = run_cli(
            ["batch", "--file", str(urls), "--retries", "1"]
        )

        assert "bad.json" in out
        assert "good.json" in out
        assert code == 1

    def test_empty_batch_file_is_not_a_vacuous_success(self, tmp_path):
        urls = tmp_path / "empty.txt"
        urls.write_text("\n  \n")

        code, _out, err = run_cli(
            ["batch", "--file", str(urls), "--format", "json"]
        )

        assert code == 1
        assert "no agent card URLs" in err

    def test_missing_batch_file_reports_cleanly(self, tmp_path):
        code, _out, err = run_cli(["batch", "--file", str(tmp_path / "nope.txt")])

        assert code == 1
        assert "no such file" in err


class TestRetriesFlag:
    """--retries is validated at the CLI boundary instead of crashing later."""

    @pytest.mark.parametrize("value", ["0", "-1", "-5"])
    def test_non_positive_retries_is_an_argument_error(self, value):
        code, out, err = run_cli(
            ["check", "https://example.com/card.json", "--retries", value]
        )

        assert code == 2
        assert "must be >= 1" in err
        assert out == ""

    @pytest.mark.parametrize("value", ["0", "-1"])
    def test_non_positive_retries_is_an_argument_error_for_probe(self, value):
        code, out, err = run_cli(
            ["probe", "https://example.com/a2a", "--retries", value]
        )

        assert code == 2
        assert "must be >= 1" in err
        assert out == ""


class TestSpecVersionFlag:
    """--spec-version selects the version drift is measured against."""

    @patch("a2a_drift.httpx.get")
    def test_legacy_card_is_current_when_targeting_v03(self, mock_get):
        mock_get.return_value = card_response(LEGACY_CARD)

        code, out, _err = run_cli(
            [
                "check",
                "https://example.com/card.json",
                "--spec-version",
                "0.3",
                "--format",
                "json",
            ]
        )

        report = json.loads(out)
        assert report["target_spec_version"] == "0.3"
        assert report["spec_version"] == "0.3"
        assert [d for d in report["drift"] if d["type"] == "spec-version"] == []
        assert code == 0

    @patch("a2a_drift.httpx.get")
    def test_current_card_drifts_when_targeting_v03(self, mock_get, valid_agent_card):
        mock_get.return_value = card_response(valid_agent_card)

        code, out, _err = run_cli(
            [
                "check",
                "https://example.com/card.json",
                "--spec-version",
                "0.3",
                "--format",
                "json",
            ]
        )

        report = json.loads(out)
        assert [d["type"] for d in report["drift"]] == ["spec-version"]
        assert report["drift"][0]["severity"] == "warning"

    @patch("a2a_drift.httpx.get")
    def test_default_target_is_current_spec(self, mock_get, valid_agent_card):
        mock_get.return_value = card_response(valid_agent_card)

        _, out, _err = run_cli(
            ["check", "https://example.com/card.json", "--format", "json"]
        )

        assert json.loads(out)["target_spec_version"] == "1.0"


class TestDenyInternalFlag:
    """--deny-internal blocks requests to internal network addresses."""

    @patch("a2a_drift.httpx.get")
    def test_internal_url_blocked_by_default_in_ci_mode(self, mock_get):
        code, out, _err = run_cli(
            [
                "check",
                "http://127.0.0.1:9999/agent-card.json",
                "--deny-internal",
                "--format",
                "json",
            ]
        )

        report = json.loads(out)
        assert code == 1
        assert "internal URL blocked" in report["error"]
        assert mock_get.call_count == 0

    @patch("a2a_drift.httpx.get")
    def test_internal_url_allowed_when_flag_is_absent(self, mock_get, valid_agent_card):
        mock_get.return_value = card_response(valid_agent_card)

        code, out, _err = run_cli(
            ["check", "http://127.0.0.1:9999/agent-card.json", "--format", "json"]
        )

        assert code == 0
        assert json.loads(out)["is_compliant"] is True
        assert mock_get.call_count == 1

    @patch("a2a_drift.httpx.post")
    def test_probe_respects_deny_internal(self, mock_post):
        code, out, _err = run_cli(
            ["probe", "http://169.254.169.254/latest/", "--deny-internal"]
        )

        assert code == 1
        assert "internal URL blocked" in out
        assert mock_post.call_count == 0

    @patch("a2a_drift.httpx.get")
    def test_allow_internal_wins_when_both_flags_are_passed(
        self, mock_get, valid_agent_card
    ):
        """Passing both flags currently resolves to "allow internal".

        Documented as a known ambiguity in BACKLOG.md: the flags are
        independent booleans and the effective value is
        ``allow_internal or not deny_internal``, so the permissive flag wins.
        This test pins the current behaviour so a future decision to make them
        mutually exclusive changes it deliberately.
        """
        mock_get.return_value = card_response(valid_agent_card)

        code, out, _err = run_cli(
            [
                "check",
                "http://127.0.0.1:9999/agent-card.json",
                "--deny-internal",
                "--allow-internal",
                "--format",
                "json",
            ]
        )

        assert code == 0
        assert json.loads(out)["is_compliant"] is True
        assert mock_get.call_count == 1


class TestModuleEntryPoint:
    """`python -m a2a_drift` must dispatch to the CLI, not just re-export names."""

    def test_dunder_main_exposes_the_public_api(self):
        import a2a_drift.__main__ as entry

        assert entry.AgentCardChecker is not None
        assert entry.EndpointProber is not None
        assert callable(entry.main)

    def test_dunder_main_runs_the_cli(self, capsys):
        import subprocess
        import sys

        completed = subprocess.run(
            [sys.executable, "-m", "a2a_drift", "--help"],
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0
        assert "Detect A2A protocol compliance drift" in completed.stdout
        assert "{check,probe,batch}" in completed.stdout
