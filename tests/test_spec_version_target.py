"""--spec-version target must be normalised like the detected value, or rejected.

The bug this pins: only the *detected* ``protocolVersion`` went through
``_normalize_spec_version``. The *target* came from the command line verbatim,
so it was compared in a different space than the value it was being compared to.

    --spec-version 1.0.0   -> phantom drift against a conformant v1.0 agent
    --spec-version v1.0    -> phantom drift, and the message reads "vv1.0"
    --spec-version banana  -> accepted silently, exit 0
    --spec-version '   '   -> a whitespace target that silently became the default

A drift tool that reports phantom drift, or that cannot tell a typo apart from
a clean run, is worse than one that reports nothing: CI goes green against a
broken card, or red against a healthy one, for the wrong reason.

The CONTROL test at the end is the one that matters most. Every case above is a
*false positive* case, so a "fix" that simply refuses to compare anything would
make them all pass. ``test_genuine_mismatch_is_still_reported`` proves a real
v0.3-vs-v1.0 mismatch is still reported, with the existing severity and message.
"""

import contextlib
import io
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from a2a_drift import AgentCardChecker, cli

# The accepted values, spelled out rather than read from the class, so a change
# to SPEC_VERSIONS that breaks these tests reports itself instead of moving the
# goalposts along with the implementation.
KNOWN_SPEC_VERSIONS = ("0.3", "1.0")


def v10_card():
    """A conformant v1.0 agent card: zero drift against a 1.0 target."""
    return {
        "name": "Test Agent",
        "description": "A test agent",
        "url": "https://example.com/a2a",
        "version": "1.0.0",
        "protocolVersion": "1.0",
        "capabilities": {"streaming": True},
    }


def v03_card():
    """A conformant v0.3 agent card: zero drift against a 0.3 target."""
    return {
        "name": "Legacy Agent",
        "description": "Old spec",
        "url": "https://example.com/a2a",
        "version": "0.3.0",
        "protocolVersion": "0.3",
        "capabilities": {"streaming": True},
    }


def run_cli(argv):
    """Run cli.main() with argv. Returns (exit_code, stdout, stderr)."""
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


def check_with_target(target, card):
    """Run `check` against `card` with an explicit --spec-version target.

    Returns (exit_code, report_or_None, stderr). report is None when the CLI
    refused to run, which is what an unusable target must do.
    """
    with patch("a2a_drift.httpx.get") as mock_get:
        mock_get.return_value = card_response(card)
        code, out, err = run_cli(
            [
                "check",
                "https://example.com/card.json",
                "--spec-version",
                target,
                "--format",
                "json",
            ]
        )
    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        report = None
    return code, report, err


def spec_drift(report):
    return [d for d in report["drift"] if d["type"] == "spec-version"]


class TestTargetNormalisation:
    """A target naming a known version must measure drift in the same space as
    the detected value, so an equivalent spelling reports no drift."""

    @pytest.mark.parametrize("target", ["1.0.0", "1.0.1", "1.0.0.0", "1.0"])
    def test_patch_component_target_reports_no_drift(self, target):
        """--spec-version 1.0.0 is the same version as 1.0.

        The detected side already truncates to major.minor, so the patch level
        is noise. Comparing the raw strings reported a mismatch against a card
        that is perfectly conformant. "1.0.0.0" is included because the target
        now goes through the same helper as the card: anything it reads as 1.0
        the target must read as 1.0 too, or a card declaring "1.0.0.0" would
        only be checkable against the narrower spelling "1.0".
        """
        code, report, _err = check_with_target(target, v10_card())

        assert spec_drift(report) == []
        assert code == 0

    @pytest.mark.parametrize("target", ["1.0-rc.1", "1.0+build.7", "1.0.0-rc.2"])
    def test_prerelease_and_build_suffix_target_reports_no_drift(self, target):
        """A pre-release/build suffix is stripped, exactly as on the detected side."""
        code, report, _err = check_with_target(target, v10_card())

        assert spec_drift(report) == []
        assert code == 0

    @pytest.mark.parametrize("target", ["v1.0", "V1.0"])
    def test_leading_v_target_reports_no_drift(self, target):
        """`v1.0` is how people write the version; it must not be read as a
        different one, and must not be echoed back as "vv1.0" in the message."""
        code, report, _err = check_with_target(target, v10_card())

        assert spec_drift(report) == []
        assert code == 0

    @pytest.mark.parametrize("target", ["0.3.0", "0.3", "v0.3"])
    def test_legacy_card_accepts_an_equivalent_03_target(self, target):
        """The same normalisation applies to the 0.3 line, in both directions."""
        code, report, _err = check_with_target(target, v03_card())

        assert spec_drift(report) == []
        assert report["spec_version"] == "0.3"
        assert code == 0

    def test_normalised_target_is_what_the_report_records(self):
        """The report must name the version actually measured against.

        Echoing the raw spelling ("1.0.0") here would keep the phantom drift out
        of the finding list while still telling a reader the check ran against
        something the tool does not recognise.
        """
        _, report, _err = check_with_target("v1.0.0", v10_card())

        assert report["target_spec_version"] == "1.0"

    @patch("a2a_drift.httpx.get")
    def test_library_normalises_the_target_too(self, mock_get):
        """The library is a public API; the fix cannot live only in the CLI."""
        mock_get.return_value = card_response(v10_card())

        checker = AgentCardChecker(
            "https://example.com/card.json", target_spec_version="1.0.0"
        )
        result = checker.validate()

        assert checker.target_spec_version == "1.0"
        assert result.spec_version_target == "1.0"
        assert [d for d in result.drift if d.drift_type == "spec-version"] == []
        assert result.is_compliant is True


class TestTargetRejection:
    """An explicit target that names no known version is an error, not a guess.

    Silently falling back to the current spec would make `--spec-version banana`
    behave like `--spec-version 1.0`, which is exactly the typo this must catch.
    """

    @pytest.mark.parametrize("target", ["banana", "9.9", "0.1.0", "1"])
    def test_unknown_target_exits_2_naming_the_accepted_values(self, target):
        code, report, err = check_with_target(target, v10_card())

        assert code == 2
        assert report is None
        for known in KNOWN_SPEC_VERSIONS:
            assert known in err
        assert target in err

    @pytest.mark.parametrize("target", ["", " ", "   ", "\t"])
    def test_empty_or_whitespace_target_is_rejected(self, target):
        """An empty target must not quietly become the default.

        ``target_spec_version or CURRENT_SPEC`` treated "" as "unset", so an
        empty --spec-version in a CI matrix looked identical to omitting it.
        """
        code, report, err = check_with_target(target, v10_card())

        assert code == 2
        assert report is None
        assert "--spec-version" in err

    @patch("a2a_drift.httpx.get")
    def test_rejected_target_never_fetches_the_agent_card(self, mock_get):
        """The target is validated before any network work: a typo must not
        cost a request, and must not depend on the card being reachable."""
        code, _report, _err = check_with_target("banana", v10_card())

        assert code == 2
        assert mock_get.call_count == 0

    def test_library_rejects_an_unusable_explicit_target(self):
        """Same rule for the library, so the CLI is not the only door."""
        with pytest.raises(ValueError) as excinfo:
            AgentCardChecker(
                "https://example.com/card.json", target_spec_version="banana"
            )

        for known in KNOWN_SPEC_VERSIONS:
            assert known in str(excinfo.value)

    def test_library_rejects_an_empty_explicit_target(self):
        """Passing "" is passing a value, not omitting the argument."""
        with pytest.raises(ValueError):
            AgentCardChecker("https://example.com/card.json", target_spec_version="  ")


class TestUnchangedBehaviour:
    """The fix must not disturb what already worked."""

    @patch("a2a_drift.httpx.get")
    def test_omitting_the_target_still_defaults_to_the_current_spec(
        self, mock_get, valid_agent_card
    ):
        mock_get.return_value = card_response(valid_agent_card)

        checker = AgentCardChecker("https://example.com/card.json")
        result = checker.validate()

        assert checker.target_spec_version == "1.0"
        assert result.spec_version_target == "1.0"
        assert result.is_compliant is True

    @patch("a2a_drift.httpx.get")
    def test_known_target_spelling_still_reported_verbatim_in_output(
        self, mock_get, valid_agent_card
    ):
        """A target that needs no normalisation is reported exactly as given."""
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

        assert json.loads(out)["target_spec_version"] == "0.3"
        assert code == 0


class TestGenuineMismatchStillReported:
    """CONTROL: the fix removes false positives, it does not remove drift.

    Every other test in this file asserts that drift is *absent*. A "fix" that
    rejected or ignored the target outright would satisfy all of them while
    making the tool useless, so these tests are the ones that answer "did this
    just refuse to compare anything?".
    """

    @patch("a2a_drift.httpx.get")
    def test_genuine_mismatch_is_still_reported(self, mock_get):
        """A v0.3 agent measured against a 1.0 target is real drift.

        Severity and message are unchanged: this fix is about the target being
        comparable, not about softening what a mismatch means.
        """
        mock_get.return_value = card_response(v03_card())

        code, out, _err = run_cli(
            [
                "check",
                "https://example.com/card.json",
                "--spec-version",
                "1.0",
                "--format",
                "json",
            ]
        )

        report = json.loads(out)
        findings = spec_drift(report)
        assert len(findings) == 1
        assert findings[0]["severity"] == "warning"
        assert findings[0]["message"] == (
            "Agent uses spec v0.3; v1.0 is the expected version"
        )
        assert report["spec_version"] == "0.3"
        assert report["target_spec_version"] == "1.0"
        assert code == 0

    @patch("a2a_drift.httpx.get")
    def test_mismatch_is_still_reported_for_an_equivalent_10_spelling(self, mock_get):
        """A normalised target must not normalise a mismatch away either."""
        mock_get.return_value = card_response(v03_card())

        code, out, _err = run_cli(
            [
                "check",
                "https://example.com/card.json",
                "--spec-version",
                "v1.0.0",
                "--format",
                "json",
            ]
        )

        findings = spec_drift(json.loads(out))
        assert len(findings) == 1
        assert findings[0]["message"] == (
            "Agent uses spec v0.3; v1.0 is the expected version"
        )
        assert code == 0

    @patch("a2a_drift.httpx.get")
    def test_undeterminable_protocol_version_is_still_reported(self, mock_get):
        """A card with no usable protocolVersion still reports undetermined.

        Another false-positive class a blunt "normalise harder" fix could
        swallow: the target is fine here, so this must stay a finding.
        """
        card = v10_card()
        card["protocolVersion"] = "banana"
        mock_get.return_value = card_response(card)

        code, out, _err = run_cli(
            [
                "check",
                "https://example.com/card.json",
                "--spec-version",
                "1.0",
                "--format",
                "json",
            ]
        )

        findings = spec_drift(json.loads(out))
        assert len(findings) == 1
        assert "Could not determine A2A spec version" in findings[0]["message"]
        assert code == 0
