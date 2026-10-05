"""A hostname that cannot be IDNA-encoded is a validation message, not a crash.

``validate_url`` caught ``socket.gaierror`` from ``socket.getaddrinfo`` but not
the failure that call raises *before* any resolution is attempted: a hostname
that does not encode (a DNS label longer than 63 characters, or an empty label)
raises ``UnicodeError``, which escaped the function and every caller. The
``probe`` subcommand has no per-item handler, so an untrusted URL reached the
user as a traceback; ``check`` downgraded it to an ``internal-error`` finding,
which reads like a transient tool failure rather than a bad URL.

``validate_url`` is documented as returning a message or ``None`` and is part
of the public library API, so raising from untrusted input violates its
contract. These cases need no network: the failure happens at name encoding.
"""

import sys
from unittest.mock import patch

import pytest

from a2a_drift import EndpointProber, cli, validate_url

# Both inputs from issue #51: an over-long label and an empty one.
LONG_LABEL = "a" * 300 + ".com"
EMPTY_LABEL = "host..com"


class TestIdnaHostname:
    """``validate_url`` reports an unencodable hostname instead of raising."""

    @pytest.mark.parametrize("hostname", [LONG_LABEL, EMPTY_LABEL])
    def test_unencodable_hostname_returns_a_message(self, hostname):
        message = validate_url(f"https://{hostname}/card.json")

        assert isinstance(message, str), "validate_url must not raise"
        assert "invalid hostname" in message

    def test_over_long_label_is_named(self):
        message = validate_url(f"https://{LONG_LABEL}/card.json")

        assert "label" in message

    def test_empty_label_is_named(self):
        message = validate_url(f"https://{EMPTY_LABEL}/card.json")

        assert "label" in message

    def test_resolvable_host_is_unaffected(self):
        with patch("a2a_drift.socket.getaddrinfo", return_value=[]):
            assert validate_url("https://example.com/card.json") is None

    def test_internal_still_blocks_before_name_resolution(self):
        """The SSRF verdict is unaffected by the new handler.

        ``127.0.0.1`` encodes cleanly, so it must still reach the address loop
        and be refused there -- the new clause must not short-circuit it.
        """
        with patch(
            "a2a_drift.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("127.0.0.1", 0, 0, 0))],
        ):
            message = validate_url("https://127.0.0.1/card.json")

        assert message is not None and "internal URL blocked" in message

    def test_probe_reports_the_finding_instead_of_raising(self):
        """The library caller gets a ValidationResult, not an exception."""
        prober = EndpointProber(f"https://{LONG_LABEL}/a2a", allow_internal=False)
        result = prober.probe("message/send")

        assert result.is_compliant is False
        assert any(d.drift_type == "security-transport" for d in result.drift)


class TestProbeCliWithUnencodableHost:
    """``probe`` must exit on a verdict, not on a traceback."""

    def test_probe_exits_nonzero_without_a_traceback(self, capsys):
        argv = ["a2a-drift", "probe", f"https://{LONG_LABEL}/a2a", "--deny-internal"]
        with patch.object(sys, "argv", argv), pytest.raises(SystemExit) as exit_info:
            cli.main()
        captured = capsys.readouterr()

        assert exit_info.value.code == 1
        assert "Traceback" not in captured.err
        assert "internal-error" not in captured.out
        assert "invalid hostname" in captured.out

    def test_check_subcommand_reports_it_as_a_url_finding(self, capsys):
        """--deny-internal is the mode that reaches name resolution.

        With internal addresses allowed, ``validate_url`` short-circuits before
        ``getaddrinfo`` (no resolution is needed to allow a URL), so the guard
        under test is only reached when the policy asks for resolution.
        """
        argv = [
            "a2a-drift",
            "check",
            f"https://{EMPTY_LABEL}/card.json",
            "--deny-internal",
        ]
        with patch.object(sys, "argv", argv), pytest.raises(SystemExit):
            cli.main()
        captured = capsys.readouterr()

        assert "internal-error" not in captured.out
        assert "fetch-error" not in captured.out
        assert "security-transport: invalid hostname" in captured.out

    def test_no_request_is_issued_for_an_unencodable_host(self):
        """The failure precedes the request, so none is attempted."""
        with patch("a2a_drift.httpx.get") as mock_get:
            prober = EndpointProber(f"https://{LONG_LABEL}/a2a", allow_internal=False)
            prober.probe("message/send")

        mock_get.assert_not_called()
