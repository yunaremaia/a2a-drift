"""Tests for ``validate_url``, the pre-flight check every fetch path runs.

``validate_url`` is the only thing standing between an untrusted agent card URL
and a request to a loopback, link-local or otherwise internal address
(CWE-918), so each rejection branch is pinned here rather than left to the CLI
tests that happen to pass through it.
"""

import socket
from unittest.mock import patch

import pytest

from a2a_drift import validate_url

pytestmark = pytest.mark.unit


def _getaddrinfo(address):
    """Build a getaddrinfo result list resolving to ``address``."""
    return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 0, 0, 0))]


class TestUrlWellFormedness:
    """A URL that cannot be fetched at all is rejected before any network use."""

    def test_url_without_a_scheme_is_rejected(self):
        assert validate_url("example.com/card.json") == ("invalid URL scheme: (none)")

    def test_non_http_scheme_is_rejected(self):
        assert validate_url("ftp://example.com/card.json") == (
            "invalid URL scheme: ftp"
        )

    def test_file_scheme_is_rejected(self):
        assert validate_url("file:///etc/passwd") == "invalid URL scheme: file"

    def test_url_without_a_hostname_is_rejected(self):
        assert validate_url("http:///card.json") == "invalid URL: no hostname"

    @pytest.mark.parametrize("url", ["http://[::1", "http://[::1]junk"])
    def test_malformed_ipv6_url_is_reported_instead_of_raised(self, url):
        """A bracketed host that is not valid IPv6 must not escape as a crash.

        ``urllib.parse.urlparse`` raises ``ValueError`` on a malformed IPv6
        literal. Nothing caught it, so a malformed URL reached the user as an
        unhandled traceback instead of the usual validation message.
        """
        message = validate_url(url)

        assert message is not None
        assert message.startswith("invalid URL")


class TestInternalAddressBlocking:
    """--deny-internal mode refuses to resolve to an internal address."""

    def test_link_local_metadata_address_is_blocked(self):
        with patch(
            "a2a_drift.socket.getaddrinfo",
            return_value=_getaddrinfo("169.254.169.254"),
        ):
            message = validate_url("http://metadata.internal/latest/")

        assert message is not None
        assert "internal URL blocked (169.254.169.254)" in message
        assert "--allow-internal" in message

    def test_loopback_address_is_blocked(self):
        with patch(
            "a2a_drift.socket.getaddrinfo", return_value=_getaddrinfo("127.0.0.1")
        ):
            message = validate_url("http://127.0.0.1:8080/agent-card.json")

        assert message is not None
        assert "internal URL blocked" in message

    def test_a_single_internal_answer_blocks_the_host(self):
        """DNS returning one public and one internal address is still blocked."""
        addresses = _getaddrinfo("93.184.216.34") + _getaddrinfo("10.0.0.5")
        with patch("a2a_drift.socket.getaddrinfo", return_value=addresses):
            message = validate_url("http://rebind.example.com/card.json")

        assert message is not None
        assert "internal URL blocked" in message

    def test_public_address_is_allowed(self):
        with patch(
            "a2a_drift.socket.getaddrinfo",
            return_value=_getaddrinfo("93.184.216.34"),
        ):
            assert validate_url("https://example.com/card.json") is None

    def test_unresolvable_hostname_is_reported(self):
        with patch(
            "a2a_drift.socket.getaddrinfo", side_effect=socket.gaierror("no such host")
        ):
            message = validate_url("https://nonexistent.invalid/card.json")

        assert message == "could not resolve hostname: nonexistent.invalid"


class TestAllowInternalShortCircuit:
    """Internal targets stay reachable, and that path costs no DNS lookup."""

    def test_allow_internal_accepts_a_loopback_url(self):
        assert (
            validate_url("http://127.0.0.1:8080/agent-card.json", allow_internal=True)
            is None
        )

    def test_allow_internal_does_not_resolve_the_hostname(self):
        """With internal addresses allowed nothing is resolved at all.

        This is what keeps the default path offline: an allow-internal URL that
        only exists on the operator's own network still validates without a
        DNS round trip.
        """
        with patch("a2a_drift.socket.getaddrinfo") as mock_getaddrinfo:
            assert (
                validate_url("http://intranet.internal/card.json", allow_internal=True)
                is None
            )

        assert mock_getaddrinfo.call_count == 0
