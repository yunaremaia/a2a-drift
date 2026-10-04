"""Tests for the deny-internal policy across redirect hops (issue #36).

``validate_url`` used to guard only the URL as written, while the fetch itself
was issued with ``follow_redirects=True``. A remote party therefore chose the
address that was actually contacted: a public host answering ``302 Location:
http://127.0.0.1:PORT/card.json`` was fetched anyway and its card reported
compliant. The guard was bypassable with one hop, which is the standard SSRF
pivot (CWE-918).

The policy has to hold for the address actually contacted, so every hop is
validated before it is requested. These tests pin that: the important assertion
is not only the reported finding but ``httpx.get.call_count``, which proves the
internal address was never contacted at all.
"""

import ipaddress
import json
import socket
from unittest.mock import MagicMock, patch

import pytest

from a2a_drift import AgentCardChecker

pytestmark = pytest.mark.unit

PUBLIC_IP = "93.184.216.34"


def _getaddrinfo(address):
    """Build a getaddrinfo result list resolving to ``address``."""
    return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 0, 0, 0))]


def _resolver(**addresses):
    """Answer the guard's ``getaddrinfo(host, None)`` the way DNS would.

    A host given in ``addresses`` resolves to that address, anything else
    resolves to ``PUBLIC_IP``. An IP literal is the one case that needs no
    mapping: it resolves to itself, which is what ``socket.getaddrinfo``
    already does, and which is why a redirect straight to ``127.0.0.1`` needs no
    DNS round trip to be caught.
    """
    default = addresses.get("*", PUBLIC_IP)

    def resolve(host, port=None, *args, **kwargs):
        if host in addresses:
            return _getaddrinfo(addresses[host])
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return _getaddrinfo(default)
        return _getaddrinfo(host)

    return resolve


def card_response(payload, status_code=200, location=None):
    """A response mock: 2xx by default, or a redirect when ``location`` is set."""
    response = MagicMock()
    response.status_code = status_code if location is None else 302
    response.raise_for_status.return_value = None
    response.headers = {} if location is None else {"location": location}
    response.json.return_value = payload
    return response


class TestRedirectTargetIsValidated:
    """A hop to a refused address is refused, and never requested."""

    @patch("a2a_drift.httpx.get")
    def test_redirect_to_loopback_is_blocked(self, mock_get):
        """The pinning test: a public URL 302ing to loopback is a drift finding.

        Before the fix the guard saw only the public URL, httpx followed the
        Location header silently, and the loopback card was reported compliant
        with exit code 0.
        """
        mock_get.side_effect = [
            card_response({}, location="http://127.0.0.1:8080/card.json")
        ]
        checker = AgentCardChecker(
            "https://pivot.example.com/card.json", allow_internal=False
        )

        with patch("a2a_drift.socket.getaddrinfo", side_effect=_resolver()):
            result = checker.validate()

        assert result.is_compliant is False
        assert "security-transport" in [d.drift_type for d in result.drift]
        assert result.error is not None
        assert "127.0.0.1" in result.error
        # The guard's verdict on that exact URL, so the drift is a real
        # application of the policy rather than a coincidentally similar string.
        assert "internal URL blocked" in result.error
        # The address was never contacted: only the public URL was requested.
        assert mock_get.call_count == 1
        assert mock_get.call_args.args[0] == "https://pivot.example.com/card.json"

    @pytest.mark.parametrize(
        "target",
        [
            "http://127.0.0.1:8080/card.json",
            "http://169.254.169.254/latest/meta-data/iam/",
            "http://10.0.0.5/card.json",
            "http://[::1]/card.json",
        ],
    )
    @patch("a2a_drift.httpx.get")
    def test_every_refused_range_is_blocked_on_a_redirect(self, mock_get, target):
        """Loopback, cloud metadata and private space are all denied, as documented.

        ``--deny-internal`` promises to refuse "loopback, private, link-local
        (including cloud metadata at 169.254.169.254), reserved and multicast
        addresses"; a redirect must not be an exemption from that promise.
        """
        mock_get.side_effect = [card_response({}, location=target)]
        checker = AgentCardChecker("https://pivot.example.com/card.json")

        with patch("a2a_drift.socket.getaddrinfo", side_effect=_resolver()):
            result = checker.validate()

        assert result.is_compliant is False
        assert "security-transport" in [d.drift_type for d in result.drift]
        assert mock_get.call_count == 1

    @patch("a2a_drift.httpx.get")
    def test_a_later_hop_in_a_chain_is_validated_too(self, mock_get):
        """Every hop is checked, not just the last one.

        A chain that is public at hop 1 and internal at hop 3 is the case that
        a "check the final target only" fix would miss.
        """
        mock_get.side_effect = [
            card_response({}, location="https://hop2.example.com/card.json"),
            card_response({}, location="http://192.168.1.10/card.json"),
        ]
        checker = AgentCardChecker("https://pivot.example.com/card.json")

        with patch("a2a_drift.socket.getaddrinfo", side_effect=_resolver()):
            result = checker.validate()

        assert result.is_compliant is False
        assert "security-transport" in [d.drift_type for d in result.drift]
        assert "192.168.1.10" in result.error
        # Hops 1 and 2 were requested, hop 3 never was.
        assert mock_get.call_count == 2

    @patch("a2a_drift.httpx.get")
    def test_redirect_to_a_non_http_scheme_is_blocked(self, mock_get):
        """A hop is re-validated as a URL, so ``file:`` is refused too.

        Re-validating through ``validate_url`` means the redirect inherits the
        scheme check, not only the address check.
        """
        mock_get.side_effect = [
            card_response({}, location="file:///etc/passwd"),
        ]
        checker = AgentCardChecker("https://pivot.example.com/card.json")

        with patch("a2a_drift.socket.getaddrinfo", side_effect=_resolver()):
            result = checker.validate()

        assert result.is_compliant is False
        assert "invalid URL scheme: file" in result.error
        assert mock_get.call_count == 1


class TestPublicRedirectsStillWork:
    """The fix must not break legitimate redirect following."""

    @patch("a2a_drift.httpx.get")
    def test_public_redirect_to_public_target_is_followed(
        self, mock_get, valid_agent_card
    ):
        """``http -> https`` and vanity-host redirects keep working."""
        mock_get.side_effect = [
            card_response({}, location="https://cards.example.com/card.json"),
            card_response(valid_agent_card),
        ]
        checker = AgentCardChecker(
            "http://pivot.example.com/card.json", allow_internal=False
        )

        with patch(
            "a2a_drift.socket.getaddrinfo",
            side_effect=_resolver(**{"cards.example.com": PUBLIC_IP}),
        ):
            result = checker.validate()

        assert result.is_compliant is True
        assert result.error is None
        assert mock_get.call_count == 2
        assert mock_get.call_args.args[0] == "https://cards.example.com/card.json"

    @patch("a2a_drift.httpx.get")
    def test_relative_redirect_is_resolved_against_the_current_url(
        self, mock_get, valid_agent_card
    ):
        """A relative Location resolves against the URL that produced it."""
        mock_get.side_effect = [
            card_response({}, location="../v1/.well-known/agent-card.json"),
            card_response(valid_agent_card),
        ]
        checker = AgentCardChecker(
            "https://cards.example.com/a2a/card.json", allow_internal=False
        )

        with patch("a2a_drift.socket.getaddrinfo", side_effect=_resolver()):
            result = checker.validate()

        assert result.is_compliant is True
        assert (
            mock_get.call_args.args[0]
            == "https://cards.example.com/v1/.well-known/agent-card.json"
        )

    @patch("a2a_drift.httpx.get")
    def test_redirect_to_internal_is_followed_when_internals_are_allowed(
        self, mock_get, valid_agent_card
    ):
        """``--allow-internal`` (the default) is unchanged: redirects are followed.

        ``validate_url`` short-circuits before resolving when internal addresses
        are allowed, so the hop costs no DNS lookup here either.
        """
        mock_get.side_effect = [
            card_response({}, location="http://127.0.0.1:8080/card.json"),
            card_response(valid_agent_card),
        ]
        checker = AgentCardChecker(
            "https://pivot.example.com/card.json", allow_internal=True
        )

        with patch("a2a_drift.socket.getaddrinfo") as mock_getaddrinfo:
            result = checker.validate()

        assert result.is_compliant is True
        assert mock_get.call_count == 2
        assert mock_getaddrinfo.call_count == 0


class TestRedirectChainLimits:
    """A hop chain must terminate, whatever the remote party sends."""

    @patch("a2a_drift.httpx.get")
    def test_an_endless_redirect_chain_is_reported_not_looped(self, mock_get):
        """A Location that always points somewhere new stops at the hop limit.

        Without a limit this is an unbounded request loop against a host the
        caller does not control.
        """
        mock_get.side_effect = [
            card_response({}, location=f"https://hop{n}.example.com/card.json")
            for n in range(50)
        ]
        checker = AgentCardChecker(
            "https://pivot.example.com/card.json", allow_internal=False
        )

        with patch("a2a_drift.socket.getaddrinfo", side_effect=_resolver()):
            result = checker.validate()

        assert result.is_compliant is False
        assert "fetch-error" in [d.drift_type for d in result.drift]
        assert result.error is not None
        assert "redirect" in result.error.lower()
        assert mock_get.call_count <= 21

    @patch("a2a_drift.httpx.get")
    def test_a_redirect_without_a_location_header_is_not_followed(self, mock_get):
        """A 3xx with no Location cannot be resolved, so it is not retried."""
        response = MagicMock()
        response.status_code = 302
        response.raise_for_status.return_value = None
        response.headers = {}
        response.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
        mock_get.side_effect = [response]
        checker = AgentCardChecker(
            "https://pivot.example.com/card.json", allow_internal=False
        )

        with patch("a2a_drift.socket.getaddrinfo", side_effect=_resolver()):
            result = checker.validate()

        assert result.is_compliant is False
        assert mock_get.call_count == 1
