"""The agent card's ``url`` must parse as the URL it claims to be.

``REQUIRED_FIELD_EXPECTATIONS`` gave ``url`` the pair ``(str, False)``, so the
check it drives was "is a string, and is not blank". ``not-a-url`` *is* a
string and ``javascript:alert(1)`` *is* a string, so a card advertising either
one reported ``is_compliant=True``, ``drift_count=0`` and exit code 0 -- the
same verdict a clean run gets, for a card that names no fetchable endpoint at
all.

``url`` is the one required field that carries a format rather than a type, so
it is the one where the type check is not enough. The value it must satisfy
already exists in this package as ``validate_url()``, used by every other
caller of an untrusted URL; this file pins the card body onto that same check.
"""

from unittest.mock import MagicMock, patch

import pytest

from a2a_drift import AgentCardChecker

# The three values from issue #50, which the type-only check passed verbatim.
REJECTED_URLS = [
    "not-a-url",
    "javascript:alert(1)",
    "ftp://internal.corp/x",
]


def card_with_url(url):
    """A minimal v1.0 card whose only questionable field is ``url``."""
    return {
        "name": "Example Agent",
        "description": "An example agent",
        "url": url,
        "version": "1.0.0",
        "protocolVersion": "1.0",
        "capabilities": {"streaming": True},
    }


def check(card):
    """Validate ``card`` through the public API with the HTTP fetch stubbed."""
    response = MagicMock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.return_value = card
    with patch("a2a_drift.httpx.get", return_value=response):
        return AgentCardChecker("https://example.com/card.json").validate()


def url_messages(result):
    """The messages of the findings raised against ``$.url``."""
    return [d.message for d in result.drift if d.path == "$.url"]


class TestCardUrlFormat:
    """A url field that names no reachable HTTP(S) endpoint is a schema error."""

    @pytest.mark.parametrize("url", REJECTED_URLS)
    def test_non_http_url_is_non_compliant(self, url):
        result = check(card_with_url(url))

        assert result.is_compliant is False
        assert any(d.severity == "error" for d in result.drift)

    @pytest.mark.parametrize("url", REJECTED_URLS)
    def test_finding_names_the_rejected_value(self, url):
        messages = url_messages(check(card_with_url(url)))

        assert messages, f"no finding raised against $.url for {url!r}"
        assert any(url in message for message in messages)

    @pytest.mark.parametrize("url", REJECTED_URLS)
    def test_finding_names_the_check_that_failed(self, url):
        messages = url_messages(check(card_with_url(url)))

        assert any(
            "url" in message and "HTTP(S) URL" in message for message in messages
        )

    def test_well_formed_url_is_still_compliant(self):
        result = check(card_with_url("https://example.com/a2a"))

        assert result.is_compliant is True
        assert url_messages(result) == []

    def test_oversized_url_is_not_a_dupe_of_the_empty_finding(self):
        """A blank url is one finding, reported as empty -- not twice.

        The format check runs on a non-blank string, so a value the
        empty-value check already rejected does not gain a second, vaguer
        finding naming the same field.
        """
        result = check(card_with_url("   "))

        assert [d.message for d in result.drift if d.path == "$.url"] == [
            "Required field url is empty"
        ]

    def test_internal_card_url_is_a_format_pass_not_a_schema_error(self):
        """The format check does not double as the network policy.

        Whether a private address is reachable is already a caller decision
        (``--allow-internal`` / ``--deny-internal`` against the URL being
        fetched). Asserting it here would make a schema finding appear and
        disappear with a network policy switch.
        """
        result = check(card_with_url("http://127.0.0.1:8080/a2a"))

        assert result.is_compliant is True
        assert url_messages(result) == []
