"""Required agent-card fields must be validated as *values*, not as keys.

``REQUIRED_FIELDS`` was checked with ``if field_name not in card``, which proves
only that a key exists. A card whose required fields are all ``null``, hold a
number where a string belongs, or hold an empty string reported
``is_compliant=True``, ``drift_count=0`` and exit code 0 -- a green gate over a
card that tells a peer agent nothing at all.

The control for the null case is the asymmetry with the pre-existing missing-key
test: an absent key was caught, a stored null was not, because ``not in card``
cannot see either value.

``capabilities={}`` (present, empty) deliberately stays a WARNING here and is
out of scope for this change; what must change is that it stops being
*indistinguishable* from ``capabilities=null``.
"""

from unittest.mock import MagicMock, patch

from a2a_drift import AgentCardChecker

REQUIRED = ["name", "description", "url", "version", "capabilities"]


def all_null_card():
    """Every required field present, every one of them explicitly null."""
    return {
        "name": None,
        "description": None,
        "url": None,
        "version": None,
        "capabilities": None,
        "protocolVersion": "1.0",
    }


def check(card):
    """Validate ``card`` through the public API with the HTTP fetch stubbed."""
    response = MagicMock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.return_value = card
    with patch("a2a_drift.httpx.get", return_value=response):
        return AgentCardChecker("https://example.com/card.json").validate()


def messages(result):
    return [d.message for d in result.drift]


def error_messages(result):
    return [d.message for d in result.drift if d.severity == "error"]


class TestNullRequiredFields:
    """A present key holding null is not a satisfied requirement."""

    def test_all_required_fields_null_is_non_compliant(self):
        result = check(all_null_card())

        assert result.is_compliant is False
        assert error_messages(result), "null required fields must be errors"

    def test_all_required_fields_null_reports_one_error_per_field(self):
        result = check(all_null_card())

        assert len(error_messages(result)) == len(REQUIRED)

    def test_a_single_null_required_field_is_still_non_compliant(self):
        card = {
            "name": "Agent",
            "description": "d",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "capabilities": {"streaming": True},
            "protocolVersion": "1.0",
        }
        card["url"] = None

        result = check(card)

        assert result.is_compliant is False
        assert any("url" in m for m in error_messages(result))

    def test_a_null_field_is_named_as_null_not_as_missing(self):
        """'present but null' is a different defect from 'absent'."""
        result = check(all_null_card())

        joined = " ".join(messages(result))
        assert "null" in joined.lower()
        assert "Missing required field" not in messages(result)


class TestMissingRequiredFields:
    """The pre-existing presence check must keep working: the control pair."""

    def test_an_absent_required_field_is_still_reported_as_missing(self):
        card = {
            "name": "Agent",
            "description": "d",
            "version": "1.0.0",
            "capabilities": {"streaming": True},
            "protocolVersion": "1.0",
        }

        result = check(card)

        assert result.is_compliant is False
        assert "Missing required field: url" in messages(result)

    def test_absent_and_null_produce_different_messages(self):
        absent = check({f: None for f in []} | {"protocolVersion": "1.0"})
        null = check(all_null_card())

        absent_url = [m for m in messages(absent) if "url" in m]
        null_url = [m for m in messages(null) if "url" in m]
        assert absent_url and null_url
        assert absent_url != null_url


class TestWrongTypedRequiredFields:
    """A number where a string belongs is a schema violation."""

    def test_an_integer_where_a_string_is_expected_is_non_compliant(self):
        card = {
            "name": 42,
            "description": "d",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "capabilities": {"streaming": True},
            "protocolVersion": "1.0",
        }

        result = check(card)

        assert result.is_compliant is False
        assert any("name" in m for m in error_messages(result))

    def test_a_string_where_an_object_is_expected_is_non_compliant(self):
        card = {
            "name": "Agent",
            "description": "d",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "capabilities": "streaming",
            "protocolVersion": "1.0",
        }

        result = check(card)

        assert result.is_compliant is False
        assert any("capabilities" in m for m in error_messages(result))

    def test_a_list_where_an_object_is_expected_is_non_compliant(self):
        card = {
            "name": "Agent",
            "description": "d",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "capabilities": ["streaming"],
            "protocolVersion": "1.0",
        }

        result = check(card)

        assert result.is_compliant is False
        assert any("capabilities" in m for m in error_messages(result))

    def test_a_wrong_type_is_named_as_a_type_error(self):
        card = {
            "name": 42,
            "description": "d",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "capabilities": {"streaming": True},
            "protocolVersion": "1.0",
        }

        result = check(card)

        joined = " ".join(error_messages(result)).lower()
        assert "int" in joined or "type" in joined or "expected" in joined


class TestEmptyRequiredFields:
    """An empty string satisfies a key check and conveys nothing."""

    def test_an_empty_string_required_field_is_non_compliant(self):
        card = {
            "name": "",
            "description": "d",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "capabilities": {"streaming": True},
            "protocolVersion": "1.0",
        }

        result = check(card)

        assert result.is_compliant is False
        assert any("name" in m for m in error_messages(result))

    def test_a_whitespace_only_required_field_is_non_compliant(self):
        card = {
            "name": "   ",
            "description": "d",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "capabilities": {"streaming": True},
            "protocolVersion": "1.0",
        }

        result = check(card)

        assert result.is_compliant is False
        assert any("name" in m for m in error_messages(result))

    def test_an_empty_description_is_non_compliant(self):
        card = {
            "name": "Agent",
            "description": "",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "capabilities": {"streaming": True},
            "protocolVersion": "1.0",
        }

        result = check(card)

        assert result.is_compliant is False
        assert any("description" in m for m in error_messages(result))


class TestCapabilitiesNullVersusEmpty:
    """The pair that proves the null/empty confusion is really gone.

    ``card.get('capabilities', {})`` returns the stored ``None`` for a null
    value, and the ``if not capabilities`` branch then reported 'No
    capabilities declared' -- byte-for-byte the same finding as a genuine
    ``capabilities={}``. They must now differ.
    """

    def test_null_and_empty_capabilities_produce_different_output(self):
        base = {
            "name": "Agent",
            "description": "d",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "protocolVersion": "1.0",
        }
        null_card = dict(base, capabilities=None)
        empty_card = dict(base, capabilities={})

        null_result = check(null_card)
        empty_result = check(empty_card)

        assert messages(null_result) != messages(empty_result)
        assert error_messages(null_result)
        assert not error_messages(empty_result)

    def test_a_null_capabilities_card_is_non_compliant(self):
        base = {
            "name": "Agent",
            "description": "d",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "protocolVersion": "1.0",
        }

        result = check(dict(base, capabilities=None))

        assert result.is_compliant is False

    def test_an_empty_capabilities_object_stays_a_warning_not_an_error(self):
        """Deliberate scope boundary: this behaviour is unchanged by this fix."""
        base = {
            "name": "Agent",
            "description": "d",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "protocolVersion": "1.0",
        }

        result = check(dict(base, capabilities={}))

        assert result.is_compliant is True
        assert "No capabilities declared in agent card" in messages(result)
        assert not error_messages(result)


class TestValidCardControls:
    """Positive controls: the value check must not reject conforming cards."""

    def test_a_complete_valid_card_reports_zero_drift(self):
        result = check(
            {
                "name": "Test Agent",
                "description": "A test agent",
                "url": "https://example.com/a2a",
                "version": "1.0.0",
                "protocolVersion": "1.0",
                "capabilities": {"streaming": True},
            }
        )

        assert result.is_compliant is True
        assert result.drift == []

    def test_a_populated_capabilities_object_reports_no_capability_warning(self):
        result = check(
            {
                "name": "Test Agent",
                "description": "A test agent",
                "url": "https://example.com/a2a",
                "version": "1.0.0",
                "protocolVersion": "1.0",
                "capabilities": {"streaming": True, "pushNotifications": False},
            }
        )

        assert result.is_compliant is True
        assert result.drift == []

    def test_a_card_with_optional_extra_fields_is_unaffected(self):
        """Unknown keys must not be judged by the required-field expectations."""
        result = check(
            {
                "name": "Test Agent",
                "description": "A test agent",
                "url": "https://example.com/a2a",
                "version": "1.0.0",
                "protocolVersion": "1.0",
                "capabilities": {"streaming": True},
                "documentationUrl": None,
                "defaultInputModes": [],
                "provider": None,
            }
        )

        assert result.is_compliant is True
