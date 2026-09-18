"""Tests for a2a-drift."""

import pytest
from unittest.mock import patch, MagicMock
import json

from a2a_drift import AgentCardChecker, EndpointProber, ValidationResult, DriftFinding


class TestAgentCardChecker:
    def setup_method(self):
        self.checker = AgentCardChecker("https://example.com/.well-known/agent-card.json")

    @patch("a2a_drift.httpx.get")
    def test_valid_agent_card_v1(self, mock_get):
        """A valid v1.0 agent card should be compliant."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "Test Agent",
            "description": "A test agent",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "protocolVersion": "1.0",
            "capabilities": {"streaming": True},
            "defaultInputModes": ["text"],
            "defaultOutputModes": ["text"],
            "skills": []
        }
        mock_get.return_value = mock_response

        result = self.checker.validate()
        assert result.is_compliant is True
        assert result.spec_version == "1.0"
        assert len(result.drift) == 0

    @patch("a2a_drift.httpx.get")
    def test_missing_required_fields(self, mock_get):
        """Missing required fields should create error drift."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "Test Agent",
            "description": "Missing required fields"
        }
        mock_get.return_value = mock_response

        result = self.checker.validate()
        assert result.is_compliant is False
        assert len(result.drift) >= 3
        error_types = [d.drift_type for d in result.drift if d.severity == "error"]
        assert "schema-violation" in error_types

    @patch("a2a_drift.httpx.get")
    def test_spec_version_drift_v03(self, mock_get):
        """v0.3 agent cards should generate spec-version drift warning."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "Legacy Agent",
            "description": "Old spec",
            "url": "https://example.com/a2a",
            "version": "0.3.0",
            "protocolVersion": "0.3",
            "capabilities": {},
            "skills": []
        }
        mock_get.return_value = mock_response

        result = self.checker.validate()
        assert result.spec_version == "0.3"
        spec_drift = [d for d in result.drift if d.drift_type == "spec-version"]
        assert len(spec_drift) == 1
        assert spec_drift[0].severity == "warning"
        assert "0.3" in spec_drift[0].message

    @patch("a2a_drift.httpx.get")
    def test_fetch_error(self, mock_get):
        """HTTP errors should create fetch-error drift."""
        mock_get.side_effect = Exception("Connection refused")

        result = self.checker.validate()
        assert result.is_compliant is False
        assert result.error is not None
        assert "fetch-error" in [d.drift_type for d in result.drift]

    @patch("a2a_drift.httpx.get")
    def test_invalid_json(self, mock_get):
        """Non-JSON response should create json-parse-error drift."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("invalid", "doc", 0)
        mock_get.return_value = mock_response

        result = self.checker.validate()
        assert result.error is not None
        assert "json-parse-error" in [d.drift_type for d in result.drift]


class TestEndpointProber:
    def setup_method(self):
        self.prober = EndpointProber("https://example.com/a2a")

    @patch("a2a_drift.httpx.post")
    def test_valid_jsonrpc_response(self, mock_post):
        """Valid JSON-RPC 2.0 response should be compliant."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "result": {"task": "abc-123"},
            "id": 1
        }
        mock_post.return_value = mock_response

        result = self.prober.probe("message/send", {"message": {}})
        assert result.jsonrpc_compliant is True
        assert result.response_time_ms is not None

    @patch("a2a_drift.httpx.post")
    def test_missing_jsonrpc_field(self, mock_post):
        """Missing jsonrpc field should be non-compliant."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": {}, "id": 1}
        mock_post.return_value = mock_response

        result = self.prober.probe("tasks/get", {"id": "123"})
        assert result.jsonrpc_compliant is False

    @patch("a2a_drift.httpx.post")
    def test_error_response(self, mock_post):
        """JSON-RPC error response with proper structure should be compliant."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "Invalid Request"},
            "id": 1
        }
        mock_post.return_value = mock_response

        result = self.prober.probe("unknown/method", {})
        # Error response is valid JSON-RPC, so jsonrpc_compliant should be True
        assert result.jsonrpc_compliant is True

    @patch("a2a_drift.httpx.post")
    def test_non_json_response(self, mock_post):
        """Non-JSON response should be non-compliant."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("not json", "", 0)
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response

        result = self.prober.probe("message/send", {})
        assert result.jsonrpc_compliant is False


class TestValidationResult:
    def test_add_drift(self):
        result = ValidationResult(url="https://example.com")
        result.add_drift("spec-version", "warning", "test message")
        assert len(result.drift) == 1
        assert result.is_compliant is True  # warnings don't break compliance

    def test_error_drift_breaks_compliance(self):
        result = ValidationResult(url="https://example.com", is_compliant=True)
        result.add_drift("schema-violation", "error", "missing field")
        assert result.is_compliant is False
