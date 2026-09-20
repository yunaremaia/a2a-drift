"""Tests for a2a-drift retry with exponential backoff (issue #1)."""

import pytest
from unittest.mock import patch, MagicMock, call
import httpx

from a2a_drift import AgentCardChecker, EndpointProber, ValidationResult


class TestAgentCardCheckerRetry:
    """Tests for retry with exponential backoff on transient failures."""

    @patch("a2a_drift.httpx.get")
    def test_retry_on_500_error_then_succeed(self, mock_get):
        """Server returns 500 first, then 200 — should succeed after retry."""
        mock_response_fail = MagicMock()
        mock_response_fail.status_code = 500
        mock_response_fail.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=mock_response_fail
        )
        
        mock_response_ok = MagicMock()
        mock_response_ok.status_code = 200
        mock_response_ok.raise_for_status.return_value = None
        mock_response_ok.json.return_value = {
            "name": "Test Agent",
            "description": "A test agent",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "protocolVersion": "1.0",
            "capabilities": {"streaming": True},
        }
        
        mock_get.side_effect = [mock_response_fail, mock_response_ok]
        
        checker = AgentCardChecker("https://example.com/.well-known/agent-card.json")
        result = checker.validate()
        
        assert result.is_compliant is True
        assert result.attempts == 2
        assert result.error is None
        assert mock_get.call_count == 2

    @patch("a2a_drift.httpx.get")
    def test_retry_on_timeout_then_succeed(self, mock_get):
        """Timeout first, then success — should succeed after retry."""
        mock_response_ok = MagicMock()
        mock_response_ok.status_code = 200
        mock_response_ok.raise_for_status.return_value = None
        mock_response_ok.json.return_value = {
            "name": "Test Agent",
            "description": "A test agent",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "protocolVersion": "1.0",
            "capabilities": {"streaming": True},
        }
        
        mock_get.side_effect = [httpx.TimeoutException("Timed out"), mock_response_ok]
        
        checker = AgentCardChecker("https://example.com/.well-known/agent-card.json")
        result = checker.validate()
        
        assert result.is_compliant is True
        assert result.attempts == 2
        assert mock_get.call_count == 2

    @patch("a2a_drift.httpx.get")
    @patch("a2a_drift.time.sleep")
    def test_retries_exhausted_returns_error(self, mock_sleep, mock_get):
        """All retries fail — should return error after max_retries attempts."""
        mock_get.side_effect = httpx.TimeoutException("Timed out")
        
        checker = AgentCardChecker("https://example.com/.well-known/agent-card.json", max_retries=3)
        result = checker.validate()
        
        assert result.is_compliant is False
        assert result.attempts == 3
        assert "Failed to fetch agent card" in result.error
        assert mock_get.call_count == 3
        assert mock_sleep.call_count == 2  # No sleep after last attempt
        mock_sleep.assert_any_call(1)  # 2^0
        mock_sleep.assert_any_call(2)  # 2^1

    @patch("a2a_drift.httpx.get")
    def test_no_retry_on_400_error(self, mock_get):
        """Client errors (4xx) should NOT be retried."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found", request=MagicMock(), response=mock_response
        )
        mock_get.return_value = mock_response
        
        checker = AgentCardChecker("https://example.com/.well-known/agent-card.json")
        result = checker.validate()
        
        assert result.is_compliant is False
        assert result.attempts == 1
        assert mock_get.call_count == 1  # No retries for 4xx

    @patch("a2a_drift.httpx.get")
    def test_custom_max_retries(self, mock_get):
        """Custom max_retries should override default."""
        mock_get.side_effect = httpx.TimeoutException("Timed out")
        
        checker = AgentCardChecker("https://example.com/.well-known/agent-card.json", max_retries=5)
        result = checker.validate()
        
        assert result.attempts == 5
        assert mock_get.call_count == 5

    @patch("a2a_drift.httpx.get")
    def test_retry_on_502_bad_gateway(self, mock_get):
        """502 Bad Gateway should be retried."""
        mock_response_fail = MagicMock()
        mock_response_fail.status_code = 502
        mock_response_fail.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Bad Gateway", request=MagicMock(), response=mock_response_fail
        )
        
        mock_response_ok = MagicMock()
        mock_response_ok.status_code = 200
        mock_response_ok.raise_for_status.return_value = None
        mock_response_ok.json.return_value = {
            "name": "Test Agent",
            "description": "A test agent",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "protocolVersion": "1.0",
            "capabilities": {"streaming": True},
        }
        
        mock_get.side_effect = [mock_response_fail, mock_response_ok]
        
        checker = AgentCardChecker("https://example.com/.well-known/agent-card.json")
        result = checker.validate()
        
        assert result.is_compliant is True
        assert result.attempts == 2

    @patch("a2a_drift.httpx.get")
    def test_retry_on_503_service_unavailable(self, mock_get):
        """503 Service Unavailable should be retried."""
        mock_response_fail = MagicMock()
        mock_response_fail.status_code = 503
        mock_response_fail.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Service Unavailable", request=MagicMock(), response=mock_response_fail
        )
        
        mock_response_ok = MagicMock()
        mock_response_ok.status_code = 200
        mock_response_ok.raise_for_status.return_value = None
        mock_response_ok.json.return_value = {
            "name": "Test Agent",
            "description": "A test agent",
            "url": "https://example.com/a2a",
            "version": "1.0.0",
            "protocolVersion": "1.0",
            "capabilities": {"streaming": True},
        }
        
        mock_get.side_effect = [mock_response_fail, mock_response_ok]
        
        checker = AgentCardChecker("https://example.com/.well-known/agent-card.json")
        result = checker.validate()
        
        assert result.is_compliant is True
        assert result.attempts == 2


class TestEndpointProberRetry:
    """Tests for retry with exponential backoff on EndpointProber."""

    @patch("a2a_drift.httpx.post")
    def test_probe_retry_on_500(self, mock_post):
        """Probe should retry on 500 error."""
        mock_response_fail = MagicMock()
        mock_response_fail.status_code = 500
        mock_response_fail.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=mock_response_fail
        )
        
        mock_response_ok = MagicMock()
        mock_response_ok.status_code = 200
        mock_response_ok.raise_for_status.return_value = None
        mock_response_ok.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": {}}
        
        mock_post.side_effect = [mock_response_fail, mock_response_ok]
        
        prober = EndpointProber("https://example.com/a2a")
        result = prober.probe("message/send")
        
        assert result.is_compliant is True
        assert result.attempts == 2
        assert mock_post.call_count == 2

    @patch("a2a_drift.httpx.post")
    @patch("a2a_drift.time.sleep")
    def test_probe_retries_exhausted(self, mock_sleep, mock_post):
        """All probe retries fail — should return error."""
        mock_post.side_effect = httpx.ConnectError("Connection refused")
        
        prober = EndpointProber("https://example.com/a2a", max_retries=3)
        result = prober.probe("message/send")
        
        assert result.is_compliant is False
        assert result.attempts == 3
        assert "Failed to probe endpoint" in result.error
        assert mock_post.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("a2a_drift.httpx.post")
    def test_probe_no_retry_on_400(self, mock_post):
        """Probe should NOT retry on 4xx client errors."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Bad Request", request=MagicMock(), response=mock_response
        )
        mock_post.return_value = mock_response
        
        prober = EndpointProber("https://example.com/a2a")
        result = prober.probe("message/send")
        
        assert result.attempts == 1
        assert mock_post.call_count == 1

