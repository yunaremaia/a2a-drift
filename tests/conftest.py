"""Shared pytest fixtures for the a2a-drift test suite."""

import pytest


@pytest.fixture
def valid_agent_card():
    """A minimal v1.0 agent card that validates with zero drift.

    Returned fresh per test so a test that mutates it cannot leak into another.
    """
    return {
        "name": "Test Agent",
        "description": "A test agent",
        "url": "https://example.com/a2a",
        "version": "1.0.0",
        "protocolVersion": "1.0",
        "capabilities": {"streaming": True},
    }
