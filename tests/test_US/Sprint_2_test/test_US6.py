import json
import os
from typing import Any, Dict, List
from unittest.mock import MagicMock
import httpx
import pytest

from groq import RateLimitError
from app.core.interfaces.llm import LLMResponse
from app.infrastructure.config import config
from app.infrastructure.llm import GroqLLMClient


class MockMessage:
    def __init__(self, content: str):
        self.content = content


class MockChoice:
    def __init__(self, content: str, finish_reason: str = "stop"):
        self.message = MockMessage(content)
        self.finish_reason = finish_reason


class MockUsage:
    def __init__(
        self,
        prompt_tokens: int = 24,
        completion_tokens: int = 42,
        total_tokens: int = 66,
    ):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = total_tokens


class MockCompletion:
    def __init__(
        self,
        content: str,
        model: str = "llama-3.3-70b-versatile",
    ):
        self.choices = [MockChoice(content)]
        self.model = model
        self.usage = MockUsage()


def create_rate_limit_error(message: str = "Rate limit reached") -> RateLimitError:
    """Helper to instantiate a real Groq RateLimitError for retry testing."""
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    response = httpx.Response(429, request=request)
    return RateLimitError(message, response=response, body={"error": "rate_limit_exceeded"})


def test_us6_unconfigured_client_availability(monkeypatch):
    """Verify that client reports unavailable and rejects calls when API key is missing."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    client = GroqLLMClient(api_key=None)

    assert client.is_available() is False
    assert client.api_key_configured is False

    with pytest.raises(RuntimeError) as exc_info:
        client.chat(messages=[{"role": "user", "content": "Hello"}])
    assert "GROQ_API_KEY" in str(exc_info.value)


def test_us6_configuration_source_of_truth_and_overrides():
    """Verify client pulls default configuration from config.yaml and allows explicit overrides."""
    # 1. Defaults from config.yaml
    default_client = GroqLLMClient(api_key="mock_key")
    assert default_client.model_name == config.llm_default_model
    assert default_client.temperature == config.llm_temperature
    assert default_client.max_tokens == config.llm_max_context_tokens

    # 2. Explicit overrides
    custom_client = GroqLLMClient(
        api_key="mock_key",
        model_name="llama-3.1-8b-instant",
        temperature=0.7,
        max_tokens=1500,
    )
    assert custom_client.model_name == "llama-3.1-8b-instant"
    assert custom_client.temperature == 0.7
    assert custom_client.max_tokens == 1500


def test_us6_chat_completion_with_mocked_groq():
    """Verify standard chat completion returns structured LLMResponse with token metrics."""
    mock_sdk = MagicMock()
    mock_sdk.chat.completions.create.return_value = MockCompletion(
        content="Detected no vulnerabilities in this snippet.",
        model="llama-3.3-70b-versatile",
    )

    client = GroqLLMClient(api_key="mock_key", client=mock_sdk)
    assert client.is_available() is True

    messages = [
        {"role": "system", "content": "You are a secure code auditor."},
        {"role": "user", "content": "def add(a, b): return a + b"},
    ]
    response = client.chat(messages=messages, temperature=0.2, max_tokens=1000)

    assert isinstance(response, LLMResponse)
    assert "Detected no vulnerabilities" in response.content
    assert response.model == "llama-3.3-70b-versatile"
    assert response.prompt_tokens == 24
    assert response.completion_tokens == 42
    assert response.total_tokens == 66
    assert response.metadata.get("finish_reason") == "stop"

    # Verify serialization
    response_dict = response.to_dict()
    assert response_dict["content"] == response.content
    assert response_dict["total_tokens"] == 66


def test_us6_chat_json_parsing_and_markdown_cleaning():
    """Verify chat_json cleanly extracts JSON wrapped in markdown fences."""
    mock_sdk = MagicMock()
    fenced_json = """```json
    {
        "is_vulnerable": true,
        "vulnerability_type": "SQL_INJECTION",
        "severity": "CRITICAL",
        "cwe_id": "CWE-89",
        "description": "User input directly formatted into query string."
    }
    ```"""
    mock_sdk.chat.completions.create.return_value = MockCompletion(content=fenced_json)

    client = GroqLLMClient(api_key="mock_key", client=mock_sdk)
    result = client.chat_json(messages=[{"role": "user", "content": "Audit this SQL"}])

    assert isinstance(result, dict)
    assert result["is_vulnerable"] is True
    assert result["vulnerability_type"] == "SQL_INJECTION"
    assert result["severity"] == "CRITICAL"
    assert result["cwe_id"] == "CWE-89"


def test_us6_chat_json_malformed_syntax_error():
    """Verify chat_json raises a clear descriptive ValueError when LLM outputs invalid JSON."""
    mock_sdk = MagicMock()
    mock_sdk.chat.completions.create.return_value = MockCompletion(
        content="This is definitely not a JSON payload {"
    )

    client = GroqLLMClient(api_key="mock_key", client=mock_sdk)

    with pytest.raises(ValueError) as exc_info:
        client.chat_json(messages=[{"role": "user", "content": "Audit"}])
    assert "Failed to parse LLM response as JSON" in str(exc_info.value)


def test_us6_rate_limit_retry_and_backoff():
    """Verify client recovers and succeeds after transient rate limits using exponential backoff."""
    mock_sdk = MagicMock()
    mock_sdk.chat.completions.create.side_effect = [
        create_rate_limit_error("Rate limit hit"),
        MockCompletion(content="Analysis succeeded after backoff."),
    ]

    client = GroqLLMClient(
        api_key="mock_key",
        client=mock_sdk,
        max_retries=2,
        retry_delay=0.1,  # Short delay for fast test execution
    )

    response = client.chat(messages=[{"role": "user", "content": "Scan"}])
    assert "Analysis succeeded after backoff." in response.content
    assert mock_sdk.chat.completions.create.call_count == 2


def test_us6_rate_limit_max_retries_exceeded():
    """Verify client raises RuntimeError when rate limit persists beyond max retries."""
    mock_sdk = MagicMock()
    mock_sdk.chat.completions.create.side_effect = create_rate_limit_error("Persistent limit")

    client = GroqLLMClient(
        api_key="mock_key",
        client=mock_sdk,
        max_retries=1,
        retry_delay=0.1,
    )

    with pytest.raises(RuntimeError) as exc_info:
        client.chat(messages=[{"role": "user", "content": "Scan"}])
    assert "failed after 1 retries" in str(exc_info.value)

def test_us6_fallback_model_activation():
    """Verify that when primary 70B model fails, the client seamlessly falls back to the 8B model."""
    mock_sdk = MagicMock()

    def mock_create(model: str, messages: list, temperature: float, max_tokens: int):
        if model == "llama-3.3-70b-versatile":
            raise create_rate_limit_error("Primary model TPM quota reached")
        return MockCompletion(
            content="Fallback model successfully analyzed the code.",
            model="llama-3.1-8b-instant",
        )

    mock_sdk.chat.completions.create.side_effect = mock_create

    client = GroqLLMClient(
        api_key="mock_key",
        client=mock_sdk,
        max_retries=1,
        retry_delay=0.05,
    )

    response = client.chat(messages=[{"role": "user", "content": "Analyze SQL snippet"}])

    assert response.model == "llama-3.1-8b-instant"
    assert "Fallback model successfully analyzed" in response.content
    assert mock_sdk.chat.completions.create.call_count >= 2
