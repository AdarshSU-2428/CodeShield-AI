import json
import os
import re
import time
from typing import Any, Dict, List, Optional

try:
    from groq import Groq, RateLimitError, APIConnectionError, APIError
except ImportError:
    Groq = None
    RateLimitError = Exception
    APIConnectionError = Exception
    APIError = Exception

from app.core.interfaces.llm import LLMClient, LLMResponse
from app.infrastructure.config import config


class GroqLLMClient(LLMClient):
    """Concrete Groq LLM adapter with retry resilience and automated fallback."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        fallback_model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        fallback_max_tokens: Optional[int] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        client: Optional[Any] = None,
    ):
        resolved_model = model_name if model_name is not None else config.llm_default_model
        resolved_temp = temperature if temperature is not None else config.llm_temperature
        resolved_tokens = max_tokens if max_tokens is not None else config.llm_max_context_tokens

        super().__init__(
            model_name=resolved_model,
            temperature=resolved_temp,
            max_tokens=resolved_tokens,
        )

        self._fallback_model: str = (
            fallback_model if fallback_model is not None else config.llm_fallback_model
        )
        self._fallback_max_tokens: int = (
            fallback_max_tokens if fallback_max_tokens is not None else config.llm_fallback_max_tokens
        )
        self._api_key: str = (api_key or os.getenv("GROQ_API_KEY", "")).strip()
        self._max_retries: int = max(0, max_retries)
        self._retry_delay: float = max(0.1, retry_delay)

        # Injectable client for testing or direct initialization
        if client is not None:
            self._client = client
        elif self._api_key and Groq is not None:
            self._client = Groq(api_key=self._api_key)
        else:
            self._client = None

    @property
    def fallback_model(self) -> str:
        """Return the configured fallback model name."""
        return self._fallback_model

    @property
    def fallback_max_tokens(self) -> int:
        """Return the configured fallback token limit."""
        return self._fallback_max_tokens

    @property
    def api_key_configured(self) -> bool:
        """Check if an API key is available."""
        return bool(self._api_key)

    def is_available(self) -> bool:
        """Return True if Groq is installed, client is ready, and API key is present."""
        return bool(self._client is not None and self._api_key)

    def _clean_markdown_json(self, raw_text: str) -> str:
        """Strip markdown code block fences and extract the cleanest JSON string."""
        text = raw_text.strip()
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return text

    def _call_groq_api(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> Any:
        """Single model attempt with exponential backoff on transient errors."""
        attempts = 0
        current_delay = self._retry_delay

        while True:
            try:
                return self._client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except (RateLimitError, APIConnectionError) as exc:
                attempts += 1
                if attempts > self._max_retries:
                    raise RuntimeError(
                        f"Groq API call to '{model}' failed after {self._max_retries} retries: {exc}"
                    ) from exc
                time.sleep(current_delay)
                current_delay *= 2.0
            except APIError as exc:
                raise RuntimeError(f"Groq API error on '{model}': {exc}") from exc

    def _execute_chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> Any:
        """Execute chat completion with automatic fallback model failover."""
        try:
            return self._call_groq_api(
                model=self.model_name,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except Exception as primary_error:
            # If fallback model is different from primary, attempt failover
            if self._fallback_model and self._fallback_model != self.model_name:
                try:
                    return self._call_groq_api(
                        model=self._fallback_model,
                        messages=messages,
                        temperature=temperature,
                        max_tokens=self._fallback_max_tokens,
                    )
                except Exception as fallback_error:
                    raise RuntimeError(
                        f"Both primary model ('{self.model_name}') and fallback model "
                        f"('{self._fallback_model}') failed. Primary error: {primary_error}. "
                        f"Fallback error: {fallback_error}"
                    ) from fallback_error
            raise primary_error

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Send chat messages and return the raw LLM response."""
        if not self.is_available():
            raise RuntimeError(
                "Groq LLM is not available. Please configure the GROQ_API_KEY environment variable."
            )

        effective_temp = temperature if temperature is not None else self.temperature
        effective_tokens = max_tokens if max_tokens is not None else self.max_tokens

        completion = self._execute_chat_completion(
            messages=messages,
            temperature=effective_temp,
            max_tokens=effective_tokens,
        )

        choice = completion.choices[0]
        content = choice.message.content or ""

        usage = getattr(completion, "usage", None)
        prompt_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
        completion_tokens = getattr(usage, "completion_tokens", 0) if usage else 0
        total_tokens = getattr(usage, "total_tokens", 0) if usage else 0

        return LLMResponse(
            content=content,
            model=getattr(completion, "model", self.model_name),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            metadata={"finish_reason": getattr(choice, "finish_reason", "stop")},
        )

    def chat_json(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Send chat messages and parse the response into a structured JSON dict."""
        response = self.chat(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        cleaned_json = self._clean_markdown_json(response.content)

        try:
            return json.loads(cleaned_json)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Failed to parse LLM response as JSON. Content received: '{cleaned_json}'"
            ) from exc
