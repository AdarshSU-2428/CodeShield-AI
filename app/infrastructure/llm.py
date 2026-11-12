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
from app.infrastructure.logger import logger


class GroqLLMClient(LLMClient):
    """Concrete Groq LLM adapter with retry resilience, timeout recovery, and automated fallback."""

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
        self._retry_delay: float = max(0.05, retry_delay)

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
        """Strip markdown code block fences and extract the cleanest JSON object or array."""
        if not raw_text:
            return ""
        text = raw_text.strip()

        # 1. Try fenced markdown block ```json ... ```
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
        if match:
            return match.group(1).strip()

        # 2. If conversational prose surrounds raw JSON, extract outermost {...} or [...]
        obj_start = text.find("{")
        obj_end = text.rfind("}")
        arr_start = text.find("[")
        arr_end = text.rfind("]")

        if obj_start != -1 and obj_end > obj_start:
            if arr_start == -1 or obj_start < arr_start:
                return text[obj_start : obj_end + 1].strip()
        if arr_start != -1 and arr_end > arr_start:
            return text[arr_start : arr_end + 1].strip()

        return text

    def _call_groq_api(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> Any:
        """Single model attempt with exponential backoff on transient cloud/network errors."""
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
            except (RateLimitError, APIConnectionError, TimeoutError, ConnectionError, OSError) as exc:
                attempts += 1
                logger.warning(
                    f"Transient cloud error on '{model}' (attempt {attempts}/{self._max_retries}): {exc}"
                )
                if attempts > self._max_retries:
                    raise RuntimeError(
                        f"Groq API call to '{model}' failed after {self._max_retries} retries: {exc}"
                    ) from exc
                time.sleep(current_delay)
                current_delay *= 2.0
            except APIError as exc:
                logger.error(f"Groq API error on '{model}': {exc}")
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
            logger.warning(f"Primary model '{self.model_name}' failed: {primary_error}")
            if self._fallback_model and self._fallback_model != self.model_name:
                try:
                    logger.info(f"Attempting failover to fallback model '{self._fallback_model}'...")
                    return self._call_groq_api(
                        model=self._fallback_model,
                        messages=messages,
                        temperature=temperature,
                        max_tokens=self._fallback_max_tokens,
                    )
                except Exception as fallback_error:
                    logger.error(f"Fallback model '{self._fallback_model}' also failed: {fallback_error}")
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
        """Send chat messages and return the raw LLM response safely."""
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

        # Guard against malformed/empty cloud response objects
        if completion is None or not getattr(completion, "choices", None):
            raise RuntimeError("Cloud LLM returned an empty or malformed response without choices.")

        choice = completion.choices[0]
        message_obj = getattr(choice, "message", None)
        content = (getattr(message_obj, "content", None) or "") if message_obj is not None else ""

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

        if not cleaned_json:
            raise ValueError("LLM returned empty content when JSON was expected.")

        try:
            parsed = json.loads(cleaned_json)
            if isinstance(parsed, list):
                return {"vulnerabilities": parsed}
            if not isinstance(parsed, dict):
                raise ValueError(f"Expected JSON object, got {type(parsed).__name__}")
            return parsed
        except json.JSONDecodeError as exc:
            logger.warning(f"Malformed JSON from LLM: {exc}")
            raise ValueError(
                f"Failed to parse LLM response as JSON. Content received: '{cleaned_json[:200]}'"
            ) from exc