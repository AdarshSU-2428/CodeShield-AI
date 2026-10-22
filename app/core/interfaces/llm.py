from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class LLMResponse:
    """Encapsulates the response from an LLM inference call."""

    def __init__(
        self,
        content: str,
        model: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self._content: str = content
        self._model: str = model
        self._prompt_tokens: int = prompt_tokens
        self._completion_tokens: int = completion_tokens
        self._total_tokens: int = total_tokens
        self._metadata: Dict[str, Any] = metadata if metadata is not None else {}

    @property
    def content(self) -> str:
        return self._content

    @property
    def model(self) -> str:
        return self._model

    @property
    def prompt_tokens(self) -> int:
        return self._prompt_tokens

    @property
    def completion_tokens(self) -> int:
        return self._completion_tokens

    @property
    def total_tokens(self) -> int:
        return self._total_tokens

    @property
    def metadata(self) -> Dict[str, Any]:
        return self._metadata

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self._content,
            "model": self._model,
            "prompt_tokens": self._prompt_tokens,
            "completion_tokens": self._completion_tokens,
            "total_tokens": self._total_tokens,
            "metadata": self._metadata,
        }


class LLMClient(ABC):
    """Abstract interface for LLM cloud assistance providers."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ):
        self._model_name: Optional[str] = model_name
        self._temperature: Optional[float] = temperature
        self._max_tokens: Optional[int] = max_tokens

    @property
    def model_name(self) -> Optional[str]:
        return self._model_name

    @property
    def temperature(self) -> Optional[float]:
        return self._temperature

    @property
    def max_tokens(self) -> Optional[int]:
        return self._max_tokens

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the underlying provider is configured and ready."""
        pass

    @abstractmethod
    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Send chat messages and return the raw LLM response."""
        pass

    @abstractmethod
    def chat_json(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Send chat messages and parse the returned content as a JSON object."""
        pass
