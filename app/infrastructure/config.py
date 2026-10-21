import os
from pathlib import Path
from typing import Any, Dict, List, Set
import yaml

from app.core.enums import Language


class AppConfig:
    """Manages application-wide configuration settings."""

    _DEFAULT_CONFIG_PATH = Path("config/config.yaml")

    def __init__(self, config_path: Path = None):
        self.config_path = config_path if config_path else self._find_config_path()
        self._raw_config: Dict[str, Any] = self._load_config()

        # Cache frequently accessed scanner collections
        self._extension_to_language: Dict[str, Language] = self._build_extension_map()
        self._ignore_directories: Set[str] = set(
            self._raw_config.get("scanner", {}).get("ignore_directories", [])
        )
        self._ignore_patterns: List[str] = self._raw_config.get("scanner", {}).get(
            "ignore_patterns", []
        )
        self._max_file_size: int = self._raw_config.get("scanner", {}).get(
            "max_file_size_bytes", 1048576
        )

    def _find_config_path(self) -> Path:
        """Locate config.yaml relative to current working directory or project root."""
        possible_paths = [
            Path("config/config.yaml"),
            Path(__file__).resolve().parent.parent.parent / "config" / "config.yaml",
        ]
        for p in possible_paths:
            if p.exists():
                return p.resolve()
        return self._DEFAULT_CONFIG_PATH

    def _load_config(self) -> Dict[str, Any]:
        """Load YAML configuration safely with empty dict fallback."""
        if not self.config_path.exists():
            return {}
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def _build_extension_map(self) -> Dict[str, Language]:
        """Map every file extension in config to its corresponding Language enum."""
        mapping: Dict[str, Language] = {}
        scanner_cfg = self._raw_config.get("scanner", {})
        extensions_cfg = scanner_cfg.get("supported_extensions", {})

        lang_lookup = {
            "python": Language.PYTHON,
            "javascript": Language.JAVASCRIPT,
            "java": Language.JAVA,
            "c": Language.C,
            "cpp": Language.CPP,
        }

        for lang_str, exts in extensions_cfg.items():
            lang_enum = lang_lookup.get(lang_str.lower(), Language.UNKNOWN)
            if lang_enum != Language.UNKNOWN:
                for ext in exts:
                    mapping[ext.lower()] = lang_enum

        return mapping

    @property
    def extension_to_language(self) -> Dict[str, Language]:
        """Return dict mapping lowercase extensions (e.g. '.py') to Language enum."""
        return self._extension_to_language

    @property
    def supported_extensions(self) -> Set[str]:
        """Return set of all supported extensions (e.g., {'.py', '.js', ...})."""
        return set(self._extension_to_language.keys())

    @property
    def ignore_directories(self) -> Set[str]:
        """Return set of directory names to skip during scanning."""
        return self._ignore_directories

    @property
    def ignore_patterns(self) -> List[str]:
        """Return list of file patterns to exclude."""
        return self._ignore_patterns

    @property
    def max_file_size_bytes(self) -> int:
        """Return maximum allowed file size in bytes."""
        return self._max_file_size


# Singleton global config instance for convenience
config = AppConfig()
