from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from app.core.models.code import SourceFile


class ContextBuilder:
    """
    Assembles token-budgeted prompt bundles combining the focal source file
    with locally retrieved cross-file and semantic code context.
    Ensures zero full-repository leakage.
    """

    def __init__(
        self,
        max_context_chars: Optional[int] = None,
        max_tokens_budget: int = 4000,
    ):
        self.max_tokens_budget: int = max(25, max_tokens_budget)
        if max_context_chars is not None:
            self.max_context_chars: int = max(100, max_context_chars)
        else:
            # Dynamically derive char budget from max_tokens_budget (~4 chars/token)
            self.max_context_chars = max(100, self.max_tokens_budget * 4)

    def estimate_tokens(self, text: str) -> int:
        """Heuristic estimation of token count (~4 chars per token)."""
        if not text:
            return 0
        return max(1, len(text) // 4)

    def format_snippet_block(self, snippet_item: Dict[str, Any]) -> str:
        """Format an individual cross-file or semantic snippet with clean metadata fences."""
        file_name = str(snippet_item.get("file") or snippet_item.get("file_path") or "unknown_file").replace("\\", "/")
        comp_name = snippet_item.get("component_name")
        start_line = snippet_item.get("start_line")
        end_line = snippet_item.get("end_line")
        snippet_type = snippet_item.get("type", "related_context")
        raw_code = str(snippet_item.get("snippet") or "").strip()

        header_parts = [f"File: {file_name}"]
        if comp_name:
            header_parts.append(f"Component: {comp_name}")
        if start_line and end_line:
            header_parts.append(f"Lines: {start_line}-{end_line}")
        elif start_line:
            header_parts.append(f"Line: {start_line}")
        header_parts.append(f"Type: {snippet_type}")

        header = " | ".join(header_parts)
        return f"--- {header} ---\n```\n{raw_code}\n```\n"

    def build_context_block(
        self,
        context_snippets: Optional[List[Dict[str, Any]]],
    ) -> str:
        """
        Assemble and format all retrieved context snippets into a coherent markdown section,
        enforcing the character/token budget strictly.
        """
        if not context_snippets:
            return ""

        formatted_blocks: List[str] = []
        current_chars = 0

        for snippet in context_snippets:
            block = self.format_snippet_block(snippet)
            if current_chars + len(block) > self.max_context_chars:
                break
            formatted_blocks.append(block)
            current_chars += len(block)

        if not formatted_blocks:
            return ""

        count = len(formatted_blocks)
        plural = "snippet" if count == 1 else "snippets"
        header = f"\n### Relevant Cross-File Context (Retrieved Locally - {count} {plural})\n"
        return header + "\n".join(formatted_blocks)

    def build_messages(
        self,
        source_file: SourceFile,
        context_snippets: Optional[List[Dict[str, Any]]] = None,
        system_prompt: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """
        Build complete chat prompt messages combining system instructions,
        focal source file code, and locally retrieved context snippets.
        """
        sys_prompt = system_prompt or (
            "You are CodeShield AI, an advanced code security auditor. "
            "Analyze the provided source file for security vulnerabilities, "
            "architectural anti-patterns, and logic bugs using the given cross-file context. "
            "Respond strictly in structured JSON."
        )

        fpath = str(source_file.relative_path or Path(source_file.file_path).name).replace("\\", "/")
        lang = source_file.language.value if hasattr(source_file.language, "value") else str(source_file.language)

        user_content = (
            f"Focal File: {fpath}\n"
            f"Language: {lang}\n\n"
            f"Source Code:\n```\n{source_file.content or ''}\n```\n"
        )

        context_block = self.build_context_block(context_snippets)
        if context_block:
            user_content += context_block

        return [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_content},
        ]