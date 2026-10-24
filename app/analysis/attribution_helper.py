from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from app.core.interfaces.filesystem import FileSystem
from app.core.models.audit import AuditFinding
from app.infrastructure.filesystem import LocalFileSystem


class FindingAttributionHelper:
    """
    Validates, clamps, and hydrates findings with exact file paths,
    bounded line numbers, code snippets, and formatted context windows.
    """

    def __init__(self, filesystem: Optional[FileSystem] = None):
        self.filesystem = filesystem if filesystem is not None else LocalFileSystem()

    def extract_snippet(self, file_content: str, start_line: int, end_line: int) -> str:
        """Extract the exact lines of code between start_line and end_line (1-indexed)."""
        if not file_content:
            return ""
        lines = file_content.splitlines()
        total = len(lines)
        if total == 0:
            return ""

        s = max(1, min(start_line, total))
        e = max(s, min(end_line, total))
        return "\n".join(lines[s - 1:e])

    def extract_context_snippet(
        self,
        file_content: str,
        start_line: int,
        end_line: int,
        context_lines: int = 2,
    ) -> str:
        """
        Generate a human-readable snippet showing surrounding lines of context,
        line numbers, and a '>' indicator on the offending lines.
        """
        if not file_content:
            return ""
        lines = file_content.splitlines()
        total = len(lines)
        if total == 0:
            return ""

        s = max(1, min(start_line, total))
        e = max(s, min(end_line, total))

        win_start = max(1, s - context_lines)
        win_end = min(total, e + context_lines)

        result_lines = []
        for line_no in range(win_start, win_end + 1):
            marker = ">" if (s <= line_no <= e) else " "
            line_str = lines[line_no - 1]
            result_lines.append(f"{marker} {line_no:4d} | {line_str}")

        return "\n".join(result_lines)

    def hydrate_finding(
        self,
        finding: AuditFinding,
        file_content: Optional[str] = None,
        context_lines: int = 2,
    ) -> AuditFinding:
        """Enrich a single finding with clamped line coordinates and context snippets."""
        # 1. Multi-file attribution from metadata (e.g. circular dependencies or taint paths)
        affected = set(finding.affected_files) if finding.affected_files else set()
        if finding.file_path:
            affected.add(Path(finding.file_path).as_posix())

        if "cycle_files" in finding.metadata:
            for cf in finding.metadata["cycle_files"]:
                affected.add(Path(cf).as_posix())

        if "related_files" in finding.metadata:
            for rf in finding.metadata["related_files"]:
                affected.add(Path(rf).as_posix())

        finding.affected_files = sorted(list(affected))

        if not getattr(finding, "relative_file_path", None) and finding.file_path:
            finding.relative_file_path = Path(finding.file_path).as_posix()

        # 2. Content retrieval
        content = file_content
        if content is None and finding.file_path:
            try:
                if self.filesystem.exists(finding.file_path):
                    content = self.filesystem.read_text(finding.file_path)
            except Exception:
                content = None

        if not content:
            return finding

        # 3. Line boundary clamping
        total_lines = len(content.splitlines())
        if total_lines > 0:
            finding.start_line = max(1, min(finding.start_line, total_lines))
            finding.end_line = max(finding.start_line, min(finding.end_line, total_lines))

        # 4. Snippet extraction
        if not finding.code_snippet or not finding.code_snippet.strip():
            finding.code_snippet = self.extract_snippet(content, finding.start_line, finding.end_line)

        # 5. Context snippet generation
        if not finding.context_snippet or not finding.context_snippet.strip():
            finding.context_snippet = self.extract_context_snippet(
                content,
                finding.start_line,
                finding.end_line,
                context_lines=context_lines,
            )

        return finding

    def hydrate_findings(
        self,
        findings: List[AuditFinding],
        context_lines: int = 2,
    ) -> List[AuditFinding]:
        """Batch hydrate a list of findings, caching file reads across identical paths."""
        file_cache: Dict[str, str] = {}

        for finding in findings:
            content = None
            if finding.file_path:
                norm_path = Path(finding.file_path).as_posix()
                if norm_path not in file_cache:
                    try:
                        if self.filesystem.exists(finding.file_path):
                            file_cache[norm_path] = self.filesystem.read_text(finding.file_path)
                    except Exception:
                        pass
                content = file_cache.get(norm_path)

            self.hydrate_finding(finding, file_content=content, context_lines=context_lines)

        return findings
