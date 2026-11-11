import difflib
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from app.core.models.audit import AuditFinding
from app.core.models.patch import PatchDiff


class DiffGenerator:
    """Generates standard unified Git diffs and structured line-by-line diff models."""

    def __init__(self, context_lines: int = 3):
        self.context_lines: int = max(0, context_lines)
        self._hunk_header_regex = re.compile(
            r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
        )

    def _parse_hunk_header(self, line: str) -> Dict[str, int]:
        """Extract line numbers and counts from @@ -old_start,old_count +new_start,new_count @@."""
        match = self._hunk_header_regex.match(line)

        if not match:
            return {"old_start": 1, "old_lines": 0, "new_start": 1, "new_lines": 0}

        old_start = int(match.group(1))
        old_lines = int(match.group(2)) if match.group(2) else 1
        new_start = int(match.group(3))
        new_lines = int(match.group(4)) if match.group(4) else 1

        return {
            "old_start": old_start,
            "old_lines": old_lines,
            "new_start": new_start,
            "new_lines": new_lines,
        }

    def _parse_hunks(self, diff_lines: List[str]) -> Tuple[int, int, List[Dict[str, Any]]]:
        """Parse raw diff lines into additions count, deletions count, and structured hunks."""
        additions = 0
        deletions = 0
        hunks: List[Dict[str, Any]] = []
        current_hunk: Optional[Dict[str, Any]] = None

        old_cursor = 1
        new_cursor = 1

        for raw_line in diff_lines:
            # Skip file header lines (--- a/... and +++ b/...)
            if raw_line.startswith(("---", "+++")):
                continue

            if raw_line.startswith("@@"):
                header_info = self._parse_hunk_header(raw_line)
                old_cursor = header_info["old_start"]
                new_cursor = header_info["new_start"]

                current_hunk = {
                    "header": raw_line.strip(),
                    "old_start": header_info["old_start"],
                    "old_lines": header_info["old_lines"],
                    "new_start": header_info["new_start"],
                    "new_lines": header_info["new_lines"],
                    "lines": [],
                }

                hunks.append(current_hunk)
                continue

            if current_hunk is None:
                continue

            content = raw_line[1:] if len(raw_line) > 1 else ""

            if raw_line.startswith("+"):
                additions += 1
                current_hunk["lines"].append({
                    "type": "addition",
                    "content": content,
                    "old_line_number": None,
                    "new_line_number": new_cursor,
                })
                new_cursor += 1

            elif raw_line.startswith("-"):
                deletions += 1
                current_hunk["lines"].append({
                    "type": "deletion",
                    "content": content,
                    "old_line_number": old_cursor,
                    "new_line_number": None,
                })
                old_cursor += 1

            elif raw_line.startswith(" "):
                current_hunk["lines"].append({
                    "type": "context",
                    "content": content,
                    "old_line_number": old_cursor,
                    "new_line_number": new_cursor,
                })
                old_cursor += 1
                new_cursor += 1

        return additions, deletions, hunks

    def generate_diff(
        self,
        original_code: str,
        modified_code: str,
        file_name: str = "file",
    ) -> PatchDiff:
        """Compute unified diff between original and proposed code."""
        orig_lines = original_code.splitlines(keepends=True)
        mod_lines = modified_code.splitlines(keepends=True)

        diff_iterator = difflib.unified_diff(
            orig_lines,
            mod_lines,
            fromfile=f"a/{file_name}",
            tofile=f"b/{file_name}",
            n=self.context_lines,
        )

        raw_diff_lines = list(diff_iterator)
        raw_diff = "".join(raw_diff_lines)

        additions, deletions, hunks = self._parse_hunks(raw_diff_lines)

        return PatchDiff(
            raw_diff=raw_diff,
            additions_count=additions,
            deletions_count=deletions,
            hunks=hunks,
        )


class PatchGenerator(DiffGenerator):
    """
    US 14: Generates concrete remediated source code and unified diffs directly
    from an AuditFinding's line span and suggested remediation code.
    """

    def apply_inline_remediation(
        self,
        original_code: str,
        start_line: int,
        end_line: int,
        replacement_code: str,
    ) -> str:
        """Replace lines [start_line, end_line] (1-indexed) with replacement_code, preserving indentation."""
        lines = original_code.splitlines()
        total_lines = len(lines)
        if total_lines == 0:
            return replacement_code

        s = max(1, min(start_line, total_lines))
        e = max(s, min(end_line, total_lines))

        # Detect leading indentation from original starting line
        orig_first_line = lines[s - 1]
        indent = re.match(r"^\s*", orig_first_line).group(0)

        # Format replacement lines with matching indentation if replacement lines aren't already indented
        rep_lines = replacement_code.splitlines()
        formatted_rep = []
        for line in rep_lines:
            if not line.strip():
                formatted_rep.append("")
            elif not line.startswith(indent) and not line.startswith(" ") and not line.startswith("\t"):
                formatted_rep.append(indent + line)
            else:
                formatted_rep.append(line)

        new_lines = lines[:s - 1] + formatted_rep + lines[e:]
        newline_char = "\r\n" if "\r\n" in original_code else "\n"
        result = newline_char.join(new_lines)
        if original_code.endswith("\n") and not result.endswith("\n"):
            result += newline_char
        return result

    def generate_remediation(
        self,
        original_code: str,
        finding: AuditFinding,
        custom_remediation_code: Optional[str] = None,
        file_name: str = "file",
    ) -> Tuple[str, PatchDiff]:
        """
        Produce remediated source code and unified PatchDiff for an AuditFinding.
        Returns: (modified_code, patch_diff)
        """
        code_to_apply = custom_remediation_code or finding.remediation_code
        if not code_to_apply:
            raise ValueError(f"No remediation code available for finding: {finding.title}")

        modified_code = self.apply_inline_remediation(
            original_code=original_code,
            start_line=finding.start_line,
            end_line=finding.end_line,
            replacement_code=code_to_apply,
        )

        diff = self.generate_diff(
            original_code=original_code,
            modified_code=modified_code,
            file_name=file_name,
        )

        return modified_code, diff