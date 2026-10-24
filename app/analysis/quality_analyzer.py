from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from app.analysis.cross_file import CrossFileContextResolver
from app.core.enums import Confidence, FindingCategory, Language, Severity
from app.core.models.audit import AuditFinding
from app.core.models.code import SourceFile


class CodeQualityAnalyzer:
    """Evaluates single-file maintainability, complexity, and code quality anti-patterns."""

    def __init__(
        self,
        max_function_lines: int = 75,
        max_nesting_depth: int = 4,
        max_parameters: int = 5,
    ):
        self.max_function_lines: int = max_function_lines
        self.max_nesting_depth: int = max_nesting_depth
        self.max_parameters: int = max_parameters

    def _check_bare_excepts(self, source_file: SourceFile) -> List[AuditFinding]:
        """Detect bare except clauses or empty catch blocks that swallow errors silently."""
        findings: List[AuditFinding] = []
        lines = source_file.content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            
            # Python bare except
            if source_file.language == Language.PYTHON:
                if re.match(r"^except\s*:", stripped) or re.match(r"^except\s+BaseException\s*:", stripped):
                    findings.append(AuditFinding(
                        title="Bare Exception Clause",
                        description=(
                            "Catching bare 'except:' or 'BaseException' suppresses critical errors "
                            "and system signals (e.g. KeyboardInterrupt, SystemExit), making debugging difficult."
                        ),
                        category=FindingCategory.CODE_QUALITY,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file_path=source_file.file_path,
                        start_line=idx,
                        end_line=idx,
                        code_snippet=stripped,
                        recommendation="Catch specific exceptions (e.g. 'except ValueError:') rather than catching all exceptions.",
                        source="quality_analyzer",
                    ))

            # JavaScript / Java / C++ catch all
            elif source_file.language in (Language.JAVASCRIPT, Language.JAVA, Language.CPP):
                if re.search(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}", stripped) or re.search(r"catch\s*\(\s*(?:Exception|Throwable|\.\.\.)", stripped):
                    findings.append(AuditFinding(
                        title="Empty or Overly Broad Catch Block",
                        description="Catching general exceptions and silently ignoring them hides fatal runtime failures.",
                        category=FindingCategory.CODE_QUALITY,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file_path=source_file.file_path,
                        start_line=idx,
                        end_line=idx,
                        code_snippet=stripped,
                        recommendation="Handle the exception explicitly, log the stack trace, or rethrow.",
                        source="quality_analyzer",
                    ))

        return findings

    def _check_nesting_depth(self, source_file: SourceFile) -> List[AuditFinding]:
        """Detect excessively nested control structures (indentation level >= max_nesting_depth)."""
        findings: List[AuditFinding] = []
        lines = source_file.content.splitlines()

        for idx, line in enumerate(lines, start=1):
            if not line.strip() or line.strip().startswith(("#", "//", "/*", "*")):
                continue

            # Calculate indentation depth (assuming 4 spaces or 1 tab per level)
            leading_spaces = len(line) - len(line.lstrip(" "))
            leading_tabs = len(line) - len(line.lstrip("\t"))
            depth = max(leading_spaces // 4, leading_tabs)

            if depth >= self.max_nesting_depth:
                stripped = line.strip()
                if any(stripped.startswith(k) for k in ("if", "for", "while", "switch", "try")):
                    findings.append(AuditFinding(
                        title=f"Excessive Control Flow Nesting (Depth: {depth})",
                        description=(
                            f"Control flow is nested {depth} levels deep. Deep nesting significantly increases "
                            "cyclomatic complexity and reduces cognitive maintainability."
                        ),
                        category=FindingCategory.CODE_QUALITY,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        file_path=source_file.file_path,
                        start_line=idx,
                        end_line=idx,
                        code_snippet=stripped,
                        recommendation="Refactor using guard clauses (early returns) or extract nested blocks into helper functions.",
                        source="quality_analyzer",
                    ))

        return findings

    @staticmethod
    def _split_parameters(params_str: str) -> List[str]:
        """Split parameters safely honoring nested brackets, quotes, and lambdas."""
        params = []
        current = []
        paren_depth = 0
        in_quote = None
        for char in params_str:
            if in_quote:
                current.append(char)
                if char == in_quote:
                    in_quote = None
            elif char in ('"', "'"):
                in_quote = char
                current.append(char)
            elif char in ('(', '[', '{'):
                paren_depth += 1
                current.append(char)
            elif char in (')', ']', '}'):
                paren_depth = max(0, paren_depth - 1)
                current.append(char)
            elif char == ',' and paren_depth == 0:
                params.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        if current:
            params.append("".join(current).strip())
        return [p for p in params if p and p != "self"]

    def _check_long_functions_and_parameters(self, source_file: SourceFile) -> List[AuditFinding]:
        """Detect oversized functions and excessive parameter lists."""
        findings: List[AuditFinding] = []
        lines = source_file.content.splitlines()

        # Regular expressions for function declarations
        fn_pattern = None
        if source_file.language == Language.PYTHON:
            fn_pattern = re.compile(r"^def\s+([a-zA-Z0-9_]+)\s*\((.*)\):\s*$")
        elif source_file.language in (Language.JAVASCRIPT, Language.JAVA, Language.C, Language.CPP):
            fn_pattern = re.compile(r"(?:function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)|(?:public|private|protected|static|\w+)\s+(?:\w+\s+)?([a-zA-Z0-9_]+)\s*\((.*?)\)\s*\{)")

        if not fn_pattern:
            return []

        for idx, line in enumerate(lines, start=1):
            match = fn_pattern.search(line.strip())
            if match:
                groups = [g for g in match.groups() if g is not None]
                fn_name = groups[0] if groups else "function"
                params_str = groups[1] if len(groups) > 1 else ""

                # Check excessive parameters
                if params_str.strip():
                    params = self._split_parameters(params_str)
                    if len(params) > self.max_parameters:
                        findings.append(AuditFinding(
                            title=f"Excessive Parameter List in '{fn_name}' ({len(params)} params)",
                            description=(
                                f"Function '{fn_name}' declares {len(params)} parameters (threshold: {self.max_parameters}). "
                                "Functions with too many parameters indicate high coupling and violate the Single Responsibility Principle."
                            ),
                            category=FindingCategory.CODE_QUALITY,
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            file_path=source_file.file_path,
                            start_line=idx,
                            end_line=idx,
                            code_snippet=line.strip(),
                            recommendation="Encapsulate parameters into a dedicated configuration object, struct, or dictionary.",
                            source="quality_analyzer",
                        ))

        return findings

    def evaluate_file(self, source_file: SourceFile) -> List[AuditFinding]:
        """Execute full code quality checks on a source file."""
        findings: List[AuditFinding] = []
        findings.extend(self._check_bare_excepts(source_file))
        findings.extend(self._check_nesting_depth(source_file))
        findings.extend(self._check_long_functions_and_parameters(source_file))
        return findings


class ArchitecturalSmellDetector:
    """Detects system-wide architectural smells: circular dependencies and God classes."""

    def __init__(
        self,
        cross_file_resolver: Optional[CrossFileContextResolver] = None,
        max_god_class_lines: int = 250,
    ):
        self.resolver = cross_file_resolver if cross_file_resolver is not None else CrossFileContextResolver()
        self.max_god_class_lines: int = max_god_class_lines

    def detect_circular_dependencies(self, files: List[SourceFile]) -> List[AuditFinding]:
        """Detect circular import cycles (e.g. A -> B -> A) across project source files."""
        findings: List[AuditFinding] = []

        # 1. Build adjacency list of project dependencies: file_path -> Set[imported_file_paths]
        adj: Dict[str, Set[str]] = {}
        file_map: Dict[str, SourceFile] = {}

        for sf in files:
            norm_path = Path(sf.file_path).as_posix().lower()
            file_map[norm_path] = sf
            adj[norm_path] = set()

            imports = self.resolver.extract_imports(sf.content, sf.language)
            for imp in imports:
                matched = self.resolver.resolve_import_to_file(imp, sf.file_path, files)
                if matched:
                    cand_norm = Path(matched.file_path).as_posix().lower()
                    if cand_norm != norm_path:
                        adj[norm_path].add(cand_norm)

        # 2. Cycle detection via Depth-First Search
        visited: Dict[str, int] = {k: 0 for k in adj}  # 0=unvisited, 1=visiting, 2=visited
        reported_cycles: Set[Tuple[str, ...]] = set()

        def dfs(current: str, path: List[str]):
            visited[current] = 1
            path.append(current)

            for neighbor in adj.get(current, []):
                if visited.get(neighbor) == 1:
                    # Found cycle: neighbor is in current recursion stack
                    cycle_start_idx = path.index(neighbor)
                    cycle = path[cycle_start_idx:]
                    sorted_cycle = tuple(sorted(cycle))

                    if sorted_cycle not in reported_cycles and len(cycle) >= 2:
                        reported_cycles.add(sorted_cycle)
                        
                        rel_cycle_names = [
                            file_map[p].relative_path or Path(file_map[p].file_path).name
                            for p in cycle
                        ]
                        cycle_str = " -> ".join([str(n) for n in rel_cycle_names]) + f" -> {rel_cycle_names[0]}"

                        findings.append(AuditFinding(
                            title="Circular Dependency Architectural Smell",
                            description=(
                                f"Circular import cycle detected across modules: {cycle_str}. "
                                "Circular dependencies couple modules tightly, prevent independent testing, and cause runtime import errors."
                            ),
                            category=FindingCategory.ARCHITECTURE,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            file_path=file_map[current].file_path,
                            start_line=1,
                            end_line=1,
                            code_snippet=cycle_str,
                            recommendation="Break the cycle by applying Dependency Inversion, using interfaces, or extracting shared logic to a separate module.",
                            source="architectural_analyzer",
                            metadata={"cycle_files": [str(n) for n in rel_cycle_names]},
                        ))

                elif visited.get(neighbor, 0) == 0:
                    dfs(neighbor, path)

            path.pop()
            visited[current] = 2

        for node in list(adj.keys()):
            if visited[node] == 0:
                dfs(node, [])

        return findings

    def detect_god_classes(self, files: List[SourceFile]) -> List[AuditFinding]:
        """Detect monolithic 'God Classes' that accumulate too many responsibilities."""
        findings: List[AuditFinding] = []

        for sf in files:
            lines = sf.content.splitlines()
            total_lines = len(lines)

            # Heuristic: File/class contains more lines than threshold
            if total_lines >= self.max_god_class_lines:
                rel_name = sf.relative_path or Path(sf.file_path).name
                findings.append(AuditFinding(
                    title=f"Monolithic God Class/Module Detected ({total_lines} lines)",
                    description=(
                        f"Module '{rel_name}' contains {total_lines} lines of code (threshold: {self.max_god_class_lines}). "
                        "Monolithic files often violate the Single Responsibility Principle, centralizing too much logic and becoming fragile to change."
                    ),
                    category=FindingCategory.ARCHITECTURE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    file_path=sf.file_path,
                    start_line=1,
                    end_line=total_lines,
                    code_snippet=f"# Module length: {total_lines} lines",
                    recommendation="Decompose this large class/module into smaller, focused service or repository components.",
                    source="architectural_analyzer",
                ))

        return findings

    def evaluate_architecture(self, files: List[SourceFile]) -> List[AuditFinding]:
        """Run complete architectural smell detection across all project files."""
        findings: List[AuditFinding] = []
        findings.extend(self.detect_circular_dependencies(files))
        findings.extend(self.detect_god_classes(files))
        return findings
