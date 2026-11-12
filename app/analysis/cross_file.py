import ast
import os
from pathlib import Path
import re
from collections import deque
from typing import Any, Dict, List, Optional, Set, Union

from app.core.enums import Language
from app.core.interfaces.filesystem import FileSystem
from app.core.interfaces.vector_store import VectorStore
from app.core.models.code import SourceFile
from app.infrastructure.filesystem import LocalFileSystem


PYTHON_BUILTINS: Set[str] = {
    "print", "len", "range", "str", "int", "float", "bool", "list", "dict", "set", "tuple",
    "open", "close", "read", "write", "min", "max", "sum", "any", "all", "isinstance",
    "issubclass", "getattr", "setattr", "hasattr", "enumerate", "zip", "map", "filter",
    "sorted", "reversed", "super", "format", "id", "type", "round", "repr", "dir", "exec", "eval",
}

class DependencyGraph:
    """
    Repository-level dependency graph tracking file/component relationships,
    coupling metrics (Fan-In, Fan-Out, Instability), and transitive impact analysis.
    """

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self.adjacency: Dict[str, Set[str]] = {}
        self.reverse_adjacency: Dict[str, Set[str]] = {}
        self._edge_keys: Set[tuple] = set()

    def _norm(self, path: Union[str, Path]) -> str:
        return Path(path).as_posix().lower()

    def _resolve_key(self, file_path: Union[str, Path]) -> Optional[str]:
        """Resolve an absolute, relative, or filename path to its canonical node key."""
        norm = self._norm(file_path)
        norm_space = norm.replace("_", " ")
        if norm in self.nodes:
            return norm
        for key, info in self.nodes.items():
            rel = str(info.get("relative_path", "")).replace("\\", "/").lower()
            rel_space = rel.replace("_", " ")
            if (
                rel == norm
                or rel_space == norm_space
                or key.endswith(f"/{norm}")
                or rel.endswith(f"/{norm}")
                or rel_space.endswith(f"/{norm_space}")
            ):
                return key
        return None

    def add_node(
        self,
        file_path: Union[str, Path],
        relative_path: Optional[str] = None,
        language: Optional[Language] = None,
    ) -> str:
        key = self._norm(file_path)
        if key not in self.nodes:
            rel_str = str(relative_path or Path(file_path).name).replace("\\", "/")
            self.nodes[key] = {
                "file_path": Path(file_path).as_posix(),
                "relative_path": rel_str,
                "language": language.value if hasattr(language, "value") else str(language or "unknown"),
                "fan_in": 0,
                "fan_out": 0,
                "instability": 0.0,
            }
            self.adjacency.setdefault(key, set())
            self.reverse_adjacency.setdefault(key, set())
        return key

    def add_edge(
        self,
        source_path: Union[str, Path],
        target_path: Union[str, Path],
        relation: str = "imports",
        symbol: Optional[str] = None,
    ) -> None:
        src_key = self._norm(source_path)
        tgt_key = self._norm(target_path)
        if src_key == tgt_key:
            return
        if src_key not in self.nodes:
            self.add_node(source_path)
        if tgt_key not in self.nodes:
            self.add_node(target_path)

        edge_sig = (src_key, tgt_key, relation, symbol or "")
        if edge_sig not in self._edge_keys:
            self._edge_keys.add(edge_sig)
            self.edges.append({
                "source": self.nodes[src_key]["relative_path"],
                "target": self.nodes[tgt_key]["relative_path"],
                "source_path": self.nodes[src_key]["file_path"],
                "target_path": self.nodes[tgt_key]["file_path"],
                "relation": relation,
                "symbol": symbol,
            })
        self.adjacency[src_key].add(tgt_key)
        self.reverse_adjacency[tgt_key].add(src_key)

    def compute_metrics(self) -> None:
        """Calculate Fan-In (Ca), Fan-Out (Ce), and Instability (I = Ce / (Ca + Ce)) for all nodes."""
        for key, node in self.nodes.items():
            fan_out = len(self.adjacency.get(key, set()))
            fan_in = len(self.reverse_adjacency.get(key, set()))
            total = fan_in + fan_out
            instability = round(fan_out / total, 2) if total > 0 else 0.0
            node["fan_in"] = fan_in
            node["fan_out"] = fan_out
            node["instability"] = instability

    def get_dependencies(self, file_path: Union[str, Path]) -> List[str]:
        """Return direct outgoing dependencies (files imported/called by file_path)."""
        key = self._resolve_key(file_path)
        if not key:
            return []
        return sorted(self.nodes[t]["relative_path"] for t in self.adjacency.get(key, set()))

    def get_dependents(self, file_path: Union[str, Path]) -> List[str]:
        """Return direct incoming dependents (files that import/call file_path)."""
        key = self._resolve_key(file_path)
        if not key:
            return []
        return sorted(self.nodes[s]["relative_path"] for s in self.reverse_adjacency.get(key, set()))

    def get_impacted_files(self, file_path: Union[str, Path]) -> List[str]:
        """Compute transitive closure of all files impacted if file_path is modified."""
        start_key = self._resolve_key(file_path)
        if not start_key:
            return []

        visited: Set[str] = {start_key}
        queue = deque([start_key])
        impacted: List[str] = []

        while queue:
            curr = queue.popleft()
            for caller_key in self.reverse_adjacency.get(curr, set()):
                if caller_key not in visited:
                    visited.add(caller_key)
                    impacted.append(self.nodes[caller_key]["relative_path"])
                    queue.append(caller_key)

        return sorted(impacted)

    def get_coupling_metrics(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Return Fan-In, Fan-Out, and Instability metrics for a given file."""
        key = self._resolve_key(file_path)
        if not key:
            return {"fan_in": 0, "fan_out": 0, "instability": 0.0}
        node = self.nodes[key]
        return {
            "fan_in": node["fan_in"],
            "fan_out": node["fan_out"],
            "instability": node["instability"],
        }

    def get_hub_modules(self, min_fan_out: int = 5) -> List[Dict[str, Any]]:
        """Return modules with excessive efferent coupling (fan_out >= min_fan_out)."""
        return [
            dict(node) for node in self.nodes.values()
            if node["fan_out"] >= min_fan_out
        ]

    def get_orphaned_modules(self) -> List[Dict[str, Any]]:
        """Return modules with zero incoming dependencies (fan_in == 0)."""
        return [
            dict(node) for node in self.nodes.values()
            if node["fan_in"] == 0
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize entire dependency graph to a JSON-friendly dictionary."""
        self.compute_metrics()
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }


class CrossFileContextResolver:
    """Resolves cross-file dependencies, imports, and semantic context for multi-file security audits."""

    def __init__(
        self,
        filesystem: Optional[FileSystem] = None,
        vector_store: Optional[VectorStore] = None,
        max_context_chars_per_file: int = 2500,
        max_related_files: int = 4,
    ):
        self.filesystem: FileSystem = filesystem if filesystem is not None else LocalFileSystem()
        self.vector_store: Optional[VectorStore] = vector_store
        self.max_context_chars_per_file: int = max_context_chars_per_file
        self.max_related_files: int = max_related_files

    def extract_imports(self, source_code: str, language: Language) -> List[str]:
        """Extract imported module names and file references across languages."""
        if not source_code or not source_code.strip():
            return []

        imports: Set[str] = set()

        if language == Language.PYTHON:
            # e.g., import auth, from services.db import execute_query
            for match in re.finditer(r"(?:from\s+([a-zA-Z0-9_\.]+)\s+import|import\s+([a-zA-Z0-9_\.]+))", source_code):
                mod = match.group(1) or match.group(2)
                if mod:
                    imports.add(mod.split(".")[0])
                    imports.add(mod.replace(".", "/"))

        elif language == Language.JAVASCRIPT:
            # e.g., import foo from './foo', const db = require('../db')
            for match in re.finditer(r"""(?:import\s+.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))""", source_code):
                mod = match.group(1) or match.group(2)
                if mod:
                    imports.add(Path(mod).name)
                    imports.add(mod.lstrip("./").lstrip("../"))

        elif language in (Language.C, Language.CPP):
            # e.g., #include "auth_helper.h"
            for match in re.finditer(r'#include\s*["<]([^">]+)[">]', source_code):
                header = match.group(1)
                imports.add(Path(header).stem)
                imports.add(Path(header).name)

        elif language == Language.JAVA:
            # e.g., import com.app.services.DatabaseService;
            for match in re.finditer(r"import\s+(?:static\s+)?([a-zA-Z0-9_\.]+);", source_code):
                mod = match.group(1)
                parts = mod.split(".")
                if parts:
                    imports.add(parts[-1])  # Class name or static method
                    if len(parts) >= 2:
                        imports.add(parts[-2])  # Enclosing class

        return sorted(list(imports))

    def resolve_import_to_file(
        self,
        import_name: str,
        current_file: Union[str, Path],
        available_files: List[SourceFile],
    ) -> Optional[SourceFile]:
        """Find matching SourceFile in the project for a given imported identifier."""
        norm_raw = import_name.replace("\\", "/").strip().lower()
        clean_stem = Path(norm_raw).stem.lower()
        if norm_raw.endswith((".py", ".js", ".jsx", ".java", ".c", ".cpp", ".h", ".hpp")):
            norm_no_ext = norm_raw.rsplit(".", 1)[0]
        else:
            norm_no_ext = norm_raw
        norm_import = norm_no_ext.replace(".", "/")
        parts = [p for p in norm_import.split("/") if p]
        leaf_name = parts[-1] if parts else norm_import

        current_path_str = Path(current_file).as_posix().lower()

        for candidate in available_files:
            cand_path_str = Path(candidate.file_path).as_posix().lower()
            if cand_path_str == current_path_str:
                continue

            cand_stem = Path(candidate.file_path).stem.lower()
            cand_rel = str(candidate.relative_path or "").replace("\\", "/").lower()
            cand_rel_no_ext = cand_rel.rsplit(".", 1)[0]

            # Space-normalized variants for cross-platform/underscore module naming
            norm_import_space = norm_import.replace("_", " ")
            cand_rel_space = cand_rel_no_ext.replace("_", " ")
            leaf_space = leaf_name.replace("_", " ")
            cand_stem_space = cand_stem.replace("_", " ")

            if (
                norm_import == cand_rel_no_ext
                or norm_import_space == cand_rel_space
                or cand_rel == norm_raw
                or cand_rel_no_ext.endswith(f"/{norm_import}")
                or cand_rel_space.endswith(f"/{norm_import_space}")
                or leaf_name == cand_stem
                or leaf_space == cand_stem_space
                or clean_stem == cand_stem
            ):
                return candidate

        return None

    def get_imported_context(
        self,
        source_file: SourceFile,
        all_project_files: List[SourceFile],
    ) -> List[Dict[str, Any]]:
        """Identify imported project files and extract their code context."""
        extracted_imports = self.extract_imports(source_file.content, source_file.language)
        context_items: List[Dict[str, Any]] = []
        seen_paths: Set[str] = set()

        for imp in extracted_imports:
            if len(context_items) >= self.max_related_files:
                break

            matched_file = self.resolve_import_to_file(imp, source_file.file_path, all_project_files)
            if matched_file and matched_file.file_path not in seen_paths:
                seen_paths.add(matched_file.file_path)
                
                content = matched_file.content
                if len(content) > self.max_context_chars_per_file:
                    content = content[: self.max_context_chars_per_file] + "\n# [TRUNCATED CONTEXT]"

                rel_str = str(matched_file.relative_path or Path(matched_file.file_path).name).replace("\\", "/")
                context_items.append({
                    "file": rel_str,
                    "file_path": str(matched_file.file_path),
                    "snippet": content,
                    "type": "import_dependency",
                })

        return context_items

    def get_semantic_context(
        self,
        query: str,
        project_id: str,
        exclude_file_path: Optional[str] = None,
        top_k: int = 2,
    ) -> List[Dict[str, Any]]:
        """Query ChromaDB vector store for semantically related code across other files."""
        if not self.vector_store or not query or not query.strip():
            return []

        try:
            matches = self.vector_store.query_similar(
                query_text=query,
                project_id=project_id,
                top_k=top_k + 2,
            )
        except Exception:
            return []

        results: List[Dict[str, Any]] = []
        norm_exclude = Path(exclude_file_path).as_posix() if exclude_file_path else None

        for match in matches:
            metadata = match.get("metadata", {})
            file_path = metadata.get("file_path", "")
            
            if norm_exclude and Path(file_path).as_posix() == norm_exclude:
                continue

            content = match.get("content", "")
            if not content:
                continue

            if len(content) > self.max_context_chars_per_file:
                content = content[: self.max_context_chars_per_file] + "\n# [TRUNCATED CONTEXT]"

            rel_sem = str(metadata.get("relative_path") or Path(file_path).name).replace("\\", "/")
            results.append({
                "file": rel_sem,
                "file_path": str(file_path),
                "snippet": content,
                "type": "semantic_similarity",
            })

            if len(results) >= top_k:
                break

        return results

    def bundle_cross_file_context(
        self,
        source_file: SourceFile,
        all_project_files: List[SourceFile],
        project_id: Optional[str] = None,
        semantic_query: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Assemble a unified cross-file context bundle combining import graph and vector search."""
        bundled_context: List[Dict[str, Any]] = []
        seen_files: Set[str] = set()

        # 1. Structural import-driven context
        import_context = self.get_imported_context(source_file, all_project_files)
        for item in import_context:
            seen_files.add(item["file"])
            bundled_context.append(item)

        # 2. Semantic vector-driven context
        remaining_slots = self.max_related_files - len(bundled_context)
        if remaining_slots > 0 and self.vector_store and project_id and semantic_query:
            semantic_items = self.get_semantic_context(
                query=semantic_query,
                project_id=project_id,
                exclude_file_path=str(source_file.file_path),
                top_k=remaining_slots,
            )
            for item in semantic_items:
                if item["file"] not in seen_files:
                    seen_files.add(item["file"])
                    bundled_context.append(item)

        return bundled_context[: self.max_related_files]

    def resolve_enclosing_component(
        self,
        source_code: str,
        line_number: int,
        language: Language = Language.PYTHON,
    ) -> Optional[Dict[str, Any]]:
        """Resolve the innermost enclosing class, function, or method for a given line."""
        if not source_code or not source_code.strip():
            return None

        # 1. AST Parsing for Python
        if language == Language.PYTHON:
            try:
                tree = ast.parse(source_code)
                best_node = None
                best_span = float("inf")

                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        start = getattr(node, "lineno", 1)
                        end = getattr(node, "end_lineno", start)
                        if start <= line_number <= end:
                            span = end - start
                            if span < best_span:
                                best_span = span
                                best_node = node

                if best_node:
                    comp_type = "class" if isinstance(best_node, ast.ClassDef) else (
                        "async_function" if isinstance(best_node, ast.AsyncFunctionDef) else "function"
                    )
                    return {
                        "component_name": best_node.name,
                        "component_type": comp_type,
                        "start_line": getattr(best_node, "lineno", 1),
                        "end_line": getattr(best_node, "end_lineno", getattr(best_node, "lineno", 1)),
                    }
            except Exception:
                pass

        # 2. Line-by-line fallback regex scanning
        lines = source_code.splitlines()
        target_idx = min(len(lines), max(1, line_number)) - 1

        fn_pattern = re.compile(r"^\s*(?:async\s+)?def\s+([a-zA-Z0-9_]+)\s*\(")
        class_pattern = re.compile(r"^\s*class\s+([a-zA-Z0-9_]+)")
        js_fn_pattern = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+([a-zA-Z0-9_]+)|\b([a-zA-Z0-9_]+)\s*=\s*(?:async\s*)?\()")

        for i in range(target_idx, -1, -1):
            line = lines[i]
            m_fn = fn_pattern.search(line)
            if m_fn:
                return {
                    "component_name": m_fn.group(1),
                    "component_type": "function",
                    "start_line": i + 1,
                    "end_line": target_idx + 1,
                }
            m_js = js_fn_pattern.search(line)
            if m_js:
                name = m_js.group(1) or m_js.group(2)
                if name:
                    return {
                        "component_name": name,
                        "component_type": "function",
                        "start_line": i + 1,
                        "end_line": target_idx + 1,
                    }
            m_cls = class_pattern.search(line)
            if m_cls:
                return {
                    "component_name": m_cls.group(1),
                    "component_type": "class",
                    "start_line": i + 1,
                    "end_line": target_idx + 1,
                }

        return None

    def find_callers(
        self,
        target_symbol: str,
        target_file: Union[str, Path],
        all_project_files: List[SourceFile],
        max_callers: int = 5,
    ) -> List[Dict[str, Any]]:
        """Identify functions/components across other repository files that invoke target_symbol."""
        if not target_symbol or not target_symbol.strip() or not all_project_files:
            return []

        callers: List[Dict[str, Any]] = []
        target_file_str = Path(target_file).as_posix().lower() if target_file else ""
        pattern = re.compile(rf"\b{re.escape(target_symbol)}\s*\(")

        for sf in all_project_files:
            cand_path = Path(sf.file_path).as_posix().lower()
            if cand_path == target_file_str:
                continue

            content = sf.content or ""
            if not content and self.filesystem and self.filesystem.exists(sf.file_path):
                try:
                    content = self.filesystem.read_text(sf.file_path)
                except Exception:
                    continue

            if not content or target_symbol not in content:
                continue

            lines = content.splitlines()
            for line_no, line in enumerate(lines, start=1):
                if pattern.search(line):
                    enclosing = self.resolve_enclosing_component(content, line_no, sf.language)
                    caller_name = enclosing["component_name"] if enclosing else f"caller_line_{line_no}"
                    caller_type = enclosing["component_type"] if enclosing else "caller"

                    callers.append({
                        "component_name": caller_name,
                        "component_type": caller_type,
                        "file_path": Path(sf.file_path).as_posix(),
                        "line_number": line_no,
                        "relation": "caller",
                        "metadata": {
                            "invoked_symbol": target_symbol,
                            "caller_line": line.strip(),
                        },
                    })
                    if len(callers) >= max_callers:
                        return callers

        return callers

    def find_callees_in_snippet(
        self,
        code_snippet: str,
        all_project_files: List[SourceFile],
        current_file: Optional[Union[str, Path]] = None,
        max_callees: int = 5,
    ) -> List[Dict[str, Any]]:
        """Identify definitions across repository files for functions invoked in code_snippet."""
        if not code_snippet or not code_snippet.strip() or not all_project_files:
            return []

        invoked_symbols = set(re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(", code_snippet))
        invoked_symbols -= PYTHON_BUILTINS

        if not invoked_symbols:
            return []

        callees: List[Dict[str, Any]] = []
        current_path_str = Path(current_file).as_posix().lower() if current_file else ""

        for symbol in invoked_symbols:
            for sf in all_project_files:
                cand_path = Path(sf.file_path).as_posix().lower()
                if current_path_str and cand_path == current_path_str:
                    continue

                content = sf.content or ""
                if not content and self.filesystem and self.filesystem.exists(sf.file_path):
                    try:
                        content = self.filesystem.read_text(sf.file_path)
                    except Exception:
                        continue

                if not content or symbol not in content:
                    continue

                def_match = re.search(rf"^\s*(?:async\s+)?def\s+({re.escape(symbol)})\s*\(", content, re.MULTILINE)
                if not def_match:
                    def_match = re.search(rf"^\s*class\s+({re.escape(symbol)})\b", content, re.MULTILINE)

                if def_match:
                    line_no = content[: def_match.start()].count("\n") + 1
                    is_class = "class " in def_match.group(0)
                    callees.append({
                        "component_name": symbol,
                        "component_type": "class" if is_class else "callee",
                        "file_path": Path(sf.file_path).as_posix(),
                        "line_number": line_no,
                        "relation": "callee",
                        "metadata": {
                            "defined_in": sf.relative_path or Path(sf.file_path).name,
                        },
                    })
                    if len(callees) >= max_callees:
                        return callees
                    break

        return callees

    def link_finding_components(
        self,
        finding: Any,
        source_file: Optional[SourceFile] = None,
        all_project_files: Optional[List[SourceFile]] = None,
    ) -> Any:
        """Enrich an AuditFinding with enclosing components, callers, and callees across the repository."""
        if not finding:
            return finding

        all_files = all_project_files or []

        # 1. Resolve source_file if not explicitly passed
        sf = source_file
        if sf is None and finding.file_path and all_files:
            norm_f = Path(finding.file_path).as_posix().lower()
            for candidate in all_files:
                if Path(candidate.file_path).as_posix().lower() == norm_f:
                    sf = candidate
                    break

        # 2. Enclosing component (function or class)
        content = sf.content if sf else None
        if not content and finding.file_path and self.filesystem and self.filesystem.exists(finding.file_path):
            try:
                content = self.filesystem.read_text(finding.file_path)
            except Exception:
                pass

        enclosing_name: Optional[str] = None
        if content:
            lang = sf.language if sf else Language.PYTHON
            enclosing = self.resolve_enclosing_component(content, finding.start_line, lang)
            if enclosing:
                enclosing_name = enclosing["component_name"]
                finding.add_related_component(
                    component_name=enclosing["component_name"],
                    component_type=enclosing["component_type"],
                    file_path=finding.file_path,
                    line_number=enclosing["start_line"],
                    relation=f"enclosing_{enclosing['component_type']}",
                    metadata={"end_line": enclosing.get("end_line")},
                )

        # 3. Callers across the repository
        if enclosing_name and all_files:
            callers = self.find_callers(
                target_symbol=enclosing_name,
                target_file=finding.file_path,
                all_project_files=all_files,
            )
            for caller in callers:
                finding.add_related_component(
                    component_name=caller["component_name"],
                    component_type=caller["component_type"],
                    file_path=caller["file_path"],
                    line_number=caller["line_number"],
                    relation="caller",
                    metadata=caller.get("metadata"),
                )

        # 4. Callees invoked in finding's code snippet
        snippet_to_check = finding.code_snippet or finding.context_snippet or ""
        if snippet_to_check and all_files:
            callees = self.find_callees_in_snippet(
                code_snippet=snippet_to_check,
                all_project_files=all_files,
                current_file=finding.file_path,
            )
            for callee in callees:
                finding.add_related_component(
                    component_name=callee["component_name"],
                    component_type=callee["component_type"],
                    file_path=callee["file_path"],
                    line_number=callee["line_number"],
                    relation="callee",
                    metadata=callee.get("metadata"),
                )

        return finding

    def build_dependency_graph(
        self,
        all_project_files: List[SourceFile],
    ) -> DependencyGraph:
        """
        Builds a complete repository-level dependency graph across all project files,
        linking import relationships and calculating coupling metrics.
        """
        graph = DependencyGraph()
        if not all_project_files:
            return graph

        # Register all nodes first
        for sf in all_project_files:
            rel = str(sf.relative_path or Path(sf.file_path).name).replace("\\", "/")
            graph.add_node(sf.file_path, relative_path=rel, language=sf.language)

        # Build edges from imports
        for sf in all_project_files:
            content = sf.content or ""
            if not content and self.filesystem and self.filesystem.exists(sf.file_path):
                try:
                    content = self.filesystem.read_text(sf.file_path)
                except Exception:
                    content = ""

            if not content:
                continue

            imports = self.extract_imports(content, sf.language)
            for imp in imports:
                matched = self.resolve_import_to_file(imp, sf.file_path, all_project_files)
                if matched:
                    graph.add_edge(
                        source_path=sf.file_path,
                        target_path=matched.file_path,
                        relation="imports",
                        symbol=imp,
                    )

        graph.compute_metrics()
        return graph