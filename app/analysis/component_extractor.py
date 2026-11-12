import re
from typing import Any, Dict, List, Optional
from tree_sitter import Node, Tree
from app.core.enums import Language
from app.core.models.code import CodeComponent, SourceFile


class ComponentExtractor:
    """Traverses Tree-sitter syntax trees and extracts normalized CodeComponents with unified metadata."""

    # Node types that represent classes/structs per language
    CLASS_NODE_TYPES = {
        Language.PYTHON: {"class_definition"},
        Language.JAVASCRIPT: {"class_declaration", "class"},
        Language.JAVA: {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration"},
        Language.C: {"struct_specifier", "union_specifier"},
        Language.CPP: {"class_specifier", "struct_specifier", "namespace_definition"},
    }

    # Node types that represent functions/methods per language
    FUNCTION_NODE_TYPES = {
        Language.PYTHON: {"function_definition"},
        Language.JAVASCRIPT: {"function_declaration", "method_definition", "arrow_function"},
        Language.JAVA: {"method_declaration", "constructor_declaration"},
        Language.C: {"function_definition"},
        Language.CPP: {"function_definition"},
    }

    def extract_components(
        self,
        tree: Tree,
        source_code: str,
        source_file: Optional[SourceFile] = None,
        language: Optional[Language] = None,
    ) -> List[CodeComponent]:
        """
        Extract all classes, functions, and methods from a parsed Tree-sitter Tree.
        Returns a list of normalized CodeComponent objects with consistent metadata.
        """
        if not tree or not tree.root_node:
            return []
        
        effective_lang = language if language else (source_file.language if source_file else Language.UNKNOWN)
        file_path = source_file.file_path if source_file else "unknown"
        components: List[CodeComponent] = []
        code_bytes = source_code.encode("utf-8") if isinstance(source_code, str) else source_code
        
        # Recursively traverse the AST
        self._traverse_node(
            node=tree.root_node,
            code_bytes=code_bytes,
            language=effective_lang,
            file_path=file_path,
            components=components,
            current_parent=None,
        )
        return components

    def _traverse_node(
        self,
        node: Node,
        code_bytes: bytes,
        language: Language,
        file_path: Any,
        components: List[CodeComponent],
        current_parent: Optional[str] = None,
    ) -> None:
        """Walks AST nodes, extracting components and maintaining parent hierarchy."""
        node_type = node.type
        class_types = self.CLASS_NODE_TYPES.get(language, set())
        func_types = self.FUNCTION_NODE_TYPES.get(language, set())
        is_class = node_type in class_types
        is_func = node_type in func_types
        new_parent = current_parent

        if is_class:
            name = self._get_node_name(node, code_bytes, language, is_class=True)
            if name:
                comp = self._create_component(
                    node=node,
                    code_bytes=code_bytes,
                    name=name,
                    component_type="class",
                    language=language,
                    file_path=file_path,
                    parent_name=current_parent,
                )
                components.append(comp)
                new_parent = name
        elif is_func:
            name = self._get_node_name(node, code_bytes, language, is_class=False)
            if name:
                comp_type = "method" if current_parent else "function"
                comp = self._create_component(
                    node=node,
                    code_bytes=code_bytes,
                    name=name,
                    component_type=comp_type,
                    language=language,
                    file_path=file_path,
                    parent_name=current_parent,
                )
                components.append(comp)

        # Recurse down children to find nested functions, methods, or inner classes
        for child in node.children:
            self._traverse_node(
                node=child,
                code_bytes=code_bytes,
                language=language,
                file_path=file_path,
                components=components,
                current_parent=new_parent,
            )

    def _get_node_name(
        self,
        node: Node,
        code_bytes: bytes,
        language: Language,
        is_class: bool = False,
    ) -> Optional[str]:
        """Extract the identifier name of a class, function, or method node."""
        name_node = node.child_by_field_name("name")
        if name_node:
            return self._node_text(name_node, code_bytes)

        declarator = node.child_by_field_name("declarator")
        if declarator:
            return self._extract_c_declarator_name(declarator, code_bytes)

        for child in node.children:
            if child.type in {"identifier", "type_identifier", "property_identifier", "field_identifier"}:
                return self._node_text(child, code_bytes)

        # For anonymous/arrow functions assigned to variables, object properties, or assignments
        if node.parent:
            if node.parent.type == "variable_declarator":
                id_node = node.parent.child_by_field_name("name")
                if id_node:
                    return self._node_text(id_node, code_bytes)
            elif node.parent.type == "pair":
                key_node = node.parent.child_by_field_name("key")
                if key_node:
                    return self._node_text(key_node, code_bytes)
            elif node.parent.type == "assignment_expression":
                left_node = node.parent.child_by_field_name("left")
                if left_node:
                    return self._node_text(left_node, code_bytes)

        return None
    
    def _extract_c_declarator_name(self, declarator: Node, code_bytes: bytes) -> Optional[str]:
        """Handles nested declarators in C / C++ (e.g. pointer functions, references)."""
        curr = declarator
        while curr:
            name_node = curr.child_by_field_name("declarator")
            if not name_node:
                for child in curr.children:
                    if child.type in {"identifier", "field_identifier"}:
                        return self._node_text(child, code_bytes)
                if curr.type in {"identifier", "field_identifier"}:
                    return self._node_text(curr, code_bytes)
                break
            curr = name_node
        return None

    def _split_parameters(self, raw_params: str) -> List[str]:
        """Split parameter list safely, respecting nested angle brackets and parentheses."""
        inner = raw_params.strip()
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1].strip()
        if not inner:
            return []

        params: List[str] = []
        current: List[str] = []
        depth = 0
        for ch in inner:
            if ch in "(<[{":
                depth += 1
                current.append(ch)
            elif ch in ")>]}":
                depth = max(0, depth - 1)
                current.append(ch)
            elif ch == "," and depth == 0:
                token = "".join(current).strip()
                if token:
                    params.append(token)
                current = []
            else:
                current.append(ch)

        last_token = "".join(current).strip()
        if last_token:
            params.append(last_token)
        return params

    def _extract_metadata(
        self,
        node: Node,
        code_bytes: bytes,
        name: str,
        component_type: str,
        language: Language,
        source_content: str,
    ) -> Dict[str, Any]:
        """Extract standardized metadata (signature, params, visibility, async, docstring, decorators)."""
        start_line = node.start_point.row + 1
        end_line = node.end_point.row + 1
        lines = source_content.splitlines()
        first_line = lines[0].strip() if lines else ""

        # 1. Signature extraction using AST 'body' boundary (handles type annotations like 'a: int' cleanly)
        body_node = node.child_by_field_name("body")
        if body_node and body_node.start_byte > node.start_byte:
            header_text = code_bytes[node.start_byte:body_node.start_byte].decode("utf-8", errors="replace").strip()
            if header_text.endswith((":", "{")):
                header_text = header_text[:-1].strip()
            signature = " ".join(header_text.split())
        elif language == Language.PYTHON:
            signature = first_line.rstrip(":")
        else:
            sig_part = source_content.split("{", 1)[0].strip()
            signature = " ".join(sig_part.split()) if sig_part else first_line

        # 2. Parameters extraction via AST node or signature regex
        parameters: List[str] = []
        if component_type in ("function", "method"):
            param_node = node.child_by_field_name("parameters")
            if not param_node:
                declarator = node.child_by_field_name("declarator")
                if declarator:
                    param_node = declarator.child_by_field_name("parameters")
            if not param_node:
                for child in node.children:
                    if child.type in {"parameters", "formal_parameters", "parameter_list"}:
                        param_node = child
                        break

            if param_node:
                parameters = self._split_parameters(self._node_text(param_node, code_bytes))
            else:
                paren_match = re.search(r"\(([^)]*)\)", signature)
                if paren_match:
                    parameters = self._split_parameters(paren_match.group(1))

        # 3. Visibility extraction
        visibility = "public"
        if language == Language.PYTHON:
            if name.startswith("__") and not name.endswith("__"):
                visibility = "private"
            elif name.startswith("_"):
                visibility = "protected"
        elif language == Language.JAVASCRIPT:
            if name.startswith("#"):
                visibility = "private"
        elif language in (Language.JAVA, Language.CPP):
            lower_sig = signature.lower()
            if re.search(r"\bprivate\b", lower_sig):
                visibility = "private"
            elif re.search(r"\bprotected\b", lower_sig):
                visibility = "protected"

        # 4. Async detection
        is_async = bool(re.match(r"^(?:public|private|protected|export|static|\s)*\basync\b", signature))

        # 5. Docstring extraction (Python triple-quoted docstrings)
        docstring: Optional[str] = None
        if language == Language.PYTHON:
            doc_match = re.search(r':\s*\n\s*(?:"""([\s\S]*?)"""|\'\'\'([\s\S]*?)\'\'\')', source_content)
            if doc_match:
                docstring = (doc_match.group(1) or doc_match.group(2) or "").strip()

        # 6. Decorators / Annotations
        decorators: List[str] = []
        if node.parent and node.parent.type == "decorated_definition":
            for sib in node.parent.children:
                if sib.type == "decorator":
                    decorators.append(self._node_text(sib, code_bytes).strip())
        elif language == Language.JAVA:
            for child in node.children:
                if child.type == "modifiers":
                    mod_text = self._node_text(child, code_bytes)
                    decorators.extend(re.findall(r"@[A-Za-z0-9_]+(?:\([^)]*\))?", mod_text))

        return {
            "language": language.value if hasattr(language, "value") else str(language),
            "component_type": component_type,
            "line_count": max(1, end_line - start_line + 1),
            "signature": signature,
            "parameters": parameters,
            "parameter_count": len(parameters),
            "visibility": visibility,
            "is_async": is_async,
            "docstring": docstring,
            "decorators": decorators,
        }

    def _create_component(
        self,
        node: Node,
        code_bytes: bytes,
        name: str,
        component_type: str,
        language: Language,
        file_path: Any,
        parent_name: Optional[str],
    ) -> CodeComponent:
        """Constructs a clean CodeComponent domain object with 1-indexed lines and normalized metadata."""
        start_line = node.start_point.row + 1
        end_line = node.end_point.row + 1
        source_content = self._node_text(node, code_bytes)
        metadata = self._extract_metadata(
            node=node,
            code_bytes=code_bytes,
            name=name,
            component_type=component_type,
            language=language,
            source_content=source_content,
        )
        return CodeComponent(
            name=name,
            component_type=component_type,
            start_line=start_line,
            end_line=end_line,
            source_content=source_content,
            file_path=file_path,
            parent_name=parent_name,
            language=language,
            metadata=metadata,
        )
    
    def _node_text(self, node: Node, code_bytes: bytes) -> str:
        """Safely extract UTF-8 text from byte slice represented by a Tree-sitter node."""
        return code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")