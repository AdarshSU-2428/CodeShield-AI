from typing import List, Optional
from tree_sitter import Node, Tree
from app.core.enums import Language
from app.core.models.code import CodeComponent, SourceFile

class ComponentExtractor:
    """Traverses Tree-sitter syntax trees and extracts normalized CodeComponents."""
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
        Returns a list of normalized CodeComponent objects.
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
        file_path: any,
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
        # 1. Direct 'name' field query (most reliable in Tree-sitter)
        name_node = node.child_by_field_name("name")
        if name_node:
            return self._node_text(name_node, code_bytes)
        # 2. Declarator pattern in C / C++
        declarator = node.child_by_field_name("declarator")
        if declarator:
            return self._extract_c_declarator_name(declarator, code_bytes)
        # 3. Fallback: Search direct children for identifier node
        for child in node.children:
            if child.type in {"identifier", "type_identifier", "property_identifier", "field_identifier"}:
                return self._node_text(child, code_bytes)
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
    
    def _create_component(
        self,
        node: Node,
        code_bytes: bytes,
        name: str,
        component_type: str,
        language: Language,
        file_path: any,
        parent_name: Optional[str],
    ) -> CodeComponent:
        """Constructs a clean CodeComponent domain object with 1-indexed lines."""
        # Tree-sitter line numbers are 0-indexed, we convert to 1-indexed for human readability
        start_line = node.start_point.row + 1
        end_line = node.end_point.row + 1
        source_content = self._node_text(node, code_bytes)
        return CodeComponent(
            name=name,
            component_type=component_type,
            start_line=start_line,
            end_line=end_line,
            source_content=source_content,
            file_path=file_path,
            parent_name=parent_name,
            language=language,
        )
    
    def _node_text(self, node: Node, code_bytes: bytes) -> str:
        """Safely extract UTF-8 text from byte slice represented by a Tree-sitter node."""
        return code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
