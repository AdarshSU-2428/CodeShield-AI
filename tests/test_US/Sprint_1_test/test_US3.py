import pytest
from app.analysis.parser import parser_registry
from app.core.enums import Language
from app.core.models.code import SourceFile

def test_us3_python_parsing():
    """Verify parsing and syntax validation of Python source code."""
    python_code = """
import os
class DatabaseConnector:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
    def query(self, sql: str):
        return f"Executing {sql} on {self.host}"
"""
    tree = parser_registry.parse_code(Language.PYTHON, python_code)
    assert tree is not None
    assert tree.root_node.type == "module"
    assert parser_registry.is_syntax_valid(Language.PYTHON, python_code) is True
    # Check syntax error detection
    broken_python = "class Broken { def bad_syntax(): pass }"
    assert parser_registry.is_syntax_valid(Language.PYTHON, broken_python) is False
    print("\n[PASS] US3 Python parsing verified.")

def test_us3_javascript_parsing():
    """Verify parsing and syntax validation of JavaScript source code."""
    js_code = """
const express = require('express');
const app = express();
function authenticate(user, token) {
    if (!token) return false;
    return user.isActive && token.length > 10;
}
const handler = async (req, res) => {
    res.json({ status: "ok" });
};
"""
    tree = parser_registry.parse_code(Language.JAVASCRIPT, js_code)
    assert tree is not None
    assert tree.root_node.type == "program"
    assert parser_registry.is_syntax_valid(Language.JAVASCRIPT, js_code) is True
    broken_js = "const fn = (a, b) => { return a + ; }"
    assert parser_registry.is_syntax_valid(Language.JAVASCRIPT, broken_js) is False
    print("\n[PASS] US3 JavaScript parsing verified.")

def test_us3_java_parsing():
    """Verify parsing and syntax validation of Java source code."""
    java_code = """
package com.codeshield.auth;
public class SecurityManager {
    private String secretKey;
    public SecurityManager(String key) {
        this.secretKey = key;
    }
    public boolean validateToken(String token) {
        return token != null && token.equals(this.secretKey);
    }
}
"""
    tree = parser_registry.parse_code(Language.JAVA, java_code)
    assert tree is not None
    assert tree.root_node.type == "program"
    assert parser_registry.is_syntax_valid(Language.JAVA, java_code) is True
    broken_java = "public class Broken { void method( { } }"
    assert parser_registry.is_syntax_valid(Language.JAVA, broken_java) is False
    print("\n[PASS] US3 Java parsing verified.")

def test_us3_c_parsing():
    """Verify parsing and syntax validation of C source code."""
    c_code = """
#include <stdio.h>
#include <stdlib.h>
typedef struct {
    int id;
    char username[50];
} UserRecord;
int verify_user(const UserRecord* user) {
    if (user == NULL) {
        return -1;
    }
    return user->id > 0 ? 1 : 0;
}
"""
    tree = parser_registry.parse_code(Language.C, c_code)
    assert tree is not None
    assert tree.root_node.type == "translation_unit"
    assert parser_registry.is_syntax_valid(Language.C, c_code) is True
    broken_c = "int main(void) { int x = ; return 0; }"
    assert parser_registry.is_syntax_valid(Language.C, broken_c) is False
    print("\n[PASS] US3 C parsing verified.")

def test_us3_cpp_parsing():
    """Verify parsing and syntax validation of C++ source code."""
    cpp_code = """
#include <iostream>
#include <memory>
#include <string>
namespace Security {
    class BufferValidator {
    public:
        explicit BufferValidator(size_t max_len) : max_len_(max_len) {}
        bool is_safe(const std::string& input) const {
            return input.length() <= max_len_;
        }
    private:
        size_t max_len_;
    };
}
"""
    tree = parser_registry.parse_code(Language.CPP, cpp_code)
    assert tree is not None
    assert tree.root_node.type == "translation_unit"
    assert parser_registry.is_syntax_valid(Language.CPP, cpp_code) is True
    broken_cpp = "namespace Broken { class Incomplete { int x = ; }; }"
    assert parser_registry.is_syntax_valid(Language.CPP, broken_cpp) is False
    print("\n[PASS] US3 C++ parsing verified.")
    
def test_us3_source_file_routing():
    """Verify that SourceFile objects are routed to the correct parser automatically."""
    src_py = SourceFile(file_path="server.py", relative_path="server.py", language=Language.PYTHON)
    src_js = SourceFile(file_path="app.js", relative_path="app.js", language=Language.JAVASCRIPT)
    src_java = SourceFile(file_path="User.java", relative_path="User.java", language=Language.JAVA)
    src_c = SourceFile(file_path="memory.c", relative_path="memory.c", language=Language.C)
    src_cpp = SourceFile(file_path="engine.cpp", relative_path="engine.cpp", language=Language.CPP)
    assert parser_registry.parse_file(src_py, "x = 1\n").root_node.type == "module"
    assert parser_registry.parse_file(src_js, "let x = 1;\n").root_node.type == "program"
    assert parser_registry.parse_file(src_java, "class X {}\n").root_node.type == "program"
    assert parser_registry.parse_file(src_c, "int x = 1;\n").root_node.type == "translation_unit"
    assert parser_registry.parse_file(src_cpp, "int x = 1;\n").root_node.type == "translation_unit"
    print("\n[PASS] US3 SourceFile routing verified across all 5 languages.")
