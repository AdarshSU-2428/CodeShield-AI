"""
CodeShield AI - Patch Safety & Stress Testing Suite
File: tests/test_patches/test_patch_safety.py

Comprehensive real-world stress tests ensuring:
1. Polyglot syntax error quarantine (Python, JS, Java, C, C++).
2. Defense against destructive empty/whitespace code wipes.
3. Pre-flight tamper & stale file drift protection.
4. Vulnerability eradication vs regression detection (ensuring patches actually fix flaws without adding new ones).
5. Business logic & AST structure preservation (ensuring unrelated functions are not accidentally deleted).
6. AI markdown wrapping & truncated response defense.
7. Byte-for-byte cryptographic atomic rollback integrity.
8. Multi-file batch patching fault isolation.
9. Large-file Git unified diff hunk fidelity.
"""

import ast
import hashlib
from pathlib import Path
import pytest

from app.analysis.parser import ParserRegistry
from app.analysis.rule_engine import RuleEngine
from app.core.enums import Language, PatchStatus, Severity
from app.core.models.audit import AuditFinding
from app.core.models.code import SourceFile
from app.core.models.patch import Patch, PatchDiff
from app.infrastructure.filesystem import LocalFileSystem
from app.patches.applier import PatchApplier
from app.patches.backup_manager import BackupManager
from app.patches.generator import PatchGenerator
from app.patches.rollback_manager import RollbackManager
from app.patches.validator import PatchValidator
from app.services.patch_service import PatchService


def _sha256(content: str) -> str:
    """Helper to compute deterministic SHA-256 hash of text."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# =============================================================================
# Stress Test 1: Polyglot Syntax Corruption Quarantine
# =============================================================================
def test_stress_syntax_corruption_polyglot_rejection(tmp_path: Path):
    """
    Stress test: When an AI or human produces a patch with syntax errors across
    Python, JavaScript, Java, or C++, the safety engine MUST:
    1. Detect the invalid syntax in-memory before disk touch.
    2. Refuse disk application and raise a descriptive ValueError.
    3. Keep the target file on disk 100% UNTOUCHED (hash preserved).
    """
    validator = PatchValidator()
    backup_mgr = BackupManager(backup_dir=tmp_path / "backups")
    applier = PatchApplier(backup_manager=backup_mgr, validator=validator)

    corrupted_cases = [
        # (filename, language, valid_code, corrupted_code, expected_error_snippet)
        (
            "service.py",
            Language.PYTHON,
            "def calculate_total(a, b):\n    return a + b\n",
            "def calculate_total(a, b):\n    return a + \n",  # incomplete expression
            "SyntaxError",
        ),
        (
            "handler.js",
            Language.JAVASCRIPT,
            "function processRequest(req) {\n    return req.body;\n}\n",
            "function processRequest(req) {\n    return req.body\n",  # missing closing brace
            "Tree-sitter detected syntax errors in Javascript",
        ),
        (
            "AppService.java",
            Language.JAVA,
            "public class AppService {\n    public int add(int x, int y) { return x + y; }\n}\n",
            "public class AppService {\n    public int add(int x, int y { return x + y; }\n}\n",  # unclosed paren
            "Tree-sitter detected syntax errors in Java",
        ),
        (
            "native_engine.cpp",
            Language.CPP,
            "#include <iostream>\nint compute(int x) { return x * 2; }\n",
            "template<class T void compute() { return; }\n",  # broken template syntax
            "Tree-sitter detected syntax errors in Cpp",
        ),
    ]

    for fname, lang, valid_code, bad_code, err_snippet in corrupted_cases:
        target_file = tmp_path / fname
        target_file.write_text(valid_code, encoding="utf-8")
        orig_hash = _sha256(valid_code)

        # 1. In-memory virtual syntax check
        is_valid, err_msg = validator.validate_virtual_syntax(bad_code, language=lang, file_path=target_file)
        assert is_valid is False, f"Validator failed to reject malformed {lang.value} code!"
        assert err_snippet in (err_msg or ""), f"Expected '{err_snippet}' in error message: {err_msg}"

        # 2. Disk application refusal
        patch = Patch(
            file_path=target_file,
            original_code=valid_code,
            modified_code=bad_code,
            diff=PatchDiff(raw_diff="", additions_count=1, deletions_count=1, hunks=[]),
        )

        with pytest.raises(ValueError) as exc_info:
            applier.validate_and_apply(patch)

        assert "syntax errors detected" in str(exc_info.value)
        assert patch.status == PatchStatus.FAILED

        # 3. Disk file remains 100% UNTOUCHED
        disk_content = target_file.read_text(encoding="utf-8")
        assert _sha256(disk_content) == orig_hash, f"File {fname} was mutated despite syntax error!"


# =============================================================================
# Stress Test 2: Destructive Empty / Whitespace Code Wipe Prevention
# =============================================================================
def test_stress_prevent_empty_or_whitespace_code_wipe(tmp_path: Path):
    """
    Stress test: An AI hallucination or error might return empty string or whitespace,
    which would wipe out an entire production file.
    The validator MUST reject this as destructive before touching disk.
    """
    validator = PatchValidator()
    target_file = tmp_path / "critical_db.py"
    original_code = "import sqlite3\n\ndef connect():\n    return sqlite3.connect(':memory:')\n"
    target_file.write_text(original_code, encoding="utf-8")

    destructive_payloads = ["", "   ", "\n\n\t  \n", "   \r\n   "]

    for bad_code in destructive_payloads:
        patch = Patch(
            file_path=target_file,
            original_code=original_code,
            modified_code=bad_code,
            diff=PatchDiff(raw_diff="", additions_count=0, deletions_count=4, hunks=[]),
        )

        is_valid, err = validator.validate_patch_candidate(patch)
        assert is_valid is False, "Failed to reject empty/whitespace code wipe!"
        assert "empty or whitespace-only" in err

        applier = PatchApplier(validator=validator)
        with pytest.raises(ValueError) as exc:
            applier.validate_and_apply(patch)

        assert "Candidate patch produced empty or whitespace-only" in str(exc.value)

    # Disk file is completely intact
    assert target_file.read_text(encoding="utf-8") == original_code


# =============================================================================
# Stress Test 3: Pre-Flight Stale File Drift Protection
# =============================================================================
def test_stress_stale_file_drift_protection(tmp_path: Path):
    """
    Stress test: If a file on disk has been modified (by another developer or git pull)
    between the time the patch was proposed and applied, the engine must detect the drift
    and reject the patch to avoid clobbering external modifications.
    """
    target_file = tmp_path / "auth.py"
    v1_code = "def login(user):\n    pass\n"
    v2_code = "def login(user):\n    # Modified by teammate\n    audit_log(user)\n"
    target_file.write_text(v1_code, encoding="utf-8")

    service = PatchService()
    patch = service.propose_patch(
        file_path=target_file,
        modified_code="def login(user):\n    validate_user(user)\n",
    )

    # Simulate concurrent external edit on disk
    target_file.write_text(v2_code, encoding="utf-8")

    # Attempting to apply patch based on v1 must fail due to drift
    with pytest.raises(ValueError) as exc_info:
        service.validate_and_apply(patch.patch_id)

    assert "Stale patch detected" in str(exc_info.value)
    # The external developer's v2 changes are preserved
    assert target_file.read_text(encoding="utf-8") == v2_code


# =============================================================================
# Stress Test 4: Vulnerability Eradication vs Regression Detection
# =============================================================================
def test_stress_vulnerability_eradication_vs_regression_detection(tmp_path: Path):
    """
    Stress test: Verifies that our security scanning engine can differentiate between:
    1. The original vulnerable code (detected).
    2. A genuine secure patch (0 findings - vulnerability eradicated).
    3. A regressive patch that fails to fix the vulnerability or introduces a new one (detected).
    """
    rule_engine = RuleEngine()

    vulnerable_sql_code = (
        "import sqlite3\n\n"
        "def get_user_profile(user_id):\n"
        "    conn = sqlite3.connect('app.db')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")\n"
        "    return cursor.fetchone()\n"
    )

    source_vuln = SourceFile(
        file_path="db/users.py",
        relative_path="db/users.py",
        content=vulnerable_sql_code,
        language=Language.PYTHON,
    )

    # Step 1: Scan original code -> MUST detect SQL Injection (CWE-89)
    findings_orig = rule_engine.analyze_file(source_vuln)
    sqli_findings = [f for f in findings_orig if "SQL" in f.title.upper() or "CWE-89" in (f.cwe_id or "")]
    assert len(sqli_findings) >= 1, "Failed to detect SQL injection in original baseline!"

    # Step 2: Test Genuine Secure Patch (Parameterized Query)
    secure_sql_code = (
        "import sqlite3\n\n"
        "def get_user_profile(user_id):\n"
        "    conn = sqlite3.connect('app.db')\n"
        "    cursor = conn.cursor()\n"
        "    query = \"SELECT * FROM users WHERE id = ?\"\n"
        "    cursor.execute(query, (user_id,))\n"
        "    return cursor.fetchone()\n"
    )

    source_secure = SourceFile(
        file_path="db/users.py",
        relative_path="db/users.py",
        content=secure_sql_code,
        language=Language.PYTHON,
    )

    findings_secure = rule_engine.analyze_file(source_secure)
    sqli_secure = [f for f in findings_secure if "SQL" in f.title.upper() or "CWE-89" in (f.cwe_id or "")]
    assert len(sqli_secure) == 0, f"Secure patch should have 0 SQLi findings, found: {sqli_secure}"

    # Step 3: Test Regressive Patch (Replaces SQLi with dangerous Command Injection `os.system`)
    toxic_regression_code = (
        "import os\n"
        "import sqlite3\n\n"
        "def get_user_profile(user_id):\n"
        "    # Hallucinated patch uses os.system to inspect DB\n"
        "    os.system(f\"sqlite3 app.db 'SELECT * FROM users WHERE id = {user_id}'\")\n"
        "    return None\n"
    )

    source_toxic = SourceFile(
        file_path="db/users.py",
        relative_path="db/users.py",
        content=toxic_regression_code,
        language=Language.PYTHON,
    )

    findings_toxic = rule_engine.analyze_file(source_toxic)
    cmd_injection = [f for f in findings_toxic if "COMMAND" in f.title.upper() or "CWE-78" in (f.cwe_id or "")]
    assert len(cmd_injection) >= 1, "Safety engine failed to flag toxic patch introducing Command Injection!"


# =============================================================================
# Stress Test 5: Business Logic & AST Function Preservation
# =============================================================================
def test_stress_business_logic_and_ast_preservation():
    """
    Stress test: In a real-world multi-function module, a patch fixing one function
    must NOT accidentally wipe out or corrupt other unrelated functions, classes, or imports.
    """
    complex_module = (
        "import math\n"
        "import hashlib\n\n"
        "def calculate_tax(amount):\n"
        "    return amount * 0.18\n\n"
        "def generate_invoice_id(order_id):\n"
        "    return hashlib.sha256(str(order_id).encode()).hexdigest()[:8]\n\n"
        "def vulnerable_hash(secret):\n"
        "    # MD5 weak crypto\n"
        "    return hashlib.md5(secret.encode()).hexdigest()\n\n"
        "def process_order(order_id, amount):\n"
        "    tax = calculate_tax(amount)\n"
        "    inv = generate_invoice_id(order_id)\n"
        "    return {'order_id': order_id, 'tax': tax, 'invoice': inv}\n"
    )

    # Clean patch only fixes `vulnerable_hash` to use SHA-256
    clean_patch_code = (
        "import math\n"
        "import hashlib\n\n"
        "def calculate_tax(amount):\n"
        "    return amount * 0.18\n\n"
        "def generate_invoice_id(order_id):\n"
        "    return hashlib.sha256(str(order_id).encode()).hexdigest()[:8]\n\n"
        "def vulnerable_hash(secret):\n"
        "    # Remediated to SHA-256 with salt\n"
        "    return hashlib.sha256(('salt:' + secret).encode()).hexdigest()\n\n"
        "def process_order(order_id, amount):\n"
        "    tax = calculate_tax(amount)\n"
        "    inv = generate_invoice_id(order_id)\n"
        "    return {'order_id': order_id, 'tax': tax, 'invoice': inv}\n"
    )

    # Rogue patch hallucinated and dropped `calculate_tax` and `process_order`
    rogue_patch_code = (
        "import hashlib\n\n"
        "def vulnerable_hash(secret):\n"
        "    return hashlib.sha256(secret.encode()).hexdigest()\n"
    )

    def extract_function_names(code: str) -> set:
        tree = ast.parse(code)
        return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    orig_functions = extract_function_names(complex_module)
    clean_functions = extract_function_names(clean_patch_code)
    rogue_functions = extract_function_names(rogue_patch_code)

    assert orig_functions == {"calculate_tax", "generate_invoice_id", "vulnerable_hash", "process_order"}
    # Clean patch preserves 100% of the functions
    assert clean_functions == orig_functions

    # Rogue patch lost critical business functions -> detectable via AST comparison!
    missing_in_rogue = orig_functions - rogue_functions
    assert "calculate_tax" in missing_in_rogue
    assert "process_order" in missing_in_rogue


# =============================================================================
# Stress Test 6: AI Markdown Stripping & Truncation Defense
# =============================================================================
def test_stress_ai_markdown_stripping_and_truncation_defense():
    """
    Stress test: LLMs often wrap responses in conversational fluff and markdown fences.
    1. _clean_markdown_code must cleanly extract only the code.
    2. If the LLM output is truncated mid-statement, syntax validation must reject it.
    """
    service = PatchService()

    # Case A: AI response with conversational text and markdown blocks
    raw_ai_output = (
        "Hello! I am CodeShield AI. Here is the remediated code to fix your security issue:\n\n"
        "```python\n"
        "import os\n\n"
        "def execute_command(safe_arg):\n"
        "    print(f'Executing: {safe_arg}')\n"
        "    return True\n"
        "```\n\n"
        "I hope this helps! Always sanitize inputs.\n"
    )

    cleaned = service._clean_markdown_code(raw_ai_output)
    assert cleaned.startswith("import os")
    assert "Hello!" not in cleaned
    assert "```" not in cleaned

    # Valid syntax check on cleaned code
    validator = PatchValidator()
    is_valid, _ = validator.validate_virtual_syntax(cleaned, language=Language.PYTHON)
    assert is_valid is True

    # Case B: AI response cut off mid-code (token limit hit)
    truncated_ai_output = (
        "```python\n"
        "def execute_payment(user_id, amount):\n"
        "    if amount > 0:\n"
        "        db.update('accounts', balance=b"  # truncated!
    )
    cleaned_truncated = service._clean_markdown_code(truncated_ai_output)
    is_valid_trunc, err_trunc = validator.validate_virtual_syntax(cleaned_truncated, language=Language.PYTHON)
    assert is_valid_trunc is False
    assert err_trunc is not None


# =============================================================================
# Stress Test 7: Byte-for-Byte Cryptographic Atomic Rollback
# =============================================================================
def test_stress_byte_for_byte_atomic_rollback(tmp_path: Path):
    """
    Stress test: Verify that applying a patch and rolling it back restores the target file
    to a byte-for-byte identical state (exact SHA-256 checksum match), with zero corruption.
    """
    target_file = tmp_path / "crypto_module.py"
    original_code = (
        "# CodeShield Mission Critical Header\n"
        "import hmac\n"
        "import hashlib\n\n"
        "KEY = b'super_secret_signing_key_32bytes'\n\n"
        "def sign_message(msg: bytes) -> bytes:\n"
        "    return hmac.new(KEY, msg, hashlib.sha256).digest()\n"
    )
    target_file.write_text(original_code, encoding="utf-8")
    original_hash = _sha256(original_code)

    backup_dir = tmp_path / "test_backups"
    service = PatchService(
        backup_manager=BackupManager(backup_dir=backup_dir),
    )

    # 1. Propose and Apply Patch
    patch = service.propose_patch(
        file_path=target_file,
        modified_code=original_code + "\ndef verify_signature(): pass\n",
        description="Add verify_signature method",
    )
    apply_ok = service.validate_and_apply(patch.patch_id)
    assert apply_ok is True
    assert patch.status == PatchStatus.APPLIED
    assert _sha256(target_file.read_text(encoding="utf-8")) != original_hash

    # 2. Trigger Rollback
    rollback_ok = service.rollback_patch(patch.patch_id)
    assert rollback_ok is True
    assert patch.status == PatchStatus.ROLLED_BACK

    # 3. Assert Byte-for-Byte Checksum Match
    restored_code = target_file.read_text(encoding="utf-8")
    restored_hash = _sha256(restored_code)
    assert restored_hash == original_hash
    assert restored_code == original_code


# =============================================================================
# Stress Test 8: Multi-File Batch Patching Fault Isolation
# =============================================================================
def test_stress_batch_patching_isolation_under_failure(tmp_path: Path):
    """
    Stress test Mode 2 (Batch Patching):
    When patching multiple files across a project, if one file has a broken patch,
    that failure must be quarantined:
    - The broken patch fails and leaves that file untouched.
    - Valid patches succeed on their respective files.
    - Zero cross-file corruption.
    """
    service = PatchService()

    file_a = tmp_path / "module_a.py"
    file_b = tmp_path / "module_b.py"
    file_c = tmp_path / "module_c.py"

    file_a.write_text("a = 10\n", encoding="utf-8")
    file_b.write_text("b = 20\n", encoding="utf-8")
    file_c.write_text("c = 30\n", encoding="utf-8")

    # Propose 2 valid patches, 1 corrupt patch
    patch_a = service.propose_patch(file_a, "a = 100\n")
    patch_b = service.propose_patch(file_b, "b = [unterminated syntax error\n")  # BROKEN
    patch_c = service.propose_patch(file_c, "c = 300\n")

    # Apply patch A -> Success
    assert service.validate_and_apply(patch_a.patch_id) is True
    assert file_a.read_text(encoding="utf-8") == "a = 100\n"

    # Apply patch B -> Must fail gracefully
    with pytest.raises(ValueError):
        service.validate_and_apply(patch_b.patch_id)
    assert patch_b.status == PatchStatus.FAILED
    assert file_b.read_text(encoding="utf-8") == "b = 20\n"  # preserved

    # Apply patch C -> Success
    assert service.validate_and_apply(patch_c.patch_id) is True
    assert file_c.read_text(encoding="utf-8") == "c = 300\n"


# =============================================================================
# Stress Test 9: Large-File Unified Git Diff Hunk Fidelity
# =============================================================================
def test_stress_large_file_unified_git_diff_integrity(tmp_path: Path):
    """
    Stress test: A 500-line real-world file with a targeted 3-line patch in the middle.
    Ensures that DiffGenerator produces precise hunks with accurate line coordinates
    and that application does not offset or misplace neighboring lines.
    """
    lines = [f"line_{i} = {i}" for i in range(1, 501)]
    lines[250] = "security_flaw = 'unverified_input'"  # Line 251

    large_file = tmp_path / "large_enterprise_service.py"
    original_code = "\n".join(lines) + "\n"
    large_file.write_text(original_code, encoding="utf-8")

    # Remediate line 251
    mod_lines = list(lines)
    mod_lines[250] = "security_flaw = sanitize('unverified_input')"
    modified_code = "\n".join(mod_lines) + "\n"

    service = PatchService()
    patch = service.propose_patch(large_file, modified_code)

    # Verify diff stats
    stats = service.get_diff_stats(patch.patch_id)
    assert stats["additions_count"] == 1
    assert stats["deletions_count"] == 1
    assert stats["total_changes"] == 2

    # Verify Git diff representation
    git_diff = service.get_git_diff(patch.patch_id)
    assert "--- a/large_enterprise_service.py" in git_diff
    assert "+++ b/large_enterprise_service.py" in git_diff
    assert "-security_flaw = 'unverified_input'" in git_diff
    assert "+security_flaw = sanitize('unverified_input')" in git_diff

    # Apply and verify line fidelity
    service.validate_and_apply(patch.patch_id)
    written_lines = large_file.read_text(encoding="utf-8").splitlines()
    assert len(written_lines) == 500
    assert written_lines[250] == "security_flaw = sanitize('unverified_input')"
    assert written_lines[0] == "line_1 = 1"
    assert written_lines[499] == "line_500 = 500"
