from pathlib import Path
import pytest
from app.ai.sanitizer import CodeSanitizer, sanitizer
@pytest.fixture
def clean_sanitizer():
    return CodeSanitizer()
def test_us13_redact_api_keys(clean_sanitizer):
    """Verify redacting Groq, OpenAI, GitHub, and AWS keys."""
    code = """
GROQ_API_KEY = "gsk_12345678901234567890123456789012"
OPENAI_KEY = "sk-12345678901234567890123456789012"
GITHUB_TOKEN = "ghp_123456789012345678901234567890123456"
AWS_KEY = "AKIA1234567890123456"
"""
    result = clean_sanitizer.sanitize(code)
    assert result.redacted_count >= 4
    assert "[REDACTED_API_KEY]" in result.sanitized_text
    assert "gsk_" not in result.sanitized_text
    assert "ghp_" not in result.sanitized_text
    assert "AKIA" not in result.sanitized_text
    print("\n[PASS] US13 Cloud API keys redacted successfully.")
def test_us13_redact_private_keys(clean_sanitizer):
    """Verify redacting multiline RSA/EC private keys."""
    pem_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+abcdefghijklmnopqrstuvwxyz1234567890
-----END RSA PRIVATE KEY-----
"""
    result = clean_sanitizer.sanitize(pem_key)
    assert result.redacted_count == 1
    assert "[REDACTED_PRIVATE_KEY]" in result.sanitized_text
    assert "MIIEow" not in result.sanitized_text
    print("\n[PASS] US13 Private keys redacted successfully.")
def test_us13_redact_database_passwords(clean_sanitizer):
    """Verify redacting passwords inside DB connection strings."""
    code = 'DATABASE_URL = "postgres://admin:SuperSecretPass123@db.prod.internal:5432/core_db"'
    result = clean_sanitizer.sanitize(code)
    assert "[REDACTED_PASSWORD]" in result.sanitized_text
    assert "SuperSecretPass123" not in result.sanitized_text
    assert "postgres://admin:[REDACTED_PASSWORD]@db.prod.internal" in result.sanitized_text
    print("\n[PASS] US13 Database password redacted successfully.")
def test_us13_redact_local_user_paths(clean_sanitizer):
    """Verify masking local Windows and Unix user directory paths."""
    code = r'backup_path = "C:\Users\ADARSH S SAHOO\Projects\secrets.json"'
    result = clean_sanitizer.sanitize(code)
    assert "[REDACTED_USER_PATH]" in result.sanitized_text
    assert "ADARSH S SAHOO" not in result.sanitized_text
    print("\n[PASS] US13 Local user profile path masked successfully.")
def test_us13_disk_safety_guarantee(tmp_path, clean_sanitizer):
    """Crucial test: Verify that sanitization does NOT modify original disk files."""
    test_file = tmp_path / "sensitive_service.py"
    original_content = 'API_TOKEN = "gsk_12345678901234567890123456789012"\n'
    test_file.write_text(original_content, encoding="utf-8")
    # Read from disk and sanitize in-memory
    content_to_send = test_file.read_text(encoding="utf-8")
    result = clean_sanitizer.sanitize(content_to_send)
    # 1. In-memory version MUST be sanitized
    assert "gsk_" not in result.sanitized_text
    assert "[REDACTED_API_KEY]" in result.sanitized_text
    # 2. File on disk MUST be completely unchanged!
    disk_content = test_file.read_text(encoding="utf-8")
    assert disk_content == original_content, "Sanitization must NEVER alter original files on disk!"
    print("\n[PASS] US13 Disk safety verified: original source file untouched.")
