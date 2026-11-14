"""
FastAPI Backend Integration Test Suite
Validates all endpoints across Project Management, Audit Pipelines,
Mode 1 (File-by-File) Patching, and Mode 2 (Batch Whole-Project) Patching.
"""

import hashlib
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes.project import project_service
from app.api.routes.audit import audit_service
from app.api.routes.patch import patch_service


@pytest.fixture
def client():
    """FastAPI test client fixture."""
    return TestClient(app)


@pytest.fixture
def temp_project(tmp_path):
    """
    Creates a temporary polyglot codebase with known vulnerabilities
    to test scanning, tree generation, and Mode 1/2 patching.
    """
    proj_dir = tmp_path / "sample_project"
    proj_dir.mkdir()

    src_dir = proj_dir / "src"
    src_dir.mkdir()

    # 1. Vulnerable Python file (SQL injection)
    py_file = src_dir / "db_handler.py"
    py_code = (
        "import sqlite3\n\n"
        "def query_user(user_id):\n"
        "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
        "    return query\n"
    )
    py_file.write_text(py_code, encoding="utf-8")

    # 2. JavaScript file
    js_file = src_dir / "app.js"
    js_code = (
        "function evaluateInput(str) {\n"
        "    eval(str);\n"
        "}\n"
    )
    js_file.write_text(js_code, encoding="utf-8")

    # 3. Ignored directory (.git)
    git_dir = proj_dir / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("[core]\n\trepositoryformatversion = 0\n", encoding="utf-8")

    return proj_dir


# =============================================================================
# 1. HEALTH & ROOT ENDPOINT TESTS
# =============================================================================

def test_api_health_endpoint(client):
    """Verify /api/health reports engine availability and system status."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["app_name"] == "CodeShield AI"
    assert data["version"] == "0.1.0"
    assert data["tree_sitter_available"] is True
    assert "timestamp" in data


def test_api_root_endpoint(client):
    """Verify / root returns service metadata."""
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["app"] == "CodeShield AI"
    assert data["status"] == "online"
    assert "/api/health" in data["health_url"]


# =============================================================================
# 2. PROJECT MANAGEMENT & SIDEBAR TREE TESTS
# =============================================================================

def test_project_registration_and_listing(client, temp_project):
    """Test registering a new project and listing all projects."""
    reg_payload = {
        "root_path": str(temp_project),
        "name": "Sample Test Project",
    }
    res = client.post("/api/projects/register", json=reg_payload)
    assert res.status_code == 201
    proj_data = res.json()
    project_id = proj_data["project_id"]
    assert proj_data["name"] == "Sample Test Project"
    assert proj_data["total_files"] >= 2
    assert proj_data["supported_files"] >= 2

    # Listing projects
    list_res = client.get("/api/projects")
    assert list_res.status_code == 200
    projects = list_res.json()
    assert any(p["project_id"] == project_id for p in projects)

    # Get single project
    get_res = client.get(f"/api/projects/{project_id}")
    assert get_res.status_code == 200
    assert get_res.json()["project_id"] == project_id


def test_project_registration_invalid_path(client):
    """Test registering a non-existent path raises 404."""
    reg_payload = {
        "root_path": "C:/NonExistentPath/ShouldFail/12345",
        "name": "Invalid Project",
    }
    res = client.post("/api/projects/register", json=reg_payload)
    assert res.status_code == 404


def test_project_sidebar_file_tree(client, temp_project):
    """Test fetching the recursive sidebar file tree structure."""
    reg_res = client.post("/api/projects/register", json={"root_path": str(temp_project)})
    project_id = reg_res.json()["project_id"]

    tree_res = client.get(f"/api/projects/{project_id}/tree")
    assert tree_res.status_code == 200
    tree_data = tree_res.json()
    assert tree_data["project_id"] == project_id

    root_node = tree_data["tree"]
    assert root_node["type"] == "directory"
    # Verify .git was ignored
    child_names = [c["name"] for c in root_node.get("children", [])]
    assert ".git" not in child_names
    assert "src" in child_names

    # Check src child files
    src_node = next(c for c in root_node["children"] if c["name"] == "src")
    src_child_names = [c["name"] for c in src_node.get("children", [])]
    assert "db_handler.py" in src_child_names
    assert "app.js" in src_child_names


def test_project_file_content_and_path_traversal_guard(client, temp_project):
    """Test reading file content and verifying path traversal security."""
    reg_res = client.post("/api/projects/register", json={"root_path": str(temp_project)})
    project_id = reg_res.json()["project_id"]

    # Valid read
    res = client.get(f"/api/projects/{project_id}/file-content", params={"path": "src/db_handler.py"})
    assert res.status_code == 200
    content_data = res.json()
    assert "query_user" in content_data["content"]
    assert content_data["language"] == "python"

    # Path traversal attack attempt
    attack_res = client.get(f"/api/projects/{project_id}/file-content", params={"path": "../../windows/system32/cmd.exe"})
    assert attack_res.status_code in [400, 403, 404]

    # Non-existent file in project
    missing_res = client.get(f"/api/projects/{project_id}/file-content", params={"path": "src/missing_file.py"})
    assert missing_res.status_code == 404


# =============================================================================
# 3. AUDIT PIPELINE & REPORT EXPORT TESTS
# =============================================================================

def test_audit_workflow_and_export(client, temp_project):
    """Test initiating an audit job, polling progress, and exporting SARIF & Markdown."""
    reg_res = client.post("/api/projects/register", json={"root_path": str(temp_project)})
    project_id = reg_res.json()["project_id"]

    # Start audit job (local rules only, fast and offline)
    start_res = client.post("/api/audit/start", json={"project_id": project_id, "enable_ai": False})
    assert start_res.status_code == 202
    job_id = start_res.json()["job_id"]

    # Poll until completed (local rule engine runs in background thread or very fast)
    max_wait = 10.0
    start_time = time.time()
    completed = False
    while time.time() - start_time < max_wait:
        poll_res = client.get(f"/api/audit/jobs/{job_id}")
        assert poll_res.status_code == 200
        job_data = poll_res.json()
        if job_data["status"] in ["completed", "failed"]:
            completed = True
            break
        time.sleep(0.1)

    assert completed is True
    assert job_data["status"] == "completed"

    # Fetch results
    results_res = client.get(f"/api/audit/jobs/{job_id}/results")
    assert results_res.status_code == 200
    results_data = results_res.json()
    assert "findings" in results_data

    # Download SARIF v2.1.0 report
    sarif_res = client.get(f"/api/audit/jobs/{job_id}/sarif")
    assert sarif_res.status_code == 200
    sarif_json = sarif_res.json()
    assert sarif_json.get("version") == "2.1.0"
    assert "$schema" in sarif_json
    assert len(sarif_json.get("runs", [])) > 0

    # Download Markdown report
    md_res = client.get(f"/api/audit/jobs/{job_id}/markdown")
    assert md_res.status_code == 200
    assert "# CodeShield AI Security & Quality Audit Report" in md_res.text


# =============================================================================
# 4. MODE 1: FILE-BY-FILE / SURGICAL PATCH WORKFLOW TESTS
# =============================================================================

def test_mode_1_file_patch_complete_lifecycle(client, temp_project):
    """
    US 18, US 21, US 30: Test the full Mode 1 file-by-file patch workflow:
    1. Click file in tree -> view content.
    2. Propose patch for this specific file.
    3. Validate pre-patch syntax in-memory.
    4. Attempt apply before approval -> must fail (403 Forbidden).
    5. Approve patch.
    6. Apply patch -> file on disk updated, SHA-256 backup created.
    7. Rollback patch -> file restored byte-for-byte to original.
    """
    py_file = temp_project / "src" / "db_handler.py"
    orig_content = py_file.read_text(encoding="utf-8")
    orig_sha256 = hashlib.sha256(orig_content.encode("utf-8")).hexdigest()

    remediated_code = (
        "import sqlite3\n\n"
        "def query_user(user_id):\n"
        "    query = 'SELECT * FROM users WHERE id = ?'\n"
        "    return query\n"
    )

    # 1. Propose Mode 1 patch
    prop_payload = {
        "file_path": str(py_file),
        "modified_code": remediated_code,
        "description": "Fix SQL injection via parameterized query",
    }
    prop_res = client.post("/api/patches/propose", json=prop_payload)
    assert prop_res.status_code == 201
    patch_data = prop_res.json()
    patch_id = patch_data["patch_id"]
    assert patch_data["status"] == "proposed"
    assert patch_data["total_changes"] > 0
    assert len(patch_data["hunks"]) > 0
    assert "---" in patch_data["git_diff"]
    assert "+++" in patch_data["git_diff"]

    # Invariant: File on disk must remain strictly untouched
    assert py_file.read_text(encoding="utf-8") == orig_content

    # 2. Syntax validation
    val_res = client.get(f"/api/patches/{patch_id}/validate")
    assert val_res.status_code == 200
    assert val_res.json()["is_valid"] is True

    # 3. Attempt apply before approval (Gate Check)
    unapproved_res = client.post(f"/api/patches/{patch_id}/apply")
    assert unapproved_res.status_code == 403
    assert "approval" in unapproved_res.json()["detail"].lower()

    # 4. Explicitly Approve Patch
    appr_res = client.post(f"/api/patches/{patch_id}/approve", json={"approved_by": "SecurityLead"})
    assert appr_res.status_code == 200
    assert appr_res.json()["status"] == "approved"
    assert appr_res.json()["approved_by"] == "SecurityLead"

    # 5. Apply Patch to Disk
    apply_res = client.post(f"/api/patches/{patch_id}/apply")
    assert apply_res.status_code == 200
    apply_data = apply_res.json()
    assert apply_data["success"] is True
    assert apply_data["status"] == "applied"
    assert apply_data["backup_path"] is not None

    # Verify disk content is updated
    applied_disk_code = py_file.read_text(encoding="utf-8")
    assert "SELECT * FROM users WHERE id = ?" in applied_disk_code

    # 6. Rollback Patch
    rb_res = client.post(f"/api/patches/{patch_id}/rollback")
    assert rb_res.status_code == 200
    rb_data = rb_res.json()
    assert rb_data["success"] is True
    assert rb_data["status"] == "rolled_back"

    # Invariant: File restored byte-for-byte to original SHA-256 hash
    restored_disk_code = py_file.read_text(encoding="utf-8")
    restored_sha256 = hashlib.sha256(restored_disk_code.encode("utf-8")).hexdigest()
    assert restored_sha256 == orig_sha256
    assert restored_disk_code == orig_content


def test_mode_1_syntax_error_detection_and_rejection(client, temp_project):
    """Test that a patch with invalid syntax is detected and can be rejected."""
    py_file = temp_project / "src" / "db_handler.py"
    bad_syntax_code = "def query_user(user_id):\n    print('broken syntax"  # unterminated string

    prop_res = client.post(
        "/api/patches/propose",
        json={"file_path": str(py_file), "modified_code": bad_syntax_code, "description": "Broken patch"},
    )
    assert prop_res.status_code == 201
    patch_id = prop_res.json()["patch_id"]

    # Validate syntax -> should fail
    val_res = client.get(f"/api/patches/{patch_id}/validate")
    assert val_res.status_code == 200
    assert val_res.json()["is_valid"] is False
    assert val_res.json()["error_message"] is not None

    # Reject patch
    rej_res = client.post(f"/api/patches/{patch_id}/reject", json={"reason": "Contains syntax error"})
    assert rej_res.status_code == 200
    assert rej_res.json()["status"] == "rejected"
    assert rej_res.json()["rejection_reason"] == "Contains syntax error"


# =============================================================================
# 5. MODE 2: WHOLE-PROJECT BATCH PATCH WORKFLOW TESTS
# =============================================================================

def test_mode_2_batch_propose_apply_and_rollback(client, temp_project):
    """
    Test Mode 2 batch patching:
    1. Propose patches across multiple files.
    2. Batch apply all patches with auto-approval.
    3. Verify all affected files modified on disk.
    4. Batch rollback all patches restoring all original files.
    """
    py_file = temp_project / "src" / "db_handler.py"
    js_file = temp_project / "src" / "app.js"

    py_orig = py_file.read_text(encoding="utf-8")
    js_orig = js_file.read_text(encoding="utf-8")

    # Propose patch 1 (Python)
    p1_res = client.post(
        "/api/patches/propose",
        json={"file_path": str(py_file), "modified_code": py_orig + "\n# Patched 1\n", "description": "Patch 1"},
    )
    p1_id = p1_res.json()["patch_id"]

    # Propose patch 2 (JS)
    p2_res = client.post(
        "/api/patches/propose",
        json={"file_path": str(js_file), "modified_code": js_orig + "\n// Patched 2\n", "description": "Patch 2"},
    )
    p2_id = p2_res.json()["patch_id"]

    # Batch Apply Mode 2
    batch_apply_payload = {
        "patch_ids": [p1_id, p2_id],
        "approved_by": "BatchAdmin",
    }
    apply_batch_res = client.post("/api/patches/batch/apply", json=batch_apply_payload)
    assert apply_batch_res.status_code == 200
    apply_batch_data = apply_batch_res.json()
    assert apply_batch_data["success_count"] == 2
    assert apply_batch_data["failed_count"] == 0

    # Verify both files modified on disk
    assert "# Patched 1" in py_file.read_text(encoding="utf-8")
    assert "// Patched 2" in js_file.read_text(encoding="utf-8")

    # Batch Rollback Mode 2
    batch_rb_payload = {"patch_ids": [p1_id, p2_id]}
    rb_batch_res = client.post("/api/patches/batch/rollback", json=batch_rb_payload)
    assert rb_batch_res.status_code == 200
    rb_batch_data = rb_batch_res.json()
    assert rb_batch_data["success_count"] == 2

    # Invariant: Both files restored to original content
    assert py_file.read_text(encoding="utf-8") == py_orig
    assert js_file.read_text(encoding="utf-8") == js_orig
