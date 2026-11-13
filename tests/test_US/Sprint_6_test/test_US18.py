from pathlib import Path
import pytest

from app.core.enums import Language, PatchStatus
from app.core.models.audit import AuditFinding
from app.core.models.patch import Patch, PatchDiff
from app.infrastructure.filesystem import LocalFileSystem
from app.patches.generator import DiffGenerator, PatchGenerator
from app.services.patch_service import PatchService


class VirtualFS(LocalFileSystem):
    """In-memory filesystem for testing patch diff generation without disk mutation."""

    def __init__(self, files=None):
        self._files = files or {}

    def exists(self, path) -> bool:
        norm = Path(path).as_posix().lower()
        return any(norm.endswith(k.lower()) or k.lower().endswith(norm) for k in self._files)

    def read_text(self, path, encoding="utf-8") -> str:
        norm = Path(path).as_posix().lower()
        for k, v in self._files.items():
            if norm.endswith(k.lower()) or k.lower().endswith(norm):
                return v
        raise FileNotFoundError(str(path))


def test_us18_git_diff_standard_headers_and_hunks():
    """Verify DiffGenerator produces standard Git-style diff with diff --git and hunk headers."""
    orig = (
        "def authenticate(user, password):\n"
        "    if user == 'admin':\n"
        "        return True\n"
        "    return False\n"
    )
    mod = (
        "def authenticate(user, password):\n"
        "    if verify_hash(user, password):\n"
        "        return True\n"
        "    return False\n"
    )

    diff_gen = DiffGenerator(context_lines=2)
    diff = diff_gen.generate_diff(orig, mod, file_name="auth/service.py")

    assert isinstance(diff, PatchDiff)
    assert diff.git_diff.startswith("diff --git a/auth/service.py b/auth/service.py\n")
    assert "--- a/auth/service.py\n" in diff.git_diff
    assert "+++ b/auth/service.py\n" in diff.git_diff
    assert "@@ -" in diff.git_diff
    assert "-    if user == 'admin':\n" in diff.git_diff
    assert "+    if verify_hash(user, password):\n" in diff.git_diff


def test_us18_git_diff_change_statistics():
    """Verify calculation of additions, deletions, total changes, and diffstat summary."""
    orig = "line1\nline2\nline3\nline4\n"
    mod = "line1\nmodified_2\nmodified_3\nline4\nnew_line5\n"

    diff_gen = DiffGenerator()
    diff = diff_gen.generate_diff(orig, mod, file_name="core/utils.py")

    assert diff.deletions_count == 2   # line2, line3 deleted
    assert diff.additions_count == 3   # modified_2, modified_3, new_line5 added
    assert diff.total_changes == 5
    assert "core/utils.py" in diff.file_stat
    assert "1 file changed, 3 insertions(+), 2 deletions(-)" == diff.diff_stat


def test_us18_patch_model_git_diff_properties_and_serialization():
    """Verify Patch domain model exposes git_diff property and serializes diff details cleanly."""
    orig = "a = 1\nb = 2\n"
    mod = "a = 100\nb = 2\n"

    diff = DiffGenerator().generate_diff(orig, mod, file_name="config.py")
    patch = Patch(
        file_path="config.py",
        original_code=orig,
        modified_code=mod,
        diff=diff,
        description="Fix config value",
    )

    assert patch.git_diff == diff.raw_diff
    assert patch.to_git_diff() == diff.raw_diff
    assert "1 file changed" in patch.diff_stat

    dumped = patch.to_dict()
    assert dumped["git_diff"] == diff.raw_diff
    assert dumped["diff_stat"] == diff.diff_stat
    assert dumped["diff"]["additions_count"] == 1
    assert dumped["diff"]["deletions_count"] == 1


def test_us18_patch_service_get_git_diff_and_stats():
    """Verify PatchService exposes get_git_diff and get_diff_stats for reviewer inspection."""
    file_path = "services/payment.py"
    orig_code = (
        "def process_payment(amount):\n"
        "    charge_card(amount)\n"
    )
    mod_code = (
        "def process_payment(amount):\n"
        "    validate_amount(amount)\n"
        "    charge_card(amount)\n"
    )

    fs = VirtualFS({file_path: orig_code})
    svc = PatchService(filesystem=fs)

    patch = svc.propose_patch(
        file_path=file_path,
        modified_code=mod_code,
        description="Add amount validation before payment",
    )

    git_diff = svc.get_git_diff(patch.patch_id)
    assert "diff --git a/payment.py b/payment.py" in git_diff
    assert "+    validate_amount(amount)" in git_diff

    stats = svc.get_diff_stats(patch.patch_id)
    assert stats["patch_id"] == patch.patch_id
    assert stats["additions_count"] == 1
    assert stats["deletions_count"] == 0
    assert stats["total_changes"] == 1
    assert "1 insertion(+)" in stats["diff_stat"]


def test_us18_structured_hunk_inspection_for_code_review():
    """Verify code reviewers can navigate structured hunks and inspect line coordinates."""
    orig = "row1\nrow2\nrow3\nrow4\nrow5\n"
    mod = "row1\nROW2_MODIFIED\nrow3\nrow4\nrow5\n"

    fs = VirtualFS({"data.txt": orig})
    svc = PatchService(filesystem=fs)
    patch = svc.propose_patch(file_path="data.txt", modified_code=mod)

    hunks = svc.get_patch_hunks(patch.patch_id)
    assert len(hunks) == 1
    hunk = hunks[0]

    assert hunk["header"].startswith("@@ -")
    assert hunk["old_start"] >= 1
    assert hunk["new_start"] >= 1

    # Check line breakdown
    types = [line["type"] for line in hunk["lines"]]
    assert "deletion" in types
    assert "addition" in types
    assert "context" in types

    del_line = next(l for l in hunk["lines"] if l["type"] == "deletion")
    assert del_line["content"] == "row2"
    assert del_line["old_line_number"] == 2
    assert del_line["new_line_number"] is None

    add_line = next(l for l in hunk["lines"] if l["type"] == "addition")
    assert add_line["content"] == "ROW2_MODIFIED"
    assert add_line["old_line_number"] is None
    assert add_line["new_line_number"] == 2


def test_us18_remediation_patch_generator_produces_git_diff():
    """Verify PatchGenerator.generate_remediation produces Git-style diff from AuditFinding."""
    original_code = (
        "import os\n"
        "def execute_cmd(user_input):\n"
        "    os.system(user_input)\n"
    )
    finding = AuditFinding(
        title="Command Injection",
        description="os.system call with unescaped input",
        file_path="cli.py",
        start_line=3,
        end_line=3,
        remediation_code="subprocess.run(['echo', user_input], check=True)",
    )

    patch_gen = PatchGenerator()
    modified, diff = patch_gen.generate_remediation(
        original_code=original_code,
        finding=finding,
        file_name="cli.py",
    )

    assert "diff --git a/cli.py b/cli.py" in diff.raw_diff
    assert "-    os.system(user_input)" in diff.raw_diff
    assert "+    subprocess.run(['echo', user_input], check=True)" in diff.raw_diff
    assert diff.additions_count == 1
    assert diff.deletions_count == 1


def test_us18_identical_code_produces_empty_git_diff():
    """Verify that identical original and modified code produces clean empty diff with zero changes."""
    code = "def unchanged():\n    return 42\n"
    diff = DiffGenerator().generate_diff(code, code, file_name="same.py")

    assert diff.raw_diff == ""
    assert diff.git_diff == ""
    assert diff.additions_count == 0
    assert diff.deletions_count == 0
    assert diff.total_changes == 0
    assert len(diff.hunks) == 0