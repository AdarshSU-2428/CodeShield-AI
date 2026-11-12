import pytest

from app.analysis.quality_analyzer import ArchitecturalSmellDetector
from app.core.enums import FindingCategory, Language, Severity
from app.core.models.code import SourceFile
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem
from app.services.audit_service import AuditService


class InMemoryFileSystem(LocalFileSystem):
    def __init__(self, virtual_files=None):
        self._files = virtual_files or {}

    def exists(self, path) -> bool:
        from pathlib import Path
        norm = Path(path).as_posix()
        return norm in self._files or str(path) in self._files

    def read_text(self, path, encoding="utf-8") -> str:
        from pathlib import Path
        norm = Path(path).as_posix()
        if norm in self._files:
            return self._files[norm]
        if str(path) in self._files:
            return self._files[str(path)]
        raise FileNotFoundError(f"File {path} not found.")


def test_us25_detect_excessive_fan_out_octopus_module():
    """Verify detection of Hub/Octopus modules with excessive outgoing dependencies."""
    deps = [
        SourceFile(file_path=f"pkg/dep_{i}.py", relative_path=f"pkg/dep_{i}.py", content=f"x_{i} = {i}\n", language=Language.PYTHON)
        for i in range(6)
    ]
    octopus = SourceFile(
        file_path="pkg/orchestrator.py",
        relative_path="pkg/orchestrator.py",
        content="\n".join(f"import pkg.dep_{i}" for i in range(6)),
        language=Language.PYTHON,
    )

    detector = ArchitecturalSmellDetector(max_fan_out=5)
    findings = detector.detect_excessive_fan_out(deps + [octopus])

    assert len(findings) == 1
    assert findings[0].category == FindingCategory.ARCHITECTURE
    assert "Excessive Fan-Out" in findings[0].title
    assert findings[0].evidence["fan_out"] == 6
    assert len(findings[0].remediation_steps) >= 1


def test_us25_detect_high_coupling_bottleneck_hub():
    """Verify detection of fragile bottleneck hubs with both high Fan-In and high Fan-Out."""
    downstreams = [
        SourceFile(file_path=f"core/d{i}.py", relative_path=f"core/d{i}.py", content="pass\n", language=Language.PYTHON)
        for i in range(3)
    ]
    hub = SourceFile(
        file_path="core/hub.py",
        relative_path="core/hub.py",
        content="\n".join(f"import core.d{i}" for i in range(3)),
        language=Language.PYTHON,
    )
    upstreams = [
        SourceFile(file_path=f"api/u{i}.py", relative_path=f"api/u{i}.py", content="import core.hub\n", language=Language.PYTHON)
        for i in range(3)
    ]

    detector = ArchitecturalSmellDetector(hub_coupling_threshold=3)
    findings = detector.detect_high_coupling_hubs(downstreams + [hub] + upstreams)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Bottleneck Hub" in findings[0].title
    assert findings[0].evidence["fan_in"] == 3
    assert findings[0].evidence["fan_out"] == 3


def test_us25_detect_orphaned_dead_module():
    """Verify detection of completely isolated modules while ignoring entrypoints and tests."""
    f_core = SourceFile(file_path="app/core.py", relative_path="app/core.py", content="def run(): pass\n", language=Language.PYTHON)
    f_main = SourceFile(file_path="app/main.py", relative_path="app/main.py", content="from app.core import run\n", language=Language.PYTHON)
    f_orphan = SourceFile(file_path="app/legacy_unused.py", relative_path="app/legacy_unused.py", content="def old(): pass\n", language=Language.PYTHON)
    f_test = SourceFile(file_path="tests/test_core.py", relative_path="tests/test_core.py", content="pass\n", language=Language.PYTHON)

    detector = ArchitecturalSmellDetector()
    findings = detector.detect_orphaned_modules([f_core, f_main, f_orphan, f_test])

    assert len(findings) == 1
    assert "legacy_unused.py" in findings[0].title
    assert findings[0].severity == Severity.LOW


def test_us25_detect_circular_dependency_with_evidence():
    """Verify circular dependency smell includes structured evidence and remediation steps."""
    fa = SourceFile(file_path="mod/a.py", relative_path="mod/a.py", content="import mod.b\n", language=Language.PYTHON)
    fb = SourceFile(file_path="mod/b.py", relative_path="mod/b.py", content="import mod.a\n", language=Language.PYTHON)

    detector = ArchitecturalSmellDetector()
    findings = detector.detect_circular_dependencies([fa, fb])

    assert len(findings) >= 1
    assert findings[0].severity == Severity.HIGH
    assert "cycle_path" in findings[0].evidence
    assert len(findings[0].remediation_steps) >= 1


def test_us25_detect_monolithic_god_class_with_evidence():
    """Verify monolithic God Class smell detects oversized files with structured evidence."""
    big_code = "\n".join(f"def fn_{i}(): return {i}" for i in range(260))
    f_big = SourceFile(file_path="app/god_service.py", relative_path="app/god_service.py", content=big_code, language=Language.PYTHON)

    detector = ArchitecturalSmellDetector(max_god_class_lines=250)
    findings = detector.detect_god_classes([f_big])

    assert len(findings) == 1
    assert "God Class" in findings[0].title
    assert findings[0].evidence["line_count"] == 260


def test_us25_evaluate_architecture_combines_all_smells():
    """Verify evaluate_architecture runs all 5 architectural detectors cleanly."""
    files = [
        SourceFile(file_path=f"m/d{i}.py", relative_path=f"m/d{i}.py", content="pass\n", language=Language.PYTHON)
        for i in range(5)
    ]
    files.append(SourceFile(
        file_path="m/hub.py",
        relative_path="m/hub.py",
        content="\n".join(f"import m.d{i}" for i in range(5)),
        language=Language.PYTHON,
    ))
    files.append(SourceFile(
        file_path="m/orphan.py",
        relative_path="m/orphan.py",
        content="pass\n",
        language=Language.PYTHON,
    ))

    findings = ArchitecturalSmellDetector(max_fan_out=5).evaluate_architecture(files)
    titles = [f.title for f in findings]
    assert any("Excessive Fan-Out" in t for t in titles)
    assert any("Orphaned" in t for t in titles)


def test_us25_audit_service_end_to_end_architectural_smells():
    """Verify AuditService surfaces architectural smells in final AuditReport."""
    f1 = SourceFile(file_path="svc/a.py", relative_path="svc/a.py", content="import svc.b\n", language=Language.PYTHON)
    f2 = SourceFile(file_path="svc/b.py", relative_path="svc/b.py", content="import svc.a\n", language=Language.PYTHON)
    f3 = SourceFile(file_path="svc/unused.py", relative_path="svc/unused.py", content="x = 1\n", language=Language.PYTHON)

    fs = InMemoryFileSystem({
        f1.file_path.as_posix(): f1.content,
        f2.file_path.as_posix(): f2.content,
        f3.file_path.as_posix(): f3.content,
    })

    class MockScanner:
        def scan_project(self, project):
            return [f1, f2, f3]

    service = AuditService(scanner=MockScanner(), filesystem=fs)
    project = Project(name="US25ArchTest", root_path=".")
    job = service.create_job(project)
    report = service.run_audit(job.job_id, project)

    arch_findings = [f for f in report.findings if f.category == FindingCategory.ARCHITECTURE]
    assert len(arch_findings) >= 2
    assert any("Circular Dependency" in f.title for f in arch_findings)
    assert any("Orphaned" in f.title for f in arch_findings)