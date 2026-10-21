from pathlib import Path
import pytest
from app.analysis.scanner import RepositoryScanner
from app.core.enums import FileStatus, Language
from app.core.models.project import Project
def test_real_world_project_scanning():
    """Test scanning the actual CodeShield AI project directory."""
    scanner = RepositoryScanner()
    current = Path(__file__).resolve().parent
    while current.parent != current:
        if (current / "app").exists() and (current / "config").exists():
            break
        current = current.parent
    project = Project(root_path=current)
    discovered = scanner.scan_project(project)
    # 1. Must find files and populate counts
    assert project.total_files > 0, "Should have found project files"
    assert project.supported_files > 0, "Should have found supported source files"
    assert len(discovered) > 0
    # 2. Check that main.py is discovered as a supported Python file
    main_files = [f for f in discovered if f.file_path.name == "main.py"]
    assert len(main_files) == 1
    main_file = main_files[0]
    assert main_file.language == Language.PYTHON
    assert main_file.is_supported is True
    assert main_file.status == FileStatus.NEW
    assert main_file.content_hash is not None
    assert len(main_file.content_hash) == 64
    # 3. Verify relative path is clean (not an absolute path)
    assert not main_file.relative_path.is_absolute()
    print(f"\n[PASS] Real-world scan: {project.total_files} total, {project.supported_files} supported files.")
def test_scanner_ignores_noise_directories_and_patterns():
    """Verify that ignored directory and file pattern rules work accurately."""
    scanner = RepositoryScanner()
    # 1. Ignored directory names
    assert scanner.should_ignore_dir(".git") is True
    assert scanner.should_ignore_dir("node_modules") is True
    assert scanner.should_ignore_dir("venv") is True
    assert scanner.should_ignore_dir("__pycache__") is True
    assert scanner.should_ignore_dir(".vscode") is True
    assert scanner.should_ignore_dir("src") is False
    assert scanner.should_ignore_dir("app") is False
    # 2. Ignored file patterns
    assert scanner.should_ignore_file("bundle.min.js") is True
    assert scanner.should_ignore_file("script.min.js") is True
    assert scanner.should_ignore_file("package-lock.json") is True
    assert scanner.should_ignore_file("app.pyc") is True
    assert scanner.should_ignore_file("auth.py") is False
    assert scanner.should_ignore_file("index.js") is False
    print("\n[PASS] Ignore rules correctly filter unwanted dirs and files.")
def test_scanner_multi_language_detection(tmp_path):
    """Test scanner on a synthetic multi-language project folder."""
    # Create sample files for each supported language
    (tmp_path / "test.py").write_text("print('python')", encoding="utf-8")
    (tmp_path / "test.js").write_text("console.log('js')", encoding="utf-8")
    (tmp_path / "Test.java").write_text("class Test {}", encoding="utf-8")
    (tmp_path / "test.c").write_text("int main() { return 0; }", encoding="utf-8")
    (tmp_path / "test.cpp").write_text("int main() { return 0; }", encoding="utf-8")
    
    # Unsupported / ignored files
    (tmp_path / "notes.txt").write_text("unsupported text", encoding="utf-8")
    (tmp_path / "bundle.min.js").write_text("minified", encoding="utf-8")
    # Ignored directory
    ignored_dir = tmp_path / "node_modules"
    ignored_dir.mkdir()
    (ignored_dir / "dep.js").write_text("dependency", encoding="utf-8")
    project = Project(root_path=tmp_path)
    scanner = RepositoryScanner()
    discovered = scanner.scan_project(project)
    # Validate counts: exactly 5 supported languages, txt is unsupported, min.js & node_modules ignored
    assert project.supported_files == 5
    supported_langs = {f.language for f in discovered if f.is_supported}
    expected_langs = {Language.PYTHON, Language.JAVASCRIPT, Language.JAVA, Language.C, Language.CPP}
    assert supported_langs == expected_langs
    # Ensure unsupported text file was tracked but not supported
    txt_files = [f for f in discovered if f.extension == ".txt"]
    assert len(txt_files) == 1
    assert txt_files[0].is_supported is False
    assert txt_files[0].status == FileStatus.UNSUPPORTED
    # Ensure node_modules was completely skipped
    dep_files = [f for f in discovered if "node_modules" in str(f.file_path)]
    assert len(dep_files) == 0
    print("\n[PASS] Multi-language directory scanner verified with 5 supported languages.")