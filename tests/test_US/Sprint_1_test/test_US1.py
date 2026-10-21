
from pathlib import Path
import pytest
from app.core.models.project import Project
from app.infrastructure.filesystem import LocalFileSystem
def test_real_world_project_directory_selection():
    """Test selecting the actual CodeShield AI project directory on disk."""
    fs = LocalFileSystem()
    
    # 1. Use the actual real-world project path with spaces
    real_path = Path(r"C:\Users\ADARSH S SAHOO\Desktop\Engineering folder\CodeShield AI")
    
    # Validate with filesystem adapter
    assert fs.exists(real_path) is True, "Real-world project directory must exist"
    assert fs.is_directory(real_path) is True, "Selected path must be recognized as a directory"
    # 2. Instantiate Project model with the real path
    project = Project(root_path=real_path)
    
    # Verify auto-detection of project name from path
    assert project.name == "CodeShield AI", f"Expected 'CodeShield AI', got '{project.name}'"
    assert project.root_path == real_path.resolve()
    assert project.project_id is not None
    assert project.is_indexed is False
    print(f"\n[PASS] Successfully loaded real-world project: {project}")
def test_invalid_and_non_directory_selection():
    """Test that non-existent paths and files are properly rejected."""
    fs = LocalFileSystem()
    
    # 1. Non-existent path
    fake_path = Path(r"C:\NonExistentFolder_12345_XYZ")
    assert fs.exists(fake_path) is False
    assert fs.is_directory(fake_path) is False
    
    # 2. Pointing to a file instead of a folder
    file_path = Path(__file__).resolve()
    assert fs.exists(file_path) is True
    assert fs.is_directory(file_path) is False, "A file must NOT be accepted as a project directory"
    print("\n[PASS] Successfully rejected invalid/file paths")
def test_real_filesystem_read_and_hashing():
    """Test reading and hashing a real project file."""
    fs = LocalFileSystem()
    enums_file = Path(r"C:\Users\ADARSH S SAHOO\Desktop\Engineering folder\CodeShield AI\app\core\enums.py")
    
    # Read text content
    content = fs.read_text(enums_file)
    assert "class Language" in content
    assert "PYTHON" in content
    
    # Compute SHA-256 hash
    file_hash = fs.compute_hash(enums_file)
    assert len(file_hash) == 64
    print(f"\n[PASS] Real-world read and SHA-256 hash verified: {file_hash[:16]}...")
