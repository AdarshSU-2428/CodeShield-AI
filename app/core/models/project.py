from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union
import uuid
class Project:
    """Represents a code repository/project workspace selected by the user."""
    def __init__(
        self,
        root_path: Union[str, Path],
        name: Optional[str] = None,
        project_id: Optional[str] = None,
        created_at: Optional[datetime] = None,
        total_files: int = 0,
        supported_files: int = 0,
        is_indexed: bool = False,
        last_indexed_at: Optional[datetime] = None,
    ):

        if isinstance(root_path, str):
            self.root_path = Path(root_path).resolve()
        else:
            self.root_path = root_path.resolve()

        self.name = name if name else self.root_path.name
        self.project_id = project_id if project_id else str(uuid.uuid4())
        self.created_at = created_at if created_at else datetime.now(timezone.utc)
        self.total_files = total_files
        self.supported_files = supported_files
        self.is_indexed = is_indexed
        self.last_indexed_at = last_indexed_at
        
    def __repr__(self) -> str:
        return f"<Project name='{self.name}' path='{self.root_path}' files={self.total_files}>"