from enum import Enum

class Language(str, Enum):
    """Supported programming languages for code understanding and parsing."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    C = "c"
    CPP = "cpp"
    UNKNOWN = "unknown"
    
class FileStatus(str, Enum):
    """Lifecycle status of a project file for change detection and indexing."""
    NEW = "new"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"
    DELETED = "deleted"
    UNSUPPORTED = "unsupported"
    ERROR = "error"

class Severity(str, Enum):
    """Severity levels for audit findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Confidence(str, Enum):
    """Confidence score of an audit finding."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class FindingCategory(str, Enum):
    """Broad categories for detected audit issues."""
    SECURITY = "security"
    CODE_QUALITY = "code_quality"
    ARCHITECTURE = "architecture"
    LOGIC = "logic"

class JobStatus(str, Enum):
    """Lifecycle states of an analysis audit job."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class PatchStatus(str, Enum):
    """Lifecycle states of a proposed code patch."""
    PROPOSED = "proposed"
    PENDING = "pending"
    VALIDATED = "validated"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    STALE = "stale"