import logging
from pathlib import Path
import sys
from typing import Optional


DEFAULT_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_logger(
    name: str = "codeshield",
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
) -> logging.Logger:
    """
    Create or retrieve a configured CodeShield AI logger.
    Ensures no duplicate handlers are attached across repeated imports.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        formatter = logging.Formatter(fmt=DEFAULT_LOG_FORMAT, datefmt=DEFAULT_DATE_FORMAT)

        # Console stream handler (UTF-8 safe)
        console_handler = logging.StreamHandler(stream=sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # Optional rotating/file handler for persistent audit diagnostics
        if log_file is not None:
            try:
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_path, encoding="utf-8")
                file_handler.setLevel(level)
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except Exception:
                # Never crash application if log directory is read-only
                pass

    logger.propagate = False
    return logger


# Default application-wide logger singleton
logger = get_logger("codeshield")