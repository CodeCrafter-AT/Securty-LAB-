"""Privacy-preserving logging configuration.

Logs go to stderr at WARNING+ by default (never persisted to disk) and pass
through a redacting filter that strips SHA-1 digests, suffixes, and secret fields.
"""

import logging
import re
import sys
from typing import Any

_SHA1_FULL_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
_SHA1_SUFFIX_RE = re.compile(r"\b[0-9a-fA-F]{35}\b")
_SECRET_KV_RE = re.compile(
    r"(?i)\b(password|passphrase|secret|hash_suffix|full_hash)\s*[:=]\s*([^\s,;]+)"
)


def redact_sensitive_text(text: str) -> str:
    """Redact full SHA-1 hashes, 35-char suffixes, and labeled secret values."""
    sanitized = _SHA1_FULL_RE.sub("[REDACTED_SHA1]", text)
    sanitized = _SHA1_SUFFIX_RE.sub("[REDACTED_SHA1_SUFFIX]", sanitized)
    sanitized = _SECRET_KV_RE.sub(r"\1=[REDACTED]", sanitized)
    return sanitized


class SecretRedactingFilter(logging.Filter):
    """Logging filter that ensures sensitive hashes or secret markers are redacted."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            rendered = str(record.msg)
        record.msg = redact_sensitive_text(rendered)
        record.args = ()
        if record.exc_info and record.exc_info[1] is not None:
            # Keep exception type/traceback intact while avoiding secret string interpolation
            pass
        return True


def configure_logging(level: int = logging.WARNING) -> logging.Logger:
    """Configure the application logger without disk persistence."""
    logger = logging.getLogger("password_security_lab")
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        handler.addFilter(SecretRedactingFilter())
        logger.addHandler(handler)
    else:
        for existing_handler in logger.handlers:
            has_filter = any(isinstance(f, SecretRedactingFilter) for f in existing_handler.filters)
            if not has_filter:
                existing_handler.addFilter(SecretRedactingFilter())

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the privacy-filtered root namespace."""
    configure_logging()
    suffix = name.removeprefix("src.")
    return logging.getLogger(f"password_security_lab.{suffix}")


def safe_error_context(exc: Exception) -> dict[str, Any]:
    """Return non-sensitive error metadata suitable for structured logging."""
    return {
        "error_type": type(exc).__name__,
        "message": redact_sensitive_text(str(exc)),
    }
