"""Structured logging for ACPG."""
import logging
import json
import sys
from datetime import datetime
from typing import Any, Optional
from contextvars import ContextVar

from .config import settings

# Context variable for request ID
request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add request ID if available
        request_id = request_id_ctx.get()
        if request_id:
            log_data["request_id"] = request_id
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)
        
        return json.dumps(log_data)


class StructuredLogger:
    """Logger with structured data support."""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
    
    def _log(self, level: int, message: str, **kwargs):
        """Log with extra structured data."""
        extra = {"extra_data": kwargs} if kwargs else {}
        self.logger.log(level, message, extra=extra)
    
    def debug(self, message: str, **kwargs):
        self._log(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self._log(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        self._log(logging.CRITICAL, message, **kwargs)
    
    # Compliance-specific logging methods
    def log_analysis(
        self,
        artifact_hash: str,
        language: str,
        violation_count: int,
        compliant: bool,
        duration_ms: float
    ):
        """Log a compliance analysis."""
        self.info(
            "Compliance analysis completed",
            event="analysis",
            artifact_hash=artifact_hash,
            language=language,
            violation_count=violation_count,
            compliant=compliant,
            duration_ms=round(duration_ms, 2)
        )
    
    def log_enforcement(
        self,
        artifact_hash: str,
        iterations: int,
        compliant: bool,
        violations_fixed: int,
        duration_ms: float
    ):
        """Log an enforcement action."""
        self.info(
            "Compliance enforcement completed",
            event="enforcement",
            artifact_hash=artifact_hash,
            iterations=iterations,
            compliant=compliant,
            violations_fixed=violations_fixed,
            duration_ms=round(duration_ms, 2)
        )
    
    def log_proof_generated(
        self,
        artifact_hash: str,
        policy_count: int,
        signature_fingerprint: str
    ):
        """Log proof bundle generation."""
        self.info(
            "Proof bundle generated",
            event="proof_generated",
            artifact_hash=artifact_hash,
            policy_count=policy_count,
            signature_fingerprint=signature_fingerprint
        )
    
    def log_api_request(
        self,
        method: str,
        path: str,
        status_code: int,
        duration_ms: float,
        client_ip: str
    ):
        """Log an API request."""
        self.info(
            f"{method} {path} - {status_code}",
            event="api_request",
            method=method,
            path=path,
            status_code=status_code,
            duration_ms=round(duration_ms, 2),
            client_ip=client_ip
        )


def setup_logging(json_format: bool = True):
    """
    Configure logging for the application.
    
    Args:
        json_format: If True, use JSON logging (for production).
                    If False, use human-readable format (for development).
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper()))
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    
    if json_format:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        ))
    
    root_logger.addHandler(handler)
    
    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)


def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance."""
    return StructuredLogger(name)


# Application logger
logger = get_logger("acpg")

