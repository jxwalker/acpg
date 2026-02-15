"""Request-scoped middleware for ACPG."""
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .logging import get_logger, request_id_ctx

logger = get_logger("acpg.middleware")


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Assign a unique request ID, propagate it via ContextVar, and log request metrics."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        token = request_id_ctx.set(request_id)

        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            request_id_ctx.reset(token)

        response.headers["X-Request-ID"] = request_id

        logger.log_api_request(
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            client_ip=request.client.host if request.client else "unknown",
        )

        return response
