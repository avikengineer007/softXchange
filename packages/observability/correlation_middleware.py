"""
packages/observability/correlation_middleware.py

Lightweight, production-grade structured logging and request correlation middleware.
- Extracts or generates correlation/request IDs (X-Correlation-ID / X-Request-ID).
- Propagates correlation IDs across inter-service calls.
- Emits structured log records including timestamp, service name, correlation ID, method, path, status, and latency.
"""

import contextvars
import logging
import time
import uuid
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# Context variable preserving correlation ID across async task contexts
correlation_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "correlation_id", default=None
)


def get_current_correlation_id() -> str:
    """Returns the active correlation ID or generates a fallback ID."""
    cid = correlation_id_ctx.get()
    return cid or f"fallback_{uuid.uuid4().hex[:12]}"


class CorrelationIdFilter(logging.Filter):
    """Injects correlation_id into standard python logging LogRecords."""
    def filter(self, record):
        record.correlation_id = get_current_correlation_id()
        return True


class StructuredCorrelationMiddleware(BaseHTTPMiddleware):
    """
    Middleware attaching X-Correlation-ID to inbound requests and outbound responses.
    Logs structured telemetry on request completion.
    """

    def __init__(self, app, service_name: str = "service"):
        super().__init__(app)
        self.service_name = service_name
        self.logger = logging.getLogger(f"softxchange.{service_name}")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Extract or generate correlation ID
        correlation_id = (
            request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Request-ID")
            or f"req_{uuid.uuid4().hex[:16]}"
        )
        token = correlation_id_ctx.set(correlation_id)
        start_time = time.perf_counter()

        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            
            # Inject header into response
            response.headers["X-Correlation-ID"] = correlation_id

            # Emit structured access log
            self.logger.info(
                f"[{self.service_name}] [{correlation_id}] {request.method} {request.url.path} -> {response.status_code} ({duration_ms}ms)"
            )
            return response
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            self.logger.error(
                f"[{self.service_name}] [{correlation_id}] UNHANDLED ERROR {request.method} {request.url.path} ({duration_ms}ms): {exc}",
                exc_info=True,
            )
            raise
        finally:
            correlation_id_ctx.reset(token)
