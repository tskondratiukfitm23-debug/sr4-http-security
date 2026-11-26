"""Middleware заголовків безпеки (RFC 6797 HSTS, W3C CSP, Fetch nosniff тощо)."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; object-src 'none'; "
                                "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; "
                                "upgrade-insecure-requests"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp: Response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp
