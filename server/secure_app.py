"""HTTPS (порт 8443): ті самі ендпоінти + заголовки безпеки, захищені cookie, rate-limit."""
import base64
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .security_headers import SecurityHeaders

app = FastAPI(title="Secure HTTPS Demo")
app.add_middleware(SecurityHeaders)

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>HTTPS Demo</title>
<script src="/static/app.js"></script></head><body>
<h1>HTTPS Demo (TLS 1.3)</h1>
<form method="post" action="/login">User: <input name="username"/>
Pass: <input type="password" name="password"/><button>Login</button></form>
</body></html>"""

RATE_LIMIT, RATE_WINDOW = 5, 60  # не більше 5 спроб входу за 60 с з однієї IP
_attempts: dict[str, deque] = defaultdict(deque)


def _rate_limited(ip: str) -> bool:
    now, q = time.monotonic(), _attempts[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False


@app.get("/")
def index():
    return HTMLResponse(PAGE)


@app.get("/static/app.js")
def app_js():
    return HTMLResponse("console.log('legit app.js');", media_type="application/javascript")


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if _rate_limited(request.client.host):
        return JSONResponse({"detail": "too many attempts"}, status_code=429,
                            headers={"Retry-After": str(RATE_WINDOW)})
    resp = JSONResponse({"ok": True, "user": username})
    resp.set_cookie("__Host-session", f"sess-{username}-123456", secure=True,
                    httponly=True, samesite="strict", path="/", max_age=1800)
    return resp


@app.get("/basic")
def basic(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        return JSONResponse({"detail": "auth required"}, status_code=401,
                            headers={"WWW-Authenticate": 'Basic realm="demo"'})
    user = base64.b64decode(auth.split()[1]).decode().split(":", 1)[0]
    return {"ok": True, "user": user}


@app.get("/echo")
def echo(msg: str):
    return {"echo": msg}
