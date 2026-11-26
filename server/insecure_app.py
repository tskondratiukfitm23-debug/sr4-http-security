"""HTTP/1.1 без TLS (порт 8081) — навмисно вразлива версія для демонстрації."""
import base64

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="Insecure HTTP Demo")

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>HTTP Demo</title>
<script src="/static/app.js"></script></head><body>
<h1>HTTP Demo (без TLS)</h1>
<form method="post" action="/login">User: <input name="username"/>
Pass: <input type="password" name="password"/><button>Login</button></form>
</body></html>"""


@app.get("/")
def index():
    return HTMLResponse(PAGE)


@app.get("/static/app.js")
def app_js():
    return HTMLResponse("console.log('legit app.js');", media_type="application/javascript")


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    resp = JSONResponse({"ok": True, "user": username,
                         "note": "Credentials travelled in cleartext over HTTP"})
    # Cookie БЕЗ Secure/HttpOnly/SameSite — типова помилка
    resp.set_cookie("session", f"sess-{username}-123456")
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
