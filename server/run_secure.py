"""Запуск HTTPS-сервера лише з TLS 1.3 (TLS 1.0–1.2 відхиляються) + HTTP→HTTPS редирект.

python -m server.run_secure            # HTTPS :8443
python -m server.run_secure --redirect # HTTP  :8080 -> 301 https://localhost:8443
"""
import argparse
import ssl

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

CERT, KEY = "server/certs/server.crt", "server/certs/server.key"

redirect_app = FastAPI(title="HTTP->HTTPS redirect")


@redirect_app.api_route("/{path:path}", methods=["GET", "POST", "HEAD"])
def to_https(path: str, request: Request):
    q = f"?{request.url.query}" if request.url.query else ""
    return RedirectResponse(f"https://localhost:8443/{path}{q}", status_code=301)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--redirect", action="store_true")
    ap.add_argument("--min-tls", default="1.3", choices=["1.2", "1.3"])
    a = ap.parse_args()
    if a.redirect:
        uvicorn.run(redirect_app, host=a.host, port=8080 if a.port == 8443 else a.port,
                    log_level="warning")
        return
    cfg = uvicorn.Config("server.secure_app:app", host=a.host, port=a.port,
                         ssl_keyfile=KEY, ssl_certfile=CERT, log_level="warning",
                         server_header=False)
    cfg.load()  # створює SSLContext, далі посилюємо його
    ctx: ssl.SSLContext = cfg.ssl
    ctx.minimum_version = (ssl.TLSVersion.TLSv1_3 if a.min_tls == "1.3"
                           else ssl.TLSVersion.TLSv1_2)
    if a.min_tls == "1.2":  # лише AEAD + ECDHE (PFS)
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION
    print(f"HTTPS on https://{a.host}:{a.port}  min TLS {a.min_tls}", flush=True)
    uvicorn.Server(cfg).run()


if __name__ == "__main__":
    main()
