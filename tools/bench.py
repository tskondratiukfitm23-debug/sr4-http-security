#!/usr/bin/env python3
"""Заміри latency/CPU: HTTP:8081 vs HTTPS:8443 (нове з'єднання на кожен запит vs keep-alive).

Використання: python tools/bench.py --n 300 --out outputs/bench.json
CPU рахується як приріст cpu_times процесу сервера (psutil) за час серії.
"""
import argparse
import json
import socket
import ssl
import statistics as st
import time

import http.client
import psutil


def server_proc(port):
    for c in psutil.net_connections("tcp"):
        if c.laddr and c.laddr.port == port and c.status == psutil.CONN_LISTEN and c.pid:
            return psutil.Process(c.pid)
    return None


def conn(scheme, port, ctx):
    if scheme == "https":
        return http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
    return http.client.HTTPConnection("127.0.0.1", port, timeout=5)


def series(scheme, port, n, keepalive, ctx, path="/echo?msg=ping"):
    proc = server_proc(port)
    cpu0 = sum(proc.cpu_times()[:2]) if proc else 0
    lat, c, t0 = [], None, time.perf_counter()
    for _ in range(n):
        s = time.perf_counter()
        if not keepalive or c is None:
            c = conn(scheme, port, ctx)
        c.request("GET", path)
        c.getresponse().read()
        if not keepalive:
            c.close()
        lat.append((time.perf_counter() - s) * 1000)
    total = time.perf_counter() - t0
    cpu = (sum(proc.cpu_times()[:2]) - cpu0) if proc else float("nan")
    lat.sort()
    return {"scheme": scheme, "keepalive": keepalive, "n": n,
            "mean_ms": round(st.mean(lat), 3), "p50_ms": round(lat[n // 2], 3),
            "p95_ms": round(lat[int(n * .95)], 3), "rps": round(n / total, 1),
            "server_cpu_ms_per_req": round(cpu * 1000 / n, 3)}


def handshake_only(n, ctx):
    t = []
    for _ in range(n):
        s = time.perf_counter()
        with socket.create_connection(("127.0.0.1", 8443)) as raw:
            with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                ver = tls.version(); cipher = tls.cipher()[0]
        t.append((time.perf_counter() - s) * 1000)
    return {"tls_handshake_ms_p50": round(sorted(t)[n // 2], 3), "version": ver, "cipher": cipher}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--out", default="outputs/bench.json")
    a = ap.parse_args()
    ctx = ssl.create_default_context(cafile="server/certs/ca.crt")
    for sch, port in (("http", 8081), ("https", 8443)):  # прогрів
        series(sch, port, 20, True, ctx)
    rows = [series(s, p, a.n, k, ctx) for k in (False, True) for s, p in (("http", 8081), ("https", 8443))]
    hs = handshake_only(a.n, ctx)
    print(f"{'схема':6} {'keep-alive':10} {'mean,мс':>8} {'p50,мс':>8} {'p95,мс':>8} {'RPS':>8} {'CPU,мс/запит':>13}")
    for r in rows:
        print(f"{r['scheme']:6} {str(r['keepalive']):10} {r['mean_ms']:8} {r['p50_ms']:8} "
              f"{r['p95_ms']:8} {r['rps']:8} {r['server_cpu_ms_per_req']:13}")
    print(f"TLS handshake p50: {hs['tls_handshake_ms_p50']} мс ({hs['version']}, {hs['cipher']})")
    json.dump({"rows": rows, "handshake": hs}, open(a.out, "w"), ensure_ascii=False, indent=2)
