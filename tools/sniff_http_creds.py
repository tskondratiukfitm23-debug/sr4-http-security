#!/usr/bin/env python3
"""Scapy-сніфер: шукає Basic-Auth, паролі у формах та cookie у HTTP-трафіку (демо, лише loopback)."""
import argparse
import base64
import datetime as dt
import re

from scapy.all import IP, TCP, Raw, sniff

BASIC = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.I)
FORMU = re.compile(rb"(?:^|&|\r\n\r\n)(username|user|login)=([^&\s]+)", re.I)
FORMP = re.compile(rb"(password|pass|pwd)=([^&\s]+)", re.I)
COOKIE = re.compile(rb"(Set-Cookie|Cookie):\s*([^\r\n]+)", re.I)
TLS_HS = b"\x16\x03"  # TLS record: handshake


def cb(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return
    p, ts = pkt[Raw].load, dt.datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S")
    src = f"{pkt[IP].src}:{pkt[TCP].sport}->{pkt[IP].dst}:{pkt[TCP].dport}"
    if p.startswith(TLS_HS) or p[:1] in (b"\x17", b"\x14"):
        kind = {0x16: "handshake", 0x17: "app-data (шифр.)", 0x14: "ccs"}.get(p[0], "?")
        print(f"{ts} [TLS ] {src} {len(p):5} B {kind:16} {p[:14].hex()}...")
        return
    if m := BASIC.search(p):
        print(f"{ts} [BASIC] {src} {m.group(1).decode()} => {base64.b64decode(m.group(1)).decode()}")
    u, pw = FORMU.search(p), FORMP.search(p)
    if u or pw:
        user = u.group(0).strip(b"&\r\n").decode() if u else ""
        pwd = pw.group(0).decode() if pw else ""
        print(f"{ts} [FORM] {src} {user} {pwd}")
    for c in COOKIE.finditer(p):
        print(f"{ts} [COOKIE] {src} {c.group(1).decode()}: {c.group(2).decode()}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--pcap", help="аналізувати збережений pcap замість живого захоплення")
    a = ap.parse_args()
    if a.pcap:  # офлайн-режим: фільтр за портом виконуємо самі (BPF для offline потребує tcpdump)
        print("Reading", a.pcap, "port:", a.port, flush=True)
        sniff(offline=a.pcap, store=False,
              prn=lambda k: cb(k) if k.haslayer(TCP) and a.port in (k[TCP].sport, k[TCP].dport) else None)
    else:
        flt = f"tcp port {a.port}"
        print("Sniffing on", a.iface, "filter:", flt, flush=True)
        sniff(iface=a.iface, prn=cb, filter=flt, store=False, timeout=a.timeout)
