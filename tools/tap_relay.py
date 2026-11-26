#!/usr/bin/env python3
"""On-path «відвід» (модель скомпрометованого роутера / Wi-Fi AP): прозоро пересилає TCP
і записує кожен сегмент у pcap (Scapy PcapWriter). Використовується, коли живе захоплення
(AF_PACKET / tcpdump) заборонене середовищем.

python tools/tap_relay.py --listen 8091 --target 8081 --pcap outputs/http.pcap
"""
import argparse
import asyncio

from scapy.all import IP, TCP, Ether, PcapWriter, Raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--target", type=int, required=True)
    ap.add_argument("--pcap", required=True)
    a = ap.parse_args()
    pw = PcapWriter(a.pcap, append=False, sync=True)

    def rec(sport, dport, data):
        pw.write(Ether() / IP(src="127.0.0.1", dst="127.0.0.1") /
                 TCP(sport=sport, dport=dport, flags="PA") / Raw(data))

    async def pipe(reader, writer, sport, dport):
        try:
            while data := await reader.read(65536):
                rec(sport, dport, data)
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    async def handle(cr, cw):
        cport = cw.get_extra_info("peername")[1]
        sr, sw = await asyncio.open_connection("127.0.0.1", a.target)
        await asyncio.gather(pipe(cr, sw, cport, a.target), pipe(sr, cw, a.target, cport))

    async def run():
        srv = await asyncio.start_server(handle, "127.0.0.1", a.listen)
        print(f"tap 127.0.0.1:{a.listen} -> :{a.target}, pcap={a.pcap}", flush=True)
        async with srv:
            await srv.serve_forever()

    asyncio.run(run())


if __name__ == "__main__":
    main()
