#!/usr/bin/env python3
"""DNS query recorder for behavior_probe (network=none · REFUSED only).

Listens on 127.0.0.1:53 UDP+TCP, appends one \"epoch name QTYPE\" line per query
to /tmp/dns_queries.log, and replies with REFUSED. Does not resolve or forward.
Started by aos_bp_entrypoint.sh *outside* strace.

Epoch seconds match strace -ttt so the host can assign queries to stages.
QNAME labels are decoded from raw bytes without the idna codec (Python 3.11
idna rejects errors=\"replace\" and would kill the process on the first packet).
"""

from __future__ import annotations

import argparse
import select
import socket
import struct
import sys
import time
from pathlib import Path

LISTEN_ADDR = "127.0.0.1"
LISTEN_PORT = 53
LOG_PATH = Path("/tmp/dns_queries.log")

# Positive-control query sent by aos_bp_entrypoint.sh after recorder start.
DNS_SELFTEST_QNAME = "aos-bp-selftest.invalid"

# DNS QTYPE names we care to label; unknown → numeric.
_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def _escape_label_bytes(label: bytes) -> str:
    """Assemble a label string without idna; non-displayable bytes → \\xNN."""
    parts: list[str] = []
    for b in label:
        # Printable ASCII excluding backslash (escape marker).
        if 0x20 <= b <= 0x7E and b != 0x5C:
            parts.append(chr(b))
        else:
            parts.append(f"\\x{b:02x}")
    return "".join(parts)


def _decode_qname(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    original = offset
    seen: set[int] = set()
    while offset < len(data):
        if offset in seen:
            break
        seen.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original = offset + 2
            jumped = True
            offset = ptr
            continue
        offset += 1
        if offset + length > len(data):
            break
        labels.append(_escape_label_bytes(data[offset : offset + length]))
        offset += length
    name = ".".join(labels) if labels else "."
    return name, (original if jumped else offset)


def _parse_query(data: bytes) -> tuple[str, str] | None:
    if len(data) < 12:
        return None
    # QDCOUNT
    qdcount = struct.unpack("!H", data[4:6])[0]
    if qdcount < 1:
        return None
    name, offset = _decode_qname(data, 12)
    if offset + 4 > len(data):
        return None
    qtype = struct.unpack("!H", data[offset : offset + 2])[0]
    qtype_name = _QTYPE_NAMES.get(qtype, str(qtype))
    return name, qtype_name


def _refused_response(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    # Copy ID; flags = QR|RD|RCODE=REFUSED (0x8183); zero counts except QDCOUNT copy.
    header = bytearray(query[:12])
    header[2] = 0x81
    header[3] = 0x83
    # Keep QDCOUNT; zero AN/NS/AR
    header[6:12] = b"\x00\x00\x00\x00\x00\x00"
    # Echo question section if present
    return bytes(header) + query[12:]


def _log_line(line: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(line.rstrip("\n") + "\n")
        fh.flush()


def _now_epoch() -> str:
    return f"{time.time():.6f}"


def _log_query(name: str, qtype: str) -> None:
    _log_line(f"{_now_epoch()} {name} {qtype}")


def _log_unparsed(length: int) -> None:
    _log_line(f"{_now_epoch()} _unparsed len={length}")


def _encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii", errors="strict")
        if len(raw) > 63:
            raise ValueError(f"label too long: {label!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_query_packet(qname: str, qtype: int = 1, qid: int = 0xA05B) -> bytes:
    """Build a minimal DNS query (QDCOUNT=1) for selftest / unit tests."""
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(qname) + struct.pack("!HH", qtype, 1)  # IN
    return header + question


def send_selftest_query(
    *,
    addr: str = LISTEN_ADDR,
    port: int = LISTEN_PORT,
    timeout: float = 1.0,
) -> None:
    """Send one A query for DNS_SELFTEST_QNAME (does not require a reply)."""
    packet = build_query_packet(DNS_SELFTEST_QNAME, qtype=1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (addr, port))
        try:
            sock.recvfrom(512)
        except (socket.timeout, OSError):
            pass
    finally:
        sock.close()


def _handle_one_packet(data: bytes) -> None:
    """Parse/log one query; never raises (recorder must stay alive)."""
    try:
        parsed = _parse_query(data)
        if parsed:
            _log_query(parsed[0], parsed[1])
        else:
            _log_unparsed(len(data))
    except Exception as exc:  # noqa: BLE001 — per-packet isolation
        print(f"dns_recorder packet_error: {type(exc).__name__}: {exc}", file=sys.stderr)
        try:
            _log_unparsed(len(data))
        except Exception as log_exc:  # noqa: BLE001
            print(
                f"dns_recorder log_error: {type(log_exc).__name__}: {log_exc}",
                file=sys.stderr,
            )


def _handle_datagram(sock: socket.socket) -> None:
    data, addr = sock.recvfrom(4096)
    _handle_one_packet(data)
    resp = _refused_response(data)
    if resp:
        try:
            sock.sendto(resp, addr)
        except OSError:
            pass


def _handle_tcp(conn: socket.socket) -> None:
    try:
        hdr = b""
        while len(hdr) < 2:
            chunk = conn.recv(2 - len(hdr))
            if not chunk:
                return
            hdr += chunk
        length = struct.unpack("!H", hdr)[0]
        data = b""
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                return
            data += chunk
        _handle_one_packet(data)
        resp = _refused_response(data)
        if resp:
            conn.sendall(struct.pack("!H", len(resp)) + resp)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_forever() -> int:
    LOG_PATH.write_text("", encoding="utf-8")
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind((LISTEN_ADDR, LISTEN_PORT))
        tcp.bind((LISTEN_ADDR, LISTEN_PORT))
        tcp.listen(5)
        tcp.setblocking(False)
        udp.setblocking(False)
        while True:
            readable, _, _ = select.select([udp, tcp], [], [], 30.0)
            for sock in readable:
                if sock is udp:
                    try:
                        _handle_datagram(udp)
                    except Exception as exc:  # noqa: BLE001 — keep listening
                        print(
                            f"dns_recorder udp_error: {type(exc).__name__}: {exc}",
                            file=sys.stderr,
                        )
                elif sock is tcp:
                    try:
                        conn, _addr = tcp.accept()
                        conn.setblocking(True)
                        _handle_tcp(conn)
                    except Exception as exc:  # noqa: BLE001
                        print(
                            f"dns_recorder tcp_error: {type(exc).__name__}: {exc}",
                            file=sys.stderr,
                        )
    except KeyboardInterrupt:
        return 0
    finally:
        udp.close()
        tcp.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DNS query recorder (REFUSED only)")
    parser.add_argument(
        "--send-selftest",
        action="store_true",
        help=f"Send one A query for {DNS_SELFTEST_QNAME} and exit",
    )
    args = parser.parse_args(argv)
    if args.send_selftest:
        send_selftest_query()
        return 0
    return serve_forever()


if __name__ == "__main__":
    sys.exit(main())
