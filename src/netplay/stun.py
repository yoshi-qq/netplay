"""Minimal STUN client (RFC 5389 Binding request) to learn the public UDP address, and a NAT check.

Uses public STUN servers; no own server. Two servers are asked from the same socket: if they see
different public ports, the NAT is "symmetric" and direct peer-to-peer connections will usually fail.
"""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020

DEFAULT_SERVERS: tuple[tuple[str, int], ...] = (
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
)


class StunError(OSError):
    """No usable answer from any STUN server."""


@dataclass(frozen=True)
class NatInfo:
    public_host: str
    public_port: int
    symmetric: bool | None  # None = could not be checked (only one server answered)
    servers_answered: int


def binding_request(transaction_id: bytes) -> bytes:
    return struct.pack(">HHI", BINDING_REQUEST, 0, MAGIC_COOKIE) + transaction_id


def parse_response(data: bytes, transaction_id: bytes) -> tuple[str, int] | None:
    """Public (host, port) from a Binding success response, or None if it is not ours or malformed."""
    if len(data) < 20:
        return None
    msg_type, length, cookie = struct.unpack(">HHI", data[:8])
    if msg_type != BINDING_SUCCESS or cookie != MAGIC_COOKIE or data[8:20] != transaction_id:
        return None
    pos, end = 20, min(len(data), 20 + length)
    mapped: tuple[str, int] | None = None
    while pos + 4 <= end:
        attr_type, attr_len = struct.unpack(">HH", data[pos:pos + 4])
        value = data[pos + 4:pos + 4 + attr_len]
        pos += 4 + attr_len + (-attr_len % 4)
        if len(value) < 8 or value[1] != 0x01:  # IPv4 only
            continue
        port = struct.unpack(">H", value[2:4])[0]
        addr = struct.unpack(">I", value[4:8])[0]
        if attr_type == ATTR_XOR_MAPPED_ADDRESS:
            port ^= MAGIC_COOKIE >> 16
            addr ^= MAGIC_COOKIE
            return socket.inet_ntoa(struct.pack(">I", addr)), port
        if attr_type == ATTR_MAPPED_ADDRESS:
            mapped = socket.inet_ntoa(struct.pack(">I", addr)), port
    return mapped


def query(sock: socket.socket, server: tuple[str, int], timeout: float = 1.5, tries: int = 2) -> tuple[str, int] | None:
    """Asks one server from `sock`; other datagrams arriving meanwhile are ignored."""
    try:
        address = (socket.gethostbyname(server[0]), server[1])
    except OSError:
        return None
    old = sock.gettimeout()
    try:
        for _ in range(tries):
            tid = os.urandom(12)
            sock.settimeout(timeout)
            try:
                sock.sendto(binding_request(tid), address)
                while True:
                    data, sender = sock.recvfrom(2048)
                    if sender[0] == address[0]:
                        found = parse_response(data, tid)
                        if found:
                            return found
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return None
        return None
    finally:
        sock.settimeout(old)


def discover(sock: socket.socket, servers: tuple[tuple[str, int], ...] = DEFAULT_SERVERS) -> NatInfo:
    """Public address of `sock` and whether the NAT looks symmetric. Raises StunError if nobody answers."""
    answers = []
    for server in servers:
        found = query(sock, server)
        if found:
            answers.append(found)
        if len(answers) >= 2:
            break
    if not answers:
        raise StunError("no STUN server answered – is the computer online, or is UDP blocked by a firewall?")
    host, port = answers[0]
    symmetric = None if len(answers) < 2 else any(a != answers[0] for a in answers[1:])
    return NatInfo(host, port, symmetric, len(answers))
