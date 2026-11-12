"""UDP peer protocol of netplay: handshake/hole punching, reliable ordered and unreliable messages,
fragmentation, keepalive and round-trip time.

Packet = header (14 bytes) + chunk of an encoded message (netplay.wire, JSON):
  magic "NP" (2) · version (1) · kind (1) · session tag (2) · message seq (4) · fragment index (2) · fragment count (2)
Reliable messages are acknowledged per message and resent until acknowledged; delivery is in order.
Unreliable messages are delivered whole or not at all; older ones than the newest delivered are dropped.
"""
from __future__ import annotations

import queue
import random
import socket
import struct
import threading
import time
import warnings
from dataclasses import dataclass, field

from netplay import wire

MAGIC = b"NP"
VERSION = 1
HEADER = struct.Struct(">2sBBHIHH")
CHUNK = 1100  # payload bytes per datagram, below common internet MTUs
MAX_FRAGMENTS = (wire.MAX_MESSAGE // CHUNK) + 2

K_REL, K_UNREL, K_ACK, K_PING, K_PONG, K_HELLO, K_WELCOME, K_BYE = range(8)

Address = tuple[str, int]


@dataclass
class _Outgoing:
    packets: list[bytes]
    first_sent: float
    last_sent: float


@dataclass
class Peer:
    address: Address
    last_heard: float
    connected: bool = False
    rtt: float | None = None
    next_rel: int = 1
    next_unrel: int = 1
    unacked: dict[int, _Outgoing] = field(default_factory=dict)
    expected: int = 1
    held: dict[int, wire.Message] = field(default_factory=dict)       # reliable messages waiting for a gap
    parts: dict[tuple[int, int], dict[int, bytes]] = field(default_factory=dict)  # (kind, seq) -> fragments
    newest_unrel: int = 0
    last_ping: float = 0.0


@dataclass(frozen=True)
class PeerEvent:
    kind: str                 # "connected", "message", "disconnected"
    address: Address
    message: wire.Message | None = None
    reason: str = ""


class UdpEndpoint:
    """One UDP socket talking to any number of peers.

    tag: session tag from the join code; packets with another tag are ignored.
    accept: True on a host – new peers that greet with the right tag are accepted.
    loss: share of outgoing datagrams dropped on purpose (tests only).
    """

    def __init__(self, tag: int, port: int = 0, accept: bool = False, timeout: float = 6.0, resend: float = 0.25,
                 loss: float = 0.0, sock: socket.socket | None = None) -> None:
        self.tag = tag
        self.accept = accept
        self.timeout = timeout
        self.resend = resend
        self.loss = loss
        self.sock = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if sock is None:
            self.sock.bind(("", port))
        self.sock.settimeout(0.05)
        self.peers: dict[Address, Peer] = {}
        self.events: queue.Queue[PeerEvent] = queue.Queue()
        self.lock = threading.RLock()
        self.running = True
        self._rng = random.Random()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="netplay-udp")
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self.sock.getsockname()[1])

    # ------------------------------------------------------------ public
    def punch(self, address: Address) -> None:
        """Start greeting a peer (also opens our NAT towards it). Repeats until welcomed or timed out."""
        with self.lock:
            self.peers.setdefault(address, Peer(address, time.monotonic()))
        self._raw(address, K_HELLO, 0, b"")

    def send(self, address: Address, message: wire.Message, reliable: bool = True) -> None:
        data = wire.encode(message)
        with self.lock:
            peer = self.peers.get(address)
            if peer is None or not peer.connected:
                raise ConnectionError(f"not connected to {address[0]}:{address[1]}")
            kind = K_REL if reliable else K_UNREL
            if reliable:
                seq, peer.next_rel = peer.next_rel, peer.next_rel + 1
            else:
                seq, peer.next_unrel = peer.next_unrel, peer.next_unrel + 1
            chunks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)] or [b""]
            packets = [HEADER.pack(MAGIC, VERSION, kind, self.tag, seq, i, len(chunks)) + c for i, c in enumerate(chunks)]
            now = time.monotonic()
            if reliable:
                peer.unacked[seq] = _Outgoing(packets, now, now)
        for p in packets:
            self._send_datagram(address, p)

    def disconnect(self, address: Address) -> None:
        self._raw(address, K_BYE, 0, b"")
        with self.lock:
            peer = self.peers.pop(address, None)
        if peer and peer.connected:
            self.events.put(PeerEvent("disconnected", address, reason="closed"))

    def rtt(self, address: Address) -> float | None:
        with self.lock:
            peer = self.peers.get(address)
            return peer.rtt if peer else None

    def connected(self) -> list[Address]:
        with self.lock:
            return [a for a, p in self.peers.items() if p.connected]

    def close(self) -> None:
        if not self.running:
            return  # closing twice is harmless
        for address in self.connected():
            self._raw(address, K_BYE, 0, b"")
        self.running = False
        self._thread.join(timeout=1.0)
        try:
            self.sock.close()
        except OSError:
            pass

    # ------------------------------------------------------------ internals
    def _send_datagram(self, address: Address, packet: bytes) -> None:
        if self.loss and self._rng.random() < self.loss:
            return
        try:
            self.sock.sendto(packet, address)
        except OSError as exc:
            warnings.warn(f"netplay: sending to {address[0]}:{address[1]} failed: {exc}")

    def _raw(self, address: Address, kind: int, seq: int, payload: bytes) -> None:
        self._send_datagram(address, HEADER.pack(MAGIC, VERSION, kind, self.tag, seq, 0, 1) + payload)

    def _loop(self) -> None:
        while self.running:
            try:
                data, address = self.sock.recvfrom(65535)
                self._handle(data, (address[0], int(address[1])))
            except (TimeoutError, socket.timeout):
                pass
            except ConnectionResetError:
                pass  # Windows reports ICMP port-unreachable this way; the timeout handles dead peers
            except OSError:
                if self.running:
                    time.sleep(0.05)
            self._housekeeping()

    def _handle(self, data: bytes, address: Address) -> None:
        if len(data) < HEADER.size:
            return
        magic, version, kind, tag, seq, index, count = HEADER.unpack(data[:HEADER.size])
        if magic != MAGIC or version != VERSION or tag != self.tag:
            return
        payload = data[HEADER.size:]
        now = time.monotonic()
        with self.lock:
            peer = self.peers.get(address)
            if peer is None:
                if kind != K_HELLO or not self.accept:
                    return
                peer = self.peers[address] = Peer(address, now)
            peer.last_heard = now
            if kind in (K_HELLO, K_WELCOME):
                if kind == K_HELLO:
                    self._raw(address, K_WELCOME, 0, b"")
                if not peer.connected:
                    peer.connected = True
                    self.events.put(PeerEvent("connected", address))
                return
            if kind == K_BYE:
                self.peers.pop(address, None)
                if peer.connected:
                    self.events.put(PeerEvent("disconnected", address, reason="left"))
                return
            if not peer.connected:
                return
            if kind == K_ACK:
                peer.unacked.pop(seq, None)
            elif kind == K_PING:
                self._raw(address, K_PONG, seq, payload[:16])
            elif kind == K_PONG and len(payload) >= 8:
                sample = now - struct.unpack(">d", payload[:8])[0]
                peer.rtt = sample if peer.rtt is None else peer.rtt * 0.8 + sample * 0.2
            elif kind in (K_REL, K_UNREL):
                self._fragment(peer, kind, seq, index, count, payload)

    def _fragment(self, peer: Peer, kind: int, seq: int, index: int, count: int, payload: bytes) -> None:
        if count == 0 or count > MAX_FRAGMENTS or index >= count:
            return
        if kind == K_REL and seq < peer.expected:
            self._raw(peer.address, K_ACK, seq, b"")  # duplicate: our ack was lost
            return
        if kind == K_UNREL and seq <= peer.newest_unrel:
            return
        parts = peer.parts.setdefault((kind, seq), {})
        parts[index] = payload
        if len(peer.parts) > 64:  # forget the oldest incomplete messages
            for key in sorted(peer.parts)[: len(peer.parts) - 64]:
                peer.parts.pop(key, None)
        if len(parts) < count:
            return
        data = b"".join(parts[i] for i in range(count))
        peer.parts.pop((kind, seq), None)
        try:
            message = wire.decode(data)
        except wire.WireError as exc:
            warnings.warn(f"netplay: dropped bad message from {peer.address[0]}: {exc}")
            if kind == K_REL:
                self._raw(peer.address, K_ACK, seq, b"")
                peer.held[seq] = {"t": "_dropped"}
            return
        if kind == K_UNREL:
            peer.newest_unrel = seq
            self.events.put(PeerEvent("message", peer.address, message))
            return
        self._raw(peer.address, K_ACK, seq, b"")
        peer.held[seq] = message
        while peer.expected in peer.held:
            msg = peer.held.pop(peer.expected)
            peer.expected += 1
            if msg.get("t") != "_dropped":
                self.events.put(PeerEvent("message", peer.address, msg))

    def _housekeeping(self) -> None:
        now = time.monotonic()
        lost: list[Address] = []
        resend: list[tuple[Address, bytes]] = []
        with self.lock:
            for address, peer in self.peers.items():
                if now - peer.last_heard > self.timeout:
                    lost.append(address)
                    continue
                if not peer.connected:
                    if now - peer.last_ping >= 0.2:  # keep greeting while punching
                        peer.last_ping = now
                        resend.append((address, HEADER.pack(MAGIC, VERSION, K_HELLO, self.tag, 0, 0, 1)))
                    continue
                if now - peer.last_ping >= 1.0:
                    peer.last_ping = now
                    resend.append((address, HEADER.pack(MAGIC, VERSION, K_PING, self.tag, 0, 0, 1) + struct.pack(">d", now)))
                rto = max(self.resend, 2.0 * (peer.rtt or 0.1))
                for out in peer.unacked.values():
                    if now - out.last_sent >= rto:
                        out.last_sent = now
                        resend.extend((address, p) for p in out.packets)
            for address in lost:
                peer = self.peers.pop(address)
                reason = "no answer" if peer.connected else "could not reach the other side"
                self.events.put(PeerEvent("disconnected", address, reason=reason))
        for address, packet in resend:
            self._send_datagram(address, packet)


def drain(endpoint: UdpEndpoint) -> list[PeerEvent]:
    out = []
    while True:
        try:
            out.append(endpoint.events.get_nowait())
        except queue.Empty:
            return out


__all__ = ["UdpEndpoint", "PeerEvent", "Peer", "drain", "Address"]
