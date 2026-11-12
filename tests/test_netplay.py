"""netplay tests on this computer: message format, codes, STUN parsing with a local fake server,
UDP channel with packet loss, lobbies over UDP and over networking (TCP) with a second process."""
from __future__ import annotations

import os
import socket
import struct
import subprocess
import sys
import textwrap
import threading
import time
from typing import Callable

import pytest

import netplay
from netplay import codes, stun, wire
from netplay.udp import UdpEndpoint, drain


def wait(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    end = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > end:
            raise TimeoutError("condition not met")
        time.sleep(0.01)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return int(s.getsockname()[1])


# ---------------------------------------------------------------- wire
def test_wire_roundtrip_and_limits() -> None:
    msg = {"t": "move", "x": 1.5, "tags": ["a", "ä"], "nested": {"ok": True}}
    assert wire.decode(wire.encode(msg)) == msg
    with pytest.raises(wire.WireError):
        wire.encode({"no_type": 1})
    with pytest.raises(wire.WireError):
        wire.encode({"t": "x", "v": float("nan")})
    with pytest.raises(wire.WireError):
        wire.encode({"t": "x", "v": object()})
    with pytest.raises(wire.WireError):
        wire.decode(b'{"t":"x","v":NaN}')
    with pytest.raises(wire.WireError):
        wire.decode(b"[1,2]")
    with pytest.raises(wire.WireError):
        wire.decode(b"x" * (wire.MAX_MESSAGE + 1))
    deep: dict = {"t": "x"}
    cur = deep
    for _ in range(wire.MAX_DEPTH + 2):
        cur["n"] = {}
        cur = cur["n"]
    with pytest.raises(wire.WireError):
        wire.decode(wire.encode(deep))


# ---------------------------------------------------------------- codes
def test_codes_roundtrip_typo_and_tolerance() -> None:
    ep = codes.Endpoint("203.0.113.7", 50123, 4242)
    code = codes.make_code(ep)
    assert len(code) == 19 and code.count("-") == 3
    assert codes.read_code(code) == ep
    assert codes.read_code(code.lower().replace("-", " ")) == ep
    broken = ("3" if code[5] != "3" else "4").join([code[:5], code[6:]])
    with pytest.raises(codes.CodeError):
        codes.read_code(broken)
    with pytest.raises(codes.CodeError):
        codes.read_code("ABC")


# ---------------------------------------------------------------- STUN
class FakeStun:
    """Answers Binding requests with a fixed mapped address (XOR-MAPPED-ADDRESS)."""

    def __init__(self, mapped: tuple[str, int]) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.mapped = mapped
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    @property
    def address(self) -> tuple[str, int]:
        return ("127.0.0.1", self.sock.getsockname()[1])

    def _loop(self) -> None:
        while self.running:
            try:
                data, sender = self.sock.recvfrom(2048)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            tid = data[8:20]
            ip = struct.unpack(">I", socket.inet_aton(self.mapped[0]))[0] ^ stun.MAGIC_COOKIE
            port = self.mapped[1] ^ (stun.MAGIC_COOKIE >> 16)
            attr = struct.pack(">HHBBHI", stun.ATTR_XOR_MAPPED_ADDRESS, 8, 0, 1, port, ip)
            self.sock.sendto(struct.pack(">HHI", stun.BINDING_SUCCESS, len(attr), stun.MAGIC_COOKIE) + tid + attr, sender)

    def stop(self) -> None:
        self.running = False
        self.sock.close()


def test_stun_discover_and_symmetric_detection() -> None:
    a, b = FakeStun(("198.51.100.4", 40000)), FakeStun(("198.51.100.4", 40000))
    c = FakeStun(("198.51.100.4", 40007))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    try:
        info = stun.discover(sock, (a.address, b.address))
        assert (info.public_host, info.public_port, info.symmetric) == ("198.51.100.4", 40000, False)
        info = stun.discover(sock, (a.address, c.address))
        assert info.symmetric is True
        with pytest.raises(stun.StunError):
            stun.discover(sock, (("127.0.0.1", free_port()),))
    finally:
        sock.close()
        for s in (a, b, c):
            s.stop()


# ---------------------------------------------------------------- UDP channel
def pair(loss: float = 0.0) -> tuple[UdpEndpoint, UdpEndpoint, tuple[str, int]]:
    host = UdpEndpoint(7, accept=True, loss=loss)
    guest = UdpEndpoint(7, loss=loss)
    address = ("127.0.0.1", host.port)
    guest.punch(address)
    wait(lambda: address in guest.connected())
    return host, guest, address


def test_udp_reliable_ordered_with_loss_and_fragments() -> None:
    host, guest, address = pair(loss=0.3)
    try:
        big = {"t": "big", "blob": "x" * 20_000}
        for i in range(40):
            guest.send(address, {"t": "n", "i": i})
        guest.send(address, big)
        got: list = []
        wait(lambda: got.extend(e.message for e in drain(host) if e.kind == "message") or len(got) >= 41, timeout=15)
        assert [m["i"] for m in got[:40]] == list(range(40))
        assert got[40] == big
    finally:
        guest.close()
        host.close()


def test_udp_unreliable_rtt_wrong_tag_and_timeout() -> None:
    host, guest, address = pair()
    try:
        guest.send(address, {"t": "state", "v": 1}, reliable=False)
        wait(lambda: any(e.kind == "message" for e in drain(host)))
        wait(lambda: guest.rtt(address) is not None, timeout=4)
        intruder = UdpEndpoint(8)
        intruder.punch(address)
        time.sleep(0.5)
        assert len(host.connected()) == 1
        intruder.close()
        guest.running = False  # stop answering without saying bye
        guest._thread.join()
        host.timeout = 1.5
        wait(lambda: any(e.kind == "disconnected" for e in drain(host)), timeout=5)
    finally:
        guest.sock.close()
        host.close()


def test_udp_simultaneous_punch_both_sides() -> None:
    a, b = UdpEndpoint(9), UdpEndpoint(9)
    try:
        a.punch(("127.0.0.1", b.port))
        b.punch(("127.0.0.1", a.port))
        wait(lambda: a.connected() and b.connected())
    finally:
        a.close()
        b.close()


# ---------------------------------------------------------------- UDP lobby
def test_udp_lobby_join_messages_roster_and_host_lost() -> None:
    host = netplay.UdpHostLobby("Host", mode="lan")
    guest = netplay.UdpClientLobby(host.join_code, "Guest", check_nat=False)
    try:
        assert guest.my_id == 2 and guest.host_id == 1 and set(guest.players) == {1, 2}
        wait(lambda: any(e.kind == "joined" for e in host.poll()))
        guest.send({"t": "hello", "v": 1})
        wait(lambda: any(e.kind == "message" and e.player == 2 and e.message == {"t": "hello", "v": 1} for e in host.poll()))
        host.send({"t": "tick", "n": 5})
        wait(lambda: any(e.kind == "message" and e.message == {"t": "tick", "n": 5} for e in guest.poll()))
        wait(lambda: host.ping(2) is not None and guest.ping() is not None, timeout=4)
        host.close()
        guest.endpoint.timeout = 2.0
        wait(lambda: any(e.kind == "host_lost" for e in guest.poll()), timeout=5)
    finally:
        guest.close()
        host.close()


def test_udp_lobby_closed_rejects_and_bad_code_fails_fast() -> None:
    host = netplay.UdpHostLobby("Host", mode="lan")
    host.open = False
    try:
        with pytest.raises(netplay.LobbyError):
            netplay.UdpClientLobby(host.join_code, "Late", check_nat=False)
        dead = codes.make_code(codes.Endpoint("127.0.0.1", free_port(), 1))
        start = time.monotonic()
        with pytest.raises(netplay.LobbyError):
            netplay.UdpClientLobby(dead, "Lost", timeout=1.5, check_nat=False)
        assert time.monotonic() - start < 4
    finally:
        host.close()


def test_dedicated_server_model_has_no_own_player() -> None:
    host = netplay.UdpHostLobby("Server", mode="lan", playing=False)
    guest = netplay.UdpClientLobby(host.join_code, "Only", check_nat=False)
    try:
        assert host.my_id == 0 and guest.my_id == 1 and set(guest.players) == {1}
    finally:
        guest.close()
        host.close()


def test_relay_is_reserved() -> None:
    with pytest.raises(netplay.LobbyError):
        netplay.host_lobby("x", mode="relay")


# ---------------------------------------------------------------- LAN over networking, second process
CLIENT_SCRIPT = textwrap.dedent('''
    import sys, time, netplay
    lobby = netplay.join_lobby(sys.argv[1], "Proc")
    lobby.send({"t": "from_child", "id": lobby.my_id})
    end = time.time() + 10
    while time.time() < end:
        for e in lobby.poll():
            if e.kind == "message" and e.message.get("t") == "bye":
                print("child got bye", flush=True)
                lobby.close()
                sys.exit(0)
        time.sleep(0.02)
    sys.exit(3)
''')


def test_lan_tcp_lobby_with_second_process() -> None:
    port = free_port()
    host = netplay.host_lobby("Host", mode="lan", port=port)
    child = subprocess.Popen([sys.executable, "-c", CLIENT_SCRIPT, f"127.0.0.1:{port}"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, env={**os.environ, "PYTHONWARNINGS": "ignore"})
    try:
        got: list = []
        wait(lambda: got.extend(host.poll()) or any(e.kind == "message" for e in got), timeout=10)
        msg = next(e for e in got if e.kind == "message")
        assert msg.message == {"t": "from_child", "id": 2} and msg.player == 2
        host.send({"t": "bye"})
        out, err = child.communicate(timeout=10)
        assert child.returncode == 0, err
        assert "child got bye" in out
    finally:
        if child.poll() is None:
            child.kill()
        host.close()
