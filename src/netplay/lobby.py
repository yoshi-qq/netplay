"""Lobbies for games: one interface for LAN (TCP over networking) and internet (UDP peer-to-peer).

    host = netplay.host_lobby("Christian", mode="internet")      # or mode="lan"
    print(host.join_code)                                          # pass on by chat (internet) / shown for LAN too
    guest = netplay.join_lobby("K7QM-3XVA-PWRT-9HZE", "Ben")       # code, or "192.168.1.20:9009" for LAN
    guest.send({"t": "move", "x": 1})                             # to the host; host.send(msg, to=id) / to=None = all
    for event in host.poll(): ...                                  # LobbyEvent: joined, left, message, host_lost, error

Star topology: clients talk to the host; the host forwards nothing unless the game sends it on.
Host models: the host plays as player 1 (playing=True, default) or runs as a pure server (playing=False).
A relay connection later only needs another Lobby subclass and an entry in `join_lobby`; games keep their code.
"""
from __future__ import annotations

import json
import queue
import socket
import threading
import time
import warnings
from dataclasses import dataclass
from typing import Any

import networking

from netplay import codes, stun, wire
from netplay.udp import Address, UdpEndpoint, drain

DEFAULT_PORT = 9009
DISCOVERY_PORT = 9010
PROTOCOL = 1
CONNECT_TIMEOUT = 8.0


class LobbyError(ConnectionError):
    """Joining or hosting failed; the message says why in words a player understands."""


@dataclass(frozen=True)
class LobbyEvent:
    kind: str                   # "joined", "left", "message", "host_lost", "error"
    player: int | None = None   # player id the event is about / the sender
    message: wire.Message | None = None
    reason: str = ""


@dataclass
class PlayerInfo:
    id: int
    name: str


def _clean_name(name: object) -> str:
    text = "".join(ch for ch in str(name) if ch.isprintable()).strip()
    return text[:16] or "Player"


def local_ip() -> str:
    """Address of this computer in the local network (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            return str(probe.getsockname()[0])
    except OSError:
        return "127.0.0.1"


class Lobby:
    """Common interface. Subclasses fill `_events` and implement `_deliver`."""

    is_host = False

    def __init__(self, name: str) -> None:
        self.name = _clean_name(name)
        self.my_id = 0
        self.players: dict[int, PlayerInfo] = {}
        self._events: queue.Queue[LobbyEvent] = queue.Queue()
        self.join_code = ""

    def poll(self) -> list[LobbyEvent]:
        out = []
        while True:
            try:
                out.append(self._events.get_nowait())
            except queue.Empty:
                break
        return out

    def send(self, message: wire.Message, to: int | None = None, reliable: bool = True) -> None:
        wire.encode(message)  # validate early, also for local delivery
        self._deliver(message, to, reliable)

    def _deliver(self, message: wire.Message, to: int | None, reliable: bool) -> None:
        raise NotImplementedError

    def ping(self, player: int | None = None) -> float | None:
        """Round-trip time in seconds to a player (host) or to the host (client); None if unknown."""
        return None

    def close(self) -> None:
        return None


# ====================================================================== UDP (internet and LAN)
class UdpHostLobby(Lobby):
    is_host = True

    def __init__(self, name: str, mode: str = "internet", port: int = 0, playing: bool = True, max_players: int = 10,
                 stun_servers: tuple[tuple[str, int], ...] = stun.DEFAULT_SERVERS) -> None:
        super().__init__(name)
        self.mode = mode
        self.playing = playing
        self.max_players = max_players
        self.open = True
        self.tag = codes.new_tag()
        self.endpoint = UdpEndpoint(self.tag, port=port, accept=True)
        self.nat: stun.NatInfo | None = None
        self.warning = ""
        if mode == "internet":
            try:
                self.nat = stun.discover(self.endpoint.sock, stun_servers)
            except stun.StunError as exc:
                self.endpoint.close()
                raise LobbyError(f"Cannot host over the internet: {exc}") from exc
            if self.nat.symmetric:
                self.warning = ("Your router changes the port for every connection (symmetric NAT, common on mobile "
                                "networks and some university Wi-Fi). Others will probably not reach you; "
                                "let someone on a home network host, or use LAN.")
            self.join_code = codes.make_code(codes.Endpoint(self.nat.public_host, self.nat.public_port, self.tag))
        else:
            self.join_code = codes.make_code(codes.Endpoint(local_ip(), self.endpoint.port, self.tag))
        self.next_id = 1
        if playing:
            self.my_id = self.next_id
            self.next_id += 1
            self.players[self.my_id] = PlayerInfo(self.my_id, self.name)
        self.by_address: dict[Address, int] = {}
        self.pending: set[Address] = set()
        self.running = True
        self._thread = threading.Thread(target=self._pump, daemon=True, name="netplay-host")
        self._thread.start()

    def admit(self, reply_code: str) -> None:
        """Host side of the fallback: the guest's reply code opens our NAT towards them."""
        ep = codes.read_code(reply_code)
        if ep.tag != self.tag:
            raise LobbyError("That reply code belongs to another session.")
        self.endpoint.punch((ep.host, ep.port))

    def _roster(self) -> dict[str, str]:
        return {str(i): p.name for i, p in self.players.items()}

    def _pump(self) -> None:
        while self.running:
            for ev in drain(self.endpoint):
                self._on_peer(ev)
            time.sleep(0.005)

    def _on_peer(self, ev: Any) -> None:
        addr = ev.address
        if ev.kind == "connected":
            self.pending.add(addr)
        elif ev.kind == "disconnected":
            self.pending.discard(addr)
            pid = self.by_address.pop(addr, None)
            if pid is not None:
                self.players.pop(pid, None)
                self._events.put(LobbyEvent("left", pid, reason=ev.reason))
                self._broadcast({"t": "_roster", "players": self._roster()})
        elif ev.kind == "message" and ev.message is not None:
            msg = ev.message
            if addr in self.pending and msg.get("t") == "_join":
                self._accept(addr, msg)
            elif addr in self.by_address and not msg.get("t", "").startswith("_"):
                self._events.put(LobbyEvent("message", self.by_address[addr], msg))

    def _accept(self, addr: Address, msg: wire.Message) -> None:
        self.pending.discard(addr)
        if msg.get("protocol") != PROTOCOL:
            self._reject(addr, "Different netplay version – both need the same game version.")
            return
        if not self.open or len(self.players) >= self.max_players:
            self._reject(addr, "The lobby is closed or full.")
            return
        pid = self.next_id
        self.next_id += 1
        self.by_address[addr] = pid
        self.players[pid] = PlayerInfo(pid, _clean_name(msg.get("name")))
        self.endpoint.send(addr, {"t": "_welcome", "id": pid, "host": self.my_id, "players": self._roster()})
        self._broadcast({"t": "_roster", "players": self._roster()})
        self._events.put(LobbyEvent("joined", pid))

    def _reject(self, addr: Address, reason: str) -> None:
        try:
            self.endpoint.send(addr, {"t": "_reject", "reason": reason})
        except ConnectionError:
            pass
        threading.Timer(0.5, self.endpoint.disconnect, args=(addr,)).start()

    def _broadcast(self, message: wire.Message, reliable: bool = True) -> None:
        for addr in list(self.by_address):
            try:
                self.endpoint.send(addr, message, reliable)
            except ConnectionError:
                pass

    def _deliver(self, message: wire.Message, to: int | None, reliable: bool) -> None:
        if to is None:
            self._broadcast(message, reliable)
            return
        for addr, pid in list(self.by_address.items()):
            if pid == to:
                self.endpoint.send(addr, message, reliable)
                return
        if to != self.my_id:
            raise LobbyError(f"No player {to} in the lobby.")

    def ping(self, player: int | None = None) -> float | None:
        for addr, pid in self.by_address.items():
            if pid == player:
                return self.endpoint.rtt(addr)
        return None

    def close(self) -> None:
        self.running = False
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=1.0)
        self.endpoint.close()


class UdpClientLobby(Lobby):
    def __init__(self, code_or_address: str, name: str, timeout: float = CONNECT_TIMEOUT,
                 stun_servers: tuple[tuple[str, int], ...] = stun.DEFAULT_SERVERS, check_nat: bool = True) -> None:
        super().__init__(name)
        endpoint = codes.read_code(code_or_address)
        self.host_address: Address = (endpoint.host, endpoint.port)
        self.endpoint = UdpEndpoint(endpoint.tag)
        self.nat: stun.NatInfo | None = None
        private = endpoint.host.startswith(("10.", "192.168.", "172.", "127."))
        if check_nat and not private:
            try:
                self.nat = stun.discover(self.endpoint.sock, stun_servers)
                self.join_code = codes.make_code(codes.Endpoint(self.nat.public_host, self.nat.public_port, endpoint.tag))
            except stun.StunError:
                self.nat = None
        self.reply_code = self.join_code  # give this to the host if joining stalls
        self.host_id = 0
        self.endpoint.punch(self.host_address)
        self._wait_for_welcome(timeout)
        self.running = True
        self._thread = threading.Thread(target=self._pump, daemon=True, name="netplay-client")
        self._thread.start()

    def _wait_for_welcome(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        joined = False
        while time.monotonic() < deadline:
            for ev in drain(self.endpoint):
                if ev.kind == "connected" and not joined:
                    self.endpoint.send(self.host_address, {"t": "_join", "name": self.name, "protocol": PROTOCOL})
                    joined = True
                elif ev.kind == "message" and ev.message and ev.message.get("t") == "_welcome":
                    m = ev.message
                    self.my_id, self.host_id = int(m["id"]), int(m.get("host", 0))
                    self._set_roster(m.get("players", {}))
                    return
                elif ev.kind == "message" and ev.message and ev.message.get("t") == "_reject":
                    self.endpoint.close()
                    raise LobbyError(str(ev.message.get("reason", "The host refused the connection.")))
                elif ev.kind == "disconnected":
                    break
            time.sleep(0.01)
        self.endpoint.close()
        raise LobbyError(self._why_not(joined))

    def _why_not(self, reached: bool) -> str:
        if reached:
            return "Reached the host, but the lobby did not answer in time."
        if self.nat and self.nat.symmetric:
            return ("Could not reach the host. Your own router changes ports per connection (symmetric NAT, common on "
                    "mobile networks and university Wi-Fi) – try another network or let the host connect to you.")
        hint = f" If both are on home networks, send the host your reply code: {self.reply_code}" if self.reply_code else ""
        return ("Could not reach the host. The host's router probably blocks unknown senders, the host is offline, "
                "or the code is old." + hint)

    def _set_roster(self, players: object) -> None:
        if isinstance(players, dict):
            self.players = {int(k): PlayerInfo(int(k), _clean_name(v)) for k, v in players.items() if str(k).isdigit()}

    def _pump(self) -> None:
        while self.running:
            for ev in drain(self.endpoint):
                if ev.kind == "disconnected":
                    self.running = False
                    self._events.put(LobbyEvent("host_lost", self.host_id, reason=ev.reason))
                elif ev.kind == "message" and ev.message:
                    t = ev.message.get("t", "")
                    if t == "_roster":
                        before = set(self.players)
                        self._set_roster(ev.message.get("players", {}))
                        for pid in set(self.players) - before:
                            self._events.put(LobbyEvent("joined", pid))
                        for pid in before - set(self.players):
                            self._events.put(LobbyEvent("left", pid))
                    elif not t.startswith("_"):
                        self._events.put(LobbyEvent("message", self.host_id, ev.message))
            time.sleep(0.005)

    def _deliver(self, message: wire.Message, to: int | None, reliable: bool) -> None:
        self.endpoint.send(self.host_address, message, reliable)

    def ping(self, player: int | None = None) -> float | None:
        return self.endpoint.rtt(self.host_address)

    def close(self) -> None:
        self.running = False
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=1.0)
        self.endpoint.close()


# ====================================================================== LAN over networking (TCP)
class TcpHostLobby(Lobby):
    """LAN host on the existing networking package (TCP, JSON encoding – never pickle here)."""

    is_host = True

    def __init__(self, name: str, port: int = DEFAULT_PORT, playing: bool = True, max_players: int = 10) -> None:
        super().__init__(name)
        self._net = networking
        self.playing = playing
        self.open = True
        self.next_id = 1
        if playing:
            self.my_id, self.next_id = 1, 2
            self.players[1] = PlayerInfo(1, self.name)
        self.by_name: dict[str, int] = {}  # networking's client name -> player id
        self.server = networking.Server("", port, 0, "json", max_players)
        self.server.messageFunctions["np"] = self._on_message
        networking.onDisconnect = self._on_disconnect  # module-level hook in networking
        self.port = port
        self.join_code = f"{local_ip()}:{port}"
        self.announcer = Announcer(name, port)

    def _client(self, net_name: str) -> Any:
        return next((c for c in list(self.server.clients) if c.name == net_name), None)

    def _on_message(self, sender: str, content: Any) -> None:
        try:
            msg = wire.decode(wire.encode(content)) if isinstance(content, dict) else None
        except wire.WireError as exc:
            warnings.warn(f"netplay: dropped bad LAN message: {exc}")
            return
        if msg is None:
            return
        client = self._client(sender)
        if msg.get("t") == "_join" and sender not in self.by_name and client is not None:
            if msg.get("protocol") != PROTOCOL or not self.open:
                self.server.send(client.conn, self._net.Message("host", "np", {"t": "_reject", "reason": "Lobby closed or different version."}))
                return
            pid = self.next_id
            self.next_id += 1
            self.by_name[sender] = pid
            self.players[pid] = PlayerInfo(pid, _clean_name(msg.get("name")))
            roster = {str(i): p.name for i, p in self.players.items()}
            self.server.send(client.conn, self._net.Message("host", "np", {"t": "_welcome", "id": pid, "host": self.my_id, "players": roster}))
            self._deliver({"t": "_roster", "players": roster}, None, True)
            self._events.put(LobbyEvent("joined", pid))
        elif sender in self.by_name and not msg.get("t", "").startswith("_"):
            self._events.put(LobbyEvent("message", self.by_name[sender], msg))

    def _on_disconnect(self, this: networking.Server.Client) -> None:
        pid = self.by_name.pop(this.name, None)
        if pid is not None:
            self.players.pop(pid, None)
            self._events.put(LobbyEvent("left", pid, reason="disconnected"))

    def _deliver(self, message: wire.Message, to: int | None, reliable: bool) -> None:
        packet = self._net.Message("host", "np", message)
        if to is None:
            for name in list(self.by_name):
                client = self._client(name)
                if client is not None:
                    try:
                        self.server.send(client.conn, packet)
                    except OSError:
                        pass
            return
        for name, pid in self.by_name.items():
            if pid == to:
                client = self._client(name)
                if client is not None:
                    self.server.send(client.conn, packet)
                return

    def close(self) -> None:
        self.announcer.stop()
        self.server.close()


class TcpClientLobby(Lobby):
    def __init__(self, address: str, name: str, timeout: float = CONNECT_TIMEOUT) -> None:
        super().__init__(name)
        self._net = networking
        host, _, port = address.partition(":")
        self._welcome: queue.Queue[wire.Message] = queue.Queue()
        try:
            self.client = networking.Client(host, int(port or DEFAULT_PORT), 0, "json", debug=0)
        except OSError as exc:
            raise LobbyError(f"Could not connect to {host}: is the host running and on the same network? ({exc})") from exc
        self.client.messageFunctions["np"] = self._on_message
        deadline = time.monotonic() + timeout
        while self.client.name == "unknown client" and time.monotonic() < deadline:
            time.sleep(0.01)  # the server names us first; messages carry that name
        self.client.send(networking.Message(self.client.name, "np", {"t": "_join", "name": self.name, "protocol": PROTOCOL}))
        try:
            welcome = self._welcome.get(timeout=timeout)
        except queue.Empty as exc:
            self.client.close()
            raise LobbyError("The host did not answer.") from exc
        if welcome.get("t") == "_reject":
            self.client.close()
            raise LobbyError(str(welcome.get("reason", "The host refused the connection.")))
        self.my_id, self.host_id = int(welcome["id"]), int(welcome.get("host", 0))
        self._set_roster(welcome.get("players", {}))
        threading.Thread(target=self._watch, daemon=True).start()

    def _set_roster(self, players: object) -> None:
        if isinstance(players, dict):
            self.players = {int(k): PlayerInfo(int(k), _clean_name(v)) for k, v in players.items() if str(k).isdigit()}

    def _on_message(self, sender: str, content: Any) -> None:
        try:
            msg = wire.decode(wire.encode(content)) if isinstance(content, dict) else None
        except wire.WireError:
            return
        if msg is None:
            return
        t = msg.get("t", "")
        if t in ("_welcome", "_reject"):
            self._welcome.put(msg)
        elif t == "_roster":
            before = set(self.players)
            self._set_roster(msg.get("players", {}))
            for pid in set(self.players) - before:
                self._events.put(LobbyEvent("joined", pid))
            for pid in before - set(self.players):
                self._events.put(LobbyEvent("left", pid))
        elif not t.startswith("_"):
            self._events.put(LobbyEvent("message", self.host_id, msg))

    def _watch(self) -> None:
        while self.client.on and any(t.is_alive() for t in self.client.threads):
            time.sleep(0.2)
        if self.client.on:
            self._events.put(LobbyEvent("host_lost", self.host_id, reason="connection closed"))

    def _deliver(self, message: wire.Message, to: int | None, reliable: bool) -> None:
        try:
            self.client.send(self._net.Message(self.client.name, "np", message))
        except OSError as exc:
            self._events.put(LobbyEvent("host_lost", self.host_id, reason=str(exc)))

    def close(self) -> None:
        self.client.close()


# ====================================================================== LAN discovery
class Announcer:
    """Broadcasts 'a game is here' once per second for LAN discovery."""

    def __init__(self, name: str, port: int, game: str = "netplay") -> None:
        self.payload = json.dumps({"netplay": PROTOCOL, "game": game, "name": _clean_name(name), "port": port}).encode()
        self.running = True
        threading.Thread(target=self._loop, daemon=True, name="netplay-announce").start()

    def _loop(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            while self.running:
                try:
                    sock.sendto(self.payload, ("<broadcast>", DISCOVERY_PORT))
                except OSError:
                    pass
                time.sleep(1.0)

    def stop(self) -> None:
        self.running = False


def discover_lan(timeout: float = 2.5, game: str = "netplay") -> list[tuple[str, int, str]]:
    """Games announced on the local network: (address, port, host name)."""
    found: list[tuple[str, int, str]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", DISCOVERY_PORT))
    except OSError as exc:
        warnings.warn(f"netplay: discovery not possible ({exc})")
        sock.close()
        return found
    sock.settimeout(0.25)
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            data, addr = sock.recvfrom(1024)
            info = json.loads(data.decode())
            if isinstance(info, dict) and info.get("netplay") == PROTOCOL and info.get("game") == game:
                entry = (addr[0], int(info.get("port", DEFAULT_PORT)), _clean_name(info.get("name", "?")))
                if entry not in found:
                    found.append(entry)
        except (TimeoutError, socket.timeout, ValueError, UnicodeDecodeError):
            continue
    sock.close()
    return found


# ====================================================================== entry points
def host_lobby(name: str, mode: str = "lan", port: int | None = None, playing: bool = True, **kwargs: Any) -> Lobby:
    """mode: "lan" (TCP over networking, discoverable), "internet" (UDP + STUN + join code), "relay" (reserved)."""
    if mode == "lan":
        return TcpHostLobby(name, port or DEFAULT_PORT, playing, **kwargs)
    if mode == "internet":
        return UdpHostLobby(name, "internet", port or 0, playing, **kwargs)
    if mode == "relay":
        raise LobbyError("Relay connections are not available yet.")
    raise ValueError(f"unknown mode {mode!r}")


def join_lobby(target: str, name: str, **kwargs: Any) -> Lobby:
    """target: a join code (internet), or "address[:port]" for LAN."""
    text = target.strip()
    if any(ch == "." for ch in text) or text.lower() == "localhost":
        return TcpClientLobby(text, name, **kwargs)
    return UdpClientLobby(text, name, **kwargs)
