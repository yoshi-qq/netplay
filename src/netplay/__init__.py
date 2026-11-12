"""netplay: lobbies for small games – LAN over networking with discovery, internet peer-to-peer with join codes.

Entry points: host_lobby(), join_lobby(), discover_lan(). Messages are JSON dicts with a "t" field (netplay.wire).
"""
from netplay.codes import CodeError, Endpoint, make_code, read_code
from netplay.lobby import (DEFAULT_PORT, Lobby, LobbyError, LobbyEvent, PlayerInfo, TcpClientLobby, TcpHostLobby,
                           UdpClientLobby, UdpHostLobby, discover_lan, host_lobby, join_lobby, local_ip)
from netplay.wire import MAX_MESSAGE, WireError

__version__ = "0.1.0"
__all__ = ["host_lobby", "join_lobby", "discover_lan", "Lobby", "LobbyEvent", "LobbyError", "PlayerInfo",
           "UdpHostLobby", "UdpClientLobby", "TcpHostLobby", "TcpClientLobby", "make_code", "read_code", "Endpoint",
           "CodeError", "WireError", "MAX_MESSAGE", "DEFAULT_PORT", "local_ip"]
