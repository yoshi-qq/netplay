# netplay

Lobbies for small games, built on `networking`.

- **LAN** (the usual way, convenient): TCP over `networking` with JSON encoding, host by IP and port, plus game discovery via UDP broadcast, so nobody has to type an IP.
- **Internet, peer-to-peer:** UDP with public STUN servers. The host gets a **join code** (public address + session tag + checksum) to pass on by chat; players only type the code. No own server. If the direct connection fails (symmetric NAT, university Wi-Fi, mobile network), joining fails with a reason instead of hanging, and the guest gets a **reply code** the host can enter as a fallback.
- **Relay:** reserved (`mode="relay"` raises a clear error). A relay later is one more `Lobby` subclass behind the same interface.

## Usage

```python
import netplay

host = netplay.host_lobby("Christian", mode="internet")   # or mode="lan"; playing=False for a pure server
print(host.join_code)                                    # e.g. K7QM-3XVA-PWRT-9HZE
guest = netplay.join_lobby("K7QM-3XVA-PWRT-9HZE", "Ben") # LAN: "192.168.1.20:9009"; find games with netplay.discover_lan()

guest.send({"t": "move", "x": 1})              # client -> host
host.send({"t": "state", "n": 5})              # host -> everyone; to=player_id for one; reliable=False for fast state
for event in host.poll():                       # joined, left, message, host_lost, error
    ...
host.ping(2); guest.ping()                      # round-trip time in seconds
```

## Messages and security

- Messages are JSON objects with a string field `"t"` (`netplay.wire`). No pickle anywhere in netplay.
- Limits: 256 KiB per message, nesting depth 32, no NaN/Infinity, keys must be strings. Names are cleaned to 16 printable characters.
- UDP packets carry a session tag from the join code; packets with another tag are ignored.
- Reliable messages are ordered and resent until acknowledged; large messages are split into 1100-byte fragments.

## Tests

```bash
pip install -e ".[test]"
pytest
mypy
```

What only works with two real networks is described in [TESTING.md](TESTING.md).
