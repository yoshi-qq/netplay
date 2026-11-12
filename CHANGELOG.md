# Changelog

Versions follow [SemVer](https://semver.org/). Dates DD.MM.YYYY.

## 0.1.0 – 12.11.2026

First version.

- LAN lobby over `networking` (TCP, JSON) with discovery by UDP broadcast.
- Internet lobby: UDP peer-to-peer, STUN (RFC 5389 Binding), symmetric-NAT check, join codes with checksum, reply-code fallback.
- UDP channel: handshake/hole punching, reliable ordered and unreliable messages, fragmentation, keepalive, round-trip time, timeouts.
- One lobby interface for games (host/join, players, send/poll, ping, host lost); host as player 1 or as pure server.
- Message format `netplay.wire`: JSON only, size and depth limits, validation.
- Relay mode reserved.
