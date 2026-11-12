"""Join codes: a public IPv4 address, a UDP port and a short session tag, as letters to pass on by chat.

Format: 4 groups of 4 characters from an alphabet without look-alikes (no 0/O, 1/I/L), e.g. "K7QM-3XVA-PWRT-9HZE".
The last character group carries a 4-bit checksum, so typos are detected instead of connecting nowhere.
"""
from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass

ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"  # 31 characters
_BASE = len(ALPHABET)
_LENGTH = 16


class CodeError(ValueError):
    """The code is malformed or has a wrong checksum."""


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    tag: int = 0  # session tag (0..65535) so an old code does not join a new session by accident

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


def new_tag() -> int:
    return secrets.randbelow(1 << 16)


def _checksum(value: int) -> int:
    total = 0
    while value:
        total = (total * 7 + (value & 0xF)) & 0xF
        value >>= 4
    return total


def make_code(endpoint: Endpoint) -> str:
    ip = int(ipaddress.IPv4Address(endpoint.host))
    if not (0 < endpoint.port < 65536 and 0 <= endpoint.tag < 65536):
        raise CodeError("port or tag out of range")
    value = (ip << 32) | (endpoint.port << 16) | endpoint.tag  # 64 bits
    value = (value << 4) | _checksum(value)                       # 68 bits
    chars = []
    for _ in range(_LENGTH):
        value, digit = divmod(value, _BASE)
        chars.append(ALPHABET[digit])
    if value:
        raise CodeError("value does not fit into a code")
    text = "".join(reversed(chars))
    return "-".join(text[i:i + 4] for i in range(0, _LENGTH, 4))


def read_code(code: str) -> Endpoint:
    text = "".join(ch for ch in code.upper() if ch.isalnum())
    text = text.replace("0", "O").replace("1", "I")  # tolerate common typos, then reject unknown letters
    if len(text) != _LENGTH:
        raise CodeError(f"a code has {_LENGTH} characters, got {len(text)}")
    value = 0
    for ch in text:
        digit = ALPHABET.find(ch)
        if digit < 0:
            raise CodeError(f"character {ch!r} is not used in codes")
        value = value * _BASE + digit
    payload, check = value >> 4, value & 0xF
    if payload >> 64 or _checksum(payload) != check:
        raise CodeError("code has a typo (checksum does not match)")
    ip, port, tag = payload >> 32, (payload >> 16) & 0xFFFF, payload & 0xFFFF
    if port == 0:
        raise CodeError("code contains no port")
    return Endpoint(str(ipaddress.IPv4Address(ip)), port, tag)
