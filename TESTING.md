# Testing netplay across two real networks

The automated tests run on one computer (loopback, a second process for LAN, a local fake STUN server).
Hole punching through real routers can only be tested with two networks. This guide needs about 10 minutes.

## Setup

- Computer A at home (Wi-Fi or cable). Computer B on a **phone hotspot** (mobile network), so the two are on different networks.
- On both: `pip install -e path/to/netplay` (and networking), Python 3.11+.
- Firewall: allow Python when Windows asks (private and public networks).

## 1. Who can host?

On each computer:

```bash
python -c "import socket, netplay.stun as s; k=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); k.bind(('',0)); print(s.discover(k))"
```

`symmetric=False` means this side can host. Mobile networks often show `symmetric=True`: then that side should join, not host.

## 2. Join by code

On the host (A):

```bash
python -c "import netplay, time; h=netplay.host_lobby('A', mode='internet'); print(h.join_code, h.warning); [print(e) for _ in iter(int,1) for e in h.poll() if not time.sleep(0.1)]"
```

On B, with the printed code:

```bash
python -c "import netplay, sys; g=netplay.join_lobby(sys.argv[1], 'B'); print('joined as', g.my_id, 'ping', g.ping())" K7QM-3XVA-PWRT-9HZE
```

Expected: A prints `LobbyEvent(kind='joined', player=2, ...)`; B prints `joined as 2`.

## 3. If joining fails

B prints a reason and a reply code. On A, in a Python shell where the host runs: `h.admit("<reply code>")`, then run the join on B again within a few seconds.
Note what worked and what did not (both `symmetric` values, router type) – that decides whether a relay is needed.

## 4. Swap roles

Repeat with B as host and A joining.
