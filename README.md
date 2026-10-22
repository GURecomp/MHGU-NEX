<h1 align="center">MHGU-NEX</h1>

<h4 align="center">
A self-hosted NEX server for Monster Hunter Generations Ultimate online, written for the recompiled PC build.
</h4>

---

## What it is

MHGU talks to Nintendo's NEX servers (NEX 4.4.0, PRUDP Lite over WebSocket) for login and matchmaking, and to a few UDP
services for NAT checks. This is a small stand-in you run yourself: it answers just enough to take a game from login
through creating and joining a session between players, and it logs the traffic. One Python 3 file, standard library only;
`openssl` on PATH makes the TLS certificate on the first run. It never contacts Nintendo's servers and has no logins.

## Quick start

```
python nexcap.py          # TLS on 443, 60000-60010, UDP 10025/10026/33334/33335
python selftest.py        # local self-test
```

Point the game at it with `network_replacement_host = 127.0.0.1` in the emulator ini, or set **Online Server IP** in the
F10 menu (Multiplayer). Running it on a server for play over the internet is in [SETUP.md](SETUP.md). The server must not
run on a player's PC: the game drops UDP packets whose source IP equals the NAT-check server's.

Useful flags: `-bind`, `-log`, `-certs`, `-tls-ports`, `-auto-ports`, `-udp-ports`, `-secure-host`, `-secure-port`,
`-public-ip`, `-no-loopback-aliases`, `-trace`. Run `python nexcap.py -h` for all of them.

## What works

- PRUDP Lite connect (SYN, CONNECT, DATA, PING, DISCONNECT) with fragment reassembly.
- Login and secure connection: TicketGranting (Login, LoginEx, ValidateAndRequestTicketWithParam) with a self-made ticket,
  SecureConnection (Register, ReplaceURL, SendReport and related).
- Matchmaking: create, join, browse, find by id, open and close participation, unregister, session URLs and join
  notifications, kept in an in-memory registry.
- NAT traversal calls and the UDP NAT check (16-byte datagrams, the 33335 probe port), including the extra reply the game
  needs when both check hosts resolve to the same IP.

Not verified: the access key and the real ticket format (the CONNECT signature is only logged), and some matchmaking
replies are guesses. Unknown calls get a well-formed "not implemented" reply and a full dump in the log.

## Credits and licenses

Protocol formats and behaviour were derived from, and checked against:

- [NextendoNetwork/nextendo-nex](https://github.com/NextendoNetwork/nextendo-nex), PolyForm Shield 1.0.0: PRUDP Lite
  framing, ticket and matchmaking behaviour. Anyone who receives software derived from it must get those terms
  (<https://polyformproject.org/licenses/shield/1.0.0>), and it may not be used to provide a product that competes with
  the licensor's. This is a personal, non-commercial, self-hosted tool.
- [NextendoNetwork/citron-nextendo](https://github.com/NextendoNetwork/citron-nextendo), GPL-3.0: emulator-side reference.
- [PretendoNetwork/monster-hunter-4-ultimate](https://github.com/PretendoNetwork/monster-hunter-4-ultimate), AGPL-3.0:
  reference for the game-server design only; no code copied.

None of these forces a license on this project (the GPL and AGPL projects were references only, no code copied), so it is released under the [MIT License](LICENSE). Any part that is derived from nextendo-nex stays subject to its PolyForm Shield terms above.

## Disclaimer

No game files, keys or copyrighted assets are included; you need your own legally obtained copy of the game. Monster Hunter
is a trademark of Capcom. Nintendo, Capcom and Nextendo are not affiliated with this project. It was built with an AI coding
assistant under the maintainer's direction and testing.
