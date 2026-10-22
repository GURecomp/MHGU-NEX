<h1 align="center">MHGU-NEX</h1>

<h4 align="center">
A local and self-hosted NEX server for the first Monster Hunter Generations Ultimate online path, written for the recompiled PC build.
</h4>

---

## What it is

MHGU talks to Nintendo's NEX servers (NEX 4.4.0, PRUDP Lite over WebSocket) for login and matchmaking, plus a few UDP
services for NAT checks. Nintendo's servers are not reachable from a recompiled PC build, so this is a small stand-in:
it logs both directions of the conversation and answers just enough to get a game from login through creating and joining
a session between two players. It is one Python 3 file with no third-party packages (`openssl` on PATH makes the TLS
certificate on the first run).

It is part of the [MHGU recompilation work](https://github.com/GURecomp/SUYU-GURecomp) but runs on its own, and nothing
here contains game files, keys or Nintendo code.

## Quick start

```
python nexcap.py              # TLS on 443, 60000-60010 TLS-or-plain, UDP 10025/10026/33334/33335
python selftest.py            # high-port self-test, prints the log
```

Then point the game at the server: set `network_replacement_host = 127.0.0.1` in the emulator ini, or add
`127.0.0.1 <host>.srv.nintendo.net` to your hosts file. For play between two real machines, run the server on a VPS with a
public IP (see [Oracle Cloud VPS](#oracle-cloud-vps)); it must not run on a player's PC.

## Docs

- [SETUP.md](SETUP.md): running it locally and on a public server
- [CREDITS.md](CREDITS.md): credits, license notes (including nextendo-nex's PolyForm Shield terms) and disclaimers

## Docs

- [SETUP.md](SETUP.md): running it locally and on a public server
- [CREDITS.md](CREDITS.md): credits, license notes (including nextendo-nex's PolyForm Shield terms) and disclaimers

## Status

Experimental. Login, secure connection, the NAT checks and basic matchmaking (create, join, browse, leave) are answered
and have been exercised with two local instances. The access key and the real ticket format are not verified, and several
matchmaking replies are guesses. Details are in the notes below.

## Notes

This project was built with an AI coding assistant under the maintainer's direction and testing. Not affiliated with or
endorsed by Nintendo or Capcom. Monster Hunter is a trademark of Capcom. Use it only with your own copy of the game.

---

# Protocol notes and options


Capture/stub server for the first MHGU (NEX 4.4.0, PRUDP Lite over WebSocket) test. It logs
both directions and speaks just enough PRUDP Lite/RMC to get past connect+login (no matchmaking). Python 3 stdlib only (Go was not installed);
`openssl` on PATH is used once to make the cert.

## Run
    python nexcap.py                      # 443 TLS, 60000-60010 TLS-or-plain (sniffed), UDP 10025/10026
    python selftest.py                    # high-port self-test, prints the log

Flags: `-bind 0.0.0.0`, `-log ./capture.log`, `-certs ./certs`, `-tls-ports 443`,
`-auto-ports 60000-60010` (same port accepts wss:// or ws://, chosen by first byte),
`-plain-ports ""` (plain-only), `-udp-ports 10025,10026`.
Port 443 may need admin on Windows; a failed bind is logged ("LISTEN FAILED") and the rest keep running.

## Pointing the emulator at it
- Emulator ini: `network_replacement_host = 127.0.0.1` (per the sibling task).
- Or hosts file (`C:\Windows\System32\drivers\etc\hosts`): `127.0.0.1 <host>.srv.nintendo.net`
- Cert is self-signed (`certs/server.crt`, CN=*.srv.nintendo.net, SAN incl. localhost/127.0.0.1).
  The emulator must skip/trust it. TLS handshake failures are logged, which shows whether the client rejects it.

## Protocol status (PRUDP Lite, verified against NextendoNetwork/nextendo-nex)
Header (12 B, LE): `80 | opt_len | payload_size u16 | (src_type<<4)|dst_type | src_port | dst_port | frag_id | (flags<<4)|type u16 | packet_id u16`,
then TLV options (id0 = u32 `minor | funcs<<8`, id1 = 16 B connection sig on SYN|ACK, id128 = 16 B CONNECT sig), then payload.
Types 0 SYN, 1 CONNECT, 2 DATA, 3 DISCONNECT, 4 PING. Flags 1 ACK, 2 RELIABLE, 4 NEED_ACK, 8 HAS_SIZE, 0x200 MULTI_ACK.
The captured 18 B packet `80 06 00 00 aa 1f 01 00 40 00 00 00 | 00 04 06 00 00 00` is a **SYN with NEED_ACK**, packet_id 0,
stream types 0xa/0xa, src port 0x1f -> dst port 0x01, option SUPPORT minor_version 6, supported_functions 0
(it was mis-decoded as CONNECT earlier).

Implemented replies (all sent as binary WS frames, logged as `OUT >>>`; inbound as `IN  <<<` with a field decode):
SYN -> SYN|ACK|HAS_SIZE (ports swapped, minor=min(6,client), conn-sig = HMAC-MD5(fixed key, ip4+port)); CONNECT -> CONNECT|ACK|HAS_SIZE
(any signature accepted, but signature + the connsig we sent are logged for offline access-key recovery; `-access-keys a,b`
tests candidates); DATA NEED_ACK -> ACK, fragments reassembled, RMC dispatched; PING -> ACK; DISCONNECT -> ACK.
RMC (every request is logged with protocol/method/call_id/body hexdump; unknown ones get a NotImplemented error response so the
client does not hang): TicketGranting 0x0A Login/LoginEx (1,2) and ValidateAndRequestTicketWithParam (6) with a self-made
Kerberos ticket, SecureConnection 0x0B Register/RegisterEx (1,4) and TestConnectivity/ReplaceURL/SendReport (5,7,8) -> success.
`-empty-list 6d:N,...` answers proto:method with an empty list (method ids for GetMyBlockList etc. are NOT confirmed - learn
them from the log). `-secure-host/-secure-port` set the secure station URL handed out. `-trace` prints tracebacks.

### Matchmaking (added after the 20:24 capture)
Decoded from the real capture: `0x6D/38` = MatchmakeExtension **CreateMatchmakeSessionWithParam** (request = struct{MatchmakeSession,
list<pid> additional, u32 gid_for_participation_check, u32 create_option, string join_message, u16 participation_count}; response =
the MatchmakeSession with server-assigned id/owner/host/session key); `0x15/2` = MatchMaking **UnregisterGathering**(u32 gid) -> bool
(game sent gid 0); `0x0B/8` = SecureConnection **SendReport**(u32 report_id, qbuffer data) -> empty success (body = id 0 + 128 B blob).
Join path (2026-10-21, two local instances): Register stores [local, public] each with PID+RVCID; ReplaceURL replaces by
address+port; GetSessionURLs returns the HOST's two URLs with address rewritten to the IP we see the host on (127.0.0.1) and the
placeholder port (1) replaced by the NAT-checked port (`-no-url-rewrite` / `-url-address A` change this). Join notifications
follow common-go: 3001 to the owner (all participants if flag 0x400/0x800) plus, with 0x800, a recap per earlier participant to
the joiner. EndParticipation removes the caller.

`nexcap.py` keeps an in-memory gathering registry (`MM`) and answers: 6D/38 Create, 6D/39 Join, 6D/40 AutoMatchmake_Postpone
(join an open session with same game_mode else create), 6D/1,2 Close/OpenParticipation, 6D/8 ModifyCurrentGameAttribute, 6D/11
UpdateApplicationBuffer, 6D/12 UpdateMatchmakeSessionAttribute, 6D/0x22,0x2C,9 (empty ack), 6D/0x29,0x31 FindBy(Single)ID, 6D/0x30
FindByGidList, 6D/0x34 Browse, 6D/0x33,0x3C,0x41,10,13 (empty list), 15/2 Unregister, 15/0x1B UpdateSessionURL, 15/0x28,0x2A
UpdateSessionHost, 15/0x29 GetSessionURLs, 32/1 EndParticipation. After Create/Join it pushes a 0x0E/1 ProcessNotificationEvent
(Participate, type 3001) to the caller, as Nextendo does. The owner PID is derived from the login username (numeric NSA id when it
fits u64) and remembered per client IP so the secure connection gets the same PID. Errors are well-formed RMC errors
(`len | proto | 00 | code|0x80000000 | call_id`); unknown methods get Core::NotImplemented (0x80010002) and a full body dump.

### NATTraversal 0x03 (added after the 20:32 capture; client blocked on 0x03/6)
1 RequestProbeInitiation, 2 InitiateProbe, 4 ReportNATTraversalResult(u32 cid, bool, u32 rtt), 5 ReportNATProperties(u32 map, u32 filter,
u32 rtt), 7 ReportNATTraversalResultDetail(u32 cid, bool, u32 detail, u32 rtt) are acked with an empty success (and logged decoded);
3 RequestProbeInitiationExt(list<string> targets, string station) acks and pushes `0x03/2 InitiateProbe(station)` to each target
station found by its `RVCID=` (the RVCID handed out in Register); 6 GetRelaySignatureKey returns `i32 relay_mode, u64 utc time,
string relay_addr, u16 relay_port, i32 addr_type, u32 game_server_id` = 0 / now / "" / 0 / 0 / 0 (Nextendo advertises NO relay;
`-relay-host H -relay-port P` advertise one instead, mode 1). ReplaceURL (0x0B/7) now stores the new station. UDP ports log every
datagram (hexdump); 16-byte datagrams are answered as the NAT check (below). `-relay-port` is also opened as UDP.

Unknowns / TODO: access key (CONNECT signature not verified, only logged); real ticket format for MHGU (key derivation, source
key, ticket version are Nextendo's, unverified); supported_functions reply is 0; secure-server CONNECT is only answered
correctly for tickets this server issued; Register public URL is an echo; matchmaking replies other than the ones above are guesses (Browse ignores criteria, UpdateProgressScore etc. ack empty).

## Notes
- WS: answers 101, echoes the first requested subprotocol, logs each message as hexdump (128 bytes).
- Plain HTTP(S) GETs get `200 ok`.

## UDP NAT check (16-byte datagrams)
Nintendo NAT check, 4 x u32 big-endian: `[0]` message type (0x65/0x66/0x67 = 101..103, also 1-5), `[4]` external port, `[8]` external
IPv4, `[12]` server/NEX IP. Default `-udp-reply fill` answers every 16-byte datagram with the same type, bytes 4-7 = client's observed
source port, bytes 8-11 = client's observed IPv4 (127.0.0.1 -> 0x7F000001), bytes 12-15 as received (`-udp-nexip A.B.C.D` overrides; `-udp-extip A.B.C.D` overrides bytes 8-11 instead of the observed source IP).
Types 2, 3 and 102 are answered from a secondary socket bound on listen port + 100 (e.g. 10125 for 10025; skipped silently if the
bind fails) so the client sees a different source port; `-udp-same-socket` forces replies from the receiving socket. Other modes:
`echo`, `echo-ack`, `zero`. Every inbound datagram is decoded in the log (`UDP IN <<<`) and each reply logs
`UDP OUT >>> mode=fill type=0x.. from=port to=ip:port <hex>`.

Synthetic 0x67 reply: the game's pia NatPropertyDetecter only succeeds once it has received replies of all three types 0x65, 0x66 and 0x67
(non-zero port in 0x65 and 0x67). It sends 0x67 probes only when the second NAT-check host resolves to a different IP than the first; in a
local setup both resolve to 127.0.0.1, so 0x67 is never probed and the check fails (the game then unregisters the gathering). The reply parser
ignores the reply's source and does not require a matching probe, so in fill mode, after answering a 0x65 probe, the server also sends an
unsolicited `0x67` reply from the same (primary) socket to the same client address/port, with the same port/IP/nex fields (endpoint-independent
mapping). Sent once per 0x65 probe; a 0x66 probe triggers it only if no 0x65 was seen from that client yet. Logged as
`UDP OUT >>> mode=fill type=0x67 (synthetic) ...`. Disable with `-no-udp-67`. Type-0 replies are unchanged.

## UDP 33335 (game NAT-test service, 64-byte datagrams)
After ReplaceURL the game sends 64-byte datagrams to the NAT-check host on the hard-coded port 33335 (0x8237 at 0x13156D8 /
0x1313088, next to the 33334 type-0 check at 0x134CCE8; the sender builds the id string "NATTestId_Dummy"). With nothing listening,
Windows turned the ICMP unreachable into WSAECONNRESET on recvfrom and the game dropped the session. `-udp-probe-ports 33335`
(default) opens it; non-16-byte datagrams there are logged in full (`PROBE IN <<< ... hex=`) and answered per `-udp-probe-reply`
(echo default, zero, silent). Reply format is not confirmed yet - read the logged hex. 33334 is now in the default `-udp-ports`.

## Loopback aliases (UDP)
The game drops datagrams whose source IP equals its nncs1/nncs2 addresses. With the emulator's `network_replacement_host=127.0.0.1` it
resolves nncs1/nncs2 to 127.0.0.2/127.0.0.3, so with a wildcard `-bind` every UDP port is also bound on 127.0.0.2 and 127.0.0.3
(SO_REUSEADDR) and replies leave from the socket that received the datagram (source = address it was sent to). Non-wildcard binds
(e.g. a public address) are unchanged. `-no-loopback-aliases` disables it.

## Hosting
See [SETUP.md](SETUP.md) for requirements, running locally, and hosting on a public server.

## Credits and licenses
See [CREDITS.md](CREDITS.md).
