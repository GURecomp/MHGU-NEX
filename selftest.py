"""Self-test: starts nexcap on high ports, drives a PRUDP Lite client (SYN -> CONNECT -> RMC DATA -> PING -> DISCONNECT)
over TLS and plain WS, checks the replies, plus HTTPS GET, garbage and UDP. Prints the server log."""
import os, socket, ssl, struct, subprocess, sys, time
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
import nexcap as N
logf = os.path.join(here, "selftest.log")
if os.path.exists(logf): os.remove(logf)
srv = subprocess.Popen([sys.executable, os.path.join(here, "nexcap.py"), "-tls-ports", "44300", "-auto-ports", "61000-61001",
    "-udp-ports", "11025", "-udp-extra", "11026", "-udp-probe-ports", "11335", "-log", logf, "-certs", os.path.join(here, "certs"), "-empty-list", "6d:99"], stdout=subprocess.DEVNULL)
time.sleep(2)
fails = []
n_str_empty = struct.pack('<H', 1) + bytes(1)
REAL_CREATE = bytes.fromhex("0055010000002b0000000000000000000000000000000000000000000000000004005f00000000000000100a000000000000010000000f01000002000000060000000100000000000000000000000100000000000000000000000101000000bc000000100e0000000000004d15508937e96c6e010000000000000000000000000000000000000000000000520065006300720075006900740069006e006700210000000000000000000000000000000100e70300000000000000000100000001000000000000006a006b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff0000000000000000000064000000000000000000040000000000000000000000000000000100000000000000000100000000000000000000000000000100000100")
REAL_REPORT = bytes.fromhex("0000000080000f00fcff0061ffffffffffffffffffff3f4258795dd99ad1d62d992153bb12dd48240e68a898a07c68207790a8e2e15ae7975fed69b981c94feee8495411f054f5edae207734b484ff4de980bf509683b45604baa3b9478f75d4faf6aac005c202635261bca06b71fc415beff9502508b6b9e0cc1373ad1596c2ae84dd000f20")
def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond: fails.append(name)
_ms = N.MSession.parse(N.Rd(REAL_CREATE[5:]))
check("MSession parse/encode roundtrip is byte-exact on the real capture", _ms.encode() == REAL_CREATE[5:5 + 5 + 43 + 5 + 271])
# ---- in-process two-instance join flow, built from the REAL 2026-10-21 22:37-22:38 capture (host gid=1, joiner)
def _join_flow():
    HOST_PID, JOIN_PID = 5554434265710161006, 6930131280989431290
    def mk(port, pid):
        out = []
        s = N.Session("[t:%d]" % port, ("127.0.0.1", port), out.append)
        s.src, s.dst, s.pid, s.state = (0xa, 1), (0xa, 0xf), pid, "connected"
        N.MM.sessions[pid] = s
        return s, out
    def call(s, out, proto, method, cid, body):
        out.clear(); s.rmc(rmc_req(proto, method, cid, body))
        pls = [N.parse_lite(x)[0]["payload"] for x in out]
        resp = [p for p in pls if len(p) > 13 and p[4] == proto and struct.unpack_from("<I", p, 6)[0] == cid]
        return (resp[0] if resp else None), pls
    def notifs(pls):
        res = []
        for p in pls:
            if len(p) > 14 and p[4] == 0x8E:
                r = N.Rd(p[13:]); r.u8(); r.u32()
                res.append((r.u64(), r.u32(), r.u64(), r.u64(), r.string(), r.u64()))
        return res
    def reg(urls): return struct.pack("<I", len(urls)) + b"".join(N.n_str(u) for u in urls)
    h, ho = mk(56241, HOST_PID)
    call(h, ho, 0x0B, 1, 13, reg(["prudp:/address=192.168.1.1;port=1;Pl=3;Tpt=2;natf=0;natm=0;pmp=0;sid=30;upnp=0",
                                  "prudp:/address=192.168.1.1;port=2;Pl=3;Tpt=2;natf=0;natm=0;pmp=0;sid=30;upnp=0"]))
    rv = h.rvcid
    call(h, ho, 0x6D, 38, 15, REAL_CREATE)
    call(h, ho, 0x0B, 7, 18, N.n_str("prudp:/address=192.168.1.1;port=2;PID=%d;Pl=3;RVCID=%d;Tpt=2;natf=0;natm=0;pmp=0;sid=30;upnp=0" % (HOST_PID, rv)) +
         N.n_str("prudp:/address=192.168.1.1;port=61576;PID=%d;Pl=3;RVCID=%d;Tpt=2;natf=1;natm=1;pmp=0;sid=30;upnp=0" % (HOST_PID, rv)))
    check("ReplaceURL replaced the port=2 slot (2 stations kept)", len(h.stations) == 2 and "port=61576" in h.stations[1])
    # regression (capture 22:49:30): joiner's AUTH connection from the same IP must not steal the host's pid slot
    N.AUTH_PID_BY_IP["127.0.0.1"] = HOST_PID
    a = N.Session("[t:64032]", ("127.0.0.1", 64032), lambda raw: None)
    a.src, a.dst = (0xa, 1), (0xa, 0xf)
    a.on_connect({"sig": None, "payload": b"", "pid": 1})
    a.state = "closed"
    check("payload-less auth CONNECT from same IP does not replace host in MM.sessions",
          N.MM.sessions.get(HOST_PID) is h and a.pid == 0)
    N.MM.sessions[HOST_PID] = a          # even if something stale lands there, host_session must find the live host
    check("host_session skips a closed, station-less connection", N.host_session(N.MM.gatherings[1]) is h)
    N.MM.sessions[HOST_PID] = h
    j, jo = mk(56299, JOIN_PID)
    call(j, jo, 0x0B, 1, 13, reg(["prudp:/address=26.0.0.2;port=1;Pl=3;Tpt=2;natf=0;natm=0;pmp=0;sid=30;upnp=0",
                                  "prudp:/address=26.0.0.2;port=2;Pl=3;Tpt=2;natf=0;natm=0;pmp=0;sid=30;upnp=0"]))
    BROWSE = bytes.fromhex("00 5f 00 00 00 06 00 00 00 02 00 31 00 02 00 30  00 04 00 30 2c 31 00 07 00 31 33 2c 39 39 39 00"
                           "05 00 30 2c 32 36 00 05 00 30 2c 39 37 00 02 00  32 00 01 00 00 01 00 00 02 00 31 00 01 01 01 00"
                           "00 00 00 01 00 00 04 00 00 00 00 00 00 00 01 01  00 00 00 00 01 00 00 00 08 00 00 00 ff ff ff ff 12 00 00 00".replace(" ", ""))
    check("captured Browse body is 100 bytes", len(BROWSE) == 100)
    resp, _ = call(j, jo, 0x6D, 52, 15, BROWSE)
    r = N.Rd(resp[14:]); cnt = r.u32(); ms = N.MSession.parse(r) if cnt else None
    check("joiner Browse(52) sees the host's gid=1", cnt == 1 and ms.id == 1 and ms.host == HOST_PID)
    ho.clear()
    resp, pls = call(j, jo, 0x6D, 39, 16, bytes.fromhex(("00 27 00 00 00 01 00 00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 01 00 00 01 00 00 01 00 00 01"
                                                     "00 00 00 00 04 00 00 00 03 00 00 00").replace(" ", "")))
    check("Join(39) gid=1 -> success MatchmakeSession", resp is not None and resp[5] == 1 and N.MSession.parse(N.Rd(resp[14:])).id == 1)
    hn = notifs([N.parse_lite(x)[0]["payload"] for x in ho])
    check("host gets 3001 participation event for the joiner", any(n[1] == 3001 and n[2] == 1 and n[3] == JOIN_PID for n in hn))
    jn = notifs(pls)
    check("joiner gets 3001 recap for the host (flag 0x800)", any(n[1] == 3001 and n[3] == HOST_PID for n in jn))
    resp, _ = call(j, jo, 0x15, 41, 17, struct.pack("<I", 1))
    r = N.Rd(resp[14:]); urls = [r.string() for _ in range(r.u32())]
    print("GetSessionURLs ->", urls)
    check("GetSessionURLs: 2 host URLs, all 127.0.0.1:61576 with host PID+RVCID",
          len(urls) == 2 and not r.bad and all("address=127.0.0.1;port=61576;" in u and "PID=%d;" % HOST_PID in u and "RVCID=%d;" % rv in u for u in urls))
    resp, _ = call(j, jo, 0x32, 1, 18, bytes.fromhex("01000000010000"))
    check("EndParticipation removes joiner", resp is not None and N.MM.gatherings[1]["participants"] == [HOST_PID])
    resp, _ = call(j, jo, 0x15, 41, 19, struct.pack("<I", 99))
    check("GetSessionURLs unknown gid -> empty list", resp is not None and resp[14:] == bytes(4))
    # CID learning: the host announces its CID in its first NAT call; later GetSessionURLs + pushed stations carry it
    jst = "prudp:/address=192.168.1.2;port=49292;CID=3643289493;PID=%d;RVCID=%d;natf=1;natm=1;sid=30" % (JOIN_PID, j.rvcid)
    hst = "prudp:/address=192.168.1.1;port=61576;CID=2922777130;PID=%d;RVCID=%d;natf=1;natm=1;sid=30" % (HOST_PID, rv)
    tgt_h = "prudp:/address=127.0.0.1;port=61576;CID=0;PID=%d;RVCID=%d;sid=30" % (HOST_PID, rv)
    ho.clear()
    call(j, jo, 0x03, 3, 40, struct.pack("<I", 1) + N.n_str(tgt_h) + N.n_str(jst))
    check("joiner CID learned from station_to_probe", j.cid == 3643289493)
    check("InitiateProbe pushed to host carries joiner CID/PID/RVCID, address rewritten",
          any(b"CID=3643289493" in x and b"address=127.0.0.1" in x and ("RVCID=%d;" % j.rvcid).encode() in x for x in [N.parse_lite(y)[0]["payload"] for y in ho]))
    check("host CID not yet known -> GetSessionURLs has no CID", all(";CID=" not in u for u in
          (lambda r: [r.string() for _ in range(r.u32())])(N.Rd(call(j, jo, 0x15, 41, 41, struct.pack("<I", 1))[0][14:]))))
    call(h, ho, 0x03, 3, 42, struct.pack("<I", 1) + N.n_str("prudp:/address=127.0.0.1;port=49292;CID=0;PID=%d;RVCID=%d" % (JOIN_PID, j.rvcid)) + N.n_str(hst))
    check("host CID learned from its own station_to_probe", h.cid == 2922777130)
    r = N.Rd(call(j, jo, 0x15, 41, 43, struct.pack("<I", 1))[0][14:]); urls = [r.string() for _ in range(r.u32())]
    check("GetSessionURLs now stamps the host's real CID", len(urls) == 2 and all("CID=2922777130;" in u for u in urls))
    N.CFG["cid_stamp"] = False
    r = N.Rd(call(j, jo, 0x15, 41, 44, struct.pack("<I", 1))[0][14:]); urls = [r.string() for _ in range(r.u32())]
    check("-no-cid-stamp leaves URLs untouched", all(";CID=" not in u for u in urls))
    N.CFG["cid_stamp"] = True
    N.CFG["url_rewrite"] = False
    r = N.Rd(call(j, jo, 0x15, 41, 20, struct.pack("<I", 1))[0][14:]); urls = [r.string() for _ in range(r.u32())]
    check("-no-url-rewrite keeps the registered addresses", all("address=192.168.1.1" in u for u in urls))
    N.CFG["url_rewrite"] = True
def frame(op, payload):
    m = b"\x01\x02\x03\x04"
    n = len(payload)
    h = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else b"\xfe" + struct.pack(">H", n))
    return h + m + bytes(b ^ m[i & 3] for i, b in enumerate(payload))
def recv_frame(s):
    def rn(n):
        b = b""
        while len(b) < n:
            d = s.recv(n - len(b))
            if not d: raise EOFError
            b += d
        return b
    b0, b1 = rn(2); ln = b1 & 0x7F
    if ln == 126: ln, = struct.unpack(">H", rn(2))
    return b0 & 15, rn(ln)
def rpkt(s):
    op, d = recv_frame(s)
    assert op == 2, op
    return N.parse_lite(d)[0]
def rmc_req(proto, method, call, body=b""):
    pl = bytes([proto | 0x80]) + struct.pack("<II", call, method) + body
    return struct.pack("<I", len(pl)) + pl
def ws(s):
    s.sendall(b"GET / HTTP/1.1\r\nHost: x.srv.nintendo.net\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: NEX\r\n\r\n")
    r = s.recv(4096); print(r.decode().splitlines()[0], "|", [l for l in r.decode().splitlines() if "Accept" in l or "Protocol" in l])
    s.settimeout(5)
    # 1. the real captured SYN
    s.sendall(frame(2, bytes.fromhex("80060000aa1f01004000000000040600" "0000")))
    p = rpkt(s)
    check("SYN -> SYN|ACK", p["type"] == 0 and p["flags"] & 1 and p["connsig"] and len(p["connsig"]) == 16 and p["minor"] == 6)
    check("ports swapped", (p["src_port"], p["dst_port"]) == (1, 0x1f) and p["src_type"] == 0xa)
    # 2. CONNECT (bogus signature, empty payload)
    s.sendall(frame(2, N.encode_lite(1, 4, (0xa, 0x1f), (0xa, 1), 1, minor=6, sig=b"\x11" * 16)))
    p = rpkt(s)
    check("CONNECT -> CONNECT|ACK", p["type"] == 1 and p["flags"] & 1 and p["pid"] == 1)
    # 3. RMC: Login method 2 (auth), unknown proto (error), configured empty-list
    d = N.encode_lite(2, 6, (0xa, 0x1f), (0xa, 1), 1, payload=rmc_req(0x0A, 2, 7, N.n_str("tester") ))
    s.sendall(frame(2, d))
    a, p = rpkt(s), rpkt(s)
    check("DATA NEED_ACK -> ACK", a["type"] == 2 and a["flags"] & 1 and a["pid"] == 1)
    check("Login response is RMC success call 7", p["type"] == 2 and p["payload"][4] == 0x0A and p["payload"][5] == 1 and struct.unpack_from("<I", p["payload"], 6)[0] == 7)
    s.sendall(frame(2, N.encode_lite(2, 6, (0xa, 0x1f), (0xa, 1), 2, payload=rmc_req(0x55, 3, 8, b"zz"))))
    a, p = rpkt(s), rpkt(s)
    check("unknown RMC -> error response", p["payload"][5] == 0 and struct.unpack_from("<I", p["payload"], 6)[0] == (0x80010002))
    s.sendall(frame(2, N.encode_lite(2, 6, (0xa, 0x1f), (0xa, 1), 3, payload=rmc_req(0x6D, 99, 9))))
    a, p = rpkt(s), rpkt(s)
    check("empty-list RMC", p["payload"][-4:] == b"\0\0\0\0" and p["payload"][5] == 1)
    # 3b. REAL MHGU capture bodies: 0x6D/38 CreateMatchmakeSessionWithParam, 0x15/2 Unregister(0), 0x0B/8 SendReport
    s.sendall(frame(2, N.encode_lite(2, 6, (0xa, 0x1f), (0xa, 1), 4, payload=rmc_req(0x6D, 38, 15, REAL_CREATE))))
    a, p = rpkt(s), rpkt(s)
    pl = p["payload"]
    check("Create(38) -> success with MatchmakeSession", pl[4] == 0x6D and pl[5] == 1 and struct.unpack_from("<I", pl, 6)[0] == 15)
    ms = N.MSession.parse(N.Rd(pl[14:]))
    check("created gid=1, owner=login pid, 32B session key", ms.id >= 1 and ms.owner == N.pid_for_user("tester") and len(ms.skey) == 32 and ms.gamemode == 2 and ms.max == 4)
    n_, = struct.unpack_from("<I", pl, 0)
    check("response length prefix consistent", n_ == len(pl) - 4)
    s.sendall(frame(2, N.encode_lite(2, 6, (0xa, 0x1f), (0xa, 1), 5, payload=rmc_req(0x15, 2, 16, bytes(4)))))
    # the server also pushed a 0x0E/1 Participate notification after Create; collect packets until the Unregister reply
    seen = []
    for _ in range(6):
        q = rpkt(s)
        seen.append(q)
        if len(q["payload"]) > 5 and q["payload"][4] == 0x15: break
    notif = [q for q in seen if len(q["payload"]) > 5 and q["payload"][4] == 0x8E]
    reply = [q for q in seen if len(q["payload"]) > 5 and q["payload"][4] == 0x15]
    check("Participate notification pushed (0x0E/1, type 3001)", bool(notif) and struct.unpack_from("<I", notif[0]["payload"], 26)[0] == 3001)
    check("Unregister(0) -> bool true", bool(reply) and reply[0]["payload"][-1] == 1)
    s.sendall(frame(2, N.encode_lite(2, 6, (0xa, 0x1f), (0xa, 1), 6, payload=rmc_req(0x0B, 8, 17, REAL_REPORT))))
    for _ in range(4):
        q = rpkt(s)
        if len(q["payload"]) > 5 and q["payload"][4] == 0x0B: break
    check("SendReport -> empty success call 17", struct.unpack_from("<I", q["payload"], 6)[0] == 17 and len(q["payload"]) == 14)
    # 3c. NATTraversal 0x03
    def rpc(proto, method, call, body, pid_):
        s.sendall(frame(2, N.encode_lite(2, 6, (0xa, 0x1f), (0xa, 1), pid_, payload=rmc_req(proto, method, call, body))))
        for _ in range(6):
            q = rpkt(s)
            if len(q["payload"]) > 9 and q["payload"][4] == proto and struct.unpack_from("<I", q["payload"], 6)[0] == call: return q["payload"]
    pl = rpc(0x03, 6, 30, b"", 10)
    _b = N.Rd(pl[14:]); _mode, _t, _addr, _port, _typ, _gs = _b.u32(), _b.u64(), _b.string(), _b.u16(), _b.u32(), _b.u32()
    check("GetRelaySignatureKey body: mode 0, time, empty addr, port 0, type 0, gsid 0, fully consumed", pl is not None and (_mode, _addr, _port, _typ, _gs) == (0, "", 0, 0, 0) and _t > 0 and not _b.bad and _b.p == len(pl) - 14)
    for m_, call, body in ((5, 31, struct.pack("<III", 1, 2, 30)), (4, 32, struct.pack("<IBI", 5, 1, 20)), (7, 33, struct.pack("<IBII", 5, 1, 0, 20)),
                           (1, 34, bytes(4)), (2, 35, N.n_str("prudp:/address=1.2.3.4;port=5")), (3, 36, bytes(4) + N.n_str("prudp:/address=1.2.3.4;port=5"))):
        pl = rpc(0x03, m_, call, body, 10 + call)
        check("NAT method %d acked (empty success)" % m_, pl is not None and pl[9 + 1 - 1 + 0:] is not None and len(pl) == 14 and pl[5] == 1)
    # 4. garbage must not kill the connection
    s.sendall(frame(2, b"\x80\x06short"))
    s.sendall(frame(2, b"\x00\x01"))
    # 5. PING need-ack, DISCONNECT need-ack
    s.sendall(frame(2, N.encode_lite(4, 4, (0xa, 0x1f), (0xa, 1), 5)))
    p = rpkt(s); check("PING -> ACK", p["type"] == 4 and p["flags"] & 1 and p["pid"] == 5)
    s.sendall(frame(2, N.encode_lite(3, 4, (0xa, 0x1f), (0xa, 1), 6)))
    p = rpkt(s); check("DISCONNECT -> ACK", p["type"] == 3 and p["flags"] & 1)
    s.sendall(frame(8, struct.pack(">H", 1000))); time.sleep(.3)
try:
    _join_flow()
    cx = ssl.create_default_context(); cx.check_hostname=False; cx.verify_mode=ssl.CERT_NONE
    for port in (44300, 61000):
        s = cx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="a.srv.nintendo.net"); ws(s); s.close()
    s = cx.wrap_socket(socket.create_connection(("127.0.0.1", 44300)), server_hostname="nsd.srv.nintendo.net")
    s.sendall(b"GET / HTTP/1.1\r\nHost: nsd\r\nConnection: close\r\n\r\n"); print(s.recv(4096).split(b"\r\n")[0]); s.close()
    s = socket.create_connection(("127.0.0.1", 61001)); ws(s); s.close()
    s = socket.create_connection(("127.0.0.1", 61001)); s.sendall(b"\x00\x01garbage"); time.sleep(.3); s.close()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.sendto(b"natcheck", ("127.0.0.1", 11025))
    time.sleep(.5)
    for up in (11025, 11026):
        for typ in (0x65, 0x66, 2, 102):
            u.settimeout(2); pk = struct.pack(">IIII", typ, 0, 0, 0x0A000001)
            u.sendto(pk, ("127.0.0.1", up))
            try: r, ra = u.recvfrom(64)
            except socket.timeout: r, ra = None, None
            ok = r is not None and len(r) == 16
            if ok:
                ty, po, ip, nx = struct.unpack(">IIII", r)
                ok = ty == typ and po == u.getsockname()[1] and ip == 0x7F000001 and nx == 0x0A000001
                want = up + 100 if typ in (2, 3, 102) else up
                ok = ok and ra[1] == want
            check("UDP fill type %d on %d" % (typ, up), ok)
            if typ == 0x65:  # synthetic 0x67 follows the 0x65 reply, same socket, same port/ip fields
                try: r2, ra2 = u.recvfrom(64)
                except socket.timeout: r2, ra2 = None, None
                ok2 = r2 is not None and len(r2) == 16 and ra2 == ra
                if ok2:
                    ok2 = struct.unpack(">IIII", r2) == (0x67, po, ip, nx)
                check("UDP synthetic 0x67 after 0x65 on %d" % up, ok2)
    # loopback aliases: reply source must equal the address the datagram was sent to
    for al in ("127.0.0.1", "127.0.0.2", "127.0.0.3"):
        for up in (11025, 11335):
            u.settimeout(2)
            pk = struct.pack(">IIII", 0x65, 0, 0, 0x0A000001) if up == 11025 else bytes(range(64))
            u.sendto(pk, (al, up))
            try: r, ra = u.recvfrom(256)
            except socket.timeout: r, ra = None, None
            check("UDP reply from %s:%d has source %s" % (al, up, al), r is not None and ra == (al, up))
            if up == 11025:
                try: u.recvfrom(64)  # drain synthetic 0x67
                except socket.timeout: pass
    # 64-byte datagram on the probe port (game's 33335 NAT-test service): echoed back, same port
    u.settimeout(2); pk = bytes(range(64)); u.sendto(pk, ("127.0.0.1", 11335))
    try: r, ra = u.recvfrom(256)
    except socket.timeout: r, ra = None, None
    check("UDP probe port echoes 64-byte datagram", r == pk and ra is not None and ra[1] == 11335)
    u.sendto(struct.pack(">IIII", 0x65, 0, 0, 0x0A000001), ("127.0.0.1", 11335))
    try: r, ra = u.recvfrom(64); r2 = None
    except socket.timeout: r = None
    check("16-byte NAT check still answered on probe port", r is not None and struct.unpack(">I", r[:4])[0] == 0x65)
    try: u.recvfrom(64)  # drain synthetic 0x67
    except socket.timeout: pass
    N.UDP_EXTIP[0] = socket.inet_aton("192.168.8.126")
    r = N.udp_reply(struct.pack(">IIII", 0x65, 0, 0, 0x0A000001), ("127.0.0.1", 5555))
    check("udp_reply fill honours -udp-extip", struct.unpack(">IIII", r) == (0x65, 5555, 0xC0A8087E, 0x0A000001))
    N.UDP_EXTIP[0] = None
    # ---- Pia type-2 decoder (FIPS-197 vector, HMAC-MD5 trailer, session key registry)
    check("AES-128 ECB decrypt matches FIPS-197 vector", N.aes128_ecb_decrypt(bytes(range(16)), bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")) == bytes.fromhex("00112233445566778899aabbccddeeff"))
    _k = bytes(range(32)); N.PIA_KEYS[99] = _k
    _body = bytes.fromhex("32ab98640200000012340000") + bytes(range(100, 148))
    _pkt = _body + N.hmac.new(_k, _body, N.hashlib.md5).digest()
    check("pia_decode verifies HMAC-MD5 and decrypts", "sig=OK gid=99" in N.pia_decode(_pkt))
    check("pia_decode flags a bad signature", "NO KEY MATCHES" in N.pia_decode(_pkt[:-1] + bytes([_pkt[-1] ^ 1])))
    del N.PIA_KEYS[99]
    # ---- tunnel hosting: per-client public IPs (-public-ips) and -url-address fallback
    class _S: pass
    _a, _b, _c = _S(), _S(), _S(); _a.pid, _b.pid, _c.pid = 111, 222, 333
    N.CFG["ip_map"], N.CFG["ip_pool"], N.CFG["ip_assigned"] = {222: "9.9.9.9"}, ["1.1.1.1", "2.2.2.2"], {}
    check("public_addr: PID=IP entry wins", N.public_addr(_b, "127.0.0.1") == "9.9.9.9")
    check("public_addr: bare IPs handed out in order, then sticky",
          N.public_addr(_a, "127.0.0.1") == "1.1.1.1" and N.public_addr(_c, "127.0.0.1") == "2.2.2.2" and N.public_addr(_a, "127.0.0.1") == "1.1.1.1")
    _d = _S(); _d.pid = 444
    check("public_addr: pool exhausted -> observed IP", N.public_addr(_d, "127.0.0.1") == "127.0.0.1")
    N.CFG["ip_map"], N.CFG["ip_pool"], N.CFG["ip_assigned"] = {}, [], {}
    _e = _S(); _e.pid = 0
    check("public_addr: default unchanged without options", N.public_addr(_e, "10.1.2.3") == "10.1.2.3")
finally:
    srv.terminate(); srv.wait()
print(open(logf, encoding="utf-8").read())
print("FAILED: %s" % fails if fails else "ALL PASSED")
sys.exit(1 if fails else 0)
