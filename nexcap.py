#!/usr/bin/env python3
"""nexcap - capture/stub server for MHGU (NEX 4.4.0, PRUDP Lite over WebSocket).

Logs everything a client sends (and everything we send back, tagged IN <<< / OUT >>>):
TLS handshake info/errors, HTTP requests, WebSocket upgrades + frames, raw bytes, UDP packets.
Speaks PRUDP Lite (SYN/CONNECT/DATA/PING/DISCONNECT) and answers a few RMC calls best-effort
(accepts any client; no real auth). Stdlib only.
"""
import argparse, base64, hashlib, hmac, os, shutil, socket, ssl, struct, subprocess
import re, sys, threading, time

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"OPTI", b"DELE", b"PATC", b"CONN")
LOG_LOCK = threading.Lock()
LOG_FH = None


def log(msg):
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S") + ".%03d" % (int(time.time() * 1000) % 1000), msg)
    with LOG_LOCK:
        print(line, flush=True)
        if LOG_FH:
            LOG_FH.write(line + "\n")
            LOG_FH.flush()


def hexdump(data, limit=128):
    out = []
    d = data[:limit]
    for i in range(0, len(d), 16):
        c = d[i:i + 16]
        out.append("    %04x  %-47s  %s" % (i, " ".join("%02x" % b for b in c),
                                           "".join(chr(b) if 32 <= b < 127 else "." for b in c)))
    if len(data) > limit:
        out.append("    ... (%d bytes total, showing %d)" % (len(data), limit))
    return "\n".join(out)


# ---------------------------------------------------------------- certs
def ensure_cert(certdir):
    os.makedirs(certdir, exist_ok=True)
    crt, key = os.path.join(certdir, "server.crt"), os.path.join(certdir, "server.key")
    if os.path.exists(crt) and os.path.exists(key):
        return crt, key
    openssl = shutil.which("openssl")
    if not openssl:
        sys.exit("no certs in %s and openssl not on PATH" % certdir)
    subprocess.check_call([
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
        "-keyout", key, "-out", crt, "-subj", "/CN=*.srv.nintendo.net",
        "-addext", "subjectAltName=DNS:*.srv.nintendo.net,DNS:srv.nintendo.net,DNS:localhost,IP:127.0.0.1",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log("generated self-signed cert in %s" % certdir)
    return crt, key


# ---------------------------------------------------------------- PRUDP Lite
# Format verified against NextendoNetwork/nextendo-nex prudp_lite.go + endpoint.go.
#   12-byte header (little endian):
#     0   u8  magic 0x80
#     1   u8  options length
#     2   u16 payload size (only trusted when HASSIZE flag set; otherwise payload = rest of WS frame)
#     4   u8  (src_type << 4) | dst_type          (stream types; 0xa = NEX stream "10")
#     5   u8  source virtual port
#     6   u8  dest virtual port
#     7   u8  fragment id (0 = last/only)
#     8   u16 (flags << 4) | type
#    10   u16 packet (sequence) id
#   options: TLV (id u8, len u8, value). id 0 = supported-functions: u32 = minor_version | (funcs << 8)
#            id 1 = connection signature (server SYN|ACK, 16 bytes)
#            id 128 = CONNECT signature (client, 16 bytes)
#   No session id / substream id / PRUDP-layer encryption in Lite (TLS carries it).
T_SYN, T_CONNECT, T_DATA, T_DISCONNECT, T_PING = 0, 1, 2, 3, 4
TYPE_NAMES = {0: "SYN", 1: "CONNECT", 2: "DATA", 3: "DISCONNECT", 4: "PING"}
F_ACK, F_RELIABLE, F_NEEDACK, F_HASSIZE, F_MULTIACK = 0x1, 0x2, 0x4, 0x8, 0x200
FLAG_NAMES = ((F_ACK, "ACK"), (F_RELIABLE, "RELIABLE"), (F_NEEDACK, "NEED_ACK"), (F_HASSIZE, "HAS_SIZE"), (F_MULTIACK, "MULTI_ACK"))
LITE_CONNSIG_KEY = bytes.fromhex("26c31f381e46d6eb38e1af6ab70d11")
SRV_MINOR = 6          # highest minor version we claim; reply = min(ours, client's)
LOG_TRACE = False


def flag_str(f):
    s = "|".join(n for b, n in FLAG_NAMES if f & b)
    rest = f & ~sum(b for b, _ in FLAG_NAMES)
    if rest:
        s += ("|" if s else "") + "0x%x" % rest
    return s or "-"


def parse_lite(data):
    """Parse ONE PRUDP Lite packet (one WS frame). Returns (dict, leftover_bytes). Raises ValueError."""
    if len(data) < 12:
        raise ValueError("short packet (%d bytes)" % len(data))
    if data[0] != 0x80:
        raise ValueError("bad magic 0x%02x" % data[0])
    optlen, psize = data[1], struct.unpack_from("<H", data, 2)[0]
    tf, pid = struct.unpack_from("<HH", data, 8)
    p = dict(src_type=data[4] >> 4, dst_type=data[4] & 15, src_port=data[5], dst_port=data[6],
             frag=data[7], type=tf & 15, flags=tf >> 4, pid=pid, optlen=optlen, psize=psize,
             minor=None, funcs=None, connsig=None, sig=None, opts_raw=[])
    if 12 + optlen > len(data):
        raise ValueError("options overrun")
    o, i = data[12:12 + optlen], 0
    while i + 2 <= len(o):
        oid, ol = o[i], o[i + 1]
        v = o[i + 2:i + 2 + ol]
        i += 2 + ol
        p["opts_raw"].append((oid, bytes(v)))
        if oid == 0 and len(v) == 4:
            x = struct.unpack("<I", v)[0]
            p["minor"], p["funcs"] = x & 0xFF, x >> 8
        elif oid == 1:
            p["connsig"] = bytes(v)
        elif oid == 128:
            p["sig"] = bytes(v)
    rest = data[12 + optlen:]
    if p["flags"] & F_HASSIZE:
        p["payload"], left = rest[:psize], rest[psize:]
    else:
        p["payload"], left = rest, b""
    return p, left


def encode_lite(type_, flags, src, dst, pid, frag=0, payload=b"", minor=None, funcs=0, connsig=None, sig=None):
    """src/dst = (stream_type, port)."""
    opts = b""
    if type_ in (T_SYN, T_CONNECT) and minor is not None:
        opts += bytes([0, 4]) + struct.pack("<I", (minor & 0xFF) | (funcs << 8))
    if type_ == T_SYN and flags & F_ACK and connsig:
        opts += bytes([1, len(connsig)]) + connsig
    if type_ == T_CONNECT and not flags & F_ACK and sig:
        opts += bytes([128, len(sig)]) + sig
    return (bytes([0x80, len(opts)]) + struct.pack("<H", len(payload)) +
            bytes([(src[0] << 4) | (dst[0] & 15), src[1], dst[1], frag]) +
            struct.pack("<HH", (type_ & 15) | (flags << 4), pid) + opts + payload)


def describe_lite(p):
    s = ("PRUDP-Lite magic=0x80 opt_len=%d payload_size=%d src=(type %d,port %d) dst=(type %d,port %d) "
         "frag=%d type=%d(%s) flags=0x%03x(%s) packet_id=%d" %
         (p["optlen"], p["psize"], p["src_type"], p["src_port"], p["dst_type"], p["dst_port"], p["frag"],
          p["type"], TYPE_NAMES.get(p["type"], "?"), p["flags"], flag_str(p["flags"]), p["pid"]))
    for oid, v in p["opts_raw"]:
        if oid == 0 and len(v) == 4:
            s += "\n    option 0 SUPPORT: minor_version=%s supported_functions=0x%06x" % (p["minor"], p["funcs"])
        else:
            s += "\n    option %d%s len=%d: %s" % (oid, {1: " CONNECTION_SIG", 128: " CONNECT_SIG"}.get(oid, ""), len(v), v.hex())
    s += "\n    payload_len=%d" % len(p["payload"])
    return s


def decode_prudp_lite(data):
    """Description string for logging (never raises)."""
    try:
        p, left = parse_lite(data)
    except ValueError as e:
        return "PRUDP-Lite decode failed: %s" % e
    return describe_lite(p) + ("\n    leftover=%d bytes" % len(left) if left else "")


def hmac_md5(k, d):
    return hmac.new(k, d, hashlib.md5).digest()


def connection_signature(ip, port):
    try:
        return hmac_md5(LITE_CONNSIG_KEY, socket.inet_aton(ip) + struct.pack(">H", port))
    except OSError:
        return os.urandom(16)


def lite_connect_sig(access_key, connsig):
    """Client CONNECT signature = HMAC-MD5(md5(key), md5(key) || connsig)."""
    k = hashlib.md5(access_key.encode()).digest()
    return hmac_md5(k, k + connsig)


# ---------------------------------------------------------------- NEX / RMC helpers
RC_OK = 0x00010001           # "Core::Unknown" = success retval used by NEX
RC_NOT_IMPL = 0x00010002
ERR = 0x80000000
AUTH_PID_BY_IP = {}
CFG = {"relay_host": "", "relay_port": 0, "game_server_id": 0, "access_keys": [], "secure_host": "127.0.0.1", "secure_port": 443, "secure_password": "mhgu-secure",
       "secure_pid": 2, "empty_list": set(), "key_size": 32, "url_rewrite": True, "url_address": "", "cid_stamp": True,
       "ip_map": {}, "ip_pool": [], "ip_assigned": {}}


def n_str(s):
    b = s.encode() + b"\0"
    return struct.pack("<H", len(b)) + b


def n_buf(b):
    return struct.pack("<I", len(b)) + b


def n_datetime():
    t = time.gmtime()
    return (t.tm_year << 26) | (t.tm_mon << 22) | (t.tm_mday << 17) | (t.tm_hour << 12) | (t.tm_min << 6) | t.tm_sec


def n_struct(body, version=1):
    return bytes([version]) + struct.pack("<I", len(body)) + body


class Rd:
    """Tolerant little-endian reader; never raises (sets .bad)."""
    def __init__(self, b):
        self.b, self.p, self.bad = b, 0, False

    def take(self, n):
        if n < 0 or self.p + n > len(self.b):
            self.bad = True
            r = self.b[self.p:]
            self.p = len(self.b)
            return r
        r = self.b[self.p:self.p + n]
        self.p += n
        return r

    def u8(self): return (self.take(1) or b"\0")[0]
    def u16(self): return int.from_bytes(self.take(2).ljust(2, b"\0"), "little")
    def u32(self): return int.from_bytes(self.take(4).ljust(4, b"\0"), "little")
    def u64(self): return int.from_bytes(self.take(8).ljust(8, b"\0"), "little")

    def string(self):
        return self.take(self.u16()).rstrip(b"\0").decode("utf-8", "replace")

    def buffer(self): return self.take(self.u32())
    def rest(self): return self.take(len(self.b) - self.p)


def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 255])
    return bytes(out)


def kerb_enc(key, data):
    e = rc4(key, data)
    return e + hmac_md5(key, e)


def kerb_dec(key, data):
    if len(data) < 16 or not hmac.compare_digest(data[-16:], hmac_md5(key, data[:-16])):
        return None
    return rc4(key, data[:-16])


def derive_key(password, pid):
    k = hashlib.md5(password.encode()).digest()
    return hashlib.md5(k + struct.pack("<Q", pid)).digest()   # KerberosKeyDerivation "new"


def make_ticket(user_pid):
    """Nextendo-style ticket. TODO(unverified for MHGU): client may use another derivation / ticket version."""
    sess = os.urandom(CFG["key_size"])
    secure_key = derive_key(CFG["secure_password"], CFG["secure_pid"])
    body = struct.pack("<QQ", n_datetime(), user_pid) + sess            # ServerTicket (ticket version 1 below)
    tkey = os.urandom(16)
    final = hashlib.md5(secure_key + tkey).digest()
    internal = n_buf(tkey) + n_buf(kerb_enc(final, body))
    source_key = os.urandom(16)                                          # TODO: real server derives from account/password
    ticket = kerb_enc(source_key, sess + struct.pack("<Q", CFG["secure_pid"]) + n_buf(internal))
    return ticket, source_key, sess


def secure_station():
    return "prudps:/PID=%d;sid=1;stream=10;type=2;address=%s;port=%d;CID=1" % (
        CFG["secure_pid"], CFG["secure_host"], CFG["secure_port"])


def rvconn_data():
    return n_struct(n_str(secure_station()) + struct.pack("<I", 0) + n_str("prudp:/") + struct.pack("<Q", n_datetime()))


# ---------------------------------------------------------------- matchmaking (best effort, in memory)
# Layouts follow nextendo-nex matchmaking.go / matchmaking_handlers.go and were checked against the real MHGU capture:
#   MatchmakeExtension (0x6D): 38 = CreateMatchmakeSessionWithParam, 39 = JoinMatchmakeSessionWithParam,
#     40 = AutoMatchmakeWithParam_Postpone, 1/2 = Close/OpenParticipation, ...
#   MatchMaking (0x15): 2 = UnregisterGathering(u32 gid) -> bool
#   SecureConnection (0x0B): 8 = SendReport(u32 report_id, qbuffer data) -> nothing
VARIANT_NAMES = {0: "nil", 1: "int64", 2: "double", 3: "bool", 4: "string", 5: "datetime", 6: "uint64"}
MM_LOCK = threading.RLock()


class MSession:
    """Gathering + MatchmakeSession (NEX 4 layout, hierarchical struct headers; versions kept as seen: 0)."""
    def __init__(self):
        self.gv = self.mv = 0
        self.id = 0; self.owner = 0; self.host = 0
        self.min = 0; self.max = 0; self.policy = 0; self.arg = 0; self.flags = 0; self.state = 0; self.desc = ""
        self.gamemode = 0; self.attribs = []; self.open = 1; self.system = 0; self.appdata = b""
        self.numpart = 0; self.progress = 0; self.skey = b""; self.option = 0
        self.params = []          # (key, vtype, value)
        self.started = 0; self.pw = ""; self.refer = 0; self.pwen = 0; self.sysen = 0; self.codeword = ""

    @staticmethod
    def parse(r):
        s = MSession()
        s.gv = r.u8(); r.u32()                       # Gathering level header
        s.id = r.u32(); s.owner = r.u64(); s.host = r.u64()
        s.min = r.u16(); s.max = r.u16(); s.policy = r.u32(); s.arg = r.u32(); s.flags = r.u32(); s.state = r.u32()
        s.desc = r.string()
        s.mv = r.u8(); r.u32()                       # MatchmakeSession level header
        s.gamemode = r.u32()
        s.attribs = [r.u32() for _ in range(min(r.u32(), 64))]
        s.open = r.u8(); s.system = r.u32(); s.appdata = r.buffer()
        s.numpart = r.u32(); s.progress = r.u8(); s.skey = r.buffer(); s.option = r.u32()
        r.u8(); r.u32()                              # MatchmakeParam header
        for _ in range(min(r.u32(), 64)):
            k = r.string(); t = r.u8()
            if t == 1: v = r.u64()
            elif t == 2: v = r.u64()
            elif t == 3: v = r.u8()
            elif t == 4: v = r.string()
            elif t in (5, 6): v = r.u64()
            else: v = None
            s.params.append((k, t, v))
        s.started = r.u64(); s.pw = r.string(); s.refer = r.u32(); s.pwen = r.u8(); s.sysen = r.u8(); s.codeword = r.string()
        if r.bad:
            raise ValueError("truncated MatchmakeSession")
        return s

    def encode(self):
        g = (struct.pack("<I", self.id) + struct.pack("<QQ", self.owner, self.host) +
             struct.pack("<HHIIII", self.min, self.max, self.policy, self.arg, self.flags, self.state) + n_str(self.desc))
        pm = struct.pack("<I", len(self.params))
        for k, t, v in self.params:
            pm += n_str(k) + bytes([t])
            if t in (1, 2, 5, 6): pm += struct.pack("<Q", v)
            elif t == 3: pm += bytes([v])
            elif t == 4: pm += n_str(v)
        m = (struct.pack("<I", self.gamemode) + struct.pack("<I", len(self.attribs)) + b"".join(struct.pack("<I", a) for a in self.attribs) +
             bytes([self.open]) + struct.pack("<I", self.system) + n_buf(self.appdata) + struct.pack("<I", self.numpart) +
             bytes([self.progress]) + n_buf(self.skey) + struct.pack("<I", self.option) + n_struct(pm, 0) +
             struct.pack("<Q", self.started) + n_str(self.pw) + struct.pack("<I", self.refer) +
             bytes([self.pwen, self.sysen]) + n_str(self.codeword))
        return n_struct(g, self.gv) + n_struct(m, self.mv)

    def summary(self):
        return ("gid=%d owner=%d host=%d min/max=%d/%d policy=%d arg=%d flags=0x%x state=%d desc=%r game_mode=%d attribs=%s open=%d "
                "matchmake_system=%d appdata=%dB numpart=%d progress=%d skey=%dB option=%d params=%s started=%d pw=%r refer=%d "
                "pw_en=%d sys_en=%d codeword=%r" % (
                    self.id, self.owner, self.host, self.min, self.max, self.policy, self.arg, self.flags, self.state, self.desc,
                    self.gamemode, self.attribs, self.open, self.system, len(self.appdata), self.numpart, self.progress,
                    len(self.skey), self.option, [(k, VARIANT_NAMES.get(t), v) for k, t, v in self.params], self.started,
                    self.pw, self.refer, self.pwen, self.sysen, self.codeword))


def utf16_hint(b):
    try:
        i = b.find(b"\x52\x00\x65\x00")
        t = b.decode("utf-16-le", "ignore") if i < 0 else b[i:].decode("utf-16-le", "ignore")
        return "".join(c for c in t if c.isprintable())[:40]
    except Exception:
        return ""


class MM:
    gatherings = {}          # gid -> dict(session=MSession, participants=[pid], host_sess=Session)
    next_gid = 1
    sessions = {}            # pid -> Session (latest secure connection of that pid)
    notif_counter = 0
    next_rvcid = 1
    by_rvcid = {}


def n_list(items):
    return struct.pack("<I", len(items)) + b"".join(items)


# ---- station URLs ("prudp:/address=A;port=P;K=V...") -- modelled on nex-protocols-common-go Register/ReplaceURL/GetSessionURLs
def url_parse(u):
    scheme, _, rest = u.partition(":/")
    kv = {}
    for x in rest.split(";"):
        if "=" in x:
            k, v = x.split("=", 1)
            kv[k] = v
    return scheme or "prudp", kv


def url_format(scheme, kv):
    """address;port first, then the rest in ASCII order (the order the MHGU client itself uses)."""
    keys = [k for k in ("address", "port") if k in kv] + sorted(k for k in kv if k not in ("address", "port"))
    return "%s:/%s" % (scheme, ";".join("%s=%s" % (k, kv[k]) for k in keys))


def url_key(u):
    _, kv = url_parse(u)
    return kv.get("address"), kv.get("port")


def host_session(g):
    """Latest secure connection of the gathering host (falls back to the creating connection)."""
    for pid in (g["session"].host, g["session"].owner):
        s = MM.sessions.get(pid)
        if s is not None and s.state != "closed" and s.stations:
            return s
    hs = g["host_sess"]
    if hs is not None and hs.stations:
        return hs
    return MM.sessions.get(g["session"].host) or hs


def register_session(pid, sess):
    """pid -> secure connection. Never let a station-less connection (e.g. the auth-server connection of another local
    instance) displace a live secure connection that already registered stations for this pid."""
    if not pid:
        return
    cur = MM.sessions.get(pid)
    if cur is not None and cur is not sess and cur.state != "closed" and cur.stations and not sess.stations:
        return
    MM.sessions[pid] = sess


def public_addr(sess, default):
    """Address advertised for `sess` in handed-out station URLs. Behind a TCP/UDP tunnel every client is seen as 127.0.0.1,
    so -public-ips lets the operator state the real public IPs: 'PID=IP' entries are exact, bare IPs are handed to the
    first distinct PIDs that register, in order. Without them: -url-address, else `default` (the observed IP)."""
    pid = getattr(sess, "pid", 0)
    if pid:
        if pid in CFG["ip_map"]:
            return CFG["ip_map"][pid]
        if pid in CFG["ip_assigned"]:
            return CFG["ip_assigned"][pid]
        if CFG["ip_pool"]:
            CFG["ip_assigned"][pid] = CFG["ip_pool"].pop(0)
            log("public-ips: PID %d -> %s" % (pid, CFG["ip_assigned"][pid]))
            return CFG["ip_assigned"][pid]
    return CFG["url_address"] or default


def reachable_urls(host):
    """Host station URLs as handed to other participants. The client advertises a NIFM address that need not exist on this
    PC (host instance said 192.168.1.1; not a local interface) and a placeholder local port (1). With CFG url_rewrite
    the address becomes the address we actually see the host on (127.0.0.1 for local instances, or -url-address) and a
    placeholder port (<1024) takes the port learned from the NAT check (ReplaceURL). PID/RVCID are always present."""
    urls = list(host.stations)
    parsed = [url_parse(u) for u in urls]
    real_port = None
    for _, kv in reversed(parsed):
        if kv.get("port", "").isdigit() and int(kv["port"]) >= 1024:
            real_port = kv["port"]
            break
    out = []
    for scheme, kv in parsed:
        kv = dict(kv)
        kv["PID"] = str(host.pid)
        if getattr(host, "rvcid", None):
            kv.setdefault("RVCID", str(host.rvcid))
        if CFG["cid_stamp"] and getattr(host, "cid", 0) and kv.get("CID", "0") in ("", "0"):
            kv["CID"] = str(host.cid)      # the host's own CID as it announced it in its first NAT call (else peers key it as CID=0)
        if CFG["url_rewrite"]:
            kv["address"] = public_addr(host, host.ip)
            if real_port and not (kv.get("port", "").isdigit() and int(kv["port"]) >= 1024):
                kv["port"] = real_port
        out.append(url_format(scheme, kv))
    return out


def rewrite_station(u, sess):
    """Station string sent by `sess` (e.g. NAT station_to_probe) with the address we observe for it."""
    if not CFG["url_rewrite"]:
        return u
    scheme, kv = url_parse(u)
    kv["address"] = public_addr(sess, sess.ip)
    if CFG["cid_stamp"]:
        # the pushed station must carry the sender's identity exactly as the server handed it out (PID/RVCID) plus its real CID
        if getattr(sess, "pid", 0):
            kv["PID"] = str(sess.pid)
        if getattr(sess, "rvcid", 0):
            kv["RVCID"] = str(sess.rvcid)
        if getattr(sess, "cid", 0) and kv.get("CID", "0") in ("", "0"):
            kv["CID"] = str(sess.cid)
    return url_format(scheme, kv)


def notify_join(g, joiner_pid, join_message):
    """Participation notifications after a join, as nex-protocols-common-go JoinGatheringWithParticipants:
    3001 (source=joiner, p1=gid, p2=joiner, str=join message, p3=count) to the owner, or to every participant when
    gathering flag 0x400/0x800 is set; with 0x800 the joiner additionally gets one 3001 per earlier participant."""
    s = g["session"]
    parts = list(g["participants"])
    gid, n = s.id, len(parts)
    targets = parts if s.flags & 0xC00 else [s.owner]
    for t in dict.fromkeys(targets):
        push_notification(MM.sessions.get(t), joiner_pid, 3001, gid, joiner_pid, join_message, n)
    if s.flags & 0x800:
        for old in dict.fromkeys(parts):
            if old != joiner_pid:
                push_notification(MM.sessions.get(joiner_pid), joiner_pid, 3001, gid, old, join_message, n)


def pid_for_user(username):
    try:
        v = int(username)
        if 0 < v < 1 << 64:
            return v
    except (TypeError, ValueError):
        pass
    return 1800000000 + (int.from_bytes(hashlib.md5(str(username).encode()).digest()[:3], "little"))


def finalize_session(s, gid, pid):
    s.id, s.owner, s.host = gid, pid, pid
    if not s.max:
        s.max = 4
    s.numpart = 1
    s.skey = os.urandom(32)
    PIA_KEYS[gid] = s.skey
    log("[PIA] gid=%d session key=%s" % (gid, s.skey.hex()))
    s.started = n_datetime()
    s.sysen = 0
    while len(s.attribs) < 6:
        s.attribs.append(0)
    keys = [k for k, _, _ in s.params]
    if "@SR" not in keys: s.params.append(("@SR", 3, 1))
    if "@GIR" not in keys: s.params.append(("@GIR", 1, 3))
    return s


def mm_create(sess, s):
    with MM_LOCK:
        gid = MM.next_gid
        MM.next_gid += 1
        finalize_session(s, gid, sess.pid)
        MM.gatherings[gid] = dict(session=s, participants=[sess.pid], host_sess=sess)
    return s


def push_notification(target, source_pid, ntype, p1, p2, strp, p3):
    """Server -> client RMC request 0x0E/1 ProcessNotificationEvent (what Pia waits for after create/join)."""
    if target is None:
        return
    MM.notif_counter += 1
    body = n_struct(struct.pack("<QIQQ", source_pid, ntype, p1, p2) + n_str(strp) + struct.pack("<Q", p3), 0)
    pl = bytes([0x0E | 0x80]) + struct.pack("<II", 0xFFFE0000 + MM.notif_counter, 1) + body
    log("%s PUSH notification type=%d gid=%d p2=%d count=%d" % (target.tag, ntype, p1, p2, p3))
    target.send_rmc(struct.pack("<I", len(pl)) + pl)


def read_create_param(body):
    """CreateMatchmakeSessionParam / AutoMatchmakeParam: struct{ MatchmakeSession, list<pid> additional, u32 gid_check,
    u32 option, string join_message, u16 participation_count, ...}. Returns (session, dict)."""
    r = Rd(body)
    r.u8(); r.u32()
    s = MSession.parse(r)
    extra = dict(additional=[r.u64() for _ in range(min(r.u32(), 64))], gid_check=r.u32(), create_option=r.u32(),
                 join_message=r.string(), participation_count=r.u16(), trailing=r.rest().hex())
    return s, extra


def mm_dispatch(sess, proto, method, body):
    """Returns response body bytes, or None if not handled here. Raises on garbage (caller catches)."""
    r = Rd(body)
    if proto == 0x6D:
        if method in (38, 40):                     # CreateMatchmakeSessionWithParam / AutoMatchmakeWithParam_Postpone
            s, extra = read_create_param(body)
            log("%s   [MM] %s request: %s\n    extra=%s" % (
                sess.tag, "CreateMatchmakeSessionWithParam" if method == 38 else "AutoMatchmakeWithParam_Postpone", s.summary(), extra))
            log("%s   [MM]   appdata hint(utf16)=%r" % (sess.tag, utf16_hint(s.appdata)))
            joined = None
            if method == 40:
                with MM_LOCK:
                    for g in MM.gatherings.values():
                        c = g["session"]
                        if c.open and c.gamemode == s.gamemode and len(g["participants"]) < c.max and sess.pid not in g["participants"]:
                            g["participants"].append(sess.pid)
                            c.numpart = len(g["participants"])
                            joined = g
                            break
            if joined:
                out = joined["session"]
                parts = list(joined["participants"])
                host = joined["host_sess"]
            else:
                out = mm_create(sess, s)
                parts, host = [sess.pid], sess
            log("%s   [MM] -> gid=%d owner=%d participants=%s (%s)" % (sess.tag, out.id, out.owner, parts, "joined" if joined else "created"))
            if joined:
                sess.after.append(lambda g=joined, m=extra["join_message"]: notify_join(g, sess.pid, m))
            else:
                sess.after.append(lambda g=out.id, p=parts: [push_notification(sess, sess.pid, 3001, g, sess.pid, extra["join_message"], len(p))])
            return out.encode()
        if method == 39:                           # JoinMatchmakeSessionWithParam: struct{ gid u32, list<pid> additional, string join_message, ... }
            r2 = Rd(body); r2.u8(); r2.u32(); gid = r2.u32()
            rest = r2.rest()
            # JoinMatchmakeSessionParam: list<pid> additional, u32 gid_check, u32 option, u8 behavior, string user_pw,
            # string system_pw, string join_message, u16 participation_count, ...
            r3 = Rd(rest); [r3.u64() for _ in range(min(r3.u32(), 64))]; r3.u32(); r3.u32(); r3.u8(); r3.string(); r3.string()
            jmsg = r3.string()
            if r3.bad: jmsg = ""
            log("%s   [MM] JoinMatchmakeSessionWithParam gid=%d join_message=%r rest=%s" % (sess.tag, gid, jmsg, rest.hex()))
            full = False
            with MM_LOCK:
                g = MM.gatherings.get(gid)
                if g and sess.pid not in g["participants"]:
                    if len(g["participants"]) < (g["session"].max or 4):
                        g["participants"].append(sess.pid)
                        g["session"].numpart = len(g["participants"])
                    else:
                        full = True
            if not g:
                log("%s   [MM]   gid %d not registered (known: %s) -> SessionVoid" % (sess.tag, gid, sorted(MM.gatherings)))
                return ("ERR", 0x00030073)         # RendezVous::SessionVoid style; non-fatal for the client to handle
            if full:
                log("%s   [MM]   gid %d full -> SessionFull" % (sess.tag, gid))
                return ("ERR", 0x0003000C)         # RendezVous::SessionFull
            log("%s   [MM]   joined gid=%d participants=%s host=%d" % (sess.tag, gid, g["participants"], g["session"].host))
            sess.after.append(lambda: notify_join(g, sess.pid, jmsg))
            return g["session"].encode()
        if method in (1, 2):                       # Close/OpenParticipation(gid)
            gid = r.u32()
            with MM_LOCK:
                g = MM.gatherings.get(gid)
                if g: g["session"].open = 1 if method == 2 else 0
            log("%s   [MM] %sParticipation gid=%d known=%s" % (sess.tag, "Open" if method == 2 else "Close", gid, bool(g)))
            return b""
        if method == 12:                           # UpdateMatchmakeSessionAttribute(gid, list<u32>)
            gid = r.u32(); at = [r.u32() for _ in range(min(r.u32(), 64))]
            with MM_LOCK:
                g = MM.gatherings.get(gid)
                if g: g["session"].attribs = at
            log("%s   [MM] UpdateMatchmakeSessionAttribute gid=%d attribs=%s known=%s" % (sess.tag, gid, at, bool(g)))
            return b""
        if method == 11:                           # UpdateApplicationBuffer(gid, buffer)
            gid = r.u32(); buf = r.buffer()
            with MM_LOCK:
                g = MM.gatherings.get(gid)
                if g: g["session"].appdata = buf
            log("%s   [MM] UpdateApplicationBuffer gid=%d len=%d" % (sess.tag, gid, len(buf)))
            return b""
        if method == 8:                            # ModifyCurrentGameAttribute(gid, idx, value)
            gid, idx, val = r.u32(), r.u32(), r.u32()
            with MM_LOCK:
                g = MM.gatherings.get(gid)
                if g and idx < len(g["session"].attribs): g["session"].attribs[idx] = val
            log("%s   [MM] ModifyCurrentGameAttribute gid=%d idx=%d val=%d" % (sess.tag, gid, idx, val))
            return b""
        if method in (0x22, 0x2C, 9):              # UpdateProgressScore / UpdateMatchmakeSessionPart / UpdateNotificationData
            log("%s   [MM] method %d acked with empty success (body not decoded)" % (sess.tag, method))
            return b""
        if method in (0x29, 0x31):                 # FindMatchmakeSessionByGatheringIdDetail / BySingleID
            gid = r.u32()
            with MM_LOCK:
                g = MM.gatherings.get(gid)
            log("%s   [MM] FindMatchmakeSession(%d) gid=%d known=%s" % (sess.tag, method, gid, bool(g)))
            return g["session"].encode() if g else ("ERR", 0x00030073)
        if method == 0x30:                         # FindMatchmakeSessionByGatheringID(list<gid>) -> list<session>
            gids = [r.u32() for _ in range(min(r.u32(), 256))]
            with MM_LOCK:
                out = [MM.gatherings[g]["session"].encode() for g in gids if g in MM.gatherings]
            log("%s   [MM] FindByGatheringID %s -> %d" % (sess.tag, gids, len(out)))
            return n_list(out)
        if method == 0x34:       # BrowseMatchmakeSession* -> list<session> (criteria ignored)
            with MM_LOCK:
                out = [g["session"].encode() for g in MM.gatherings.values() if g["session"].open]
            log("%s   [MM] Browse(%d) criteria ignored -> %d open session(s)" % (sess.tag, method, len(out)))
            return n_list(out)
        if method in (0x33, 0x3C, 0x41, 10, 13):   # FindByParticipant / playing session / friends query / friend notif -> empty list
            log("%s   [MM] method %d -> empty list" % (sess.tag, method))
            return struct.pack("<I", 0)
    elif proto == 0x15:                            # MatchMaking
        if method == 2:                            # UnregisterGathering(gid) -> bool
            gid = r.u32()
            with MM_LOCK:
                g = MM.gatherings.get(gid)
                if g and g["session"].owner == sess.pid:
                    del MM.gatherings[gid]
            log("%s   [MM] UnregisterGathering gid=%d known=%s -> true" % (sess.tag, gid, bool(g)))
            return b"\x01"
        if method == 0x1B:                         # UpdateSessionURL(gid, url) -> bool
            log("%s   [MM] UpdateSessionURL gid=%d" % (sess.tag, r.u32()))
            return b"\x01"
        if method in (0x28, 0x2A):                 # UpdateSessionHost*
            log("%s   [MM] UpdateSessionHost(%d) acked" % (sess.tag, method))
            return b""
        if method == 0x29:                         # GetSessionURLs(gid) -> list<StationURL> of the gathering HOST
            gid = r.u32()
            with MM_LOCK:
                g = MM.gatherings.get(gid)
            if not g:
                log("%s   [MM] GetSessionURLs gid=%d not registered (known: %s) -> empty list" % (sess.tag, gid, sorted(MM.gatherings)))
                return n_list([])
            host = host_session(g)
            urls = reachable_urls(host)
            log("%s   [MM] GetSessionURLs gid=%d host=%s pid=%d state=%s\n    stored=%s\n    -> %s" % (
                sess.tag, gid, host.tag, host.pid, host.state, host.stations, urls))
            return n_list([n_str(u) for u in urls])
    elif proto == 0x32 and method == 1:            # MatchMakingExt EndParticipation(gid, string) -> bool
        gid = r.u32(); msg = r.string()
        with MM_LOCK:
            g = MM.gatherings.get(gid)
            if g and sess.pid in g["participants"] and sess.pid != g["session"].owner:
                g["participants"].remove(sess.pid)
                g["session"].numpart = len(g["participants"])
        log("%s   [MM] EndParticipation gid=%d msg=%r known=%s participants now %s" % (
            sess.tag, gid, msg, bool(g), g["participants"] if g else None))
        return b"\x01"
    return None


# ---------------------------------------------------------------- NATTraversal (protocol 0x03), per nextendo-nex nattraversal.go
#   1 RequestProbeInitiation(list<string> targets)  -> ack      2 InitiateProbe(StationURL string) -> ack
#   3 RequestProbeInitiationExt(list<string> targets, string station_to_probe) -> ack + push InitiateProbe (0x03/2) to each target (by RVCID)
#   4 ReportNATTraversalResult(u32 cid, bool result, u32 rtt)   7 ..Detail(u32 cid, bool result, u32 detail, u32 rtt)  -> ack
#   5 ReportNATProperties(u32 nat_mapping, u32 nat_filtering, u32 rtt) -> ack
#   6 GetRelaySignatureKey() -> i32 relay_mode, u64 current_utc_time, string relay_addr, u16 relay_port, i32 relay_addr_type, u32 game_server_id
#     (Nextendo advertises NO relay: mode 0, empty address, port 0, type 0, gsid 0 -- proven to proceed on the direct mesh.
#      -relay-host/-relay-port override that and fill the fields.)
def learn_cid(sess, url):
    """Remember a client's CID (the random 32-bit connection id it puts in its own station URLs; the server only ever sees
    it in NAT calls: station_to_probe, or a target URL a peer built from it). Returns True if it was new."""
    try:
        cid = int(url_parse(url)[1].get("CID", "0") or 0)
    except ValueError:
        return False
    if cid and getattr(sess, "cid", 0) != cid:
        sess.cid = cid
        log("%s   [NAT] learned CID=%d for pid=%s rvcid=%s" % (sess.tag, cid, getattr(sess, "pid", 0), getattr(sess, "rvcid", 0)))
        return True
    return False


def nat_dispatch(sess, method, body):
    r = Rd(body)
    if method == 6:
        host, port = CFG["relay_host"], CFG["relay_port"]
        out = (struct.pack("<iQ", 1 if host else 0, n_datetime()) + n_str(host) + struct.pack("<HiI", port, 0, CFG["game_server_id"]))
        log("%s   [NAT] GetRelaySignatureKey -> relay=%r:%d (empty = none advertised)" % (sess.tag, host, port))
        return out
    if method in (1, 2):
        log("%s   [NAT] %s body=%s -> ack" % (sess.tag, "RequestProbeInitiation" if method == 1 else "InitiateProbe", body.hex()))
        return b""
    if method == 3:
        targets = [r.string() for _ in range(min(r.u32(), 32))]
        station = r.string()
        log("%s   [NAT] RequestProbeInitiationExt targets=%s station_to_probe=%s" % (sess.tag, targets, station))
        learn_cid(sess, station)
        for t in targets:
            m = re.search(r"RVCID=(\d+)", t)
            tgt = MM.by_rvcid.get(int(m.group(1))) if m else None
            if tgt is not None:
                learn_cid(tgt, t)
            if tgt is None:
                log("%s   [NAT]   target %r not connected (no InitiateProbe pushed)" % (sess.tag, t))
                continue
            pl = bytes([0x03 | 0x80]) + struct.pack("<II", 0xFFFF0000 + (MM.notif_counter + 1), 2) + n_str(rewrite_station(station, sess))
            MM.notif_counter += 1
            tgt.send_rmc(struct.pack("<I", len(pl)) + pl)
            log("%s   [NAT]   pushed InitiateProbe to %s" % (sess.tag, tgt.tag))
        return b""
    if method in (4, 7):
        cid, res = r.u32(), r.u8()
        detail = r.u32() if method == 7 else 0
        rtt = r.u32()
        log("%s   [NAT] ReportNATTraversalResult%s cid=%d result=%d detail=%d rtt=%dms" % (sess.tag, "Detail" if method == 7 else "", cid, res, detail, rtt))
        return b""
    if method == 5:
        log("%s   [NAT] ReportNATProperties nat_mapping=%d nat_filtering=%d rtt=%d" % (sess.tag, r.u32(), r.u32(), r.u32()))
        return b""
    return None


class Session:
    """One PRUDP Lite connection (= one WebSocket). feed() never raises."""
    def __init__(self, tag, peer, send_ws):
        self.tag, self.send_ws = tag, send_ws
        self.ip, self.port = peer[0], peer[1]
        self.src = self.dst = None      # our (server) / peer virtual (type, port)
        self.connsig = None
        self.minor, self.funcs = SRV_MINOR, 0
        self.out_seq = 1
        self.frag = b""
        self.pid = 0
        self.state = "new"
        self.after = []
        self.stations = []
        self.cid = 0
        self.lock = threading.RLock()

    # -- outbound
    def tx(self, raw, note=""):
        try:
            log("%s OUT >>> %s binary len=%d\n%s\n    %s" % (self.tag, note, len(raw), hexdump(raw), decode_prudp_lite(raw)))
            with self.lock:
                self.send_ws(raw)
        except Exception as e:
            log("%s OUT send failed: %r" % (self.tag, e))

    def pkt(self, type_, flags, pid, payload=b"", frag=0, **kw):
        return encode_lite(type_, flags, self.src, self.dst, pid, frag, payload, **kw)

    def ack(self, p, note="ACK"):
        self.tx(self.pkt(p["type"], F_ACK, p["pid"], frag=p["frag"]), note)

    # -- inbound
    def feed(self, data):
        try:
            while data:
                p, data = parse_lite(data)
                log("%s IN  <<< decoded: %s" % (self.tag, describe_lite(p)))
                self.handle(p)
        except Exception as e:
            log("%s PRUDP error (ignored): %r\n%s" % (self.tag, e, hexdump(data)))
            if LOG_TRACE:
                import traceback
                log(traceback.format_exc())

    def handle(self, p):
        t, f = p["type"], p["flags"]
        if self.src is None or (t == T_SYN and not f & F_ACK):
            # respond AS the port the client targeted
            self.src, self.dst = (p["dst_type"], p["dst_port"]), (p["src_type"], p["src_port"])
        if t == T_SYN and not f & F_ACK:
            self.connsig = connection_signature(self.ip, self.port)
            self.minor = min(SRV_MINOR, p["minor"] if p["minor"] is not None else SRV_MINOR)
            self.funcs = 0   # TODO: nextendo uses (server funcs & client funcs); 0 is the safe subset
            self.out_seq, self.frag, self.state = 1, b"", "syn"
            self.tx(self.pkt(T_SYN, F_ACK | F_HASSIZE, 0, minor=self.minor, funcs=self.funcs, connsig=self.connsig),
                    "SYN|ACK (connsig=%s)" % self.connsig.hex())
        elif t == T_CONNECT and not f & F_ACK:
            self.on_connect(p)
        elif t == T_DATA:
            self.on_data(p)
        elif t == T_PING:
            if not f & F_ACK and f & F_NEEDACK:
                self.ack(p, "PING ACK")
        elif t == T_DISCONNECT:
            if not f & F_ACK:
                if f & F_NEEDACK:
                    self.ack(p, "DISCONNECT ACK")
                self.state = "closed"
        elif f & F_ACK:
            pass
        else:
            log("%s unknown packet type %d, flags %s" % (self.tag, t, flag_str(f)))
            if f & F_NEEDACK:
                self.ack(p, "ACK(unknown type)")

    def on_connect(self, p):
        sig = p["sig"]
        if sig is None:
            log("%s CONNECT carries NO signature option (id 128)" % self.tag)
        else:
            log("%s CONNECT signature=%s connsig_we_sent=%s  (sig = HMAC-MD5(md5(key), md5(key)||connsig); access key unknown)" % (
                self.tag, sig.hex(), self.connsig.hex() if self.connsig else None))
            for k in CFG["access_keys"]:
                ok = self.connsig and lite_connect_sig(k, self.connsig) == sig
                log("%s   candidate access key %r: %s" % (self.tag, k, "MATCH" if ok else "no"))
        resp = self.secure_login(p["payload"]) if p["payload"] else b""
        # IP fallback only for a secure CONNECT whose ticket we could not read. Auth-server CONNECTs carry no payload;
        # with two local instances (same IP) the fallback used to stamp the HOST's pid on the joiner's auth connection
        # and overwrite MM.sessions[host] -> GetSessionURLs returned [] -> joiner EndParticipation ("unable to join").
        if not self.pid and p["payload"]:
            self.pid = AUTH_PID_BY_IP.get(self.ip, 0)
            register_session(self.pid, self)
        self.state = "connected"
        self.tx(self.pkt(T_CONNECT, F_ACK | F_HASSIZE, p["pid"] or 1, resp, minor=self.minor, funcs=self.funcs), "CONNECT|ACK")

    def secure_login(self, pl):
        """CONNECT payload on the secure server = [buffer ticket][buffer request (kerberos, session key)].
        Response = [u32 4][u32 check+1]. Only works for tickets WE issued."""
        try:
            r = Rd(pl)
            ticket, req = r.buffer(), r.buffer()
            log("%s CONNECT payload len=%d ticket=%d request=%d" % (self.tag, len(pl), len(ticket), len(req)))
            rt = Rd(ticket)
            tkey, enc = rt.buffer(), rt.buffer()
            final = hashlib.md5(derive_key(CFG["secure_password"], CFG["secure_pid"]) + tkey).digest()
            body = kerb_dec(final, enc)
            if not body:
                log("%s   secure ticket not decryptable with our key (not issued by us)" % self.tag)
                return b""
            sess = body[16:16 + CFG["key_size"]]
            dec = kerb_dec(sess, req)
            if not dec or len(dec) < 16:
                log("%s   request not decryptable" % self.tag)
                return b""
            pid, cid, check = struct.unpack_from("<QII", dec, 0)
            self.pid = pid
            register_session(pid, self)
            log("%s   secure login ok pid=%d cid=%d check=%d" % (self.tag, pid, cid, check))
            return struct.pack("<II", 4, (check + 1) & 0xFFFFFFFF)
        except Exception as e:
            log("%s   secure_login error %r" % (self.tag, e))
            return b""

    def on_data(self, p):
        f = p["flags"]
        if f & (F_MULTIACK | F_ACK):
            return
        if f & F_NEEDACK:
            self.ack(p, "DATA ACK")
        self.frag += p["payload"]
        if p["frag"] == 0:
            msg, self.frag = self.frag, b""
            self.rmc(msg)

    # -- RMC
    def rmc(self, msg):
        r = Rd(msg)
        length = r.u32()
        pb = r.u8()
        proto = pb & 0x7F
        if proto == 0x7F:
            proto = r.u16()
        if not pb & 0x80 or r.bad or length != len(msg) - 4:
            log("%s RMC unparsable/response (len hdr=%d actual=%d)\n%s" % (self.tag, length, len(msg) - 4, hexdump(msg, 256)))
            return
        call, method = r.u32(), r.u32()
        body = r.rest()
        log("%s RMC REQUEST protocol=0x%02x method=%d call_id=%d body_len=%d\n%s" % (
            self.tag, proto, method, call, len(body), hexdump(body, 512)))
        try:
            out = self.dispatch(proto, method, body)
        except Exception as e:
            log("%s RMC handler error %r" % (self.tag, e))
            out = None
        if out is None:
            log("%s RMC UNHANDLED proto=0x%02x method=%d -> NotImplemented error" % (self.tag, proto, method))
            self.send_rmc(self.rmc_err(proto, call, RC_NOT_IMPL))
        elif isinstance(out, tuple) and out[0] == "ERR":
            log("%s RMC -> error 0x%08x" % (self.tag, out[1]))
            self.send_rmc(self.rmc_err(proto, call, out[1]))
        else:
            self.send_rmc(self.rmc_ok(proto, method, call, out))
        todo, self.after = self.after, []
        for fn in todo:
            try:
                fn()
            except Exception as e:
                log("%s post-response action failed %r" % (self.tag, e))

    @staticmethod
    def _pb(proto):
        return bytes([proto]) if proto < 0x7F else b"\x7f" + struct.pack("<H", proto)

    def rmc_ok(self, proto, method, call, body):
        pl = self._pb(proto) + b"\x01" + struct.pack("<II", call, method | 0x8000) + body
        return struct.pack("<I", len(pl)) + pl

    def rmc_err(self, proto, call, code):
        pl = self._pb(proto) + b"\x00" + struct.pack("<II", code | ERR, call)
        return struct.pack("<I", len(pl)) + pl

    def send_rmc(self, data):
        size = 1300
        chunks = [data[i:i + size] for i in range(0, len(data), size)] or [b""]
        with self.lock:                  # other connections push notifications into this one from their threads
            for i, c in enumerate(chunks):
                fid = 0 if i == len(chunks) - 1 else i + 1
                seq = self.out_seq
                self.out_seq += 1
                self.tx(self.pkt(T_DATA, F_RELIABLE | F_NEEDACK, seq, c, frag=fid), "DATA seq=%d frag=%d (RMC response)" % (seq, fid))

    def dispatch(self, proto, method, body):
        """Return response BODY bytes (success) or None (unknown -> NotImplemented). TODOs mark guessed fields."""
        r = Rd(body)
        out = nat_dispatch(self, method, body) if proto == 0x03 else mm_dispatch(self, proto, method, body)
        if out is not None:
            return out
        if (proto, method) in CFG["empty_list"]:
            return struct.pack("<I", 0)                       # empty list  (TODO: confirm real response shape)
        if proto == 0x0A and method in (1, 2):               # Login / LoginEx (TicketGranting)
            user = r.string()
            log("%s   [Auth] Login(Ex) username=%r extra=%d bytes" % (self.tag, user, len(r.rest())))
            pid = pid_for_user(user)
            AUTH_PID_BY_IP[self.ip] = pid
            self.pid = pid                                   # auth connection: identity only, not registered
            ticket, skey, _ = make_ticket(pid)
            return (struct.pack("<IQ", RC_OK, pid) + n_buf(ticket) + rvconn_data() +
                    n_str("MHGU-NEX") + n_str(skey.hex()))
        if proto == 0x0A and method == 6:                    # ValidateAndRequestTicketWithParam
            r.u8(); r.u32()                                  # struct header
            platform = r.u32()
            user = r.string()
            log("%s   [Auth] ValidateAndRequestTicketWithParam platform=%d username=%r extra=%d bytes" % (
                self.tag, platform, user, len(r.rest())))
            pid = pid_for_user(user)
            AUTH_PID_BY_IP[self.ip] = pid
            self.pid = pid                                   # auth connection: identity only, not registered
            log("%s   [Auth] -> account pid=%d" % (self.tag, pid))
            ticket, skey, _ = make_ticket(pid)
            c = (struct.pack("<Q", pid) + n_buf(ticket) + n_str(secure_station()) + struct.pack("<Q", n_datetime()) +
                 n_str("MHGU-NEX") + n_str(skey.hex()) + struct.pack("<Q", 0))   # trailing u64 per Nextendo MHGU note
            return n_struct(c)
        if proto == 0x0B and method in (1, 4):               # SecureConnection Register / RegisterEx
            n = r.u32()
            urls = [r.string() for _ in range(min(n, 16))]
            log("%s   [Secure] Register urls=%r" % (self.tag, urls))
            MM.next_rvcid += 1
            self.rvcid = MM.next_rvcid
            MM.by_rvcid[self.rvcid] = self
            pub = urls[0] if urls else "prudp:/"
            # Nextendo derives the public station from the local one: observed address/port, PID + RVCID, type=3
            kv = dict(x.split("=", 1) for x in pub.split(":/", 1)[-1].split(";") if "=" in x)
            kv.update(address=self.ip, port=str(self.port), PID=str(self.pid), RVCID=str(self.rvcid), type="3")
            pub = "prudp:/" + ";".join("%s=%s" % kv_ for kv_ in kv.items())
            # Stored station list (what GetSessionURLs hands out): [local, public], each with PID + RVCID like
            # nex-protocols-common-go. MHGU sends 2 URLs (port=1 local, port=2 public placeholder) and later
            # ReplaceURL(port=2 one, NAT-checked one); if it sent only one, the derived public station is used.
            def annot(u):
                sc, k = url_parse(u)
                k["PID"], k["RVCID"] = str(self.pid), str(self.rvcid)
                return url_format(sc, k)
            self.stations = [annot(u) for u in urls[:2]] if urls else []
            if len(self.stations) < 2:
                self.stations.append(pub)
            register_session(self.pid, self)
            log("%s   [Secure] -> public station %s\n    stored stations=%s" % (self.tag, pub, self.stations))
            return struct.pack("<II", RC_OK, self.rvcid) + n_str(pub)
        if proto == 0x0B and method == 8:                    # SendReport(u32 report_id, qbuffer data) -> nothing
            rid = r.u32(); n = r.u16(); data = r.take(n)
            log("%s   [Secure] SendReport id=%d data=%dB (%s)" % (self.tag, rid, n, data[:24].hex()))
            return b""
        if proto == 0x0B and method == 7:                    # ReplaceURL(string target, string new_url)
            tgt, new = r.string(), r.string()
            # match by (address, port) like nex-protocols-common-go; PID forced to the connection's
            sc, k = url_parse(new)
            k["PID"] = str(self.pid)
            new2 = url_format(sc, k)
            hit = [i for i, u in enumerate(self.stations) if url_key(u) == url_key(tgt)]
            for i in hit:
                self.stations[i] = new2
            if not hit:
                self.stations.append(new2)
            log("%s   [Secure] ReplaceURL target=%r new=%r %s\n    stored stations=%s" % (
                self.tag, tgt, new, "replaced #%s" % hit if hit else "NO MATCH (appended)", self.stations))
            return b""
        if proto == 0x0B and method == 5:                    # TestConnectivity
            return b""
        return None


# ---------------------------------------------------------------- I/O helpers
class Conn:
    def __init__(self, sock):
        self.s, self.buf = sock, b""

    def recv_some(self):
        d = self.s.recv(65536)
        return d

    def read_until(self, marker, maxlen=1 << 20):
        while marker not in self.buf:
            if len(self.buf) > maxlen:
                return None
            d = self.recv_some()
            if not d:
                return None
            self.buf += d
        i = self.buf.index(marker) + len(marker)
        r, self.buf = self.buf[:i], self.buf[i:]
        return r

    def read_n(self, n):
        while len(self.buf) < n:
            d = self.recv_some()
            if not d:
                raise EOFError
            self.buf += d
        r, self.buf = self.buf[:n], self.buf[n:]
        return r


def ws_send(sock, opcode, payload=b""):
    h = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        h += bytes([n])
    elif n < 65536:
        h += b"\x7e" + struct.pack(">H", n)
    else:
        h += b"\x7f" + struct.pack(">Q", n)
    sock.sendall(h + payload)


def ws_loop(c, tag, peer=("0", 0)):
    frag_op, frag_buf = None, b""
    sess = Session(tag, peer, lambda raw: ws_send(c.s, 0x2, raw))
    while True:
        b0, b1 = c.read_n(2)
        fin, op = b0 >> 7, b0 & 0xF
        masked, ln = b1 >> 7, b1 & 0x7F
        if ln == 126:
            ln, = struct.unpack(">H", c.read_n(2))
        elif ln == 127:
            ln, = struct.unpack(">Q", c.read_n(8))
        mask = c.read_n(4) if masked else None
        data = c.read_n(ln) if ln else b""
        if mask:
            data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
        if op == 0x9:
            log("%s WS PING len=%d" % (tag, len(data)))
            ws_send(c.s, 0xA, data)
            continue
        if op == 0xA:
            log("%s WS PONG len=%d" % (tag, len(data)))
            continue
        if op == 0x8:
            code = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else None
            log("%s WS CLOSE code=%s reason=%r" % (tag, code, data[2:]))
            try:
                ws_send(c.s, 0x8, data[:2])
            except OSError:
                pass
            return
        if op in (0x1, 0x2):
            frag_op, frag_buf = op, data
        elif op == 0x0:
            frag_buf += data
        else:
            log("%s WS unknown opcode %d" % (tag, op))
            continue
        if not fin:
            continue
        kind = "TEXT" if frag_op == 1 else "BINARY"
        msg = "%s WS %s message len=%d\n%s" % (tag, kind, len(frag_buf), hexdump(frag_buf))
        log(msg.replace(" WS ", " IN  <<< WS ", 1))
        if frag_op == 2:
            sess.feed(bytes(frag_buf))


def parse_headers(raw):
    lines = raw.decode("latin-1").split("\r\n")
    hdrs = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return lines[0], hdrs, [l for l in lines[1:] if l]


TL = threading.local()


def _sni_cb(s, name, c):
    TL.info["sni"] = name


def handle(sock, addr, ctx, port, kind):
    tag = "[%s:%d %s:%d]" % (addr[0], addr[1], kind, port)
    info = {}
    log("!!! ACCEPT %s:%d -> port %d (%s) !!!" % (addr[0], addr[1], port, kind))
    try:
        sock.settimeout(120)
        if kind == "auto":  # sniff: TLS ClientHello starts with 0x16
            first = sock.recv(1, socket.MSG_PEEK)
            if not first:
                log("%s closed before sending data" % tag)
                return
            if first[0] != 0x16:
                ctx = None
        if ctx:
            TL.info = info
            try:
                sock = ctx.wrap_socket(sock, server_side=True)
            except (ssl.SSLError, OSError) as e:
                log("%s TLS HANDSHAKE FAILED: %r (sni=%s)" % (tag, e, info.get("sni")))
                return
            log("%s TLS ok version=%s cipher=%s sni=%s alpn=%s" % (
                tag, sock.version(), sock.cipher()[0], info.get("sni"), sock.selected_alpn_protocol()))
        else:
            log("%s plain TCP connection" % tag)
        c = Conn(sock)
        while True:
            first = c.recv_some()
            if not first:
                log("%s closed by peer" % tag)
                return
            c.buf += first
            if not c.buf[:4] in HTTP_METHODS:
                log("%s non-HTTP raw bytes len=%d\n%s" % (tag, len(c.buf), hexdump(c.buf)))
                c.buf = b""
                # keep reading raw
                while True:
                    d = c.recv_some()
                    if not d:
                        log("%s closed by peer" % tag)
                        return
                    log("%s raw bytes len=%d\n%s" % (tag, len(d), hexdump(d)))
            raw = c.read_until(b"\r\n\r\n")
            if raw is None:
                log("%s incomplete HTTP request: %r" % (tag, c.buf[:200]))
                return
            reqline, hdrs, hl = parse_headers(raw)
            log("%s HTTP %s\n    %s" % (tag, reqline, "\n    ".join(hl)))
            if hdrs.get("upgrade", "").lower() == "websocket" and "sec-websocket-key" in hdrs:
                accept = base64.b64encode(hashlib.sha1(hdrs["sec-websocket-key"].encode() + WS_GUID).digest()).decode()
                resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n" % accept
                sp = hdrs.get("sec-websocket-protocol")
                if sp:
                    resp += "Sec-WebSocket-Protocol: %s\r\n" % sp.split(",")[0].strip()
                sock.sendall((resp + "\r\n").encode())
                log("%s WS upgrade accepted (subprotocol=%s)" % (tag, sp))
                ws_loop(c, tag, addr)
                return
            body = b"ok"
            clen = int(hdrs.get("content-length", "0") or 0)
            if clen:
                body_in = c.read_n(clen)
                log("%s HTTP request body len=%d\n%s" % (tag, clen, hexdump(body_in)))
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
            if hdrs.get("connection", "").lower() == "close":
                return
    except (EOFError, ConnectionError, socket.timeout, ssl.SSLError, OSError) as e:
        log("%s connection ended: %r" % (tag, e))
    except Exception as e:
        log("%s handler error: %r" % (tag, e))
    finally:
        try:
            sock.close()
        except Exception:
            pass


def serve_tcp(bind, port, ctx, kind):
    try:
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((bind, port))
        ls.listen(64)
    except OSError as e:
        log("LISTEN FAILED %s %s:%d: %s" % (kind, bind, port, e))
        return False
    log("listening %s %s:%d" % (kind, bind, port))

    def loop():
        while True:
            try:
                s, a = ls.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(s, a, ctx, port, kind), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return True


UDP_MODE = ["fill"]
UDP_NEXIP = [None]        # 4 bytes override for bytes 12-15 in fill mode
UDP_EXTIP = [None]        # 4 bytes override for bytes 8-11 (client IPv4) in fill mode
UDP_67 = [True]           # fill mode: also send a synthetic type 0x67 reply after 0x65/0x66 probes
UDP_SAME_SOCKET = [False]  # force replies from the receiving socket
DIFF_SOCKET_TYPES = (2, 3, 102)  # NAT-check types answered from the secondary socket (port+100)


def udp_reply(d, a):
    m = UDP_MODE[0]
    if m == "zero":
        return bytes(16)
    if m == "echo-ack":  # 4-byte BE counter + 1, rest identical
        return struct.pack(">I", (struct.unpack(">I", d[:4])[0] + 1) & 0xFFFFFFFF) + d[4:]
    if m == "fill":  # Nintendo NAT check: type kept, ext port + ext IPv4 filled from the observed source
        return d[:4] + struct.pack(">I", a[1]) + (UDP_EXTIP[0] or socket.inet_aton(a[0])) + (UDP_NEXIP[0] or d[12:16])
    return d


# ---- Pia 5.2 packet decoder (diagnostics): 12-byte header, AES-128-ECB body (key = matchmake SessionKey[:16]),
# 16-byte HMAC-MD5 trailer (key = SessionKey). The server knows every session key it issued, so it can decode the
# type-2 probe/mesh datagrams the host sends to the NAT-test port (33335) and say whether the signature checks.
PIA_KEYS = {}            # gid -> 32-byte session key


def _aes_tables():
    sb = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80: q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) & 0xFF ^ ((q << 2) | (q >> 6)) & 0xFF ^ ((q << 3) | (q >> 5)) & 0xFF ^ ((q << 4) | (q >> 4)) & 0xFF
        sb[p] = (x ^ 0x63) & 0xFF
        if p == 1: break
    sb[0] = 0x63
    return sb, [sb.index(i) for i in range(256)]


_SB, _ISB = _aes_tables()


def _xt(a): return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _gm(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a = _xt(a); b >>= 1
    return r


def aes128_ecb_decrypt(key, data):
    rk = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rc = 1
    for i in range(4, 44):
        t = list(rk[i - 1])
        if i % 4 == 0:
            t = [_SB[t[1]] ^ rc, _SB[t[2]], _SB[t[3]], _SB[t[0]]]
            rc = _xt(rc)
        rk.append([a ^ b for a, b in zip(rk[i - 4], t)])
    rkb = [sum(rk[r * 4:r * 4 + 4], []) for r in range(11)]
    out = bytearray()
    for o in range(0, len(data) - len(data) % 16, 16):
        st = [a ^ b for a, b in zip(data[o:o + 16], rkb[10])]
        for rnd in range(9, -1, -1):
            st = [st[0], st[13], st[10], st[7], st[4], st[1], st[14], st[11], st[8], st[5], st[2], st[15], st[12], st[9], st[6], st[3]]
            st = [_ISB[v] ^ rkb[rnd][i] for i, v in enumerate(st)]
            if rnd:
                n = []
                for c in range(4):
                    a = st[c * 4:c * 4 + 4]
                    n += [_gm(a[0], 14) ^ _gm(a[1], 11) ^ _gm(a[2], 13) ^ _gm(a[3], 9), _gm(a[0], 9) ^ _gm(a[1], 14) ^ _gm(a[2], 11) ^ _gm(a[3], 13),
                          _gm(a[0], 13) ^ _gm(a[1], 9) ^ _gm(a[2], 14) ^ _gm(a[3], 11), _gm(a[0], 11) ^ _gm(a[1], 13) ^ _gm(a[2], 9) ^ _gm(a[3], 14)]
                st = n
        out += bytes(st)
    return bytes(out)


def pia_decode(d):
    """Return a log string describing a Pia type-2 datagram (header, signature check against every known session key, plaintext words)."""
    if len(d) < 28 or d[:4] != bytes.fromhex("32ab9864") or d[4] != 2:
        return ""
    hdr, ct, sig = d[:12], d[12:-16], d[-16:]
    for gid, key in list(PIA_KEYS.items()):
        for kk in (key, key[:16]):
            if hmac.new(kk, d[:-16], hashlib.md5).digest() == sig:
                pt = aes128_ecb_decrypt(key[:16], ct)
                return "PIA hdr=%s sig=OK gid=%d keylen=%d plain=%s" % (hdr.hex(), gid, len(kk), " ".join(pt[i:i + 4].hex() for i in range(0, len(pt), 4)))
    return "PIA hdr=%s sig=NO KEY MATCHES (%d session keys tried; trailer HMAC-MD5 assumption wrong or key is not SessionKey)" % (hdr.hex(), len(PIA_KEYS))


PROBE_PORTS = set()       # UDP ports whose non-16-byte datagrams go to probe_reply (default 33335)
PROBE_MODE = ["echo"]


def probe_kind(d):
    if d[:2] == b"\xea\xd0":
        return "PRUDPv1"
    if d[:4] == b"\x32\xab\x98\x64":
        return "Pia"
    return "unknown"


def probe_reply(us, port, d, a):
    """Game datagram on the hard-coded port 33335 (the game's NAT-test service, sibling of the
    33334 type-0 check; built from the string "NATTestId_Dummy" at 0x13156F8). Without a listener
    Windows returns ICMP port-unreachable -> WSAECONNRESET -> the game aborts the session.
    Format still unconfirmed: logged in full; default reply echoes the datagram unchanged."""
    log("[%s:%d udp:%d] PROBE IN <<< len=%d kind=%s hex=%s" % (a[0], a[1], port, len(d), probe_kind(d), d.hex()))
    try:
        pd = pia_decode(d)
        if pd:
            log("[%s:%d udp:%d] %s" % (a[0], a[1], port, pd))
    except Exception as e:
        log("pia_decode failed: %r" % (e,))
    m = PROBE_MODE[0]
    if m == "silent":
        return
    r = d if m == "echo" else bytes(len(d))
    try:
        us.sendto(r, a)
        log("[%s:%d udp:%d] PROBE OUT >>> mode=%s len=%d %s" % (a[0], a[1], port, m, len(r), r.hex()))
    except OSError as e:
        log("[%s:%d udp:%d] PROBE OUT failed: %s" % (a[0], a[1], port, e))


LOOPBACK_ALIASES = ["127.0.0.2", "127.0.0.3"]
UDP_ALIASES = [True]


def serve_udp(bind, port):
    """Open the UDP responder. With a wildcard bind, also bind 127.0.0.2/.3 (the game's nncs1/nncs2
    stand-ins when the emulator redirects every Nintendo host to loopback) so replies carry the
    address the datagram was sent to as their source; the game drops datagrams from unexpected IPs.
    SO_REUSEADDR lets the specific binds coexist with the wildcard one (most specific wins)."""
    alias = UDP_ALIASES[0] and bind in ("0.0.0.0", "")
    ok = _serve_udp_one(bind, port, alias)
    if ok and alias:
        for ip in LOOPBACK_ALIASES:
            _serve_udp_one(ip, port, True)
    return ok


def _serve_udp_one(bind, port, reuse=False):
    try:
        us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if reuse:
            us.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        us.bind((bind, port))
    except OSError as e:
        log("LISTEN FAILED udp %s:%d: %s" % (bind, port, e))
        return False
    log("listening udp %s:%d" % (bind, port))
    sec = None
    try:
        if UDP_SAME_SOCKET[0]:
            raise OSError("secondary reply socket disabled (-udp-same-socket)")
        sec = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if reuse:
            sec.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sec.bind((bind, port + 100))
        log("listening udp %s:%d (secondary reply socket for %d)" % (bind, port + 100, port))
    except OSError:
        sec = None

    def loop():
        while True:
            try:
                d, a = us.recvfrom(65536)
            except OSError:
                continue
            log("[%s:%d udp:%d] packet len=%d\n%s" % (a[0], a[1], port, len(d), hexdump(d)))
            if len(d) != 16 and port in PROBE_PORTS:
                probe_reply(us, port, d, a)
                continue
            if len(d) == 16:
                t, p_, ip_, nx = struct.unpack(">IIII", d)
                log("[%s:%d udp:%d] UDP IN <<< type=0x%x(%d) port=%d ip=%s nexip=%s" % (
                    a[0], a[1], port, t, t, p_, socket.inet_ntoa(struct.pack(">I", ip_)), socket.inet_ntoa(struct.pack(">I", nx))))
                r = udp_reply(d, a)
                out = us
                if not UDP_SAME_SOCKET[0] and sec is not None and t in DIFF_SOCKET_TYPES:
                    out = sec
                try:
                    out.sendto(r, a)
                    log("[%s:%d udp:%d] UDP OUT >>> mode=%s type=0x%x from=%d to=%s:%d %s" % (
                        a[0], a[1], port, UDP_MODE[0], t, out.getsockname()[1], a[0], a[1], r.hex(" ")))
                except OSError as e:
                    log("[%s:%d udp:%d] UDP OUT failed: %s" % (a[0], a[1], port, e))
                if UDP_MODE[0] == "fill" and UDP_67[0] and t in (0x65, 0x66):
                    want67 = True
                    if t == 0x65:
                        seen65.add(a)
                    elif a in seen65 or a in sent67:
                        want67 = False
                    if want67:
                        sent67.add(a)
                        r67 = struct.pack(">I", 0x67) + r[4:]
                        try:
                            us.sendto(r67, a)
                            log("[%s:%d udp:%d] UDP OUT >>> mode=fill type=0x67 (synthetic) from=%d to=%s:%d %s" % (
                                a[0], a[1], port, us.getsockname()[1], a[0], a[1], r67.hex(" ")))
                        except OSError as e:
                            log("[%s:%d udp:%d] UDP OUT (synthetic 0x67) failed: %s" % (a[0], a[1], port, e))
    seen65, sent67 = set(), set()
    threading.Thread(target=loop, daemon=True).start()
    return True


def prange(s):
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            out += range(int(a), int(b) + 1)
        else:
            out.append(int(part))
    return out


def main():
    global LOG_FH
    ap = argparse.ArgumentParser(description="NEX capture/stub server")
    ap.add_argument("-bind", default="0.0.0.0")
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("-log", default=os.path.join(here, "capture.log"))
    ap.add_argument("-certs", default=os.path.join(here, "certs"))
    ap.add_argument("-tls-ports", default="443", help="TLS-only ports (comma/range list)")
    ap.add_argument("-auto-ports", default="60000-60010,47873",
                    help="ports that sniff the first byte: TLS (wss://) or plain (ws://) on the SAME port")
    ap.add_argument("-plain-ports", default="", help="plain-TCP-only ports")
    ap.add_argument("-udp-ports", default="10025,10026,47873,33334")
    ap.add_argument("-udp-probe-ports", default="33335",
                    help="UDP ports (also opened) whose non-16-byte datagrams are logged in full and answered per -udp-probe-reply")
    ap.add_argument("-udp-probe-reply", choices=("echo", "zero", "silent"), default="echo",
                    help="reply to probe-port datagrams: echo (same bytes, default), zero (same length of zeros), silent (log only)")
    ap.add_argument("-udp-reply", choices=("fill", "echo", "echo-ack", "zero"), default="fill",
                    help="reply to 16-byte UDP datagrams: fill (NAT check: type kept, src port/IP filled, default), echo (identical), echo-ack (BE counter+1), zero (16 zero bytes)")
    ap.add_argument("-udp-nexip", default="", help="A.B.C.D written into bytes 12-15 in fill mode (default: keep as received)")
    ap.add_argument("-udp-extip", default="", help="A.B.C.D written into bytes 8-11 (client IPv4) in fill mode (default: observed source IP)")
    ap.add_argument("-no-udp-67", action="store_true",
                    help="fill mode: do not send the synthetic type 0x67 reply after 0x65/0x66 probes")
    ap.add_argument("-udp-same-socket", action="store_true",
                    help="always reply from the receiving socket (default: types 2/3/102 are answered from a secondary socket on listen port+100)")
    ap.add_argument("-no-loopback-aliases", action="store_true",
                    help="with a wildcard -bind, do not also bind UDP 127.0.0.2/127.0.0.3 (replies would then come from the wildcard socket)")
    ap.add_argument("-udp-extra", default="", help="extra UDP ports answered like -udp-ports, e.g. 13954,10535")
    ap.add_argument("-secure-host", default="127.0.0.1", help="address put in the secure-server station URL we hand out")
    ap.add_argument("-secure-port", type=int, default=443)
    ap.add_argument("-access-keys", default="", help="comma list of candidate access keys tested against CONNECT signatures")
    ap.add_argument("-empty-list", default="", help="proto:method pairs (hex proto, dec method) answered with an empty list, e.g. 6d:5")
    ap.add_argument("-relay-host", default="", help="relay address advertised in GetRelaySignatureKey (default none, as Nextendo)")
    ap.add_argument("-relay-port", type=int, default=0)
    ap.add_argument("-no-url-rewrite", action="store_true",
                    help="hand out host station URLs exactly as the client registered them (default: address -> observed IP, placeholder port -> NAT-checked port)")
    ap.add_argument("-no-cid-stamp", action="store_true",
                    help="do not stamp each client's learned CID into handed-out/pushed station URLs")
    ap.add_argument("-url-address", default="", help="address written into handed-out station URLs (default: the IP we see the client on)")
    ap.add_argument("-public-ip", default="", help="tunnel/NAT hosting: public IPv4 advertised in station URLs and NAT-check replies (= -url-address + -udp-extip)")
    ap.add_argument("-public-ips", default="", help="per-client public IPs for tunnelled clients (all seen as 127.0.0.1): comma list of PID=IP and/or bare IPs "
                    "(bare IPs go to the first distinct PIDs that register, in order)")
    ap.add_argument("-trace", action="store_true")
    a = ap.parse_args()
    CFG["url_rewrite"], CFG["url_address"] = not a.no_url_rewrite, a.url_address
    CFG["cid_stamp"] = not a.no_cid_stamp
    if a.public_ip:
        CFG["url_address"] = CFG["url_address"] or a.public_ip
        a.udp_extip = a.udp_extip or a.public_ip
    for it in filter(None, (x.strip() for x in a.public_ips.split(","))):
        if "=" in it:
            k, v = it.split("=", 1)
            CFG["ip_map"][int(k)] = v.strip()
        else:
            CFG["ip_pool"].append(it)
    global LOG_TRACE
    LOG_TRACE = a.trace
    CFG["secure_host"], CFG["secure_port"] = a.secure_host, a.secure_port
    CFG["relay_host"], CFG["relay_port"] = a.relay_host, a.relay_port
    CFG["access_keys"] = [k for k in a.access_keys.split(",") if k]
    for pm in filter(None, a.empty_list.split(",")):
        pr, me = pm.split(":")
        CFG["empty_list"].add((int(pr, 16), int(me)))
    LOG_FH = open(a.log, "a", encoding="utf-8")
    crt, key = ensure_cert(a.certs)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    import warnings; warnings.simplefilter("ignore", DeprecationWarning)
    try: ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception: pass
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ctx.sni_callback = _sni_cb
    ctx.load_cert_chain(crt, key)
    ctx.set_alpn_protocols(["http/1.1"])
    for p in prange(a.tls_ports):
        serve_tcp(a.bind, p, ctx, "tls")
    for p in prange(a.auto_ports):
        serve_tcp(a.bind, p, ctx, "auto")
    for p in prange(a.plain_ports):
        serve_tcp(a.bind, p, None, "plain")
    UDP_MODE[0] = a.udp_reply
    UDP_NEXIP[0] = socket.inet_aton(a.udp_nexip) if a.udp_nexip else None
    UDP_EXTIP[0] = socket.inet_aton(a.udp_extip) if a.udp_extip else None
    UDP_SAME_SOCKET[0] = a.udp_same_socket
    UDP_67[0] = not a.no_udp_67
    UDP_ALIASES[0] = not a.no_loopback_aliases
    udp = prange(a.udp_ports) + [x for x in prange(a.udp_extra) if x not in prange(a.udp_ports)]
    PROBE_PORTS.update(prange(a.udp_probe_ports))
    PROBE_MODE[0] = a.udp_probe_reply
    udp += [x for x in sorted(PROBE_PORTS) if x not in udp]
    if a.relay_port and a.relay_port not in udp:
        udp.append(a.relay_port)
    for p in udp:
        serve_udp(a.bind, p)
    log("ready; log -> %s" % os.path.abspath(a.log))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
