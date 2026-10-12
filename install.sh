#!/usr/bin/env python3
"""
imonitor-cli — a script-only, no-web-panel reimplementation of the practical
feature set of iMonitor (https://github.com/IranMonitor/IMonitor).

Everything is driven from the command line and stored in a local SQLite
database + JSON config under ~/.imonitor/. There is no HTTP server, no admin
panel, no public status page server — only commands you run yourself (you
can still produce a status.json file with `monitor status` and serve it
however you like, e.g. a cron job + any static file host, if you ever want
one).

Design notes / scope
--------------------------------------
This covers the parts of iMonitor that map onto standard Linux tooling
(ip, wg, tc, iptables, socat, curl, ping, ssh) -- no web panel, no compiled
helper binaries, CLI/script only, by design. Deliberately out of scope:
  - the XDP/eBPF "paired rewrite" SNAT mode: this needs a custom compiled,
    kernel-verifier-passing eBPF object (xdp_ingress.o) loaded via
    `ip link ... xdp obj`, which plain shell tooling can't produce -- a
    Linux kernel requirement, not a feature of the web panel. Decision:
    skip it. `net snat` below (connection-tracked iptables SNAT) is the
    supported substitute, and covers the same NAT need for everything
    except very-high-packet-rate stateless rewriting.
  - full VMess/VLESS/Trojan/Shadowsocks proxying beyond the "direct"
    TCP-listener reachability check: needs Xray installed separately,
    same as the original project's own documented "Direct mode"
    limitation (not a gap vs. the real app -- it has the same limit).
    This script NEVER installs xray or anything xray-related — it only
    writes an Xray-compatible JSON config file and drives an already
    present `xray` binary. If you already run your own panel/stack that
    pushes traffic through xray, you can ignore the `proxy` subcommand
    entirely; nothing here touches it.
  - the hosted "Radar" central probe network (needs iMonitor's own
    central infrastructure; no local script can reproduce it).
  - EtherIP managed creation (the original project also rejects this on
    standard Linux; only monitoring an externally-created EtherIP
    interface is possible either way -- not a gap).
  - XLSX/PDF export (CSV + JSON are provided instead; say the word if you
    want XLSX/PDF added).

Everything else (10 monitor check types, every other tunnel encapsulation,
firewall/NAT/shaping controls, backups, Telegram alerts, speed tests) is
implemented for real below — entirely via CLI, no web panel, no external
binaries required.

Runtime dependencies (install what you actually use):
  ping, curl, ip, tc, iptables/ip6tables, wg (wireguard-tools), socat,
  ssh/sshpass, tar/gzip/xz/zip, aws-cli (for S3 backups), dig (optional,
  improves DNS record-type checks), haproxy (optional, only if you choose
  the haproxy forwarding method instead of iptables)

Usage:
  python3 imonitor_cli.py                 # no args -> interactive menu (role-based:
                                            # per protocol, choose Install Server for the
                                            # Iran box or Install Client for the Kharej box)
  python3 imonitor_cli.py --help
  python3 imonitor_cli.py monitor --help
  python3 imonitor_cli.py tunnel --help
  python3 imonitor_cli.py net --help
  python3 imonitor_cli.py backup --help
  python3 imonitor_cli.py notify --help

The interactive menu covers every tunnel mode (role = Install Server --> this
is the Iran box, inner 10.10.10.2 by default; Install Client --> this is the
Kharej/foreign box, inner 10.10.10.1 by default), auto-detects this box's own
outer IPv4/IPv6 address (so only the PEER's address is ever asked), applies a
shared dedicated MTU to every tunnel interface, verifies the peer inner-IP
ping after bringing each tunnel up, then ALWAYS asks (on either role; leave
blank to skip) for a comma-separated port list and wires up forwarding for
each through the tunnel automatically, via iptables or haproxy. A final
"Remove ALL" menu entry tears down every tunnel and net rule this script has
applied, and a "Status" entry shows live state for every tunnel.
All of this is also reachable without the menu via plain CLI flags (see
--help), for scripting/cron use.
"""
from types import SimpleNamespace

import argparse
import csv
import ftplib
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import sqlite3
import subprocess
import sys
import tarfile
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Paths / globals
# --------------------------------------------------------------------------

HOME_DIR = Path(os.environ.get("IMONITOR_HOME", str(Path.home() / ".imonitor")))
DB_PATH = HOME_DIR / "imonitor.db"
DRY_RUN = False

# --------------------------------------------------------------------------
# Shared Iran <-> Kharej tunnel defaults
# --------------------------------------------------------------------------
DEFAULT_TUNNEL_PORT = 2058   # shared port default for every protocol that needs one
DEFAULT_PSK = "123"          # default WireGuard preshared key (override for real deployments)
DEFAULT_MTU = 1367           # dedicated MTU applied to every tunnel interface


def ensure_home():
    HOME_DIR.mkdir(parents=True, exist_ok=True)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def eprint(*a, **kw):
    print(*a, file=sys.stderr, **kw)


def die(msg, code=1):
    eprint(f"error: {msg}")
    sys.exit(code)


# --------------------------------------------------------------------------
# Shell helper — every privileged/system action goes through here so
# --dry-run can show exactly what would run without touching the system.
# --------------------------------------------------------------------------

def run(cmd, check=True, capture=False, input_text=None, shell=False):
    """Run a system command. cmd is a list unless shell=True."""
    display = cmd if shell else " ".join(shlex.quote(c) for c in cmd)
    if DRY_RUN:
        print(f"[dry-run] {display}")
        class _R:
            returncode = 0
            stdout = ""
            stderr = ""
        return _R()
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            check=check,
            capture_output=capture,
            text=True,
            input=input_text,
        )
        return result
    except FileNotFoundError as e:
        die(f"required tool not found: {e}")
    except subprocess.CalledProcessError as e:
        if capture:
            eprint(e.stdout or "")
            eprint(e.stderr or "")
        die(f"command failed ({display})")


def which(tool):
    from shutil import which as _which
    return _which(tool) is not None


def clean_vars(namespace):
    """argparse.Namespace -> plain JSON-serializable dict (drops the
    non-serializable `func` callback that set_defaults(func=...) attaches)."""
    return {k: v for k, v in vars(namespace).items() if k != "func"}


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS monitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,
    target TEXT NOT NULL,
    port INTEGER,
    path TEXT,
    method TEXT,
    expect_status TEXT,
    expect_body TEXT,
    family INTEGER DEFAULT 4,
    interval_sec INTEGER NOT NULL DEFAULT 60,
    timeout_sec REAL NOT NULL DEFAULT 5,
    extra_json TEXT,
    public INTEGER NOT NULL DEFAULT 0,
    folder TEXT,
    fail_threshold INTEGER NOT NULL DEFAULT 3,
    consecutive_fail INTEGER NOT NULL DEFAULT 0,
    last_run_ts REAL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    ts REAL NOT NULL,
    success INTEGER NOT NULL,
    latency_ms REAL,
    message TEXT,
    FOREIGN KEY(monitor_id) REFERENCES monitors(id)
);
CREATE INDEX IF NOT EXISTS idx_results_monitor_ts ON results(monitor_id, ts);

CREATE TABLE IF NOT EXISTS tunnels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    mode TEXT NOT NULL,
    iface TEXT,
    config_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS net_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    kind TEXT NOT NULL,          -- snat | forward | shape | tcplimit | watch
    config_json TEXT NOT NULL,
    applied INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    config_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    protocol TEXT NOT NULL,       -- vmess | vless | trojan | shadowsocks
    link TEXT NOT NULL,
    parsed_json TEXT NOT NULL,
    xray_config_path TEXT NOT NULL,
    socks_port INTEGER NOT NULL,
    http_port INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"""


def db():
    ensure_home()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def kv_get(key, default=None):
    conn = db()
    row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def kv_set(key, value):
    conn = db()
    conn.execute(
        "INSERT INTO kv(key, value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Telegram notifications
# --------------------------------------------------------------------------

def telegram_send(text):
    token = kv_get("telegram_token")
    chat_ids = kv_get("telegram_chat_ids")
    if not token or not chat_ids:
        eprint("telegram not configured (use: notify telegram set --token ... --chat-id ...)")
        return False
    ok_all = True
    for chat_id in [c.strip() for c in chat_ids.split(",") if c.strip()]:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        try:
            if DRY_RUN:
                print(f"[dry-run] telegram -> chat {chat_id}: {text}")
                continue
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except Exception as e:
            eprint(f"telegram send failed for chat {chat_id}: {e}")
            ok_all = False
    return ok_all


# --------------------------------------------------------------------------
# Monitor check implementations
# Each returns (success: bool, latency_ms: float|None, message: str)
# --------------------------------------------------------------------------

def _measure(fn):
    t0 = time.monotonic()
    try:
        ok, msg = fn()
    except Exception as e:
        ok, msg = False, str(e)
    latency_ms = (time.monotonic() - t0) * 1000.0
    return ok, latency_ms, msg


def check_icmp(target, family, timeout):
    def fn():
        ping_bin = "ping6" if family == 6 and which("ping6") else "ping"
        fam_flag = ["-6"] if family == 6 and ping_bin == "ping" else []
        cmd = [ping_bin, *fam_flag, "-c", "1", "-W", str(max(1, int(timeout))), target]
        r = run(cmd, check=False, capture=True)
        if r.returncode == 0:
            return True, "reply ok"
        return False, (r.stdout + r.stderr).strip()[-300:] or "no reply"
    return _measure(fn)


def check_tcp(target, port, family, timeout):
    def fn():
        fam = socket.AF_INET6 if family == 6 else socket.AF_INET
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
        return True, "connected"
    return _measure(fn)


def check_udp(target, port, family, timeout, payload=b"ping", expect=None):
    def fn():
        fam = socket.AF_INET6 if family == 6 else socket.AF_INET
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (target, port))
            if expect is None:
                return True, "sent (unverified/degraded: no response check configured)"
            data, _ = s.recvfrom(4096)
            if expect.encode() in data:
                return True, "response matched"
            return False, f"unexpected response: {data[:80]!r}"
    return _measure(fn)


def check_http(target, path, method, expect_status, expect_body, timeout, headers=None, scheme="https"):
    def fn():
        url = f"{scheme}://{target}{path or '/'}"
        req = urllib.request.Request(url, method=method or "GET")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        ctx = None
        try:
            import ssl
            ctx = ssl._create_unverified_context() if scheme == "https" else None
        except Exception:
            ctx = None
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                status = resp.status
                body = resp.read(65536).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read(65536).decode("utf-8", "replace") if e.fp else ""
        expected_codes = [int(x) for x in str(expect_status or 200).split(",")]
        if status not in expected_codes:
            return False, f"status {status}, expected {expected_codes}"
        if expect_body and expect_body not in body:
            return False, f"status {status} ok, but expected body text not found"
        return True, f"status {status}"
    return _measure(fn)


def check_dns(server, port, name, rtype, min_answers, timeout, family):
    def fn():
        if which("dig"):
            fam_flag = ["-6"] if family == 6 else ["-4"]
            cmd = ["dig", *fam_flag, f"@{server}", "-p", str(port or 53),
                   name, rtype or "A", "+time=" + str(max(1, int(timeout))),
                   "+tries=1", "+short"]
            r = run(cmd, check=False, capture=True)
            lines = [l for l in r.stdout.splitlines() if l.strip()]
            if len(lines) >= (min_answers or 1):
                return True, f"{len(lines)} answer(s)"
            return False, f"{len(lines)} answer(s), expected >= {min_answers or 1}"
        # fallback: basic A/AAAA only, no custom server/port support
        fam = socket.AF_INET6 if family == 6 else socket.AF_INET
        infos = socket.getaddrinfo(name, None, fam)
        if len(infos) >= (min_answers or 1):
            return True, f"{len(infos)} answer(s) (fallback resolver, dig not installed)"
        return False, "no answers (install `dig` for full record-type/server support)"
    return _measure(fn)


def check_ssh_banner(target, port, family, timeout, expect_prefix="SSH-"):
    def fn():
        fam = socket.AF_INET6 if family == 6 else socket.AF_INET
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port or 22))
            banner = s.recv(256).decode("utf-8", "replace").strip()
        if banner.startswith(expect_prefix):
            return True, banner
        return False, f"unexpected banner: {banner!r}"
    return _measure(fn)


def check_ftp(target, port, family, timeout, user=None, password=None):
    def fn():
        ftp = ftplib.FTP(timeout=timeout)
        ftp.connect(target, port or 21)
        welcome = ftp.getwelcome()
        if user:
            ftp.login(user, password or "")
        ftp.quit()
        return True, welcome
    return _measure(fn)


def check_rdp(target, port, family, timeout):
    # Approximate: RDP negotiation requires sending a TPKT/X.224 Connection
    # Request and checking for a Connection Confirm. We do a minimal
    # negotiation rather than just a bare TCP connect.
    def fn():
        fam = socket.AF_INET6 if family == 6 else socket.AF_INET
        cr = bytes.fromhex(
            "0300000b06e00000000000"
        )  # TPKT + X.224 Connection Request, no negotiation data
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port or 3389))
            s.sendall(cr)
            data = s.recv(64)
        if len(data) >= 4 and data[0] == 0x03:
            return True, "RDP negotiation response received"
        return False, "no valid RDP response"
    return _measure(fn)


def check_proxy_direct(target, port, family, timeout):
    """'Direct mode' — TCP reachability of the proxy entry port only.
    Matches the original project's documented limitation: this does not
    prove an authenticated VMess/VLESS/Trojan/Shadowsocks/WireGuard session."""
    return check_tcp(target, port, family, timeout)


def check_tunnel_health(iface, peer_inner_ip, timeout, require_traffic=False, prev_counters=None):
    def fn():
        state_path = Path(f"/sys/class/net/{iface}/operstate")
        if not state_path.exists():
            return False, f"interface {iface} does not exist"
        state = state_path.read_text().strip()
        msgs = [f"state={state}"]
        ok = True
        if peer_inner_ip:
            r = run(["ping", "-c", "1", "-W", str(max(1, int(timeout))),
                     "-I", iface, peer_inner_ip], check=False, capture=True)
            if r.returncode != 0:
                ok = False
                msgs.append("peer ping failed")
            else:
                msgs.append("peer ping ok")
        if require_traffic:
            rx = int(Path(f"/sys/class/net/{iface}/statistics/rx_bytes").read_text())
            tx = int(Path(f"/sys/class/net/{iface}/statistics/tx_bytes").read_text())
            if prev_counters:
                prx, ptx = prev_counters
                if rx <= prx or tx <= ptx:
                    ok = False
                    msgs.append("no RX/TX increment since last check")
                else:
                    msgs.append("RX/TX increasing")
            kv_set(f"tunnel_counters_{iface}", json.dumps([rx, tx]))
        return ok, "; ".join(msgs)
    return _measure(fn)


# --------------------------------------------------------------------------
# Monitor commands
# --------------------------------------------------------------------------

MONITOR_TYPES = ["icmp", "tcp", "udp", "http", "https", "dns", "ssh", "ftp",
                  "rdp", "proxy", "tunnel"]


def cmd_monitor_add(args):
    conn = db()
    extra = {}
    if args.type == "udp":
        extra["payload"] = args.udp_payload
        extra["expect"] = args.udp_expect
    if args.type == "dns":
        extra["rtype"] = args.dns_type
        extra["min_answers"] = args.dns_min_answers
        extra["dns_port"] = args.dns_port
    if args.type == "tunnel":
        extra["iface"] = args.tunnel_iface
        extra["peer_inner_ip"] = args.tunnel_peer_ip
        extra["require_traffic"] = args.tunnel_require_traffic
    if args.type == "ftp":
        extra["user"] = args.ftp_user
        extra["password"] = args.ftp_password
    if args.headers:
        try:
            extra["headers"] = json.loads(args.headers)
        except json.JSONDecodeError:
            die("--headers must be valid JSON, e.g. '{\"Host\":\"example.com\"}'")
    try:
        conn.execute(
            "INSERT INTO monitors(name,type,target,port,path,method,expect_status,"
            "expect_body,family,interval_sec,timeout_sec,extra_json,public,folder,"
            "fail_threshold,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (args.name, args.type, args.target, args.port, args.path, args.method,
             args.expect_status, args.expect_body, args.family, args.interval,
             args.timeout, json.dumps(extra), 1 if args.public else 0, args.folder,
             args.fail_threshold, now_iso()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        die(f"a monitor named '{args.name}' already exists")
    print(f"added monitor '{args.name}' ({args.type} -> {args.target})")


def cmd_monitor_list(args):
    conn = db()
    rows = conn.execute("SELECT * FROM monitors ORDER BY name").fetchall()
    if not rows:
        print("no monitors configured")
        return
    for r in rows:
        last = conn.execute(
            "SELECT success, latency_ms, ts FROM results WHERE monitor_id=? "
            "ORDER BY ts DESC LIMIT 1", (r["id"],)
        ).fetchone()
        status = "never run"
        if last:
            status = ("UP" if last["success"] else "DOWN") + \
                      (f" ({last['latency_ms']:.1f}ms)" if last["latency_ms"] is not None else "")
        folder = f"[{r['folder']}] " if r["folder"] else ""
        pub = "public" if r["public"] else "private"
        print(f"{folder}{r['name']:<20} {r['type']:<7} {r['target']}"
              f"{':' + str(r['port']) if r['port'] else '':<8} "
              f"every {r['interval_sec']}s  {pub:<8} -> {status}")


def cmd_monitor_remove(args):
    conn = db()
    row = conn.execute("SELECT id FROM monitors WHERE name=?", (args.name,)).fetchone()
    if not row:
        die(f"no monitor named '{args.name}'")
    conn.execute("DELETE FROM results WHERE monitor_id=?", (row["id"],))
    conn.execute("DELETE FROM monitors WHERE id=?", (row["id"],))
    conn.commit()
    print(f"removed '{args.name}'")


def _run_one(conn, row, verbose=True):
    extra = json.loads(row["extra_json"] or "{}")
    t = row["type"]
    family = row["family"] or 4
    timeout = row["timeout_sec"] or 5
    if t == "icmp":
        ok, lat, msg = check_icmp(row["target"], family, timeout)
    elif t == "tcp":
        ok, lat, msg = check_tcp(row["target"], row["port"], family, timeout)
    elif t == "udp":
        ok, lat, msg = check_udp(row["target"], row["port"], family, timeout,
                                  payload=(extra.get("payload") or "ping").encode(),
                                  expect=extra.get("expect"))
    elif t in ("http", "https"):
        ok, lat, msg = check_http(row["target"], row["path"], row["method"],
                                   row["expect_status"], row["expect_body"], timeout,
                                   headers=extra.get("headers"), scheme=t)
    elif t == "dns":
        ok, lat, msg = check_dns(row["target"], extra.get("dns_port"), row["path"] or row["target"],
                                  extra.get("rtype", "A"), extra.get("min_answers", 1),
                                  timeout, family)
    elif t == "ssh":
        ok, lat, msg = check_ssh_banner(row["target"], row["port"], family, timeout)
    elif t == "ftp":
        ok, lat, msg = check_ftp(row["target"], row["port"], family, timeout,
                                  user=extra.get("user"), password=extra.get("password"))
    elif t == "rdp":
        ok, lat, msg = check_rdp(row["target"], row["port"], family, timeout)
    elif t == "proxy":
        ok, lat, msg = check_proxy_direct(row["target"], row["port"], family, timeout)
    elif t == "tunnel":
        prev = kv_get(f"tunnel_counters_{extra.get('iface')}")
        prev = json.loads(prev) if prev else None
        ok, lat, msg = check_tunnel_health(extra.get("iface"), extra.get("peer_inner_ip"),
                                            timeout, extra.get("require_traffic", False), prev)
    else:
        ok, lat, msg = False, None, f"unknown monitor type {t}"

    conn.execute(
        "INSERT INTO results(monitor_id, ts, success, latency_ms, message) VALUES (?,?,?,?,?)",
        (row["id"], time.time(), 1 if ok else 0, lat, msg),
    )
    conn.execute("UPDATE monitors SET last_run_ts=? WHERE id=?", (time.time(), row["id"]))

    fail_threshold = row["fail_threshold"] or 3
    consec = row["consecutive_fail"] or 0
    if ok:
        if consec >= fail_threshold:
            telegram_send(f"✅ RECOVERED: {row['name']} ({row['type']} {row['target']}) is back UP. {msg}")
        consec = 0
    else:
        consec += 1
        if consec == fail_threshold:
            telegram_send(f"🔴 DOWN: {row['name']} ({row['type']} {row['target']}) failed "
                           f"{consec} consecutive checks. {msg}")
    conn.execute("UPDATE monitors SET consecutive_fail=? WHERE id=?", (consec, row["id"]))
    conn.commit()

    if verbose:
        status = "UP  " if ok else "DOWN"
        lat_s = f"{lat:.1f}ms" if lat is not None else "n/a"
        print(f"[{status}] {row['name']:<20} {lat_s:<10} {msg}")
    return ok


def cmd_monitor_run(args):
    conn = db()
    if args.name:
        rows = conn.execute("SELECT * FROM monitors WHERE name=?", (args.name,)).fetchall()
        if not rows:
            die(f"no monitor named '{args.name}'")
    else:
        rows = conn.execute("SELECT * FROM monitors").fetchall()
        if not rows:
            print("no monitors configured")
            return
    for row in rows:
        _run_one(conn, row)


def cmd_monitor_watch(args):
    print(f"watching monitors, base loop interval {args.interval}s (Ctrl+C to stop)")
    try:
        while True:
            conn = db()
            rows = conn.execute("SELECT * FROM monitors").fetchall()
            now = time.time()
            for row in rows:
                due = row["last_run_ts"] is None or \
                      (now - row["last_run_ts"]) >= (row["interval_sec"] or 60)
                if due:
                    _run_one(conn, row)
            conn.close()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped")


def cmd_monitor_history(args):
    conn = db()
    row = conn.execute("SELECT id FROM monitors WHERE name=?", (args.name,)).fetchone()
    if not row:
        die(f"no monitor named '{args.name}'")
    results = conn.execute(
        "SELECT ts, success, latency_ms, message FROM results WHERE monitor_id=? "
        "ORDER BY ts DESC LIMIT ?", (row["id"], args.limit)
    ).fetchall()
    for r in results:
        ts = datetime.fromtimestamp(r["ts"], tz=timezone.utc).isoformat()
        status = "UP  " if r["success"] else "DOWN"
        lat = f"{r['latency_ms']:.1f}ms" if r["latency_ms"] is not None else "n/a"
        print(f"{ts}  [{status}] {lat:<10} {r['message']}")


def cmd_monitor_status(args):
    """Emit a status.json-style document for public monitors (sample-based
    availability over the window, like the original's analytics)."""
    conn = db()
    rows = conn.execute("SELECT * FROM monitors WHERE public=1 ORDER BY folder, name").fetchall()
    out = {"generated_at": now_iso(), "monitors": []}
    window_sec = args.window_hours * 3600
    cutoff = time.time() - window_sec
    for row in rows:
        samples = conn.execute(
            "SELECT success, latency_ms FROM results WHERE monitor_id=? AND ts>=?",
            (row["id"], cutoff)
        ).fetchall()
        total = len(samples)
        up = sum(1 for s in samples if s["success"])
        avail = (up / total * 100.0) if total else None
        lats = [s["latency_ms"] for s in samples if s["latency_ms"] is not None]
        last = conn.execute(
            "SELECT success, latency_ms, ts FROM results WHERE monitor_id=? "
            "ORDER BY ts DESC LIMIT 1", (row["id"],)
        ).fetchone()
        out["monitors"].append({
            "name": row["name"],
            "folder": row["folder"],
            "type": row["type"],
            "current_status": ("up" if last and last["success"] else "down") if last else "unknown",
            "availability_pct": round(avail, 3) if avail is not None else None,
            "sample_count": total,
            "avg_latency_ms": round(sum(lats) / len(lats), 2) if lats else None,
            "max_latency_ms": round(max(lats), 2) if lats else None,
            "window_hours": args.window_hours,
        })
    text = json.dumps(out, indent=2)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text)


def cmd_monitor_export(args):
    conn = db()
    row = conn.execute("SELECT id FROM monitors WHERE name=?", (args.name,)).fetchone()
    if not row:
        die(f"no monitor named '{args.name}'")
    q = "SELECT ts, success, latency_ms, message FROM results WHERE monitor_id=?"
    params = [row["id"]]
    if args.since:
        q += " AND ts >= ?"
        params.append(datetime.fromisoformat(args.since).timestamp())
    q += " ORDER BY ts"
    results = conn.execute(q, params).fetchall()
    if args.format == "json":
        data = [dict(r) for r in results]
        text = json.dumps(data, indent=2)
        if args.out:
            Path(args.out).write_text(text)
            print(f"wrote {args.out}")
        else:
            print(text)
    else:
        out_path = args.out or f"{args.name}_export.csv"
        with open(out_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["timestamp_utc", "success", "latency_ms", "message"])
            for r in results:
                ts = datetime.fromtimestamp(r["ts"], tz=timezone.utc).isoformat()
                w.writerow([ts, r["success"], r["latency_ms"], r["message"]])
        print(f"wrote {out_path}")


# --------------------------------------------------------------------------
# Tunnels
# --------------------------------------------------------------------------

def _tunnel_save(name, mode, iface, config):
    conn = db()
    try:
        conn.execute(
            "INSERT INTO tunnels(name, mode, iface, config_json, created_at) VALUES (?,?,?,?,?)",
            (name, mode, iface, json.dumps(config), now_iso()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        die(f"a tunnel named '{name}' already exists (use `tunnel delete` first)")


def _addr_up(iface, addr, mtu=None):
    if addr:
        run(["ip", "addr", "add", addr, "dev", iface], check=False)
    if mtu:
        run(["ip", "link", "set", iface, "mtu", str(mtu)], check=False)
    run(["ip", "link", "set", iface, "up"])


def tunnel_create_gre(a):
    cmd = ["ip", "link", "add", a.name, "type", "gre",
           "local", a.local, "remote", a.remote]
    if a.ttl: cmd += ["ttl", str(a.ttl)]
    if a.tos: cmd += ["tos", str(a.tos)]
    if a.key: cmd += ["key", str(a.key)]
    run(cmd)
    _addr_up(a.name, a.inner_local, getattr(a, "mtu", None) or DEFAULT_MTU)
    _tunnel_save(a.name, "gre", a.name, clean_vars(a))


def tunnel_create_gretap(a):
    cmd = ["ip", "link", "add", a.name, "type", "gretap",
           "local", a.local, "remote", a.remote]
    if a.key: cmd += ["key", str(a.key)]
    run(cmd)
    _addr_up(a.name, a.inner_local, getattr(a, "mtu", None) or DEFAULT_MTU)
    _tunnel_save(a.name, "gretap", a.name, clean_vars(a))


def tunnel_create_ipip(a):
    cmd = ["ip", "link", "add", a.name, "type", "ipip",
           "local", a.local, "remote", a.remote]
    if a.ttl: cmd += ["ttl", str(a.ttl)]
    if a.tos: cmd += ["tos", str(a.tos)]
    run(cmd)
    _addr_up(a.name, a.inner_local, getattr(a, "mtu", None) or DEFAULT_MTU)
    _tunnel_save(a.name, "ipip", a.name, clean_vars(a))


def tunnel_create_sit(a):
    cmd = ["ip", "link", "add", a.name, "type", "sit",
           "local", a.local, "remote", a.remote]
    if a.ttl: cmd += ["ttl", str(a.ttl)]
    run(cmd)
    _addr_up(a.name, a.inner_local, getattr(a, "mtu", None) or DEFAULT_MTU)
    _tunnel_save(a.name, "sit", a.name, clean_vars(a))


def tunnel_create_vxlan(a):
    cmd = ["ip", "link", "add", a.name, "type", "vxlan", "id", str(a.vni or 42),
           "remote", a.remote, "local", a.local, "dstport", str(a.port or DEFAULT_TUNNEL_PORT)]
    if a.dev: cmd += ["dev", a.dev]
    run(cmd)
    _addr_up(a.name, a.inner_local, getattr(a, "mtu", None) or DEFAULT_MTU)
    _tunnel_save(a.name, "vxlan", a.name, clean_vars(a))


def tunnel_create_geneve(a):
    cmd = ["ip", "link", "add", a.name, "type", "geneve", "id", str(a.vni or 42),
           "remote", a.remote]
    if a.port: cmd += ["dstport", str(a.port)]
    run(cmd)
    _addr_up(a.name, a.inner_local, getattr(a, "mtu", None) or DEFAULT_MTU)
    _tunnel_save(a.name, "geneve", a.name, clean_vars(a))


def tunnel_create_gue(a):
    """IPIP-over-GUE, matching the 'Gaming' profile: kernel UDP encapsulation."""
    port = a.port or DEFAULT_TUNNEL_PORT
    run(["ip", "fou", "add", "port", str(port), "gue"], check=False)
    cmd = ["ip", "link", "add", a.name, "type", "ipip",
           "local", a.local, "remote", a.remote,
           "encap", "gue", "encap-sport", "auto", "encap-dport", str(port)]
    if a.ttl: cmd += ["ttl", str(a.ttl)]
    if a.tos: cmd += ["tos", str(a.tos)]
    run(cmd)
    _addr_up(a.name, a.inner_local, getattr(a, "mtu", None) or DEFAULT_MTU)
    _tunnel_save(a.name, "gue", a.name, clean_vars(a))


def tunnel_create_wireguard(a):
    run(["ip", "link", "add", a.name, "type", "wireguard"])
    if a.privkey_file:
        setcmd = ["wg", "set", a.name, "private-key", a.privkey_file]
    else:
        die("--privkey-file is required (path to a file containing the private key; "
            "generate with: umask 077 && wg genkey | tee wg-private.key | wg pubkey > wg-public.key)")
    if a.listen_port:
        setcmd += ["listen-port", str(a.listen_port)]
    run(setcmd)
    peer_cmd = ["wg", "set", a.name, "peer", a.peer_pubkey,
                "allowed-ips", a.allowed_ips or (a.inner_peer + "/32" if a.inner_peer else "0.0.0.0/0"),
                "endpoint", f"{a.remote}:{a.remote_port}"]
    if a.psk_file:
        peer_cmd += ["preshared-key", a.psk_file]
    run(peer_cmd)
    _addr_up(a.name, a.inner_local, getattr(a, "mtu", None) or DEFAULT_MTU)
    _tunnel_save(a.name, "wireguard", a.name, clean_vars(a))


def tunnel_create_l2tpv3(a):
    enc = a.encap or "udp"
    cmd = ["ip", "l2tp", "add", "tunnel", "tunnel_id", str(a.tunnel_id),
           "peer_tunnel_id", str(a.peer_tunnel_id), "encap", enc,
           "local", a.local, "remote", a.remote]
    if enc == "udp":
        cmd += ["udp_sport", str(a.local_port), "udp_dport", str(a.remote_port)]
    run(cmd)
    sess_cmd = ["ip", "l2tp", "add", "session", "tunnel_id", str(a.tunnel_id),
                "session_id", str(a.session_id), "peer_session_id", str(a.peer_session_id),
                "name", a.name]
    run(sess_cmd)
    _addr_up(a.name, a.inner_local, getattr(a, "mtu", None) or DEFAULT_MTU)
    _tunnel_save(a.name, "l2tpv3", a.name, clean_vars(a))


def tunnel_create_esp(a):
    """Manual ESP/XFRM tunnel. Simplified vs. the original (no automatic
    directional HKDF derivation) — you supply or we generate hex keys, and
    you must mirror them (swapped) on the peer."""
    spi_out = a.spi_out or secrets.randbelow(0xFFFFFF) + 0x100
    spi_in = a.spi_in or secrets.randbelow(0xFFFFFF) + 0x100
    enc_key = a.enc_key or secrets.token_hex(32)   # aes-256 -> 32 bytes
    auth_key = a.auth_key or secrets.token_hex(32)  # hmac-sha256 -> 32 bytes

    def xfrm_state(src, dst, spi, enc_k, auth_k):
        run(["ip", "xfrm", "state", "add", "src", src, "dst", dst,
             "proto", "esp", "spi", str(spi), "mode", "tunnel",
             "enc", "aes", f"0x{enc_k}", "auth-trunc", "hmac(sha256)", f"0x{auth_k}", "96"])

    xfrm_state(a.local, a.remote, spi_out, enc_key, auth_key)
    xfrm_state(a.remote, a.local, spi_in, enc_key, auth_key)

    def xfrm_policy(src_net, dst_net, direction, tmpl_src, tmpl_dst):
        run(["ip", "xfrm", "policy", "add", "src", src_net, "dst", dst_net,
             "dir", direction, "tmpl", "src", tmpl_src, "dst", tmpl_dst,
             "proto", "esp", "mode", "tunnel"])

    local_net = a.local_net or f"{a.inner_local}/32"
    remote_net = a.remote_net or f"{a.inner_peer}/32"
    xfrm_policy(local_net, remote_net, "out", a.local, a.remote)
    xfrm_policy(remote_net, local_net, "in", a.remote, a.local)

    print(f"generated keys (SAVE THESE — put enc/auth on the peer with spi_out/spi_in SWAPPED):")
    print(f"  enc_key  = {enc_key}")
    print(f"  auth_key = {auth_key}")
    print(f"  spi_out={spi_out}  spi_in={spi_in}   (on the peer: spi_out={spi_in}  spi_in={spi_out})")
    cfg = clean_vars(a)
    cfg.update(spi_out=spi_out, spi_in=spi_in, enc_key=enc_key, auth_key=auth_key)
    _tunnel_save(a.name, "esp", None, cfg)


def tunnel_create_tun_udp(a):
    if not which("socat"):
        die("socat is required for tun-udp")
    mask = a.inner_local.split("/")[1] if "/" in a.inner_local else "30"
    addr_only = a.inner_local.split("/")[0]
    local_port = a.local_port
    cmd = (f"socat -d -d TUN:{a.inner_local},iff-up,tun-name={a.name} "
           f"UDP:{a.remote}:{a.remote_port},bind=:{local_port} &")
    run(cmd, shell=True)
    time.sleep(1)
    run(["ip", "link", "set", a.name, "mtu", str(getattr(a, "mtu", None) or DEFAULT_MTU)], check=False)
    _tunnel_save(a.name, "tun-udp", a.name, clean_vars(a))
    print(f"started socat TUN/UDP bridge for {a.name} in background")


def tunnel_create_tun_tcp(a):
    if not which("socat"):
        die("socat is required for tun-tcp")
    if a.listen:
        cmd = (f"socat -d -d TUN:{a.inner_local},iff-up,tun-name={a.name} "
               f"TCP-LISTEN:{a.local_port},reuseaddr &")
    else:
        cmd = (f"socat -d -d TUN:{a.inner_local},iff-up,tun-name={a.name} "
               f"TCP:{a.remote}:{a.remote_port} &")
    run(cmd, shell=True)
    time.sleep(1)
    run(["ip", "link", "set", a.name, "mtu", str(getattr(a, "mtu", None) or DEFAULT_MTU)], check=False)
    _tunnel_save(a.name, "tun-tcp", a.name, clean_vars(a))
    print(f"started socat TUN/TCP bridge for {a.name} in background")


def tunnel_create_tun_icmp(a):
    if not which("ptunnel-ng"):
        die("ptunnel-ng is required for tun-icmp "
            "(install it separately; this subcommand only wraps it)")
    logfile = HOME_DIR / f"{a.name}-ptunnel.log"
    ensure_home()
    if a.server_mode:
        cmd = (f"nohup ptunnel-ng -r {shlex.quote(a.local)} "
               f"-R {int(a.local_bridge_port or 2222)} "
               f">> {shlex.quote(str(logfile))} 2>&1 &")
        print(f"starting ptunnel-ng in server (proxy) mode in the background (log: {logfile})")
    else:
        cmd = (f"nohup ptunnel-ng -p {shlex.quote(a.remote)} "
               f"-l {int(a.local_bridge_port or 2222)} -r {int(a.remote_bridge_port or 22)} "
               f">> {shlex.quote(str(logfile))} 2>&1 &")
        print(f"starting ptunnel-ng in client mode in the background (log: {logfile})")
    run(cmd, shell=True)
    _tunnel_save(a.name, "tun-icmp", None, clean_vars(a))


def tunnel_create_ssh(a):
    if not which("ssh"):
        die("ssh client is required")
    tun_num = a.local_tun_num
    peer_tun_num = a.peer_tun_num
    ssh_cmd = ["ssh", "-f", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-w", f"{tun_num}:{peer_tun_num}"]
    if a.identity:
        ssh_cmd += ["-i", a.identity]
    if a.port:
        ssh_cmd += ["-p", str(a.port)]
    ssh_cmd.append(f"{a.user}@{a.remote}")
    ssh_cmd.append("true")
    if a.password:
        if not which("sshpass"):
            die("sshpass is required for password auth")
        ssh_cmd = ["sshpass", "-p", a.password] + ssh_cmd
    print("note: this creates an UNVERIFIED (host-key-checking-disabled) SSH TUN, "
          "matching the original project's documented limitation. Use a trusted "
          "path or verify host keys yourself for anything sensitive.")
    run(ssh_cmd)
    iface = f"tun{tun_num}"
    time.sleep(1)
    _addr_up(iface, a.inner_local if not a.inner_peer else f"{a.inner_local} peer {a.inner_peer}",
             getattr(a, "mtu", None) or DEFAULT_MTU)
    _tunnel_save(a.name, "ssh", iface, clean_vars(a))


def tunnel_create_reverse_ssh(a):
    print("Reverse SSH TUN is the *receiving* side of a peer's SSH TUN initiator.")
    sshd_config = Path(a.sshd_config or "/etc/ssh/sshd_config")
    if a.apply:
        if not sshd_config.exists():
            die(f"{sshd_config} not found")
        text = sshd_config.read_text()
        if re.search(r"^\s*PermitTunnel\s+yes\s*$", text, re.MULTILINE):
            print(f"{sshd_config} already has 'PermitTunnel yes'")
        else:
            backup = sshd_config.with_suffix(sshd_config.suffix + f".bak-{int(time.time())}")
            if not DRY_RUN:
                backup.write_text(text)
            text = re.sub(r"^\s*#?\s*PermitTunnel\b.*$", "", text, flags=re.MULTILINE)
            text = text.rstrip("\n") + "\nPermitTunnel yes\n"
            if DRY_RUN:
                print(f"[dry-run] would back up {sshd_config} -> {backup} and append 'PermitTunnel yes'")
            else:
                sshd_config.write_text(text)
                print(f"backed up {sshd_config} -> {backup}, added 'PermitTunnel yes'")
            svc = "ssh" if which("systemctl") else None
            if svc:
                run(["systemctl", "restart", "ssh"], check=False)
                print("restarted ssh service")
            else:
                print("restart your SSH daemon manually for the change to take effect")
    else:
        print("Run again with --apply to have this script back up sshd_config, add")
        print("'PermitTunnel yes', and restart sshd. Manually, ensure on this host's")
        print("sshd_config:")
        print("  PermitTunnel yes")
        print("and that the authenticating user is allowed to create TUN devices.")
    print("The other host should run `tunnel create ssh ...` pointed at this host.")
    _tunnel_save(a.name, "reverse-ssh", None, clean_vars(a))


def tunnel_create_etherip(a):
    die("Managed EtherIP creation isn't available via standard Linux tools here "
        "(same limitation the original project documents). You can still monitor "
        "an externally created EtherIP interface with: "
        "monitor add --type tunnel --tunnel-iface <iface>")


TUNNEL_CREATORS = {
    "gre": tunnel_create_gre,
    "gretap": tunnel_create_gretap,
    "ipip": tunnel_create_ipip,
    "sit": tunnel_create_sit,
    "vxlan": tunnel_create_vxlan,
    "geneve": tunnel_create_geneve,
    "gue": tunnel_create_gue,
    "wireguard": tunnel_create_wireguard,
    "l2tpv3": tunnel_create_l2tpv3,
    "esp": tunnel_create_esp,
    "tun-udp": tunnel_create_tun_udp,
    "tun-tcp": tunnel_create_tun_tcp,
    "tun-icmp": tunnel_create_tun_icmp,
    "ssh": tunnel_create_ssh,
    "reverse-ssh": tunnel_create_reverse_ssh,
    "etherip": tunnel_create_etherip,
}


def cmd_tunnel_create(args):
    fn = TUNNEL_CREATORS.get(args.mode)
    if not fn:
        die(f"unknown tunnel mode {args.mode}")
    fn(args)
    print(f"tunnel '{args.name}' ({args.mode}) created")


def cmd_tunnel_list(args):
    conn = db()
    rows = conn.execute("SELECT * FROM tunnels ORDER BY name").fetchall()
    if not rows:
        print("no tunnels tracked")
        return
    for r in rows:
        state = "?"
        if r["iface"]:
            p = Path(f"/sys/class/net/{r['iface']}/operstate")
            state = p.read_text().strip() if p.exists() else "missing"
        print(f"{r['name']:<20} {r['mode']:<12} iface={r['iface'] or '-':<10} state={state}")


def _tunnel_status_one(row):
    """Collect a richer live-status snapshot for one tracked tunnel row:
    interface state, peer inner-IP ping, and RX/TX byte counters."""
    cfg = json.loads(row["config_json"])
    iface = row["iface"]
    state = "n/a (no interface)"
    rx_bytes = tx_bytes = None
    if iface:
        p = Path(f"/sys/class/net/{iface}/operstate")
        state = p.read_text().strip() if p.exists() else "missing"
        rxp = Path(f"/sys/class/net/{iface}/statistics/rx_bytes")
        txp = Path(f"/sys/class/net/{iface}/statistics/tx_bytes")
        if rxp.exists() and txp.exists():
            try:
                rx_bytes = int(rxp.read_text())
                tx_bytes = int(txp.read_text())
            except ValueError:
                pass
    peer_ip = cfg.get("inner_peer")
    ping_ok = None
    if peer_ip and iface and state not in ("missing", "n/a (no interface)"):
        cmd = ["ping", "-c", "1", "-W", "2"]
        if iface:
            cmd += ["-I", iface]
        cmd.append(peer_ip)
        r = run(cmd, check=False, capture=True)
        ping_ok = (r.returncode == 0)
    return {
        "name": row["name"],
        "mode": row["mode"],
        "iface": iface,
        "state": state,
        "peer_ip": peer_ip,
        "ping_ok": ping_ok,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
    }


def cmd_tunnel_status(args):
    """`tunnel status` — live state of every tracked tunnel: interface state,
    peer inner-IP reachability, and traffic counters (used by the interactive
    menu's Status option)."""
    conn = db()
    rows = conn.execute("SELECT * FROM tunnels ORDER BY name").fetchall()
    if not rows:
        print("no tunnels tracked")
        return
    for row in rows:
        s = _tunnel_status_one(row)
        if s["ping_ok"] is None:
            ping_s = "n/a"
        else:
            ping_s = "reachable" if s["ping_ok"] else "NO REPLY"
        if s["rx_bytes"] is not None:
            rxtx = f"rx={s['rx_bytes'] / 1_000_000:.2f}MB tx={s['tx_bytes'] / 1_000_000:.2f}MB"
        else:
            rxtx = "rx/tx n/a"
        print(f"{s['name']:<20} {s['mode']:<12} iface={s['iface'] or '-':<10} "
              f"state={s['state']:<9} peer={s['peer_ip'] or '-':<14} "
              f"ping={ping_s:<10} {rxtx}")


def _teardown_tunnel(row):
    """Real teardown for one tracked tunnel row. check=False throughout so a
    missing/already-gone resource never aborts a bulk 'remove all' pass."""
    cfg = json.loads(row["config_json"])
    mode = row["mode"]
    iface = row["iface"]
    if mode == "l2tpv3":
        run(["ip", "l2tp", "del", "session", "tunnel_id", str(cfg["tunnel_id"]),
             "session_id", str(cfg["session_id"])], check=False)
        run(["ip", "l2tp", "del", "tunnel", "tunnel_id", str(cfg["tunnel_id"])], check=False)
    elif mode == "esp":
        run(["ip", "xfrm", "state", "deleteall"], check=False)
        run(["ip", "xfrm", "policy", "deleteall"], check=False)
        print("note: ESP delete clears ALL xfrm state/policy on this host (xfrm has no per-name tagging)")
    elif mode in ("tun-udp", "tun-tcp"):
        run(["pkill", "-f", f"tun-name={iface}"], check=False)
        run(["ip", "link", "del", iface], check=False)
    elif mode == "tun-icmp":
        run(["pkill", "-f", "ptunnel-ng"], check=False)
    elif mode == "reverse-ssh":
        pass  # sshd_config is left as applied; nothing interface-level to remove
    elif mode == "ssh":
        run(["pkill", "-f", f"-w {cfg.get('local_tun_num')}:{cfg.get('peer_tun_num')}"], check=False)
        if iface:
            run(["ip", "link", "del", iface], check=False)
    elif iface:
        run(["ip", "link", "del", iface], check=False)


def cmd_tunnel_delete(args):
    conn = db()
    row = conn.execute("SELECT * FROM tunnels WHERE name=?", (args.name,)).fetchone()
    if not row:
        die(f"no tunnel named '{args.name}'")
    _teardown_tunnel(row)
    conn.execute("DELETE FROM tunnels WHERE id=?", (row["id"],))
    conn.commit()
    print(f"deleted tunnel '{args.name}'")


def cmd_tunnel_ping(args):
    conn = db()
    row = conn.execute("SELECT * FROM tunnels WHERE name=?", (args.name,)).fetchone()
    if not row:
        die(f"no tunnel named '{args.name}'")
    cfg = json.loads(row["config_json"])
    peer_ip = args.peer_ip or cfg.get("inner_peer")
    if not peer_ip:
        die("no peer inner IP known; pass --peer-ip")
    cmd = ["ping", "-c", str(args.count)]
    if row["iface"]:
        cmd += ["-I", row["iface"]]
    cmd.append(peer_ip)
    run(cmd, check=False)


# --------------------------------------------------------------------------
# Built-in tunnel speed test — 4 parallel TCP streams, 10s each direction,
# HMAC-challenge authentication with a shared token (no iperf3 needed).
# --------------------------------------------------------------------------

import threading

SPEEDTEST_MAGIC = b"IMONCLI1"
SPEEDTEST_CHUNK = 65536


def _hmac_challenge_server(conn_sock, token):
    challenge = secrets.token_bytes(32)
    conn_sock.sendall(challenge)
    expected = hmac.new(token.encode(), challenge, hashlib.sha256).digest()
    got = conn_sock.recv(len(expected))
    return hmac.compare_digest(got, expected)


def _hmac_challenge_client(conn_sock, token):
    challenge = conn_sock.recv(32)
    proof = hmac.new(token.encode(), challenge, hashlib.sha256).digest()
    conn_sock.sendall(proof)


def cmd_tunnel_speedtest_server(args):
    host, port = args.bind.split(":")
    port = int(port)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(args.streams * 2)
    print(f"speedtest server listening on {args.bind}, restricted to peer {args.peer}")

    def handle(c, addr):
        if args.peer and addr[0] != args.peer:
            c.close()
            return
        try:
            if not _hmac_challenge_server(c, args.token):
                c.close()
                return
            mode = c.recv(4)  # b"UP  " or b"DOWN"
            if mode == b"UP  ":
                total = 0
                t0 = time.monotonic()
                while time.monotonic() - t0 < args.duration:
                    data = c.recv(SPEEDTEST_CHUNK)
                    if not data:
                        break
                    total += len(data)
                c.sendall(str(total).encode().ljust(32))
            elif mode == b"DOWN":
                t0 = time.monotonic()
                buf = os.urandom(SPEEDTEST_CHUNK)
                while time.monotonic() - t0 < args.duration:
                    try:
                        c.sendall(buf)
                    except (BrokenPipeError, ConnectionResetError):
                        break
        finally:
            c.close()

    try:
        while True:
            c, addr = srv.accept()
            threading.Thread(target=handle, args=(c, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nstopped")


def _speedtest_stream(server, port, token, mode, duration, result_holder, idx):
    s = socket.create_connection((server, port), timeout=10)
    _hmac_challenge_client(s, token)
    s.sendall(mode.ljust(4).encode())
    total = 0
    if mode == "UP":
        t0 = time.monotonic()
        buf = os.urandom(SPEEDTEST_CHUNK)
        while time.monotonic() - t0 < duration:
            s.sendall(buf)
            total += len(buf)
        s.settimeout(5)
        try:
            s.recv(64)
        except socket.timeout:
            pass
    else:
        t0 = time.monotonic()
        while time.monotonic() - t0 < duration + 2:
            try:
                s.settimeout(duration + 2 - (time.monotonic() - t0))
                data = s.recv(SPEEDTEST_CHUNK)
            except socket.timeout:
                break
            if not data:
                break
            total += len(data)
    s.close()
    result_holder[idx] = total


def cmd_tunnel_speedtest_client(args):
    host, port = args.server.split(":")
    port = int(port)
    for direction in ("UP", "DOWN"):
        results = [0] * args.streams
        threads = []
        t0 = time.monotonic()
        for i in range(args.streams):
            th = threading.Thread(target=_speedtest_stream,
                                   args=(host, port, args.token, direction,
                                         args.duration, results, i))
            th.start()
            threads.append(th)
        for th in threads:
            th.join()
        elapsed = time.monotonic() - t0
        total_bytes = sum(results)
        mbps = (total_bytes * 8 / 1_000_000) / elapsed if elapsed > 0 else 0
        label = "Upload" if direction == "UP" else "Download"
        print(f"{label}: {total_bytes/1_000_000:.1f} MB in {elapsed:.1f}s -> {mbps:.1f} Mbps "
              f"({args.streams} streams)")


# --------------------------------------------------------------------------
# Proxy / V2Ray-style entries — VMess, VLESS, Trojan, Shadowsocks.
#
# Matches the original project's own documented approach: "Provisioning a
# local Xray entry requires Xray to be installed separately; importing a
# link alone does not establish every supported proxy protocol." This
# script parses the share link, writes a standard Xray JSON config (local
# SOCKS5 + HTTP inbound -> the parsed outbound), and starts/stops the
# user's own `xray` binary. It does not reimplement any proxy protocol,
# and it never downloads or installs xray itself — if you already run your
# own panel/stack on top of xray, this whole `proxy` subcommand is entirely
# optional and can be ignored.
# --------------------------------------------------------------------------

import base64 as _b64

PROXY_DIR = HOME_DIR / "xray"


def _b64_pad_decode(s):
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return _b64.urlsafe_b64decode(s.replace("-", "+").replace("_", "/"))


def parse_vmess(link):
    raw = link[len("vmess://"):]
    data = json.loads(_b64_pad_decode(raw).decode("utf-8", "replace"))
    return {
        "protocol": "vmess",
        "remark": data.get("ps", "vmess"),
        "address": data["add"],
        "port": int(data["port"]),
        "id": data["id"],
        "alter_id": int(data.get("aid", 0)),
        "security": data.get("scy", "auto"),
        "network": data.get("net", "tcp"),
        "type": data.get("type", "none"),
        "host": data.get("host", ""),
        "path": data.get("path", ""),
        "tls": data.get("tls", "") in ("tls", "reality"),
        "sni": data.get("sni") or data.get("host", ""),
    }


def _parse_uri_style(link, scheme):
    rest = link[len(scheme) + 3:]  # strip "scheme://"
    remark = ""
    if "#" in rest:
        rest, remark = rest.split("#", 1)
        remark = urllib.parse.unquote(remark)
    if "?" in rest:
        main, query = rest.split("?", 1)
        q = urllib.parse.parse_qs(query)
    else:
        main, q = rest, {}
    userinfo, hostport = main.rsplit("@", 1)
    if ":" in hostport.rsplit(":", 1)[0] and hostport.count(":") > 1:
        # IPv6 literal [::1]:443
        host, port = hostport.rsplit(":", 1)
    else:
        host, port = hostport.rsplit(":", 1)
    host = host.strip("[]")
    return userinfo, host, int(port), q, remark or scheme


def parse_vless(link):
    userinfo, host, port, q, remark = _parse_uri_style(link, "vless")
    g = lambda k, d="": (q.get(k, [d])[0])
    return {
        "protocol": "vless",
        "remark": remark,
        "address": host,
        "port": port,
        "id": userinfo,
        "encryption": g("encryption", "none"),
        "flow": g("flow", ""),
        "network": g("type", "tcp"),
        "host": g("host", host),
        "path": urllib.parse.unquote(g("path", "")),
        "tls": g("security", "") in ("tls", "reality"),
        "sni": g("sni", host),
        "fp": g("fp", ""),
    }


def parse_trojan(link):
    userinfo, host, port, q, remark = _parse_uri_style(link, "trojan")
    g = lambda k, d="": (q.get(k, [d])[0])
    return {
        "protocol": "trojan",
        "remark": remark,
        "address": host,
        "port": port,
        "password": urllib.parse.unquote(userinfo),
        "network": g("type", "tcp"),
        "host": g("host", host),
        "path": urllib.parse.unquote(g("path", "")),
        "tls": g("security", "tls") in ("tls", "reality", ""),
        "sni": g("sni", host),
    }


def parse_ss(link):
    rest = link[len("ss://"):]
    remark = ""
    if "#" in rest:
        rest, remark = rest.split("#", 1)
        remark = urllib.parse.unquote(remark)
    if "@" in rest:
        # SIP002: base64(method:password)@host:port
        userinfo_b64, hostport = rest.split("@", 1)
        host, port = hostport.rsplit(":", 1)
        try:
            method, password = _b64_pad_decode(userinfo_b64).decode().split(":", 1)
        except Exception:
            method, password = urllib.parse.unquote(userinfo_b64).split(":", 1)
    else:
        # legacy: base64(method:password@host:port)
        decoded = _b64_pad_decode(rest).decode()
        cred, hostport = decoded.rsplit("@", 1)
        method, password = cred.split(":", 1)
        host, port = hostport.rsplit(":", 1)
    return {
        "protocol": "shadowsocks",
        "remark": remark or "ss",
        "address": host.strip("[]"),
        "port": int(port),
        "method": method,
        "password": password,
    }


PROXY_PARSERS = {
    "vmess": parse_vmess,
    "vless": parse_vless,
    "trojan": parse_trojan,
    "ss": parse_ss,
}


def _stream_settings(p):
    net = p.get("network", "tcp")
    ss = {"network": net, "security": "tls" if p.get("tls") else "none"}
    if p.get("tls"):
        ss["tlsSettings"] = {"serverName": p.get("sni") or p.get("address", ""),
                              "allowInsecure": False}
    if net == "ws":
        ss["wsSettings"] = {"path": p.get("path", "/") or "/",
                             "headers": {"Host": p.get("host") or p.get("address", "")}}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": p.get("path", "")}
    elif net == "h2":
        ss["httpSettings"] = {"path": p.get("path", "/") or "/",
                               "host": [p.get("host") or p.get("address", "")]}
    return ss


def build_xray_config(p, socks_port, http_port):
    outbound = {"tag": "proxy"}
    if p["protocol"] == "vmess":
        outbound.update({
            "protocol": "vmess",
            "settings": {"vnext": [{"address": p["address"], "port": p["port"],
                "users": [{"id": p["id"], "alterId": p["alter_id"], "security": p["security"]}]}]},
            "streamSettings": _stream_settings(p),
        })
    elif p["protocol"] == "vless":
        user = {"id": p["id"], "encryption": p["encryption"] or "none"}
        if p.get("flow"):
            user["flow"] = p["flow"]
        outbound.update({
            "protocol": "vless",
            "settings": {"vnext": [{"address": p["address"], "port": p["port"], "users": [user]}]},
            "streamSettings": _stream_settings(p),
        })
    elif p["protocol"] == "trojan":
        outbound.update({
            "protocol": "trojan",
            "settings": {"servers": [{"address": p["address"], "port": p["port"],
                                       "password": p["password"]}]},
            "streamSettings": _stream_settings(p),
        })
    elif p["protocol"] == "shadowsocks":
        outbound.update({
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": p["address"], "port": p["port"],
                                       "method": p["method"], "password": p["password"]}]},
        })
    else:
        die(f"unsupported proxy protocol {p['protocol']}")

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks-in", "port": socks_port, "listen": "127.0.0.1",
             "protocol": "socks", "settings": {"auth": "noauth", "udp": True}},
            {"tag": "http-in", "port": http_port, "listen": "127.0.0.1",
             "protocol": "http", "settings": {}},
        ],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }


def cmd_proxy_import(args):
    scheme = args.link.split("://", 1)[0].lower()
    parser_fn = PROXY_PARSERS.get(scheme)
    if not parser_fn:
        die(f"unsupported link scheme '{scheme}://' (supported: vmess, vless, trojan, ss)")
    parsed = parser_fn(args.link)
    PROXY_DIR.mkdir(parents=True, exist_ok=True)
    cfg_path = PROXY_DIR / f"{args.name}.json"
    xray_cfg = build_xray_config(parsed, args.socks_port, args.http_port)
    cfg_path.write_text(json.dumps(xray_cfg, indent=2))

    conn = db()
    try:
        conn.execute(
            "INSERT INTO proxies(name, protocol, link, parsed_json, xray_config_path, "
            "socks_port, http_port, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (args.name, parsed["protocol"], args.link, json.dumps(parsed), str(cfg_path),
             args.socks_port, args.http_port, now_iso()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.execute(
            "UPDATE proxies SET protocol=?, link=?, parsed_json=?, xray_config_path=?, "
            "socks_port=?, http_port=? WHERE name=?",
            (parsed["protocol"], args.link, json.dumps(parsed), str(cfg_path),
             args.socks_port, args.http_port, args.name),
        )
        conn.commit()
    print(f"imported '{args.name}' ({parsed['protocol']} -> {parsed['address']}:{parsed['port']})")
    print(f"xray config written to {cfg_path}")
    print(f"start it with: imonitor proxy start --name {args.name}")


def cmd_proxy_start(args):
    if not which("xray"):
        die("the `xray` binary is required and must be installed separately "
            "(this only generates its config and runs it — same as the original project; "
            "this script never installs xray itself)")
    conn = db()
    row = conn.execute("SELECT * FROM proxies WHERE name=?", (args.name,)).fetchone()
    if not row:
        die(f"no proxy entry named '{args.name}' (import one first with `proxy import`)")
    PROXY_DIR.mkdir(parents=True, exist_ok=True)
    pidfile = PROXY_DIR / f"{args.name}.pid"
    logfile = PROXY_DIR / f"{args.name}.log"
    cmd = f"nohup xray run -c {shlex.quote(row['xray_config_path'])} >> {shlex.quote(str(logfile))} 2>&1 & echo $!"
    if DRY_RUN:
        print(f"[dry-run] {cmd}")
        return
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    pid = result.stdout.strip()
    pidfile.write_text(pid)
    print(f"started xray for '{args.name}' (pid {pid}); "
          f"SOCKS5 127.0.0.1:{row['socks_port']}, HTTP 127.0.0.1:{row['http_port']}")


def cmd_proxy_stop(args):
    pidfile = PROXY_DIR / f"{args.name}.pid"
    if not pidfile.exists():
        die(f"no running pidfile for '{args.name}'")
    pid = pidfile.read_text().strip()
    run(["kill", pid], check=False)
    pidfile.unlink(missing_ok=True)
    print(f"stopped '{args.name}' (pid {pid})")


def cmd_proxy_list(args):
    conn = db()
    rows = conn.execute("SELECT * FROM proxies ORDER BY name").fetchall()
    if not rows:
        print("no proxy entries imported")
        return
    for r in rows:
        pidfile = PROXY_DIR / f"{r['name']}.pid"
        running = pidfile.exists()
        p = json.loads(r["parsed_json"])
        print(f"{r['name']:<20} {r['protocol']:<12} {p['address']}:{p['port']:<6} "
              f"socks={r['socks_port']} http={r['http_port']} "
              f"{'RUNNING' if running else 'stopped'}")


def cmd_proxy_test(args):
    """Full proxy-path check: route a real HTTP request through the local
    SOCKS5 Xray inbound, exactly matching the original's documented
    'use a working SOCKS5/HTTP/HTTPS entry for a full proxy-path check'."""
    if not which("curl"):
        die("curl is required for proxy path testing")
    conn = db()
    row = conn.execute("SELECT * FROM proxies WHERE name=?", (args.name,)).fetchone()
    if not row:
        die(f"no proxy entry named '{args.name}'")
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}s",
           "--socks5-hostname", f"127.0.0.1:{row['socks_port']}",
           "--max-time", str(args.timeout), args.target]
    r = run(cmd, check=False, capture=True)
    if DRY_RUN:
        return
    out = r.stdout.strip()
    print(f"{args.target} via '{args.name}' -> {out or '(no response / timeout)'}")


# --------------------------------------------------------------------------
# Network controls (iptables / tc / haproxy)
# --------------------------------------------------------------------------

def _ipt(family):
    return "ip6tables" if family == 6 else "iptables"


def _save_rule(name, kind, cfg, applied=False):
    conn = db()
    try:
        conn.execute(
            "INSERT INTO net_rules(name, kind, config_json, applied, created_at) VALUES (?,?,?,?,?)",
            (name, kind, json.dumps(cfg), 1 if applied else 0, now_iso()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.execute(
            "UPDATE net_rules SET kind=?, config_json=?, applied=? WHERE name=?",
            (kind, json.dumps(cfg), 1 if applied else 0, name),
        )
        conn.commit()


def _get_rule(name):
    conn = db()
    row = conn.execute("SELECT * FROM net_rules WHERE name=?", (name,)).fetchone()
    if not row:
        die(f"no net rule named '{name}'")
    return row


def cmd_net_snat_add(args):
    cfg = clean_vars(args)
    _save_rule(args.name, "snat", cfg)
    print(f"saved SNAT rule '{args.name}' (not yet applied — run `net snat apply --name {args.name}`)")


def cmd_net_snat_apply(args):
    row = _get_rule(args.name)
    cfg = json.loads(row["config_json"])
    ipt = _ipt(cfg["family"])
    cmd = [ipt, "-t", "nat", "-A", "POSTROUTING", "-o", cfg["iface"], "-d", cfg["dest"]]
    if cfg.get("proto") and cfg["proto"] != "all":
        cmd += ["-p", cfg["proto"]]
        if cfg.get("dport"):
            cmd += ["--dport", str(cfg["dport"])]
    cmd += ["-j", "SNAT", "--to-source", cfg["source"]]
    run(cmd)
    _save_rule(args.name, "snat", cfg, applied=True)
    print(f"applied SNAT rule '{args.name}' (connection-tracked, via iptables -- this is the "
          f"supported substitute for iMonitor's XDP paired-rewrite mode; see module docstring)")


def cmd_net_forward_add(args):
    cfg = clean_vars(args)
    _save_rule(args.name, "forward", cfg)
    print(f"saved forwarding rule '{args.name}' (apply with `net forward apply --name {args.name}`)")


def cmd_net_forward_apply(args):
    row = _get_rule(args.name)
    cfg = json.loads(row["config_json"])
    ipt = _ipt(cfg["family"])
    dnat_cmd = [ipt, "-t", "nat", "-A", "PREROUTING"]
    if cfg.get("iface"):
        dnat_cmd += ["-i", cfg["iface"]]
    dnat_cmd += ["-p", cfg["proto"], "--dport", str(cfg["listen_port"]),
                 "-j", "DNAT", "--to-destination", f"{cfg['dest_addr']}:{cfg['dest_port']}"]
    run(dnat_cmd)
    fwd_cmd = [ipt, "-A", "FORWARD", "-p", cfg["proto"], "-d", cfg["dest_addr"],
               "--dport", str(cfg["dest_port"]), "-j", "ACCEPT"]
    run(fwd_cmd)
    if cfg.get("masquerade"):
        run([ipt, "-t", "nat", "-A", "POSTROUTING", "-p", cfg["proto"],
             "-d", cfg["dest_addr"], "--dport", str(cfg["dest_port"]), "-j", "MASQUERADE"])
    _save_rule(args.name, "forward", cfg, applied=True)
    print(f"applied port-forward '{args.name}': {cfg['listen_port']} -> "
          f"{cfg['dest_addr']}:{cfg['dest_port']}")


# ---- haproxy-based TCP forwarding (alternative to iptables DNAT) --------
#
# haproxy only speaks TCP (no UDP passthrough), so this method is offered
# for TCP ports only; UDP ports always fall back to the iptables method
# above, automatically, from do_port_forward_flow().

HAPROXY_CFG_PATH = Path("/etc/haproxy/haproxy.cfg")


def _haproxy_block_markers(name):
    return (f"# >>> imonitor-cli managed block: {name} >>>",
            f"# <<< imonitor-cli managed block: {name} <<<")


def cmd_net_forward_apply_haproxy(name, listen_port, dest_addr, dest_port):
    """Append a simple TCP frontend/backend pair to haproxy.cfg for one
    forwarded port, then reload haproxy. Idempotent: re-running with the
    same name is a no-op if the block is already present."""
    if not which("haproxy"):
        die("haproxy is not installed — install it, or use the iptables method instead")
    if not HAPROXY_CFG_PATH.exists():
        die(f"{HAPROXY_CFG_PATH} not found — install/initialize haproxy first, "
            f"or use the iptables forwarding method instead")
    begin, end = _haproxy_block_markers(name)
    block = (
        f"\n{begin}\n"
        f"frontend imon_{name}_front\n"
        f"    bind :::{listen_port} v4v6\n"
        f"    mode tcp\n"
        f"    default_backend imon_{name}_back\n"
        f"backend imon_{name}_back\n"
        f"    mode tcp\n"
        f"    server imon_{name}_srv {dest_addr}:{dest_port}\n"
        f"{end}\n"
    )
    if DRY_RUN:
        print(f"[dry-run] would append to {HAPROXY_CFG_PATH}:\n{block}")
        print("[dry-run] systemctl reload haproxy")
    else:
        text = HAPROXY_CFG_PATH.read_text()
        if begin in text:
            print(f"haproxy block for '{name}' already present, leaving as-is")
        else:
            with open(HAPROXY_CFG_PATH, "a") as f:
                f.write(block)
            run(["systemctl", "reload", "haproxy"], check=False)
    print(f"applied haproxy TCP forward '{name}': *:{listen_port} -> {dest_addr}:{dest_port}")
    _save_rule(name, "forward",
               {"proto": "tcp", "listen_port": listen_port, "dest_addr": dest_addr,
                "dest_port": dest_port, "method": "haproxy", "family": 4},
               applied=True)


def _teardown_haproxy_rule(name):
    begin, end = _haproxy_block_markers(name)
    if not HAPROXY_CFG_PATH.exists():
        return
    text = HAPROXY_CFG_PATH.read_text()
    if begin not in text or end not in text:
        return
    pre, rest = text.split(begin, 1)
    _, post = rest.split(end, 1)
    new_text = pre.rstrip("\n") + "\n" + post.lstrip("\n")
    if not DRY_RUN:
        HAPROXY_CFG_PATH.write_text(new_text)
        run(["systemctl", "reload", "haproxy"], check=False)
    else:
        print(f"[dry-run] would remove haproxy block '{name}' and reload haproxy")


def cmd_net_shape_add(args):
    cfg = clean_vars(args)
    _save_rule(args.name, "shape", cfg)
    print(f"saved shaping rule '{args.name}' (apply with `net shape apply --name {args.name}`)")


def cmd_net_shape_apply(args):
    row = _get_rule(args.name)
    cfg = json.loads(row["config_json"])
    iface = cfg["iface"]
    run(["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb",
         "default", "30"], check=False)
    classid = f"1:{10 + (hash(args.name) % 200)}"
    run(["tc", "class", "add", "dev", iface, "parent", "1:", "classid", classid,
         "htb", "rate", cfg["rate"]])
    filt = ["tc", "filter", "add", "dev", iface, "protocol", "ip", "parent", "1:0",
            "prio", "1", "u32", "match", "ip"]
    if cfg.get("port"):
        filt += ["sport", str(cfg["port"]), "0xffff"]
    filt += ["flowid", classid]
    run(filt)
    _save_rule(args.name, "shape", cfg, applied=True)
    print(f"applied shaping rule '{args.name}' on {iface}: {cfg['rate']}")


def cmd_net_tcplimit_add(args):
    cfg = clean_vars(args)
    _save_rule(args.name, "tcplimit", cfg)
    print(f"saved TCP-connlimit rule '{args.name}' (apply with `net tcplimit apply --name {args.name}`)")


def cmd_net_tcplimit_apply(args):
    row = _get_rule(args.name)
    cfg = json.loads(row["config_json"])
    ipt = _ipt(cfg["family"])
    mask = "32" if cfg["family"] == 4 else "128"
    cmd = [ipt, "-A", "INPUT", "-p", "tcp", "--syn", "--dport", str(cfg["port"]),
           "-m", "connlimit", "--connlimit-above", str(cfg["limit"]),
           "--connlimit-mask", mask, "-j", "REJECT", "--reject-with", "tcp-reset"]
    run(cmd)
    _save_rule(args.name, "tcplimit", cfg, applied=True)
    print(f"applied TCP connection limit '{args.name}': port {cfg['port']} max {cfg['limit']}/src")


def cmd_net_watch_add(args):
    cfg = clean_vars(args)
    chain = f"IMON_{re.sub(r'[^A-Za-z0-9]', '', args.name).upper()[:20]}"
    cfg["chain"] = chain
    ipt = _ipt(args.family)
    run([ipt, "-N", chain], check=False)
    run([ipt, "-F", chain])
    rule = [ipt, "-A", chain, "-p", args.proto, "--dport", str(args.port)]
    if args.ip:
        rule += ["-s", args.ip]
    rule += ["-j", "RETURN"]
    run(rule)
    run([ipt, "-C", "INPUT", "-j", chain], check=False)
    r = run([ipt, "-C", "INPUT", "-j", chain], check=False, capture=True)
    if r.returncode != 0:
        run([ipt, "-I", "INPUT", "-j", chain])
    _save_rule(args.name, "watch", cfg, applied=True)
    print(f"watching port {args.port}/{args.proto} as '{args.name}'")


def cmd_net_watch_show(args):
    row = _get_rule(args.name)
    cfg = json.loads(row["config_json"])
    ipt = _ipt(cfg["family"])
    run([ipt, "-L", cfg["chain"], "-v", "-x", "-n"])


def cmd_net_list(args):
    conn = db()
    rows = conn.execute("SELECT * FROM net_rules ORDER BY kind, name").fetchall()
    if not rows:
        print("no net rules tracked")
        return
    for r in rows:
        state = "applied" if r["applied"] else "saved (not applied)"
        print(f"{r['kind']:<10} {r['name']:<20} {state}")


def _teardown_net_rule(row):
    """Real teardown for one tracked net rule: reconstructs and runs the
    exact -D / delete counterpart of whatever 'apply' did. check=False
    throughout so a missing/already-gone rule never aborts a bulk pass."""
    cfg = json.loads(row["config_json"])
    kind = row["kind"]
    if kind == "snat":
        ipt = _ipt(cfg["family"])
        cmd = [ipt, "-t", "nat", "-D", "POSTROUTING", "-o", cfg["iface"], "-d", cfg["dest"]]
        if cfg.get("proto") and cfg["proto"] != "all":
            cmd += ["-p", cfg["proto"]]
            if cfg.get("dport"):
                cmd += ["--dport", str(cfg["dport"])]
        cmd += ["-j", "SNAT", "--to-source", cfg["source"]]
        run(cmd, check=False)
    elif kind == "forward":
        if cfg.get("method") == "haproxy":
            _teardown_haproxy_rule(row["name"])
        else:
            ipt = _ipt(cfg["family"])
            dnat_cmd = [ipt, "-t", "nat", "-D", "PREROUTING"]
            if cfg.get("iface"):
                dnat_cmd += ["-i", cfg["iface"]]
            dnat_cmd += ["-p", cfg["proto"], "--dport", str(cfg["listen_port"]),
                         "-j", "DNAT", "--to-destination", f"{cfg['dest_addr']}:{cfg['dest_port']}"]
            run(dnat_cmd, check=False)
            fwd_cmd = [ipt, "-D", "FORWARD", "-p", cfg["proto"], "-d", cfg["dest_addr"],
                       "--dport", str(cfg["dest_port"]), "-j", "ACCEPT"]
            run(fwd_cmd, check=False)
            if cfg.get("masquerade"):
                run([ipt, "-t", "nat", "-D", "POSTROUTING", "-p", cfg["proto"],
                     "-d", cfg["dest_addr"], "--dport", str(cfg["dest_port"]), "-j", "MASQUERADE"],
                    check=False)
    elif kind == "shape":
        run(["tc", "qdisc", "del", "dev", cfg["iface"], "root"], check=False)
    elif kind == "tcplimit":
        ipt = _ipt(cfg["family"])
        mask = "32" if cfg["family"] == 4 else "128"
        cmd = [ipt, "-D", "INPUT", "-p", "tcp", "--syn", "--dport", str(cfg["port"]),
               "-m", "connlimit", "--connlimit-above", str(cfg["limit"]),
               "--connlimit-mask", mask, "-j", "REJECT", "--reject-with", "tcp-reset"]
        run(cmd, check=False)
    elif kind == "watch":
        ipt = _ipt(cfg["family"])
        chain = cfg["chain"]
        run([ipt, "-D", "INPUT", "-j", chain], check=False)
        run([ipt, "-F", chain], check=False)
        run([ipt, "-X", chain], check=False)


def cmd_net_delete(args):
    row = _get_rule(args.name)
    if row["applied"]:
        _teardown_net_rule(row)
    conn = db()
    conn.execute("DELETE FROM net_rules WHERE id=?", (row["id"],))
    conn.commit()
    print(f"removed rule '{args.name}'" + (" and its underlying iptables/tc/haproxy rule" if row["applied"] else ""))


# --------------------------------------------------------------------------
# Backups
# --------------------------------------------------------------------------

def _archive_paths(paths, archive_type, include_hidden, out_dir):
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    ext = {"tar.gz": "tar.gz", "tar.xz": "tar.xz", "zip": "zip"}[archive_type]
    out_path = Path(out_dir) / f"backup-{ts}.{ext}"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if archive_type in ("tar.gz", "tar.xz"):
        mode = "w:gz" if archive_type == "tar.gz" else "w:xz"
        with tarfile.open(out_path, mode) as tf:
            for p in paths:
                p = Path(p)
                for item in ([p] if p.is_file() else p.rglob("*")):
                    if not include_hidden and any(part.startswith(".") for part in item.parts):
                        continue
                    if item.is_file():
                        tf.add(item, arcname=str(item))
    else:
        if not which("zip"):
            die("zip is required for ZIP archives")
        cmd = ["zip", "-r", str(out_path)] + [str(p) for p in paths]
        if not include_hidden:
            pass  # zip includes hidden files by default; filtering is best-effort here
        run(cmd)
    return out_path


def _upload_backup(path, cfg):
    dest = cfg["dest_type"]
    if dest == "ftp":
        ftp = ftplib.FTP(timeout=30)
        ftp.connect(cfg["host"], cfg.get("port") or 21)
        ftp.login(cfg["user"], cfg["password"])
        with open(path, "rb") as f:
            ftp.storbinary(f"STOR {cfg.get('remote_dir','').rstrip('/')}/{path.name}", f)
        ftp.quit()
    elif dest == "sftp":
        if not which("curl"):
            die("curl is required for SFTP upload")
        remote = f"sftp://{cfg['host']}:{cfg.get('port') or 22}{cfg.get('remote_dir','/')}/{path.name}"
        cmd = ["curl", "-s", "-T", str(path), remote,
               "--user", f"{cfg['user']}:{cfg.get('password','')}"]
        if cfg.get("identity"):
            cmd = ["curl", "-s", "-T", str(path), remote, "--user", cfg["user"],
                   "--key", cfg["identity"]]
        run(cmd)
    elif dest == "s3":
        if not which("aws"):
            die("aws CLI is required for S3 upload")
        s3_path = f"s3://{cfg['bucket'].rstrip('/')}/{cfg.get('prefix','').strip('/')}/{path.name}".replace("//", "/").replace("s3:/", "s3://")
        run(["aws", "s3", "cp", str(path), s3_path])
    else:
        die(f"unknown destination type {dest}")


def cmd_backup_add(args):
    cfg = clean_vars(args)
    conn = db()
    try:
        conn.execute("INSERT INTO backups(name, config_json, created_at) VALUES (?,?,?)",
                     (args.name, json.dumps(cfg), now_iso()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.execute("UPDATE backups SET config_json=? WHERE name=?", (json.dumps(cfg), args.name))
        conn.commit()
    print(f"saved backup job '{args.name}'")
    if args.schedule:
        print(f"to schedule it, add this to crontab (crontab -e):")
        print(f"  {args.schedule} /usr/bin/python3 {Path(__file__).resolve()} backup run --name {args.name}")


def cmd_backup_run(args):
    conn = db()
    row = conn.execute("SELECT * FROM backups WHERE name=?", (args.name,)).fetchone()
    if not row:
        die(f"no backup job named '{args.name}'")
    cfg = json.loads(row["config_json"])
    paths = cfg["paths"]
    print(f"archiving {len(paths)} path(s)...")
    archive = _archive_paths(paths, cfg["archive_type"], cfg.get("include_hidden", False),
                              cfg.get("local_staging", "/tmp/imonitor-backups"))
    print(f"created {archive} ({archive.stat().st_size/1_000_000:.1f} MB)")
    print(f"uploading to {cfg['dest_type']}...")
    if not DRY_RUN:
        _upload_backup(archive, cfg)
    print("upload complete")
    if cfg.get("retention_count"):
        staging = Path(cfg.get("local_staging", "/tmp/imonitor-backups"))
        archives = sorted(staging.glob("backup-*.*"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in archives[cfg["retention_count"]:]:
            old.unlink(missing_ok=True)


def cmd_backup_list(args):
    conn = db()
    rows = conn.execute("SELECT * FROM backups ORDER BY name").fetchall()
    if not rows:
        print("no backup jobs configured")
        return
    for r in rows:
        cfg = json.loads(r["config_json"])
        print(f"{r['name']:<20} -> {cfg['dest_type']:<6} {len(cfg['paths'])} path(s), "
              f"{cfg['archive_type']}, schedule={cfg.get('schedule') or '-'}")


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------

def cmd_notify_telegram_set(args):
    if args.token:
        kv_set("telegram_token", args.token)
    if args.chat_id:
        existing = kv_get("telegram_chat_ids", "")
        ids = set(x.strip() for x in existing.split(",") if x.strip())
        ids.update(x.strip() for x in args.chat_id)
        kv_set("telegram_chat_ids", ",".join(sorted(ids)))
    print("telegram settings saved")


def cmd_notify_telegram_test(args):
    ok = telegram_send(args.message or "✅ imonitor-cli test message")
    print("sent" if ok else "failed — check token/chat id")


def cmd_notify_telegram_show(args):
    token = kv_get("telegram_token")
    chat_ids = kv_get("telegram_chat_ids")
    print(f"token: {'set (' + token[:6] + '...)' if token else 'not set'}")
    print(f"chat ids: {chat_ids or 'none'}")


# --------------------------------------------------------------------------
# config command
# --------------------------------------------------------------------------

def cmd_config_show(args):
    print(f"home dir : {HOME_DIR}")
    print(f"database : {DB_PATH}")
    conn = db()
    nmon = conn.execute("SELECT COUNT(*) c FROM monitors").fetchone()["c"]
    ntun = conn.execute("SELECT COUNT(*) c FROM tunnels").fetchone()["c"]
    nnet = conn.execute("SELECT COUNT(*) c FROM net_rules").fetchone()["c"]
    nbak = conn.execute("SELECT COUNT(*) c FROM backups").fetchone()["c"]
    print(f"monitors : {nmon}")
    print(f"tunnels  : {ntun}")
    print(f"net rules: {nnet}")
    print(f"backups  : {nbak}")


# --------------------------------------------------------------------------
# Argument parser
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="imonitor", description="Script-only iMonitor-style CLI (no web panel).")
    p.add_argument("--dry-run", action="store_true", help="print system commands instead of running them")
    sub = p.add_subparsers(dest="command", required=True)

    # ---------------- monitor ----------------
    mon = sub.add_parser("monitor", help="uptime/service checks")
    monsub = mon.add_subparsers(dest="subcommand", required=True)

    a = monsub.add_parser("add")
    a.add_argument("--name", required=True)
    a.add_argument("--type", required=True, choices=MONITOR_TYPES)
    a.add_argument("--target", required=True, help="host/IP/URL-host")
    a.add_argument("--port", type=int)
    a.add_argument("--path", help="HTTP path, or DNS query name if target is the resolver")
    a.add_argument("--method", default="GET")
    a.add_argument("--expect-status", default="200")
    a.add_argument("--expect-body")
    a.add_argument("--headers", help="JSON object of extra HTTP headers")
    a.add_argument("--family", type=int, choices=[4, 6], default=4)
    a.add_argument("--interval", type=int, default=60)
    a.add_argument("--timeout", type=float, default=5.0)
    a.add_argument("--public", action="store_true")
    a.add_argument("--folder")
    a.add_argument("--fail-threshold", type=int, default=3)
    a.add_argument("--udp-payload", default="ping")
    a.add_argument("--udp-expect")
    a.add_argument("--dns-type", default="A")
    a.add_argument("--dns-min-answers", type=int, default=1)
    a.add_argument("--dns-port", type=int, default=53)
    a.add_argument("--tunnel-iface")
    a.add_argument("--tunnel-peer-ip")
    a.add_argument("--tunnel-require-traffic", action="store_true")
    a.add_argument("--ftp-user")
    a.add_argument("--ftp-password")
    a.set_defaults(func=cmd_monitor_add)

    a = monsub.add_parser("list"); a.set_defaults(func=cmd_monitor_list)

    a = monsub.add_parser("remove"); a.add_argument("--name", required=True)
    a.set_defaults(func=cmd_monitor_remove)

    a = monsub.add_parser("run"); a.add_argument("--name")
    a.set_defaults(func=cmd_monitor_run)

    a = monsub.add_parser("watch"); a.add_argument("--interval", type=int, default=5,
        help="loop tick in seconds; each monitor still only runs at its own --interval")
    a.set_defaults(func=cmd_monitor_watch)

    a = monsub.add_parser("history"); a.add_argument("--name", required=True)
    a.add_argument("--limit", type=int, default=20)
    a.set_defaults(func=cmd_monitor_history)

    a = monsub.add_parser("status"); a.add_argument("--out")
    a.add_argument("--window-hours", type=float, default=24.0)
    a.set_defaults(func=cmd_monitor_status)

    a = monsub.add_parser("export"); a.add_argument("--name", required=True)
    a.add_argument("--format", choices=["csv", "json"], default="csv")
    a.add_argument("--since", help="ISO date, e.g. 2026-10-01")
    a.add_argument("--out")
    a.set_defaults(func=cmd_monitor_export)

    # ---------------- tunnel ----------------
    tun = sub.add_parser("tunnel", help="tunnel interfaces")
    tunsub = tun.add_subparsers(dest="subcommand", required=True)

    create = tunsub.add_parser("create")
    createsub = create.add_subparsers(dest="mode", required=True)

    def common(sp, inner=True):
        sp.add_argument("--name", required=True)
        sp.add_argument("--local", required=True, help="this host's outer address")
        sp.add_argument("--remote", required=True, help="peer's outer address")
        if inner:
            sp.add_argument("--inner-local", help="e.g. 10.20.0.1/30")
            sp.add_argument("--inner-peer", help="e.g. 10.20.0.2")
        sp.add_argument("--mtu", type=int, default=DEFAULT_MTU,
                         help=f"dedicated tunnel MTU (default {DEFAULT_MTU})")

    sp = createsub.add_parser("gre"); common(sp)
    sp.add_argument("--ttl", type=int); sp.add_argument("--tos", type=int); sp.add_argument("--key")
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("gretap"); common(sp)
    sp.add_argument("--key")
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("ipip"); common(sp)
    sp.add_argument("--ttl", type=int); sp.add_argument("--tos", type=int)
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("sit"); common(sp)
    sp.add_argument("--ttl", type=int)
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("vxlan"); common(sp)
    sp.add_argument("--vni", type=int, default=42); sp.add_argument("--port", type=int, default=DEFAULT_TUNNEL_PORT)
    sp.add_argument("--dev", help="physical egress device")
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("geneve"); common(sp)
    sp.add_argument("--vni", type=int, default=42); sp.add_argument("--port", type=int, default=DEFAULT_TUNNEL_PORT)
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("gue"); common(sp)
    sp.add_argument("--port", type=int, default=DEFAULT_TUNNEL_PORT)
    sp.add_argument("--ttl", type=int); sp.add_argument("--tos", type=int)
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("wireguard"); common(sp)
    sp.add_argument("--privkey-file", required=True, help="path to file containing this host's WG private key")
    sp.add_argument("--peer-pubkey", required=True)
    sp.add_argument("--psk-file")
    sp.add_argument("--listen-port", type=int, default=DEFAULT_TUNNEL_PORT)
    sp.add_argument("--remote-port", type=int, default=DEFAULT_TUNNEL_PORT)
    sp.add_argument("--allowed-ips")
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("l2tpv3"); common(sp)
    sp.add_argument("--encap", choices=["udp", "ip"], default="udp")
    sp.add_argument("--tunnel-id", type=int, required=True)
    sp.add_argument("--peer-tunnel-id", type=int, required=True)
    sp.add_argument("--session-id", type=int, required=True)
    sp.add_argument("--peer-session-id", type=int, required=True)
    sp.add_argument("--local-port", type=int, default=DEFAULT_TUNNEL_PORT)
    sp.add_argument("--remote-port", type=int, default=DEFAULT_TUNNEL_PORT)
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("esp"); common(sp)
    sp.add_argument("--local-net"); sp.add_argument("--remote-net")
    sp.add_argument("--spi-out", type=int); sp.add_argument("--spi-in", type=int)
    sp.add_argument("--enc-key"); sp.add_argument("--auth-key")
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("tun-udp"); common(sp)
    sp.add_argument("--local-port", type=int, default=DEFAULT_TUNNEL_PORT)
    sp.add_argument("--remote-port", type=int, default=DEFAULT_TUNNEL_PORT)
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("tun-tcp"); common(sp)
    sp.add_argument("--local-port", type=int, default=DEFAULT_TUNNEL_PORT)
    sp.add_argument("--remote-port", type=int, default=DEFAULT_TUNNEL_PORT)
    sp.add_argument("--listen", action="store_true", help="listen instead of connecting out")
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("tun-icmp")
    sp.add_argument("--name", required=True)
    sp.add_argument("--local")
    sp.add_argument("--remote")
    sp.add_argument("--server-mode", action="store_true")
    sp.add_argument("--local-bridge-port", type=int, default=2222)
    sp.add_argument("--remote-bridge-port", type=int, default=22)
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("ssh")
    sp.add_argument("--name", required=True)
    sp.add_argument("--remote", required=True)
    sp.add_argument("--user", required=True)
    sp.add_argument("--port", type=int, default=22)
    sp.add_argument("--identity")
    sp.add_argument("--password")
    sp.add_argument("--local-tun-num", type=int, required=True)
    sp.add_argument("--peer-tun-num", type=int, required=True)
    sp.add_argument("--inner-local")
    sp.add_argument("--inner-peer")
    sp.add_argument("--mtu", type=int, default=DEFAULT_MTU)
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("reverse-ssh")
    sp.add_argument("--name", required=True)
    sp.add_argument("--apply", action="store_true",
                     help="actually edit sshd_config (PermitTunnel yes) and restart sshd")
    sp.add_argument("--sshd-config", default="/etc/ssh/sshd_config")
    sp.set_defaults(func=cmd_tunnel_create)

    sp = createsub.add_parser("etherip")
    sp.add_argument("--name", required=True)
    sp.set_defaults(func=cmd_tunnel_create)

    a = tunsub.add_parser("list"); a.set_defaults(func=cmd_tunnel_list)
    a = tunsub.add_parser("status"); a.set_defaults(func=cmd_tunnel_status)
    a = tunsub.add_parser("delete"); a.add_argument("--name", required=True)
    a.set_defaults(func=cmd_tunnel_delete)
    a = tunsub.add_parser("ping"); a.add_argument("--name", required=True)
    a.add_argument("--peer-ip"); a.add_argument("--count", type=int, default=4)
    a.set_defaults(func=cmd_tunnel_ping)

    a = tunsub.add_parser("speedtest-server")
    a.add_argument("--bind", required=True, help="IP:PORT, e.g. 10.20.0.2:5201")
    a.add_argument("--peer", required=True, help="restrict to this inner peer IP")
    a.add_argument("--token", required=True)
    a.add_argument("--streams", type=int, default=4)
    a.add_argument("--duration", type=int, default=10)
    a.set_defaults(func=cmd_tunnel_speedtest_server)

    a = tunsub.add_parser("speedtest-client")
    a.add_argument("--server", required=True, help="IP:PORT")
    a.add_argument("--token", required=True)
    a.add_argument("--streams", type=int, default=4)
    a.add_argument("--duration", type=int, default=10)
    a.set_defaults(func=cmd_tunnel_speedtest_client)

    # ---------------- proxy (VMess/VLESS/Trojan/Shadowsocks via Xray) ----------------
    prx = sub.add_parser("proxy", help="VMess/VLESS/Trojan/Shadowsocks entries (needs the xray binary; "
                                        "entirely optional, nothing here installs xray)")
    prxsub = prx.add_subparsers(dest="subcommand", required=True)

    a = prxsub.add_parser("import")
    a.add_argument("--name", required=True)
    a.add_argument("--link", required=True, help="vmess://, vless://, trojan:// or ss:// share link")
    a.add_argument("--socks-port", type=int, default=10808)
    a.add_argument("--http-port", type=int, default=10809)
    a.set_defaults(func=cmd_proxy_import)

    a = prxsub.add_parser("start"); a.add_argument("--name", required=True)
    a.set_defaults(func=cmd_proxy_start)
    a = prxsub.add_parser("stop"); a.add_argument("--name", required=True)
    a.set_defaults(func=cmd_proxy_stop)
    a = prxsub.add_parser("list"); a.set_defaults(func=cmd_proxy_list)
    a = prxsub.add_parser("test")
    a.add_argument("--name", required=True)
    a.add_argument("--target", default="https://www.gstatic.com/generate_204")
    a.add_argument("--timeout", type=int, default=10)
    a.set_defaults(func=cmd_proxy_test)

    # ---------------- net ----------------
    net = sub.add_parser("net", help="firewall/NAT/shaping controls")
    netsub = net.add_subparsers(dest="subcommand", required=True)

    snat = netsub.add_parser("snat"); snatsub = snat.add_subparsers(dest="action", required=True)
    a = snatsub.add_parser("add")
    a.add_argument("--name", required=True); a.add_argument("--iface", required=True)
    a.add_argument("--dest", required=True); a.add_argument("--source", required=True)
    a.add_argument("--proto", default="all"); a.add_argument("--dport", type=int)
    a.add_argument("--family", type=int, choices=[4, 6], default=4)
    a.set_defaults(func=cmd_net_snat_add)
    a = snatsub.add_parser("apply"); a.add_argument("--name", required=True)
    a.set_defaults(func=cmd_net_snat_apply)

    fwd = netsub.add_parser("forward"); fwdsub = fwd.add_subparsers(dest="action", required=True)
    a = fwdsub.add_parser("add")
    a.add_argument("--name", required=True); a.add_argument("--proto", choices=["tcp", "udp"], required=True)
    a.add_argument("--listen-port", type=int, required=True)
    a.add_argument("--dest-addr", required=True); a.add_argument("--dest-port", type=int, required=True)
    a.add_argument("--iface")
    a.add_argument("--masquerade", action="store_true")
    a.add_argument("--family", type=int, choices=[4, 6], default=4)
    a.set_defaults(func=cmd_net_forward_add)
    a = fwdsub.add_parser("apply"); a.add_argument("--name", required=True)
    a.set_defaults(func=cmd_net_forward_apply)
    a = fwdsub.add_parser("apply-haproxy", help="forward one TCP port via haproxy instead of iptables")
    a.add_argument("--name", required=True)
    a.add_argument("--listen-port", type=int, required=True)
    a.add_argument("--dest-addr", required=True)
    a.add_argument("--dest-port", type=int, required=True)
    a.set_defaults(func=lambda args: cmd_net_forward_apply_haproxy(
        args.name, args.listen_port, args.dest_addr, args.dest_port))

    shp = netsub.add_parser("shape"); shpsub = shp.add_subparsers(dest="action", required=True)
    a = shpsub.add_parser("add")
    a.add_argument("--name", required=True); a.add_argument("--iface", required=True)
    a.add_argument("--rate", required=True, help="e.g. 10mbit"); a.add_argument("--port", type=int)
    a.set_defaults(func=cmd_net_shape_add)
    a = shpsub.add_parser("apply"); a.add_argument("--name", required=True)
    a.set_defaults(func=cmd_net_shape_apply)

    tcl = netsub.add_parser("tcplimit"); tclsub = tcl.add_subparsers(dest="action", required=True)
    a = tclsub.add_parser("add")
    a.add_argument("--name", required=True); a.add_argument("--port", type=int, required=True)
    a.add_argument("--limit", type=int, required=True)
    a.add_argument("--family", type=int, choices=[4, 6], default=4)
    a.set_defaults(func=cmd_net_tcplimit_add)
    a = tclsub.add_parser("apply"); a.add_argument("--name", required=True)
    a.set_defaults(func=cmd_net_tcplimit_apply)

    wch = netsub.add_parser("watch"); wchsub = wch.add_subparsers(dest="action", required=True)
    a = wchsub.add_parser("add")
    a.add_argument("--name", required=True); a.add_argument("--port", type=int, required=True)
    a.add_argument("--proto", choices=["tcp", "udp"], default="tcp"); a.add_argument("--ip")
    a.add_argument("--family", type=int, choices=[4, 6], default=4)
    a.set_defaults(func=cmd_net_watch_add)
    a = wchsub.add_parser("show"); a.add_argument("--name", required=True)
    a.set_defaults(func=cmd_net_watch_show)

    a = netsub.add_parser("list"); a.set_defaults(func=cmd_net_list)
    a = netsub.add_parser("delete"); a.add_argument("--name", required=True)
    a.set_defaults(func=cmd_net_delete)

    # ---------------- backup ----------------
    bak = sub.add_parser("backup", help="file archive backups")
    baksub = bak.add_subparsers(dest="subcommand", required=True)

    a = baksub.add_parser("add")
    a.add_argument("--name", required=True)
    a.add_argument("--paths", nargs="+", required=True)
    a.add_argument("--archive-type", choices=["tar.gz", "tar.xz", "zip"], default="tar.gz")
    a.add_argument("--include-hidden", action="store_true")
    a.add_argument("--dest-type", choices=["ftp", "sftp", "s3"], required=True)
    a.add_argument("--host"); a.add_argument("--port", type=int)
    a.add_argument("--user"); a.add_argument("--password"); a.add_argument("--identity")
    a.add_argument("--remote-dir", default="/")
    a.add_argument("--bucket"); a.add_argument("--prefix", default="")
    a.add_argument("--retention-count", type=int, default=7)
    a.add_argument("--local-staging", default="/tmp/imonitor-backups")
    a.add_argument("--schedule", help="cron schedule string, e.g. '0 3 * * *' (for your reference / crontab)")
    a.set_defaults(func=cmd_backup_add)

    a = baksub.add_parser("run"); a.add_argument("--name", required=True)
    a.set_defaults(func=cmd_backup_run)

    a = baksub.add_parser("list"); a.set_defaults(func=cmd_backup_list)

    # ---------------- notify ----------------
    ntf = sub.add_parser("notify", help="alert channels")
    ntfsub = ntf.add_subparsers(dest="subcommand", required=True)
    tg = ntfsub.add_parser("telegram"); tgsub = tg.add_subparsers(dest="action", required=True)
    a = tgsub.add_parser("set")
    a.add_argument("--token"); a.add_argument("--chat-id", action="append", default=[])
    a.set_defaults(func=cmd_notify_telegram_set)
    a = tgsub.add_parser("test"); a.add_argument("--message")
    a.set_defaults(func=cmd_notify_telegram_test)
    a = tgsub.add_parser("show"); a.set_defaults(func=cmd_notify_telegram_show)

    # ---------------- config ----------------
    cfg = sub.add_parser("config", help="show local config/db info")
    cfgsub = cfg.add_subparsers(dest="subcommand", required=True)
    a = cfgsub.add_parser("show"); a.set_defaults(func=cmd_config_show)

    return p


# ==========================================================================
# Interactive menu — Iran <-> Kharej role-based install, one protocol at a
# time, with automatic outer-IP auto-detection, a shared dedicated MTU,
# automatic post-tunnel port forwarding (iptables or haproxy), and a full
# "remove everything" / "status" option. This is what runs when you launch
# the script with no arguments; every CLI subcommand above still works
# unchanged for scripting. Default inner addressing convention used
# throughout: Iran (server) = 10.10.10.2, Kharej (client) = 10.10.10.1 --
# override any prompt if needed.
# ==========================================================================

def prompt(msg, default=None, required=False):
    suffix = f" [{default}]" if default not in (None, "") else ""
    while True:
        try:
            val = input(f"{msg}{suffix}: ").strip()
        except EOFError:
            val = ""
        if val:
            return val
        if default is not None:
            return default
        if not required:
            return ""
        print("  This value is required, please enter it.")


def prompt_int(msg, default=None, required=False):
    while True:
        v = prompt(msg, default=str(default) if default is not None else None, required=required)
        if v == "" and not required:
            return None
        try:
            return int(v)
        except ValueError:
            print("  Please enter a whole number.")


def prompt_yesno(msg, default=True):
    d = "Y/n" if default else "y/N"
    try:
        val = input(f"{msg} [{d}]: ").strip().lower()
    except EOFError:
        val = ""
    if not val:
        return default
    return val[0] == "y"


def prompt_menu(title, options):
    print(f"\n{title}")
    for key, label in options:
        print(f"  {key}) {label}")
    valid = {k for k, _ in options}
    while True:
        try:
            choice = input("Your choice: ").strip()
        except EOFError:
            return "0"
        if choice in valid:
            return choice
        print("  Invalid option, please try again.")


def detect_public_ip():
    """Auto-detect this host's own outer IPv4 address."""
    try:
        r = subprocess.run(["curl", "-4", "-s", "--max-time", "3", "https://ifconfig.me"],
                            capture_output=True, text=True, timeout=5)
        ip = r.stdout.strip()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            return ip
    except Exception:
        pass
    return None


def detect_public_ipv6():
    """Auto-detect this host's own outer IPv6 address."""
    try:
        r = subprocess.run(["curl", "-6", "-s", "--max-time", "3", "https://ifconfig.me"],
                            capture_output=True, text=True, timeout=5)
        ip = r.stdout.strip()
        if ":" in ip and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            return ip
    except Exception:
        pass
    return None


def detect_public_ip_auto():
    """Try IPv4 first, then IPv6. Returns (ip_or_None, family)."""
    ip = detect_public_ip()
    if ip:
        return ip, 4
    ip6 = detect_public_ipv6()
    if ip6:
        return ip6, 6
    return None, 4


def prompt_role():
    c = prompt_menu("Select the role of this server:", [
        ("1", "Install Server  (this machine is the Iran server — default inner 10.10.10.2)"),
        ("2", "Install Client  (this machine is the foreign/Kharej server — default inner 10.10.10.1)"),
        ("0", "Back to main menu"),
    ])
    if c == "0":
        return None
    return c == "1"  # True = Server/Iran


def prompt_common(is_server, default_name):
    """Collect this tunnel's parameters. The LOCAL outer address is always
    auto-detected (IPv4, falling back to IPv6) and is never asked — only the
    PEER's outer address (v4 or v6) is prompted for, per the Iran/Kharej
    addressing convention."""
    name = prompt("Name of this tunnel", default=default_name)
    local, local_fam = detect_public_ip_auto()
    if local:
        print(f"This server's own outer address was auto-detected: {local} (IPv{local_fam})")
    else:
        print("Could not auto-detect this server's outer address.")
        local = prompt("Enter this server's own outer address (IPv4 or IPv6)", required=True)
    peer_role = "Kharej/foreign client" if is_server else "Iran server"
    remote = prompt(f"Outer address (IPv4 or IPv6) of the peer {peer_role}", required=True)
    inner_local = prompt("Inner address of this server",
                          default="10.10.10.2/30" if is_server else "10.10.10.1/30")
    inner_peer_full = prompt("Inner address of the peer server",
                              default="10.10.10.1" if is_server else "10.10.10.2")
    inner_peer_ip = inner_peer_full.split("/")[0]
    mtu = prompt_int("Dedicated tunnel MTU", default=DEFAULT_MTU)
    return name, local, remote, inner_local, inner_peer_ip, mtu


def do_port_forward_flow(inner_peer_ip, family=4):
    print("\n--- Port forwarding through this tunnel ---")
    ports_raw = prompt("Enter the ports that should go through this tunnel, comma-separated "
                        "(e.g. 1080,443) — leave blank to skip", default="")
    if not ports_raw.strip():
        print("No forwarding rule was added.")
        return
    proto_choice = prompt("Which protocol should be forwarded? (tcp/udp/both)", default="both").lower()
    protos = ["tcp", "udp"] if proto_choice not in ("tcp", "udp") else [proto_choice]
    method = prompt("Forward automatically using iptables or haproxy? (iptables/haproxy)",
                     default="iptables").lower()
    if method not in ("iptables", "haproxy"):
        method = "iptables"
    if method == "haproxy" and "udp" in protos:
        print("note: haproxy only forwards TCP — UDP ports below will still use iptables automatically.")
    for p in [x.strip() for x in ports_raw.split(",") if x.strip()]:
        if not p.isdigit():
            print(f"  skipped (not a number): {p}")
            continue
        for proto in protos:
            rule_name = f"fwd-{inner_peer_ip.replace('.', '-').replace(':', '-')}-{p}-{proto}"
            if method == "haproxy" and proto == "tcp":
                try:
                    cmd_net_forward_apply_haproxy(rule_name, int(p), inner_peer_ip, int(p))
                    continue
                except SystemExit:
                    print(f"  haproxy forward failed for port {p}/{proto}, falling back to iptables")
            a_add = SimpleNamespace(name=rule_name, proto=proto, listen_port=int(p),
                                     dest_addr=inner_peer_ip, dest_port=int(p),
                                     iface=None, masquerade=True, family=family)
            cmd_net_forward_add(a_add)
            cmd_net_forward_apply(SimpleNamespace(name=rule_name))
    print(f"\nTraffic for port(s) {ports_raw} is now forwarded through this tunnel to {inner_peer_ip}.")


def print_peer_instructions(local, remote, inner_local, inner_peer_ip):
    """Mirrors the official docs' Server-A/Server-B table: whatever this side
    calls 'local' is the PEER's 'remote', and vice versa -- same swap for the
    inner addresses. Printed so the other server's install can be copy-pasted
    straight from here, the way 'copy the generated peer instructions' works
    in the real panel."""
    if not local or not remote:
        return
    mask = inner_local.split("/")[1] if inner_local and "/" in inner_local else "30"
    own_inner_ip = inner_local.split("/")[0] if inner_local else "?"
    print("\n" + "=" * 62)
    print("Enter these values on the peer server (opposite role):")
    print(f"  Outer (Local/Outer) address of that server    : {remote}")
    print(f"  Outer (Remote/Outer) address of this server   : {local}")
    print(f"  Inner (Local/Inner) address of that server     : {inner_peer_ip}/{mask}")
    print(f"  Inner (Peer/Inner) address of this server       : {own_inner_ip}")
    print("=" * 62)


def after_create(name, inner_peer_ip, iface, is_server, family=4,
                  local=None, remote=None, inner_local=None):
    print(f"\nTunnel '{name}' created.")
    print_peer_instructions(local, remote, inner_local, inner_peer_ip)
    print(f"\nChecking connectivity to {inner_peer_ip} ...")
    time.sleep(1)
    cmd = ["ping", "-c", "2", "-W", "2"]
    if iface:
        cmd += ["-I", iface]
    cmd.append(inner_peer_ip)
    r = run(cmd, check=False, capture=True)
    if r.returncode == 0:
        print("  \u2705 Ping succeeded — the tunnel is up.")
    else:
        print("  \u26a0 Ping failed. Make sure the peer server has installed the same tunnel with matching "
              "settings (IDs/keys/VNI/port must match exactly).")
    # Port forwarding is always offered at the end of every tunnel install,
    # on either role — leave the port list blank to skip it.
    do_port_forward_flow(inner_peer_ip, family=family)


# ---- one menu function per protocol -------------------------------------

def menu_gre():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "gre0")
    key = prompt("GRE key (shared and identical on both servers, optional)", default="")
    ttl = prompt_int("TTL", default=64)
    a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                         inner_peer=inner_peer_ip, key=key or None, ttl=ttl, tos=None, mtu=mtu)
    tunnel_create_gre(a)
    after_create(name, inner_peer_ip, name, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_gretap():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "gretap0")
    key = prompt("GRE key (shared and identical on both servers, optional)", default="")
    a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                         inner_peer=inner_peer_ip, key=key or None, mtu=mtu)
    tunnel_create_gretap(a)
    after_create(name, inner_peer_ip, name, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_ipip():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "ipip0")
    ttl = prompt_int("TTL", default=64)
    a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                         inner_peer=inner_peer_ip, ttl=ttl, tos=None, mtu=mtu)
    tunnel_create_ipip(a)
    after_create(name, inner_peer_ip, name, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_sit():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "sit0")
    ttl = prompt_int("TTL", default=64)
    a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                         inner_peer=inner_peer_ip, ttl=ttl, mtu=mtu)
    tunnel_create_sit(a)
    after_create(name, inner_peer_ip, name, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_vxlan():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "vxlan0")
    vni = prompt_int("VNI (must be the same on both servers)", default=42)
    port = prompt_int("VXLAN port (shared Iran<->Kharej tunnel port)", default=DEFAULT_TUNNEL_PORT)
    a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                         inner_peer=inner_peer_ip, vni=vni, port=port, dev=None, mtu=mtu)
    tunnel_create_vxlan(a)
    after_create(name, inner_peer_ip, name, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_geneve():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "gnv0")
    vni = prompt_int("VNI (must be the same on both servers)", default=42)
    port = prompt_int("GENEVE port (shared Iran<->Kharej tunnel port)", default=DEFAULT_TUNNEL_PORT)
    a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                         inner_peer=inner_peer_ip, vni=vni, port=port, mtu=mtu)
    tunnel_create_geneve(a)
    after_create(name, inner_peer_ip, name, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_gue():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "gue0")
    port = prompt_int("GUE port (Gaming profile, shared Iran<->Kharej tunnel port)", default=DEFAULT_TUNNEL_PORT)
    ttl = prompt_int("TTL", default=64)
    a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                         inner_peer=inner_peer_ip, port=port, ttl=ttl, tos=0, mtu=mtu)
    tunnel_create_gue(a)
    after_create(name, inner_peer_ip, name, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_wireguard():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "wg0")
    port = prompt_int("WireGuard port (shared Iran<->Kharej tunnel port)", default=DEFAULT_TUNNEL_PORT)
    ensure_home()
    priv_path = HOME_DIR / f"{name}-private.key"
    pub_path = HOME_DIR / f"{name}-public.key"
    if not priv_path.exists():
        run(["bash", "-c", f"umask 077 && wg genkey | tee {shlex.quote(str(priv_path))} "
                            f"| wg pubkey > {shlex.quote(str(pub_path))}"])
    local_pub = pub_path.read_text().strip() if pub_path.exists() else "(dry-run: unknown)"
    print(f"\nPublic key of this server — enter this on the peer server:\n  {local_pub}\n")
    peer_pub = prompt("Paste the peer server's public key here", required=True)
    psk = prompt("Shared PSK (must be identical on both servers)", default=DEFAULT_PSK)
    psk_path = None
    if psk:
        psk_path = HOME_DIR / f"{name}-psk.key"
        psk_path.write_text(psk)
    a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                         inner_peer=inner_peer_ip, privkey_file=str(priv_path),
                         peer_pubkey=peer_pub, psk_file=str(psk_path) if psk_path else None,
                         listen_port=port, remote_port=port, allowed_ips=None, mtu=mtu)
    tunnel_create_wireguard(a)
    after_create(name, inner_peer_ip, name, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_l2tpv3():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "l2tp0")
    encap = prompt("Encapsulation type (udp/ip)", default="udp")
    conn_id = prompt_int("Connection ID number (enter this exact number on the peer server too)", default=100)
    if is_server:
        tunnel_id, peer_tunnel_id, session_id, peer_session_id = conn_id, conn_id + 1, conn_id, conn_id + 1
    else:
        tunnel_id, peer_tunnel_id, session_id, peer_session_id = conn_id + 1, conn_id, conn_id + 1, conn_id
    local_port = prompt_int("Local UDP port (shared Iran<->Kharej tunnel port)",
                             default=DEFAULT_TUNNEL_PORT) if encap == "udp" else DEFAULT_TUNNEL_PORT
    remote_port = prompt_int("Peer UDP port (shared Iran<->Kharej tunnel port)",
                              default=DEFAULT_TUNNEL_PORT) if encap == "udp" else DEFAULT_TUNNEL_PORT
    a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                         inner_peer=inner_peer_ip, encap=encap, tunnel_id=tunnel_id,
                         peer_tunnel_id=peer_tunnel_id, session_id=session_id,
                         peer_session_id=peer_session_id, local_port=local_port, remote_port=remote_port,
                         mtu=mtu)
    tunnel_create_l2tpv3(a)
    after_create(name, inner_peer_ip, name, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_esp():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "esp0")
    if is_server:
        print("\nKeys will be generated automatically and shown at the end to copy to the peer server.")
        a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                             inner_peer=inner_peer_ip, local_net=None, remote_net=None,
                             spi_out=None, spi_in=None, enc_key=None, auth_key=None, mtu=mtu)
    else:
        print("\nEnter the values shown by the Iran server here "
              "(the SPIs are already swapped, as shown by the server).")
        enc_key = prompt("enc_key", required=True)
        auth_key = prompt("auth_key", required=True)
        spi_out = prompt_int("spi_out", required=True)
        spi_in = prompt_int("spi_in", required=True)
        a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                             inner_peer=inner_peer_ip, local_net=None, remote_net=None,
                             spi_out=spi_out, spi_in=spi_in, enc_key=enc_key, auth_key=auth_key, mtu=mtu)
    tunnel_create_esp(a)
    after_create(name, inner_peer_ip, None, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_tun_udp():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "tun-udp0")
    local_port = prompt_int("Local port (shared Iran<->Kharej tunnel port)", default=DEFAULT_TUNNEL_PORT)
    remote_port = prompt_int("Peer port (shared Iran<->Kharej tunnel port)", default=DEFAULT_TUNNEL_PORT)
    a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                         inner_peer=inner_peer_ip, local_port=local_port, remote_port=remote_port, mtu=mtu)
    tunnel_create_tun_udp(a)
    after_create(name, inner_peer_ip, name, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_tun_tcp():
    is_server = prompt_role()
    if is_server is None: return
    name, local, remote, inner_local, inner_peer_ip, mtu = prompt_common(is_server, "tun-tcp0")
    listen = prompt_yesno("Should this server listen (wait for a connection from the peer)?", default=is_server)
    port = prompt_int("TCP port (shared Iran<->Kharej tunnel port)", default=DEFAULT_TUNNEL_PORT)
    a = SimpleNamespace(name=name, local=local, remote=remote, inner_local=inner_local,
                         inner_peer=inner_peer_ip,
                         local_port=port if listen else None,
                         remote_port=None if listen else port,
                         listen=listen, mtu=mtu)
    tunnel_create_tun_tcp(a)
    after_create(name, inner_peer_ip, name, is_server, local=local, remote=remote, inner_local=inner_local)


def menu_tun_icmp():
    is_server = prompt_role()
    if is_server is None: return
    name = prompt("Name of this tunnel", default="tun-icmp0")
    local = prompt("Outer address of this server", default=detect_public_ip()) if is_server else None
    remote = prompt("Outer address of the peer server", required=True) if not is_server else None
    local_bridge_port = prompt_int("Local bridge port", default=2222)
    remote_bridge_port = prompt_int("Destination SSH port (for client mode)", default=22) if not is_server else 22
    a = SimpleNamespace(name=name, local=local, remote=remote, server_mode=is_server,
                         local_bridge_port=local_bridge_port, remote_bridge_port=remote_bridge_port)
    tunnel_create_tun_icmp(a)
    print("Note: this mode does not create a normal tun interface (it relays TCP over ICMP); "
          "use menu item 18 (network rules) afterward for port forwarding.")
    input("Press Enter to return...")


def menu_ssh():
    is_server = prompt_role()
    if is_server is None: return
    name = prompt("Name of this tunnel", default="ssh-tun0")
    if is_server:
        print("This server (Iran) acts as the SSH TUN initiator and connects to the foreign server.")
        local = prompt("Outer address of this server (only for the peer-side instructions)",
                        default=detect_public_ip())
        remote = prompt("Address of the foreign server (which must have Reverse SSH enabled)", required=True)
        user = prompt("SSH username on the foreign server", default="root")
        port = prompt_int("SSH port", default=22)
        identity = prompt("Path to the SSH private key file (leave empty to use a password)", default="")
        password = prompt("SSH password (if not using a key)", default="") if not identity else None
        local_tun_num = prompt_int("Local tun number", default=10)
        peer_tun_num = prompt_int("Peer tun number", default=10)
        inner_local = prompt("Inner address of this server", default="10.10.10.2/30")
        inner_peer = prompt("Inner address of the peer server", default="10.10.10.1")
        mtu = prompt_int("Dedicated tunnel MTU", default=DEFAULT_MTU)
        a = SimpleNamespace(name=name, remote=remote, user=user, port=port,
                             identity=identity or None, password=password or None,
                             local_tun_num=local_tun_num, peer_tun_num=peer_tun_num,
                             inner_local=inner_local, inner_peer=inner_peer, mtu=mtu)
        tunnel_create_ssh(a)
        after_create(name, inner_peer.split("/")[0], f"tun{local_tun_num}", True,
                     local=local, remote=remote, inner_local=inner_local)
    else:
        print("This server (foreign) acts as Reverse SSH (receiver) — the peer must connect the SSH TUN.")
        apply = prompt_yesno("Automatically edit sshd_config "
                              "('PermitTunnel yes' + restart the ssh service)?", default=True)
        a = SimpleNamespace(name=name, apply=apply, sshd_config="/etc/ssh/sshd_config")
        tunnel_create_reverse_ssh(a)
        input("\nPress Enter to return...")


def menu_etherip():
    print("\nManaged EtherIP creation is not possible on standard Linux "
          "(the original iMonitor project has the same limitation).")
    print("You can only monitor an EtherIP interface that was created elsewhere:")
    print("  python3 imonitor_cli.py monitor add --name X --type tunnel --tunnel-iface IFACE")
    input("\nPress Enter to return...")


def menu_list_tunnels():
    cmd_tunnel_list(SimpleNamespace())
    input("\nPress Enter to return...")


def menu_status():
    cmd_tunnel_status(SimpleNamespace())
    input("\nPress Enter to return...")


def menu_list_net_rules():
    cmd_net_list(SimpleNamespace())
    input("\nPress Enter to return...")


def menu_remove_all():
    print("\n\u26a0  This option will completely remove all tunnels, network rules")
    print("    (SNAT/Forward/Shaping/TCP-limit/Watch, iptables AND haproxy) and proxy entries managed by this script.")
    if not prompt_yesno("Continue?", default=False):
        print("Cancelled.")
        return
    conn = db()

    for row in conn.execute("SELECT * FROM tunnels").fetchall():
        try:
            _teardown_tunnel(row)
            print(f"  \u2714 tunnel removed: {row['name']}")
        except Exception as e:
            eprint(f"  \u26a0 failed to remove tunnel '{row['name']}': {e}")
    conn.execute("DELETE FROM tunnels")

    for row in conn.execute("SELECT * FROM net_rules WHERE applied=1").fetchall():
        try:
            _teardown_net_rule(row)
            print(f"  \u2714 network rule removed: {row['name']} ({row['kind']})")
        except Exception as e:
            eprint(f"  \u26a0 failed to remove rule '{row['name']}': {e}")
    conn.execute("DELETE FROM net_rules")

    for row in conn.execute("SELECT * FROM proxies").fetchall():
        pidfile = PROXY_DIR / f"{row['name']}.pid"
        if pidfile.exists():
            pid = pidfile.read_text().strip()
            run(["kill", pid], check=False)
            pidfile.unlink(missing_ok=True)
            print(f"  \u2714 proxy stopped: {row['name']}")
    conn.execute("DELETE FROM proxies")

    conn.commit()
    print("\n\u2705 Everything has been removed.")
    input("Press Enter to return...")


MENU_ACTIONS = {
    "1": menu_gre, "2": menu_gretap, "3": menu_ipip, "4": menu_sit,
    "5": menu_vxlan, "6": menu_geneve, "7": menu_gue, "8": menu_wireguard,
    "9": menu_l2tpv3, "10": menu_esp, "11": menu_tun_udp, "12": menu_tun_tcp,
    "13": menu_tun_icmp, "14": menu_ssh, "15": menu_etherip,
    "16": menu_list_tunnels, "17": menu_list_net_rules, "18": menu_remove_all,
    "19": menu_status,
}


def main_menu():
    while True:
        choice = prompt_menu("=== iMonitor CLI \u2014 Tunnel Management (no web panel, script only) ===", [
            ("1", "GRE"),
            ("2", "GRETAP"),
            ("3", "IPIP"),
            ("4", "SIT  (IPv6-in-IPv4)"),
            ("5", "VXLAN"),
            ("6", "GENEVE"),
            ("7", "GUE  (Gaming profile)"),
            ("8", "WireGuard  (Secure profile)"),
            ("9", "L2TPv3"),
            ("10", "ESP / XFRM (manual)"),
            ("11", "TUN/UDP"),
            ("12", "TUN/TCP"),
            ("13", "TUN/ICMP"),
            ("14", "SSH Tunnel  (+ Reverse SSH for the foreign side)"),
            ("15", "EtherIP  (monitoring only)"),
            ("16", "Show list of active tunnels"),
            ("17", "Show network rules (SNAT/Forward/Shape/...)"),
            ("18", "\u2716  Remove ALL applied changes (Remove ALL)"),
            ("19", "\U0001f4ca Show tunnel status (ping + traffic, per tunnel)"),
            ("0", "Exit"),
        ])
        if choice == "0":
            print("Goodbye.")
            return
        fn = MENU_ACTIONS.get(choice)
        if not fn:
            continue
        try:
            fn()
        except SystemExit:
            print("  \u26a0 Operation stopped due to an error (see message above). Returning to menu.")
        except KeyboardInterrupt:
            print("\n  Cancelled.")
        except Exception as e:
            eprint(f"  Unexpected error: {e}")


def main():
    global DRY_RUN
    argv = sys.argv[1:]
    if not argv or argv == ["--dry-run"]:
        DRY_RUN = "--dry-run" in argv  # `imonitor_cli.py --dry-run` -> menu in dry-run mode
        try:
            main_menu()
        except KeyboardInterrupt:
            print("\nGoodbye.")
        return
    parser = build_parser()
    args = parser.parse_args()
    DRY_RUN = args.dry_run
    args.func(args)


if __name__ == "__main__":
    main()
