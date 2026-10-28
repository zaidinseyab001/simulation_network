#!/usr/bin/env python3
"""Sender / Receiver tenant pilot.

Each tenant runs a small web server (Python standard library only) that:
  * serves a dashboard at  http://<this-machine>:<port>/
  * accepts hits at        http://<this-machine>:<port>/hit
  * sends hits to the peer tenant whose IP you enter on the dashboard

For every hit, both sides record WHERE IT CAME FROM (the TCP source IP:port the
receiving socket actually saw) and WHERE IT LANDED (the local IP:port it arrived
on). The sender also gets back what the receiver saw, so NAT / proxies in the
path become visible.
"""
import argparse
import http.client
import json
import socket
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROLES = {
    "sender": {"peer": "receiver", "port": 8001, "peer_port": 8002, "accent": "#2563eb"},
    "receiver": {"peer": "sender", "port": 8002, "peer_port": 8001, "accent": "#0f9d58"},
}
DATA_DIR = Path(__file__).resolve().parent / "data"
MAX_ROWS = 500
SEND_TIMEOUT = 5


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def clean_ip(ip):
    # IPv4 clients on a dual-stack socket show up as ::ffff:a.b.c.d
    return ip[7:] if ip.startswith("::ffff:") else ip


def local_ips():
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    primary = route_source_ip("8.8.8.8", 80)
    if primary:
        ips.add(primary)
    return sorted(ip for ip in ips if not ip.startswith("127."))


def route_source_ip(dest_ip, dest_port):
    """Source IP the OS would use to reach dest_ip (no packets are sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((dest_ip, dest_port))
            return s.getsockname()[0]
    except OSError:
        return None


class Tenant:
    def __init__(self, role, port):
        self.role = role
        self.peer_role = ROLES[role]["peer"]
        self.port = port
        self.hostname = socket.gethostname()
        self.peer_ip = ""
        self.peer_resolved = ""
        self.peer_port = ROLES[role]["peer_port"]
        self.route_ip = None
        self.auto_interval = 0
        self.incoming = deque(maxlen=MAX_ROWS)
        self.outgoing = deque(maxlen=MAX_ROWS)
        self.lock = threading.Lock()
        DATA_DIR.mkdir(exist_ok=True)
        self.config_path = DATA_DIR / f"{role}_config.json"
        self.log_path = DATA_DIR / f"{role}_hits.jsonl"
        self._load_config()
        threading.Thread(target=self._auto_loop, daemon=True).start()

    # ---- config -----------------------------------------------------------

    def _load_config(self):
        try:
            cfg = json.loads(self.config_path.read_text())
            self.set_peer(cfg.get("peer_ip", ""), cfg.get("peer_port", self.peer_port), save=False)
        except (OSError, ValueError):
            pass

    def set_peer(self, ip, port, save=True):
        ip = str(ip or "").strip()
        if ip.count(":") == 1:  # allow "10.0.0.5:8002"
            ip, port = ip.split(":")
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError("port must be 1-65535")
        resolved = socket.gethostbyname(ip) if ip else ""
        with self.lock:
            self.peer_ip, self.peer_resolved, self.peer_port = ip, resolved, port
            self.route_ip = route_source_ip(resolved, port) if resolved else None
        if save:
            self.config_path.write_text(json.dumps({"peer_ip": ip, "peer_port": port}))

    # ---- logging ----------------------------------------------------------

    def _log(self, rec):
        line = (
            f"[{rec['direction'].upper():3}] {rec.get('from_ip') or '?'}:{rec.get('from_port') or '?'}"
            f" -> {rec.get('to_ip')}:{rec.get('to_port')}  {rec.get('status')}"
        )
        print(line, flush=True)
        try:
            with self.log_path.open("a") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError:
            pass

    # ---- inbound ----------------------------------------------------------

    def receive_hit(self, handler, body, method):
        origin_ip, origin_port = clean_ip(handler.client_address[0]), handler.client_address[1]
        reached_ip, reached_port = handler.connection.getsockname()[:2]
        reached_ip = clean_ip(reached_ip)
        xff = handler.headers.get("X-Forwarded-For", "")
        real_ip = xff.split(",")[0].strip() if xff else origin_ip
        expected = self.peer_resolved
        if not expected:
            status = "unchecked"
        elif expected in (origin_ip, real_ip):
            status = "expected"
        else:
            status = "unexpected"
        rec = {
            "id": str(body.get("id") or uuid.uuid4().hex[:8]),
            "direction": "in",
            "time": now_iso(),
            "method": method,
            "from_ip": origin_ip,
            "from_port": origin_port,
            "x_forwarded_for": xff,
            "to_ip": reached_ip,
            "to_port": reached_port,
            "host_header": handler.headers.get("Host", ""),
            "caller_role": body.get("from_role") or "",
            "caller_hostname": body.get("from_hostname") or "",
            "caller_claimed_ip": body.get("claimed_from_ip") or "",
            "message": str(body.get("message") or "")[:500],
            "user_agent": handler.headers.get("User-Agent", ""),
            "expected_ip": expected,
            "status": status,
        }
        with self.lock:
            self.incoming.appendleft(rec)
        self._log(rec)
        return {
            "ok": True,
            "id": rec["id"],
            "role": self.role,
            "hostname": self.hostname,
            "seen_origin_ip": origin_ip,
            "seen_origin_port": origin_port,
            "reached_ip": reached_ip,
            "reached_port": reached_port,
            "expected_ip": expected,
            "verdict": status,
            "received_at": rec["time"],
        }

    # ---- outbound ---------------------------------------------------------

    def send_hit(self, message, trigger="manual"):
        with self.lock:
            peer_ip, peer_port = self.peer_ip, self.peer_port
        rec = {
            "id": uuid.uuid4().hex[:8],
            "direction": "out",
            "time": now_iso(),
            "trigger": trigger,
            "message": message,
            "from_ip": None,
            "from_port": None,
            "to_ip": peer_ip,
            "to_port": peer_port,
            "status": "failed",
        }
        if not peer_ip:
            rec["error"] = f"{self.peer_role} IP not set"
            self._finish_out(rec)
            return rec

        t0 = time.perf_counter()
        conn = http.client.HTTPConnection(peer_ip, peer_port, timeout=SEND_TIMEOUT)
        try:
            conn.connect()
            rec["from_ip"], rec["from_port"] = conn.sock.getsockname()[:2]
            payload = {
                "id": rec["id"],
                "from_role": self.role,
                "from_hostname": self.hostname,
                "claimed_from_ip": rec["from_ip"],
                "message": message,
                "sent_at": rec["time"],
            }
            conn.request(
                "POST", "/hit", body=json.dumps(payload),
                headers={"Content-Type": "application/json", "User-Agent": f"tenant-pilot/{self.role}"},
            )
            resp = conn.getresponse()
            raw = resp.read()
            rec["http_status"] = resp.status
            reply = json.loads(raw) if raw else {}
            rec["remote_role"] = reply.get("role")
            rec["remote_hostname"] = reply.get("hostname")
            rec["remote_seen_ip"] = reply.get("seen_origin_ip")
            rec["remote_seen_port"] = reply.get("seen_origin_port")
            rec["remote_reached_ip"] = reply.get("reached_ip")
            rec["remote_reached_port"] = reply.get("reached_port")
            rec["remote_verdict"] = reply.get("verdict")
            rec["nat"] = bool(rec["remote_seen_ip"]) and rec["remote_seen_ip"] != rec["from_ip"]
            rec["status"] = "delivered" if resp.status == 200 else "http_error"
        except (OSError, http.client.HTTPException, ValueError) as e:
            rec["error"] = f"{type(e).__name__}: {e}"
        finally:
            conn.close()
            rec["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        self._finish_out(rec)
        return rec

    def _finish_out(self, rec):
        with self.lock:
            self.outgoing.appendleft(rec)
        self._log(rec)

    def _auto_loop(self):
        next_at = 0.0
        while True:
            time.sleep(0.2)
            interval = self.auto_interval
            if interval and self.peer_ip and time.monotonic() >= next_at:
                self.send_hit("auto", trigger="auto")
                next_at = time.monotonic() + interval

    # ---- dashboard state --------------------------------------------------

    def state(self):
        with self.lock:
            incoming, outgoing = list(self.incoming), list(self.outgoing)
            return {
                "role": self.role,
                "peer_role": self.peer_role,
                "hostname": self.hostname,
                "port": self.port,
                "local_ips": local_ips(),
                "peer_ip": self.peer_ip,
                "peer_resolved": self.peer_resolved,
                "peer_port": self.peer_port,
                "route_ip": self.route_ip,
                "auto_interval": self.auto_interval,
                "incoming": incoming,
                "outgoing": outgoing,
            }

    def clear(self):
        with self.lock:
            self.incoming.clear()
            self.outgoing.clear()


class Handler(BaseHTTPRequestHandler):
    server_version = "TenantPilot/1.0"
    tenant: Tenant = None
    page: bytes = b""

    def log_message(self, fmt, *args):
        pass  # hits are logged by Tenant; dashboard polling would be noise

    def _send(self, code, data, ctype="application/json"):
        if not isinstance(data, bytes):
            data = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(min(length, 65536))
        try:
            value = json.loads(raw)
            return value if isinstance(value, dict) else {"message": str(value)}
        except ValueError:
            return {"message": raw.decode("utf-8", "replace")}

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/":
            self._send(200, self.page, "text/html; charset=utf-8")
        elif url.path == "/api/state":
            self._send(200, self.tenant.state())
        elif url.path == "/hit":
            q = parse_qs(url.query)
            body = {"message": q.get("msg", [""])[0]}
            self._send(200, self.tenant.receive_hit(self, body, "GET"))
        elif url.path == "/health":
            self._send(200, {"ok": True, "role": self.tenant.role})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        body = self._body()
        t = self.tenant
        try:
            if path == "/hit":
                self._send(200, t.receive_hit(self, body, "POST"))
            elif path == "/api/config":
                t.set_peer(body.get("peer_ip", ""), body.get("peer_port", t.peer_port))
                self._send(200, {"ok": True})
            elif path == "/api/send":
                count = max(1, min(int(body.get("count", 1)), 50))
                results = [t.send_hit(str(body.get("message", ""))[:500]) for _ in range(count)]
                self._send(200, {"ok": True, "results": results})
            elif path == "/api/auto":
                t.auto_interval = max(0.0, float(body.get("interval", 0)))
                self._send(200, {"ok": True})
            elif path == "/api/clear":
                t.clear()
                self._send(200, {"ok": True})
            else:
                self._send(404, {"error": "not found"})
        except (ValueError, OSError) as e:
            self._send(400, {"ok": False, "error": str(e)})


def main(role):
    defaults = ROLES[role]
    ap = argparse.ArgumentParser(description=f"Run the {role} tenant")
    ap.add_argument("--host", default="0.0.0.0", help="interface to listen on (default: all)")
    ap.add_argument("--port", type=int, default=defaults["port"])
    ap.add_argument("--peer", default=None, help=f"{defaults['peer']} IP (or IP:port) to preset")
    args = ap.parse_args()

    tenant = Tenant(role, args.port)
    if args.peer:
        tenant.set_peer(args.peer, tenant.peer_port)

    page = (Path(__file__).resolve().parent / "dashboard.html").read_text()
    page = page.replace("__ROLE__", role).replace("__ACCENT__", defaults["accent"])
    Handler.tenant = tenant
    Handler.page = page.encode()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    print(f"{role.upper()} tenant on {tenant.hostname}")
    print(f"  dashboard : http://{(local_ips() or ['127.0.0.1'])[0]}:{args.port}/")
    print(f"  hit URL   : http://<this-ip>:{args.port}/hit")
    print(f"  {defaults['peer']} IP : {tenant.peer_ip or '(set it on the dashboard)'}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--role", choices=ROLES, required=True)
    known, rest = ap.parse_known_args()
    sys.argv = [sys.argv[0]] + rest
    main(known.role)
