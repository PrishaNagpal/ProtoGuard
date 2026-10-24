#!/usr/bin/env python3
"""ProtoGuard dashboard server (standard library only).

Run from anywhere inside WSL:   python3 ui/server.py
Then open http://localhost:8000 in your browser.

It builds the project, then runs the REAL ./supervisor / ./namelist
binaries on demand and streams their output to the page (Server-Sent Events).
"""
import glob
import json
import os
import queue
import shutil
import signal
import socket
import statistics
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

UI_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(UI_DIR)
BIN = "/tmp/protoguard_escape_tests"
PORT = 8000
AGENT_PORT = 18080
REDIS_PORT = 6380

LABELS = {"attack": "connect after listen", "attack_exec": "execve after listen"}
PROGS = {}  # id -> path
BENCH_LOCK = threading.Lock()
RUN_LOCK = threading.Lock()

POLICIES = {
    "echo": {
        "file": "policies/echo.policy", "title": "echo.policy",
        "blurb": "Baseline protocol for the echo agent. connect/execve are fine while starting up; "
                 "once LISTENING, connect, execve, execveat and sendto are denied.",
        "scenarios": [
            {"id": "legit", "label": "Legit echo client", "kind": "legit"},
            {"id": "attack", "label": "Attack: connect after listen", "kind": "attack"},
            {"id": "preconnect", "label": "connect BEFORE listen", "kind": "allowed"},
        ],
    },
    "strict": {
        "file": "policies/strict-no-outbound.policy", "title": "strict-no-outbound.policy",
        "blurb": "Same protocol, tighter: an echo server never needs to dial out, so connect() "
                 "is denied even before listen(). One text-file edit, no rebuild.",
        "scenarios": [
            {"id": "legit", "label": "Legit echo client", "kind": "legit"},
            {"id": "attack", "label": "Attack: connect after listen", "kind": "attack"},
            {"id": "preconnect", "label": "connect BEFORE listen", "kind": "attack"},
        ],
    },
    "redis": {
        "file": "policies/redis.policy", "title": "redis.policy",
        "blurb": "Written from strace of the real, unmodified redis-server (threads share one tgid, "
                 "uses accept4). A listening Redis may not dial out or exec.",
        "scenarios": [
            {"id": "legit", "label": "Legit commands (PING/SET/GET)", "kind": "legit"},
            {"id": "replicaof", "label": "Attack: REPLICAOF forces connect()", "kind": "attack"},
        ],
    },
}


def build():
    subprocess.run(["make", "agent", "attack", "attack_exec", "supervisor", "namelist"],
                   cwd=ROOT, stdout=subprocess.DEVNULL)
    PROGS["attack"] = "./attack"
    PROGS["attack_exec"] = "./attack_exec"
    os.makedirs(BIN, exist_ok=True)
    for src in sorted(glob.glob(os.path.join(ROOT, "tests", "escape_*.c"))):
        name = os.path.basename(src)[:-2]
        out = os.path.join(BIN, name)
        r = subprocess.run(["gcc", "-O0", "-no-pie", "-o", out, src], capture_output=True)
        if r.returncode:
            subprocess.run(["gcc", "-O0", "-o", out, src], capture_output=True)
        if os.path.exists(out):
            PROGS[name] = out
            LABELS[name] = name[len("escape_"):].replace("_", " ")
    pre = os.path.join(BIN, "demo_prelisten")
    subprocess.run(["gcc", "-O0", "-o", pre, os.path.join(UI_DIR, "demo_prelisten.c")],
                   capture_output=True)
    if os.path.exists(pre):
        PROGS["_prelisten"] = pre


# ---------------------------------------------------------------- clients
def _connect(port, tries=500):
    for _ in range(tries):
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=2)
        except OSError:
            time.sleep(0.01)
    return None


def echo_client(q):
    c = _connect(AGENT_PORT)
    if not c:
        q.put("client: could not connect")
        return
    q.put("client> hello")
    c.sendall(b"hello\n")
    c.shutdown(socket.SHUT_WR)
    q.put("client< " + c.recv(64).decode(errors="replace").strip())
    c.close()


def redis_client(cmds):
    def run(q):
        c = _connect(REDIS_PORT)
        if not c:
            q.put("client: could not connect to redis")
            return
        f = c.makefile("rwb")
        for cmd in cmds:
            q.put("client> " + cmd)
            try:
                f.write(cmd.encode() + b"\r\n")
                f.flush()
                line = f.readline().decode(errors="replace").strip()
                if line.startswith("$") and line != "$-1":
                    line += "  " + f.readline().decode(errors="replace").strip()
                q.put("client< " + (line or "(connection closed)"))
            except OSError:
                q.put("client< (connection closed)")
                return
            if cmd.startswith("SHUTDOWN"):
                return
        c.close()
    return run


def plan(policy, scenario):
    """Return (cmd, client) for a policy demo, or (None, message)."""
    pol = POLICIES[policy]
    sup = ["./supervisor", "--policy", pol["file"]]
    if policy == "redis":
        path = shutil.which("redis-server")
        if not path:
            return None, "redis-server is not installed. In WSL run: sudo apt install -y redis-server"
        cmd = sup + [path, "--port", str(REDIS_PORT), "--bind", "127.0.0.1",
                     "--save", "", "--appendonly", "no", "--daemonize", "no"]
        if scenario == "replicaof":
            return cmd, redis_client(["PING", "REPLICAOF 127.0.0.1 9"])
        return cmd, redis_client(["PING", "SET demo hello", "GET demo", "SHUTDOWN NOSAVE"])
    if scenario == "legit":
        return sup + ["./agent"], echo_client
    if scenario == "attack":
        return sup + ["./attack"], None
    if scenario == "preconnect" and "_prelisten" in PROGS:
        return sup + [PROGS["_prelisten"]], None
    return None, "unknown scenario"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _sse(self, data, event=None):
        msg = ("event: %s\n" % event if event else "") + "data: " + json.dumps(data) + "\n\n"
        self.wfile.write(msg.encode())
        self.wfile.flush()

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            with open(os.path.join(UI_DIR, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if u.path == "/api/ping":
            return self._send(200, "ok")
        if u.path == "/api/progs":
            body = json.dumps([{"id": k, "label": LABELS.get(k, k)}
                               for k in PROGS if not k.startswith("_")])
            return self._send(200, body, "application/json")
        if u.path == "/api/policies":
            return self._send(200, json.dumps(
                [dict(id=k, **{x: v[x] for x in ("title", "blurb", "scenarios")})
                 for k, v in POLICIES.items()]), "application/json")
        if u.path == "/api/policy/text":
            p = q.get("policy", [""])[0]
            if p not in POLICIES:
                return self._send(400, "bad request")
            with open(os.path.join(ROOT, POLICIES[p]["file"]), encoding="utf-8", errors="replace") as f:
                return self._send(200, f.read())
        if u.path == "/api/bench":
            p = os.path.join(ROOT, "phase8_results.txt")
            txt = open(p, encoding="utf-8", errors="replace").read() if os.path.exists(p) else ""
            return self._send(200, txt)
        if u.path == "/api/bench/run":
            try:
                n = max(5, min(60, int(q.get("n", ["20"])[0])))
            except ValueError:
                n = 20
            if not BENCH_LOCK.acquire(blocking=False):
                return self._send(429, "benchmark already running")
            try:
                return self._send(200, json.dumps(measure(n)), "application/json")
            except Exception as e:
                return self._send(500, str(e))
            finally:
                BENCH_LOCK.release()
        if u.path == "/api/run":
            d = q.get("defense", ["supervisor"])[0]
            p = q.get("prog", [""])[0]
            if d not in ("supervisor", "namelist", "none") or p not in PROGS:
                return self._send(400, "bad request")
            cmd = [PROGS[p]] if d == "none" else ["./" + d, PROGS[p]]
            return self.stream(cmd, None, 5)
        if u.path == "/api/policy/run":
            pol = q.get("policy", [""])[0]
            sc = q.get("scenario", [""])[0]
            if pol not in POLICIES:
                return self._send(400, "bad request")
            cmd, client = plan(pol, sc)
            if cmd is None:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self._sse("client: " + client)
                return self._sse(1, "done")
            return self.stream(cmd, client, 8)
        self._send(404, "not found")

    def stream(self, cmd, client, timeout):
        if not RUN_LOCK.acquire(blocking=False):
            return self._send(429, "another run is in progress")
        proc = None
        timer = None
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            q = queue.Queue()
            proc = subprocess.Popen(cmd, cwd=ROOT, text=True, bufsize=1,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    start_new_session=True)

            def pump():
                for line in proc.stdout:
                    q.put(line.rstrip("\n"))
                q.put(None)

            threading.Thread(target=pump, daemon=True).start()
            if client:
                threading.Thread(target=client, args=(q,), daemon=True).start()
            timer = threading.Timer(timeout, lambda: kill_group(proc))
            timer.start()
            print("\n[dashboard] running: " + " ".join(cmd), flush=True)
            self._sse("$ " + " ".join(cmd))
            while True:
                item = q.get()
                if item is None:
                    break
                print("  | " + item, flush=True)   # same output also shows here
                self._sse(item)
            rc = proc.wait()
            print("[dashboard] finished (exit code %s)" % rc, flush=True)
            self._sse(rc, "done")
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            if timer:
                timer.cancel()
            if proc:
                kill_group(proc)
            RUN_LOCK.release()


def kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


# ------------------------------------------------------------- benchmark
def one_cycle(cmd):
    """Start server, send one echo, wait for exit. Returns elapsed ms."""
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    for line in p.stdout:
        if "listening on" in line:
            break
    c = _connect(AGENT_PORT, 200)
    if not c:
        p.kill()
        raise RuntimeError("agent never accepted a connection")
    c.sendall(b"hello\n")
    c.shutdown(socket.SHUT_WR)
    c.recv(64)
    c.close()
    try:
        p.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
    return (time.perf_counter() - t0) * 1000


def measure(n):
    """Alternate plain / supervised cycles so machine drift hits both equally."""
    base, sup = [], []
    one_cycle(["./agent"])
    one_cycle(["./supervisor", "./agent"])
    for _ in range(n):
        base.append(one_cycle(["./agent"]))
        sup.append(one_cycle(["./supervisor", "./agent"]))
    b, s = statistics.mean(base), statistics.mean(sup)
    return {"n": n, "base_ms": round(b, 2), "sup_ms": round(s, 2),
            "overhead_pct": round((s / b - 1) * 100, 1),
            "base_sd": round(statistics.pstdev(base), 2),
            "sup_sd": round(statistics.pstdev(sup), 2)}


if __name__ == "__main__":
    build()
    print(f"ProtoGuard dashboard: http://localhost:{PORT}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
    