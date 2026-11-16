#!/usr/bin/env python3
"""Ciphera local API: JWT auth, SQLite metadata, opaque E2E ciphertext relay."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("CIPHERA_DB", ROOT / "data" / "ciphera.db"))
PORT = int(os.environ.get("PORT", "8000"))
JWT_SECRET = os.environ.get("CIPHERA_SECRET", "local-development-secret-change-before-deploy")
TOKEN_TTL = int(os.environ.get("CIPHERA_TOKEN_TTL", "3600"))
AGENTS = {
    "nexa": {"name": "Nexa Industries", "secret": os.environ.get("CIPHERA_AGENT_A_SECRET", "nexa-local-demo-key")},
    "orion": {"name": "Orion Labs", "secret": os.environ.get("CIPHERA_AGENT_B_SECRET", "orion-local-demo-key")},
}


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS handshakes (
                id TEXT PRIMARY KEY, agent_a TEXT NOT NULL, agent_b TEXT NOT NULL,
                status TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS public_keys (
                handshake_id TEXT NOT NULL, agent_id TEXT NOT NULL, public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL, PRIMARY KEY(handshake_id, agent_id),
                FOREIGN KEY(handshake_id) REFERENCES handshakes(id)
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT, handshake_id TEXT NOT NULL,
                sender_id TEXT NOT NULL, recipient_id TEXT NOT NULL, nonce TEXT NOT NULL,
                ciphertext TEXT NOT NULL, created_at INTEGER NOT NULL,
                FOREIGN KEY(handshake_id) REFERENCES handshakes(id)
            );
        """)


def make_token(agent_id):
    now = int(time.time())
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64(json.dumps({"sub": agent_id, "iat": now, "exp": now + TOKEN_TTL}, separators=(",", ":")).encode())
    body = f"{header}.{payload}"
    signature = b64(hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{signature}", now + TOKEN_TTL


class Handler(BaseHTTPRequestHandler):
    server_version = "Ciphera/0.1"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        try:
            size = min(int(self.headers.get("Content-Length", 0)), 1_000_000)
            return json.loads(self.rfile.read(size) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return None

    def auth(self):
        raw = self.headers.get("Authorization", "")
        if not raw.startswith("Bearer "):
            return None
        token = raw[7:].split(".")
        if len(token) != 3:
            return None
        body = ".".join(token[:2])
        expected = b64(hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, token[2]):
            return None
        try:
            payload = json.loads(base64.urlsafe_b64decode(token[1] + "=" * (-len(token[1]) % 4)))
            if payload.get("exp", 0) <= int(time.time()) or payload.get("sub") not in AGENTS:
                return None
            return payload["sub"]
        except (ValueError, KeyError, json.JSONDecodeError):
            return None

    def do_POST(self):
        path = urlparse(self.path).path
        data = self.body()
        if data is None:
            return self.send_json({"error": "invalid_json"}, 400)
        if path == "/api/auth/token":
            agent_id, secret = data.get("agent_id"), data.get("secret", "")
            if agent_id not in AGENTS or not hmac.compare_digest(str(AGENTS[agent_id]["secret"]), str(secret)):
                return self.send_json({"error": "invalid_credentials"}, 401)
            token, expires = make_token(agent_id)
            return self.send_json({"access_token": token, "token_type": "Bearer", "expires_at": expires, "expires_in": TOKEN_TTL})
        agent = self.auth()
        if not agent:
            return self.send_json({"error": "unauthorized", "message": "Bearer JWT mancante, non valido o scaduto."}, 401)
        if path == "/api/handshakes":
            peer = data.get("peer_id")
            if peer not in AGENTS or peer == agent:
                return self.send_json({"error": "invalid_peer"}, 400)
            hid, now = secrets.token_urlsafe(18), int(time.time())
            with sqlite3.connect(DB_PATH) as db:
                db.execute("INSERT INTO handshakes VALUES (?, ?, ?, 'pending', ?, ?)", (hid, agent, peer, now, now))
            return self.send_json({"handshake_id": hid, "status": "pending", "participants": [agent, peer], "created_at": now}, 201)
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["api", "handshakes"]:
            hid, action = parts[2], parts[3]
            with sqlite3.connect(DB_PATH) as db:
                db.row_factory = sqlite3.Row
                hs = db.execute("SELECT * FROM handshakes WHERE id=?", (hid,)).fetchone()
                if not hs or agent not in (hs["agent_a"], hs["agent_b"]):
                    return self.send_json({"error": "handshake_not_found"}, 404)
                if action == "keys":
                    key = data.get("public_key", "")
                    if not isinstance(key, str) or len(key) > 512 or not key:
                        return self.send_json({"error": "invalid_public_key"}, 400)
                    db.execute("INSERT OR REPLACE INTO public_keys VALUES (?, ?, ?, ?)", (hid, agent, key, int(time.time())))
                    count = db.execute("SELECT count(*) FROM public_keys WHERE handshake_id=?", (hid,)).fetchone()[0]
                    status = "active" if count == 2 else "pending"
                    db.execute("UPDATE handshakes SET status=?, updated_at=? WHERE id=?", (status, int(time.time()), hid))
                    peer = hs["agent_b"] if agent == hs["agent_a"] else hs["agent_a"]
                    peerrow = db.execute("SELECT public_key FROM public_keys WHERE handshake_id=? AND agent_id=?", (hid, peer)).fetchone()
                    return self.send_json({"handshake_id": hid, "status": status, "peer_public_key": peerrow[0] if peerrow else None})
                if action == "messages":
                    if hs["status"] != "active":
                        return self.send_json({"error": "handshake_incomplete"}, 409)
                    ciphertext, nonce = data.get("ciphertext", ""), data.get("nonce", "")
                    if not isinstance(ciphertext, str) or len(ciphertext) > 100_000 or not isinstance(nonce, str) or len(nonce) > 128:
                        return self.send_json({"error": "invalid_envelope"}, 400)
                    recipient = hs["agent_b"] if agent == hs["agent_a"] else hs["agent_a"]
                    db.execute("INSERT INTO messages(handshake_id,sender_id,recipient_id,nonce,ciphertext,created_at) VALUES (?,?,?,?,?,?)",
                               (hid, agent, recipient, nonce, ciphertext, int(time.time())))
                    return self.send_json({"status": "relayed", "message_id": db.execute("SELECT last_insert_rowid()").fetchone()[0]}, 202)
        return self.send_json({"error": "not_found"}, 404)

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/api/dashboard/handshakes/") and path.endswith("/messages"):
            handshake_id = path[len("/api/dashboard/handshakes/"):-len("/messages")].strip("/")
            with sqlite3.connect(DB_PATH) as db:
                db.row_factory = sqlite3.Row
                exists = db.execute("SELECT 1 FROM handshakes WHERE id=?", (handshake_id,)).fetchone()
                if not exists:
                    return self.send_json({"error": "handshake_not_found"}, 404)
                messages = db.execute("SELECT id, sender_id, nonce, ciphertext, created_at FROM messages WHERE handshake_id=? ORDER BY id DESC LIMIT 100", (handshake_id,)).fetchall()
            return self.send_json({"handshake_id": handshake_id, "messages": [dict(message) for message in messages]})
        if path == "/api/agents/conversations":
            agent = self.auth()
            if not agent:
                return self.send_json({"error": "unauthorized", "message": "Bearer JWT mancante, non valido o scaduto."}, 401)
            with sqlite3.connect(DB_PATH) as db:
                db.row_factory = sqlite3.Row
                rows = db.execute("SELECT id, agent_a, agent_b, status, created_at FROM handshakes WHERE agent_a=? OR agent_b=? ORDER BY created_at", (agent, agent)).fetchall()
                return self.send_json({"conversations": [dict(row) for row in rows]})
        if path.startswith("/api/handshakes/") and path.endswith("/messages"):
            agent = self.auth()
            if not agent:
                return self.send_json({"error": "unauthorized", "message": "Bearer JWT mancante, non valido o scaduto."}, 401)
            parts = path.strip("/").split("/")
            if len(parts) == 4:
                hid = parts[2]
                with sqlite3.connect(DB_PATH) as db:
                    db.row_factory = sqlite3.Row
                    hs = db.execute("SELECT * FROM handshakes WHERE id=?", (hid,)).fetchone()
                    if not hs or agent not in (hs["agent_a"], hs["agent_b"]):
                        return self.send_json({"error": "handshake_not_found"}, 404)
                    query = urlparse(self.path).query
                    try:
                        after = int(query.split("after=")[-1].split("&")[0]) if "after=" in query else 0
                    except ValueError:
                        return self.send_json({"error": "invalid_cursor"}, 400)
                    rows = db.execute("SELECT id, sender_id, nonce, ciphertext, created_at FROM messages WHERE handshake_id=? AND recipient_id=? AND id>? ORDER BY id LIMIT 100", (hid, agent, after)).fetchall()
                    return self.send_json({"messages": [dict(r) for r in rows]})
        if path == "/api/health":
            return self.send_json({"status": "ok", "service": "ciphera", "timestamp": int(time.time())})
        if path == "/api/dashboard":
            with sqlite3.connect(DB_PATH) as db:
                db.row_factory = sqlite3.Row
                sessions = [dict(r) for r in db.execute("""
                    SELECT h.id, h.agent_a, h.agent_b, h.status, h.created_at, h.updated_at,
                    (SELECT count(*) FROM messages m WHERE m.handshake_id=h.id) AS message_count
                    FROM handshakes h ORDER BY h.created_at DESC LIMIT 30
                """)]
                totals = db.execute("SELECT count(*) FROM handshakes").fetchone()[0]
                active = db.execute("SELECT count(*) FROM handshakes WHERE status='active'").fetchone()[0]
                messages = db.execute("SELECT count(*) FROM messages").fetchone()[0]
            return self.send_json({"agents": [{"id": k, "name": v["name"]} for k, v in AGENTS.items()], "sessions": sessions,
                                   "stats": {"sessions": totals, "active": active, "messages": messages}})
        if path == "/" or path == "/index.html":
            content = (ROOT / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            return self.wfile.write(content)
        return self.send_json({"error": "not_found"}, 404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()


if __name__ == "__main__":
    init_db()
    print(f"Ciphera API and dashboard running at http://localhost:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
