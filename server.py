"""Jarri browser service: Claude's access to Brave, with access control and a visible action log.

Backend only. Jarri's browser panel is a client of this service.
Brave runs with --remote-debugging-port (start-brave.sh) on 127.0.0.1 and its own profile.
The service talks CDP to it over a small built-in WebSocket client (stdlib only).

  GET  /status                      -> {debugPort, available, paused, tabs}
  GET  /tabs                        -> [{id, title, url, origin, granted}]
  GET  /digest?tab=ID&limit=N       -> {status, url, title, loginWall, total, items}
                                       refs are valid until the next read of that tab
  POST /open {url, tab?}            -> same as digest, or 403 origin_not_granted
  POST /act {tab, action, ref?, value?, key?, approvalId?}
                                    -> {delta, url, title, loginWall}
                                       or 409 approval_required / stale_ref, 403 origin_not_granted
  GET  /events, /requests, /approvals, /permissions
  POST /permissions {origin, hours?}      hours null/absent = until revoked
  POST /permissions/revoke {origin}
  POST /approvals {id, approve}
  POST /requests/dismiss {id}
  POST /pause {on}                  -> while paused, /open and /act refuse with 423
  POST /focus {tab}

Passwords are never returned, and Claude can not type into them. Cookies and storage are never read.
Binds to 127.0.0.1 only and accepts requests from the same allowed origins as the other services.
"""

import base64
import json
import os
import re
import socket
import struct
import threading
import time
import uuid
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.error import URLError
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, urlopen

HOST = "127.0.0.1"
PORT = int(os.environ.get("JARRI_BROWSER_PORT", "8786"))
DEBUG_PORT = int(os.environ.get("JARRI_BROWSER_DEBUG_PORT", "9222"))
STATE_DIR = os.path.expanduser(os.environ.get("JARRI_BROWSER_STATE", "~/.local/state/jarri-browser"))
PERMISSIONS_FILE = os.path.join(STATE_DIR, "permissions.json")
TIMEOUT_S = 10
INTENT_S = 0.3
SETTLE_S = 0.4
DEFAULT_LIMIT = 60
MAX_LIMIT = 200
# Clicks or Enter presses whose label or form text matches this need the user's approval.
RISKY = re.compile(
    r"köp|betala|betalning|pay|checkout|faktura|invoice|"
    r"prenumer|subscribe|upgrade|uppgradera|"
    r"logga in|logga ut|log ?in|log ?out|sign ?in|sign ?out|lösenord|password|2fa|verifiera|verify|"
    r"säkerhet|security|api[- ]?nyckel|api[- ]?key|token|secret|behörighet|permission|"
    r"skicka|send|submit|radera|ta bort|delete|remove|avaktivera|disable|återkalla|revoke|"
    r"publicera|publish|deploy|dela|share|bekräfta|confirm",
    re.IGNORECASE,
)
PRESS_KEYS = {"Enter": (13, "\r"), "Tab": (9, ""), "Escape": (27, "")}
ALLOWED_ORIGINS = {
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
    "http://localhost:1420",
    "http://127.0.0.1:1420",
    "http://localhost:8792",
    "http://127.0.0.1:8792",
}
ALLOWED_HOSTS = {f"{HOST}:{PORT}", f"localhost:{PORT}"}

DIGEST_JS = """(() => {
  const LIMIT = __LIMIT__;
  const SEL = 'a[href],button,input,select,textarea,summary,[role=button],[role=link],[role=checkbox],[role=radio],[role=tab],[role=menuitem],[role=switch],[role=slider],[contenteditable=true]';
  const clean = s => (s || '').replace(/\\s+/g, ' ').trim().slice(0, 80);
  document.querySelectorAll('[data-jarri-ref]').forEach(e => e.removeAttribute('data-jarri-ref'));
  const shown = el => {
    const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && !el.disabled;
  };
  const labelOf = el => {
    const al = el.getAttribute('aria-label');
    if (al) return clean(al);
    const lb = el.getAttribute('aria-labelledby');
    if (lb) return clean(lb.split(/\\s+/).map(id => document.getElementById(id)?.textContent || '').join(' '));
    if (el.labels && el.labels.length) return clean([...el.labels].map(l => l.textContent).join(' '));
    if (el.tagName === 'INPUT' && ['submit', 'button', 'reset'].includes(el.type)) return clean(el.value);
    return clean(el.innerText || el.getAttribute('title') || el.getAttribute('placeholder') || el.getAttribute('name') || '');
  };
  const kindOf = el => {
    const t = el.tagName, role = el.getAttribute('role');
    if (t === 'INPUT') {
      const ty = (el.type || 'text').toLowerCase();
      if (ty === 'password') return 'password';
      if (['submit', 'button', 'reset', 'image'].includes(ty)) return 'button';
      if (ty === 'checkbox' || ty === 'radio' || ty === 'range') return ty === 'range' ? 'slider' : ty;
      return 'textbox';
    }
    if (t === 'TEXTAREA') return 'textarea';
    if (t === 'SELECT') return 'select';
    if (t === 'A') return 'link';
    if (el.isContentEditable) return 'textbox';
    return role || (t === 'BUTTON' || t === 'SUMMARY' ? 'button' : t.toLowerCase());
  };
  const valueOf = (el, kind) => {
    if (kind === 'password') return null;
    if (kind === 'checkbox' || kind === 'radio') return el.checked ? 'checked' : 'unchecked';
    if (kind === 'textbox' || kind === 'textarea' || kind === 'slider') return clean(el.value ?? el.textContent);
    if (kind === 'select') return clean(el.selectedOptions[0]?.textContent || '');
    return null;
  };
  const all = [...document.querySelectorAll(SEL)].filter(shown);
  const items = all.slice(0, LIMIT).map((el, i) => {
    el.setAttribute('data-jarri-ref', String(i + 1));
    const kind = kindOf(el);
    return { ref: i + 1, kind, label: labelOf(el), value: valueOf(el, kind) };
  });
  const loginWall = [...document.querySelectorAll('input[type=password]')].some(shown);
  return { url: location.href, title: document.title, loginWall, total: all.length, items };
})()"""

RESOLVE_JS = """(() => {
  const el = document.querySelector('[data-jarri-ref="__REF__"]');
  if (!el) return { stale: true };
  el.scrollIntoView({ block: 'center', inline: 'center' });
  const r = el.getBoundingClientRect();
  const frame = document.createElement('div');
  frame.style.cssText = `position:fixed;left:${r.left - 4}px;top:${r.top - 4}px;width:${r.width + 8}px;height:${r.height + 8}px;border:3px solid #7c3aed;border-radius:6px;pointer-events:none;z-index:2147483647`;
  const tag = document.createElement('div');
  tag.textContent = 'Claude arbetar här';
  tag.style.cssText = `position:fixed;left:${r.left}px;top:${Math.max(0, r.top - 28)}px;background:#7c3aed;color:#fff;font:12px system-ui,sans-serif;padding:3px 8px;border-radius:4px;pointer-events:none;z-index:2147483647`;
  document.body.append(frame, tag);
  setTimeout(() => { frame.remove(); tag.remove(); }, 1500);
  return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
})()"""

FOCUSED_JS = """(() => {
  const el = document.activeElement;
  if (!el || el === document.body) return '';
  const own = el.getAttribute('aria-label') || el.innerText || el.getAttribute('placeholder') || '';
  const form = el.form ? el.form.innerText : '';
  return (own + ' ' + form).replace(/\\s+/g, ' ').trim().slice(0, 300);
})()"""

FOCUS_JS = """(() => {
  const el = document.querySelector('[data-jarri-ref="__REF__"]');
  if (!el) return false;
  el.focus();
  if (el.select) el.select();
  return true;
})()"""


class CdpError(Exception):
    pass


class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__(body.get("error", ""))
        self.status = status
        self.body = body


class Cdp:
    """Minimal CDP client over a WebSocket on localhost."""

    def __init__(self, ws_url):
        match = re.match(r"ws://([^:/]+):(\d+)(/.*)", ws_url)
        host, port, path = match.group(1), int(match.group(2)), match.group(3)
        self.sock = socket.create_connection((host, port), timeout=TIMEOUT_S)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        head = self._read_until(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise ConnectionError("websocket handshake failed")
        self.next_id = 0

    def _read_until(self, marker):
        buf = b""
        while not buf.endswith(marker):
            chunk = self.sock.recv(1)
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf

    def _message(self):
        parts = []
        while True:
            b1, b2 = self._recv(2)
            fin, op, length = b1 & 0x80, b1 & 0x0F, b2 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._recv(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._recv(8))[0]
            payload = self._recv(length) if length else b""
            if op == 0x8:
                raise ConnectionError("closed by peer")
            if op == 0x9:
                self._frame(payload, 0xA)
                continue
            if op == 0xA:
                continue
            parts.append(payload)
            if fin:
                return b"".join(parts)

    def _frame(self, payload, op):
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            header = bytes([0x80 | op, 0x80 | n])
        elif n < 65536:
            header = bytes([0x80 | op, 0x80 | 126]) + struct.pack(">H", n)
        else:
            header = bytes([0x80 | op, 0x80 | 127]) + struct.pack(">Q", n)
        self.sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def call(self, method, params=None):
        self.next_id += 1
        mid = self.next_id
        self._frame(json.dumps({"id": mid, "method": method, "params": params or {}}).encode(), 0x1)
        while True:
            msg = json.loads(self._message())
            if msg.get("id") != mid:
                continue
            if "error" in msg:
                raise CdpError(msg["error"].get("message", "cdp error"))
            return msg.get("result", {})

    def evaluate(self, expression):
        result = self.call("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": True,
        })
        if "exceptionDetails" in result:
            raise CdpError(result["exceptionDetails"].get("text", "evaluation failed"))
        return result["result"].get("value")


STATE_LOCK = threading.RLock()
PAUSED = False
EVENTS = deque(maxlen=300)
REQUESTS = []   # access/login requests waiting for the user
APPROVALS = {}  # id -> risky action waiting for the user
REFS = {}       # tab id -> items from the last read (refs only mean something for that read)
CONNS = {}      # tab id -> Cdp
PERMS = {}      # origin -> {"until": epoch seconds | None}


def log(kind, text):
    EVENTS.append({"t": int(time.time()), "type": kind, "text": text})


def load_permissions():
    try:
        with open(PERMISSIONS_FILE, encoding="utf-8") as file:
            PERMS.update(json.load(file))
    except (OSError, ValueError):
        pass


def save_permissions():
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    tmp = PERMISSIONS_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(PERMS, file)
    os.replace(tmp, PERMISSIONS_FILE)


def origin_of(url):
    parts = urlparse(url or "")
    if parts.scheme in ("http", "https") and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    if parts.scheme in ("", "about", "chrome", "chrome-untrusted", "devtools"):
        return None  # browser-internal pages, nothing to grant
    return f"{parts.scheme}:"


def granted(origin):
    if origin is None:
        return True
    entry = PERMS.get(origin)
    return bool(entry) and (entry["until"] is None or time.time() < entry["until"])


def add_request(origin, url, kind):
    for request in REQUESTS:
        if request["origin"] == origin and request["kind"] == kind:
            return request["id"]
    request = {"id": uuid.uuid4().hex[:8], "kind": kind, "origin": origin, "url": url, "at": int(time.time())}
    REQUESTS.append(request)
    log("request", f"{kind}: {origin}")
    return request["id"]


def ensure_granted(url):
    origin = origin_of(url)
    if not granted(origin):
        rid = add_request(origin, url, "access")
        raise ApiError(403, {"error": "origin_not_granted", "origin": origin, "requestId": rid})


def check_paused():
    if PAUSED:
        raise ApiError(423, {"error": "paused"})


def page_targets():
    try:
        with urlopen(f"http://{HOST}:{DEBUG_PORT}/json/list", timeout=TIMEOUT_S) as reply:
            targets = json.load(reply)
    except (URLError, OSError, ValueError):
        return None
    return [t for t in targets if t.get("type") == "page" and "webSocketDebuggerUrl" in t]


def new_tab():
    request = Request(f"http://{HOST}:{DEBUG_PORT}/json/new?about:blank", method="PUT")
    with urlopen(request, timeout=TIMEOUT_S) as reply:
        return json.load(reply)["id"]


def tab_connection(tab_id):
    targets = page_targets()
    if targets is None:
        raise ApiError(503, {"error": "brave_not_reachable", "hint": "run browser-service/start-brave.sh"})
    target = next((t for t in targets if t["id"] == tab_id), None) if tab_id else (targets[0] if targets else None)
    if target is None:
        raise ApiError(404, {"error": "no_such_tab"})
    if target["id"] not in CONNS:
        CONNS[target["id"]] = Cdp(target["webSocketDebuggerUrl"])
    return target["id"], CONNS[target["id"]]


def current_url(cdp):
    return cdp.evaluate("location.href") or ""


def wait_ready(cdp, timeout=10):
    time.sleep(0.3)
    end = time.time() + timeout
    while time.time() < end:
        try:
            if cdp.evaluate("document.readyState") == "complete":
                return
        except CdpError:
            pass
        time.sleep(0.2)


def enforce_after_move(tab_id, cdp):
    url = current_url(cdp)
    origin = origin_of(url)
    if granted(origin):
        return
    cdp.evaluate("history.back()")  # undo the move to a page Claude may not use
    REFS.pop(tab_id, None)
    rid = add_request(origin, url, "access")
    log("blocked", f"Blockerade {origin}")
    raise ApiError(403, {"error": "origin_not_granted", "origin": origin, "requestId": rid})


def sig(item):
    if item["kind"] == "password":
        return 'password "' + item["label"] + '" [redigerat]'
    text = f'{item["kind"]} "{item["label"]}"'
    if item["value"] is not None:
        text += f' = "{item["value"]}"'
    return text


def line(item):
    return f'{item["ref"]} {sig(item)}'


def delta(before, after):
    old = [sig(i) for i in before]
    new = [sig(i) for i in after]
    added = [f"+ {s}" for s in new if s not in old][:20]
    removed = [f"- {s}" for s in old if s not in new][:20]
    return added + removed or ["(oförändrat)"]


def read_page(tab_id, cdp, limit):
    page = cdp.evaluate(DIGEST_JS.replace("__LIMIT__", str(limit)))
    REFS[tab_id] = page["items"]
    origin = origin_of(page["url"])
    if page["loginWall"] and origin:
        add_request(origin, page["url"], "login")
        log("login", f"Inloggning krävs på {origin}")
    return {
        "status": "awaiting_login" if page["loginWall"] else "ok",
        "url": page["url"],
        "title": page["title"],
        "loginWall": page["loginWall"],
        "total": page["total"],
        "items": [line(i) for i in page["items"]],
    }


def find_ref(tab_id, ref):
    items = REFS.get(tab_id)
    if items is None:
        raise ApiError(409, {"error": "read_digest_first"})
    item = next((i for i in items if str(i["ref"]) == ref), None)
    if item is None:
        raise ApiError(404, {"error": "unknown_ref"})
    return item


def locate(cdp, ref):
    pos = cdp.evaluate(RESOLVE_JS.replace("__REF__", ref))
    if not pos or pos.get("stale"):
        raise ApiError(409, {"error": "stale_ref", "hint": "read the page again"})
    return pos


def status():
    targets = page_targets()
    return {
        "debugPort": DEBUG_PORT,
        "available": targets is not None,
        "paused": PAUSED,
        "tabs": 0 if targets is None else len(targets),
    }


def tabs():
    return [
        {
            "id": t["id"],
            "title": t.get("title", ""),
            "url": t.get("url", ""),
            "origin": origin_of(t.get("url", "")),
            "granted": granted(origin_of(t.get("url", ""))),
        }
        for t in (page_targets() or [])
    ]


def digest(tab, limit):
    tab_id, cdp = tab_connection(tab)
    ensure_granted(current_url(cdp))
    return read_page(tab_id, cdp, limit)


def open_url(body):
    check_paused()
    url = body.get("url", "")
    if urlparse(url).scheme not in ("http", "https"):
        raise ApiError(400, {"error": "only http and https"})
    ensure_granted(url)
    tab = body.get("tab") or None
    targets = page_targets()
    if targets is not None and not targets and tab is None:
        tab = new_tab()
    tab_id, cdp = tab_connection(tab)
    result = cdp.call("Page.navigate", {"url": url})
    if result.get("errorText"):
        raise ApiError(502, {"error": "navigation_failed", "detail": result["errorText"]})
    log("open", f"Öppnar {url}")
    wait_ready(cdp)
    enforce_after_move(tab_id, cdp)
    return read_page(tab_id, cdp, DEFAULT_LIMIT)


def require_approval(tab_id, ref, label, action, approval_id):
    approval = APPROVALS.get(approval_id)
    if approval and approval["approved"] and approval["tab"] == tab_id \
            and approval["ref"] == ref and approval["action"] == action:
        del APPROVALS[approval_id]  # one approval, one action
        return
    approval_id = uuid.uuid4().hex[:8]
    APPROVALS[approval_id] = {
        "id": approval_id, "tab": tab_id, "ref": ref, "label": label,
        "action": action, "approved": False, "at": int(time.time()),
    }
    log("approval", f'Väntar på godkännande: {action} "{label}"')
    raise ApiError(409, {"error": "approval_required", "approvalId": approval_id, "label": label})


def act(body):
    check_paused()
    tab_id, cdp = tab_connection(body.get("tab") or None)
    ensure_granted(current_url(cdp))
    action = body.get("action")
    before = REFS.get(tab_id, [])

    if action == "press":
        key = body.get("key")
        if key not in PRESS_KEYS:
            raise ApiError(400, {"error": "bad_key", "allowed": list(PRESS_KEYS)})
        label = f"tangent {key}"
        if key == "Enter":
            context = cdp.evaluate(FOCUSED_JS) or ""
            if RISKY.search(context):
                require_approval(tab_id, "", context, "press", body.get("approvalId"))
    elif action in ("click", "type"):
        ref = str(body.get("ref", ""))
        if not ref.isdigit():
            raise ApiError(400, {"error": "bad_ref"})
        item = find_ref(tab_id, ref)
        if action == "type" and item["kind"] not in ("textbox", "textarea"):
            raise ApiError(403, {"error": "not_typeable", "kind": item["kind"]})
        label = f'{item["kind"]} "{item["label"]}"'
        if action == "click" and RISKY.search(item["label"]):
            require_approval(tab_id, ref, item["label"], action, body.get("approvalId"))
    else:
        raise ApiError(400, {"error": "bad_action"})

    log("intent", f"Nästa: {action} {label}")
    time.sleep(INTENT_S)
    check_paused()

    if action == "click":
        pos = locate(cdp, ref)
        for kind in ("mouseMoved", "mousePressed", "mouseReleased"):
            cdp.call("Input.dispatchMouseEvent", {
                "type": kind, "x": pos["x"], "y": pos["y"], "button": "left", "clickCount": 1,
            })
    elif action == "type":
        value = body.get("value")
        if not isinstance(value, str) or len(value) > 2000:
            raise ApiError(400, {"error": "bad_value"})
        locate(cdp, ref)
        cdp.evaluate(FOCUS_JS.replace("__REF__", ref))
        cdp.call("Input.insertText", {"text": value})
    else:
        code, text = PRESS_KEYS[key]
        base = {"key": key, "code": key, "windowsVirtualKeyCode": code}
        down = {**base, "type": "rawKeyDown"}
        if text:
            down["text"] = text
        cdp.call("Input.dispatchKeyEvent", down)
        cdp.call("Input.dispatchKeyEvent", {**base, "type": "keyUp"})

    time.sleep(SETTLE_S)
    wait_ready(cdp)
    enforce_after_move(tab_id, cdp)
    after = read_page(tab_id, cdp, DEFAULT_LIMIT)
    return {
        "delta": delta(before, REFS.get(tab_id, [])),
        "url": after["url"],
        "title": after["title"],
        "loginWall": after["loginWall"],
    }


def grant(body):
    origin = body.get("origin", "")
    if origin_of(origin) != origin or origin is None:
        raise ApiError(400, {"error": "origin must be scheme://host[:port]"})
    hours = body.get("hours")
    if hours is not None and (not isinstance(hours, (int, float)) or not 0 < hours <= 24 * 30):
        raise ApiError(400, {"error": "hours must be 0-720 or null"})
    PERMS[origin] = {"until": None if hours is None else time.time() + hours * 3600}
    save_permissions()
    REQUESTS[:] = [r for r in REQUESTS if r["origin"] != origin]
    log("permission", f"Åtkomst beviljad: {origin}")
    return {"ok": True, "origin": origin}


def revoke(body):
    origin = body.get("origin", "")
    PERMS.pop(origin, None)
    save_permissions()
    log("permission", f"Åtkomst återkallad: {origin}")
    return {"ok": True}


def decide(body):
    approval = APPROVALS.get(body.get("id"))
    if approval is None:
        raise ApiError(404, {"error": "no_such_approval"})
    if body.get("approve"):
        approval["approved"] = True
        log("approval", f'Godkänd: {approval["action"]} "{approval["label"]}"')
    else:
        del APPROVALS[approval["id"]]
        log("approval", f'Nekad: {approval["action"]} "{approval["label"]}"')
    return {"ok": True}


def route(method, path, qs, body):
    global PAUSED
    if method == "GET":
        if path == "/status":
            return 200, status()
        if path == "/tabs":
            return 200, tabs()
        if path == "/digest":
            limit = min(max(int(qs.get("limit", [DEFAULT_LIMIT])[0]), 1), MAX_LIMIT)
            return 200, digest(qs.get("tab", [None])[0], limit)
        if path == "/events":
            return 200, list(EVENTS)
        if path == "/requests":
            return 200, REQUESTS
        if path == "/approvals":
            return 200, [a for a in APPROVALS.values() if not a["approved"]]
        if path == "/permissions":
            return 200, PERMS
    if method == "POST":
        if path == "/open":
            return 200, open_url(body)
        if path == "/act":
            return 200, act(body)
        if path == "/permissions":
            return 200, grant(body)
        if path == "/permissions/revoke":
            return 200, revoke(body)
        if path == "/approvals":
            return 200, decide(body)
        if path == "/requests/dismiss":
            REQUESTS[:] = [r for r in REQUESTS if r["id"] != body.get("id")]
            return 200, {"ok": True}
        if path == "/pause":
            PAUSED = bool(body.get("on"))
            log("pause", "Pausad" if PAUSED else "Igång igen")
            return 200, {"paused": PAUSED}
        if path == "/focus":
            tab_id, _ = tab_connection(body.get("tab"))
            with urlopen(f"http://{HOST}:{DEBUG_PORT}/json/activate/{tab_id}", timeout=TIMEOUT_S):
                pass
            return 200, {"ok": True}
    raise ApiError(404, {"error": "not found"})


class Handler(BaseHTTPRequestHandler):
    server_version = "jarri-browser"

    def log_message(self, format, *args):
        pass

    def _allowed(self):
        origin = self.headers.get("Origin")
        if origin is not None and origin not in ALLOWED_ORIGINS:
            return False
        return self.headers.get("Host") in ALLOWED_HOSTS

    def _cors(self):
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send(self, status_code, body):
        self.send_response(status_code)
        self._cors()
        raw = json.dumps(body).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 65536:
            raise ApiError(413, {"error": "body too large"})
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            raise ApiError(400, {"error": "bad json"})

    def _dispatch(self, method):
        if not self._allowed():
            return self._send(403, {"error": "forbidden origin"})
        url = urlparse(self.path)
        try:
            with STATE_LOCK:
                body = self._body() if method == "POST" else {}
                status_code, payload = route(method, url.path, parse_qs(url.query), body)
        except ApiError as error:
            return self._send(error.status, error.body)
        except (CdpError, ConnectionError, OSError, ValueError, KeyError, TypeError, IndexError) as error:
            with STATE_LOCK:
                CONNS.clear()  # drop possibly broken sockets, the next call reconnects
            return self._send(502, {"error": "browser_error", "detail": str(error)})
        self._send(status_code, payload)

    def do_OPTIONS(self):
        if not self._allowed():
            return self._send(403, {"error": "forbidden origin"})
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


if __name__ == "__main__":
    load_permissions()
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
