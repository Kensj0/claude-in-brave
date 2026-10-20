"""Claude in Brave: Claude's access to Brave, with access control and a visible action log.

Runs on its own: start it in a terminal with `python3 server.py`. Any client can use it, for example
mcp.py for Claude Code. A visual panel is optional and not needed.
The service starts Brave itself, with --remote-debugging-pipe. The debug channel is a pipe between
this process and Brave, not a network port, so no other program can connect to Brave through it.
Brave starts when a tool needs it, and it stops when the user asks (POST /browser/stop).

  GET  /status                      -> {running, paused, tabs}
  POST /browser/start               -> opens Brave's window if it is not open
  POST /browser/stop                -> closes Brave
  GET  /tabs                        -> [{id, title, url, origin, granted}]
  GET  /digest?tab=ID&limit=N       -> {status, url, title, loginWall, total, items}
                                       refs are valid until the next read of that tab
  POST /open {url, tab?}            -> same as digest, or 403 origin_not_granted
  POST /act {tab, action, ref?, value?, key?, approvalId?}
                                    -> {delta, url, title, loginWall}
                                       or 409 approval_required / stale_ref, 403 origin_not_granted
  GET  /console?tab=ID&limit=N      -> recent console messages and errors (F12 Console)
  GET  /network?tab=ID&limit=N      -> recent requests with status and text response bodies (F12 Network).
                                       Bodies are cut to 4000 characters, and personal numbers, e-mails and tokens are removed.
  GET  /form?tab=ID                 -> every field on the page, with stable names (one read for a whole form)
  POST /batch {tab, steps}          -> many actions in order: fill, click, check, choose, press, scroll,
                                       drag, hover, wait. Stops at the first error and says where.
  GET  /screenshot?tab=ID           -> small picture of the tab for a panel (not for Claude)
  GET  /text?tab=ID&chars=N         -> visible text of the page as lines (prices, descriptions)
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

import atexit
import faulthandler
import signal
import contextlib
import json
import os
import queue
import re
import select
import subprocess
import threading
import time
import uuid
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HOST = "127.0.0.1"
PORT = int(os.environ.get("JARRI_BROWSER_PORT", "8786"))
_STATE = os.path.expanduser(os.environ.get("JARRI_BROWSER_STATE", "~/.local/state/jarri-browser"))
os.makedirs(_STATE, mode=0o700, exist_ok=True)
_STACKS = open(os.path.join(_STATE, "stacks.log"), "a")
faulthandler.register(signal.SIGUSR1, file=_STACKS, all_threads=True)  # kill -USR1 writes every thread's stack
STATE_DIR = os.path.expanduser(os.environ.get("JARRI_BROWSER_STATE", "~/.local/state/jarri-browser"))
PERMISSIONS_FILE = os.path.join(STATE_DIR, "permissions.json")
BRAVE_BIN = os.environ.get("JARRI_BRAVE_BIN", "/opt/brave.com/brave/brave")
BRAVE_PROFILE = os.path.expanduser(os.environ.get("JARRI_BROWSER_PROFILE", "~/.brave-claude"))
# Brave opens its own window. Set JARRI_BROWSER_HEADLESS=1 to run it without one.
BRAVE_HEADLESS = os.environ.get("JARRI_BROWSER_HEADLESS", "0") == "1"
LOG_LIMIT = 200
BODY_LIMIT = 4000
# What is removed from response bodies before Claude or the panel sees them.
REDACT = [
    (re.compile(r"\b\d{6,8}[-+]?\d{4}\b"), "[personnummer]"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[e-post]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[token]"),
    (re.compile(r'(?i)("?(?:password|passwd|pw|token|secret|api[_-]?key)"?\s*[:=]\s*)"[^"]*"'), r'\1"[hidden]"'),
]
TEXT_TYPES = ("text/", "json", "xml", "javascript")


def redact(text):
    for pattern, replacement in REDACT:
        text = pattern.sub(replacement, text)
    return text[:BODY_LIMIT]
TIMEOUT_S = 10
INTENT_S = 0.3
SETTLE_S = 0.4
DEFAULT_LIMIT = 60
MAX_LIMIT = 200
# Clicks or Enter presses whose label or form text matches this need the user's approval.
# Swedish words match as a prefix ("köp" also finds "köpa"). English words must be whole words,
# so "pay" does not match "display".
RISKY_SV = (
    r"köp|betal|faktura|prenumer|uppgradera|logga in|logga ut|lösenord|verifiera|säkerhet|"
    r"api[- ]?nyckel|behörighet|skicka|radera|ta bort|avaktivera|återkalla|publicera|dela|bekräfta|"
    r"ladda ner|exportera|hämta|ladda upp|välj fil|bifoga|spara som"
)
RISKY_EN = (
    r"pay|payment|checkout|buy|purchase|order|place order|transfer|withdraw|deposit|"
    r"subscribe|unsubscribe|upgrade|cancel|"
    r"log ?in|log ?out|sign ?in|sign ?out|password|2fa|verify|security|api[- ]?key|token|secret|"
    r"permission|authori[sz]e|approve|allow|revoke|disable|"
    r"send|submit|delete|remove|close account|unlink|invite|publish|deploy|share|confirm|"
    r"download|export|upload|choose file|attach|save as"
)
RISKY = re.compile(
    rf"{RISKY_SV}|\b(?:{RISKY_EN})\b",
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
      if (ty === 'file') return 'file';
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
  const all = [...document.querySelectorAll(SEL)].filter(el => !el.closest('[data-jarri-ui]') && shown(el));
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
  tag.textContent = 'Claude is working here';
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

# The control bar at the bottom of every page. Its buttons call window.jarriControl, which the
# service receives over the pipe. The bar is marked data-jarri-ui, so Claude never sees its buttons.
BAR_JS = """(() => {
  if (window.__jarriBar) return;
  const bar = document.createElement('div');
  bar.setAttribute('data-jarri-ui', 'bar');
  bar.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:2147483647;display:flex;align-items:center;gap:8px;padding:6px 12px;background:#1e1b2e;color:#fff;font:13px system-ui,sans-serif;box-shadow:0 -2px 8px rgba(0,0,0,.3)';
  const text = document.createElement('span');
  text.style.cssText = 'flex:1;overflow:hidden;white-space:nowrap;text-overflow:ellipsis';
  text.textContent = 'Claude is waiting';
  const button = (label, cmd) => {
    const b = document.createElement('button');
    b.textContent = label;
    b.setAttribute('data-cmd', cmd);
    b.style.cssText = 'padding:4px 10px;border:0;border-radius:4px;cursor:pointer;background:#7c3aed;color:#fff;font:13px system-ui,sans-serif';
    b.onclick = () => window.jarriControl(cmd);
    return b;
  };
  bar.append(text, button('▶ Kör', 'play'), button('❚❚ Paus', 'pause'), button('■ Stopp', 'stop'));
  document.documentElement.appendChild(bar);
  window.__jarriBar = { set: t => { text.textContent = t; } };
})();"""

# The visible text of the page, line by line, without the control bar. Prices and descriptions live here.
TEXT_JS = """(() => {
  const MAX = __MAX__;
  const bar = document.querySelector('[data-jarri-ui]');
  const shown = bar ? bar.style.display : null;
  if (bar) bar.style.display = 'none';
  const raw = document.body ? document.body.innerText : '';
  if (bar) bar.style.display = shown;
  const lines = raw.split('\\n').map(s => s.replace(/\\s+/g, ' ').trim()).filter(Boolean);
  const out = [];
  let size = 0;
  for (const line of lines) {
    if (size + line.length > MAX) break;
    out.push(line);
    size += line.length + 1;
  }
  return { url: location.href, title: document.title, lines: out, total: lines.length, truncated: out.length < lines.length };
})()"""

FOCUS_JS = """(() => {
  const el = document.querySelector('[data-jarri-ref="__REF__"]');
  if (!el) return false;
  el.focus();
  if (el.select) el.select();
  else {
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
  return true;
})()"""


class CdpError(Exception):
    pass


class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__(body.get("error", ""))
        self.status = status
        self.body = body


class Pipe:
    """CDP over Brave's --remote-debugging-pipe: messages are JSON terminated by a NUL byte."""

    def __init__(self, proc, cmd_w, resp_r):
        self.proc = proc
        self.cmd_w = cmd_w
        self.resp_r = resp_r
        self.next_id = 0
        self.pending = {}
        self.frames = {}  # page session -> latest JPEG from Brave's screencast (base64)
        self.logs = {}     # page session -> recent console messages and errors (F12 Console)
        self.network = {}  # page session -> recent requests and their status (F12 Network)
        self.closed = False
        self.cond = threading.Condition()
        # Commands go through a queue and a writer thread. The reader thread must never block on a write,
        # or it stops reading Brave's answers, Brave stops reading our commands, and both sides freeze.
        self.outbox = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._writer, daemon=True).start()

    def _reader(self):
        buf = b""
        while True:
            try:
                chunk = os.read(self.resp_r, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                with self.cond:
                    self.closed = True
                    self.cond.notify_all()
                return
            buf += chunk
            while b"\0" in buf:
                raw, buf = buf.split(b"\0", 1)
                if not raw:
                    continue
                message = json.loads(raw)
                if "id" not in message:
                    self.record(message)
                if "id" in message:
                    with self.cond:
                        self.pending[message["id"]] = message
                        self.cond.notify_all()
                elif message.get("method") == "Page.screencastFrame":
                    params = message["params"]
                    self.frames[message["sessionId"]] = params["data"]
                    self.send_no_wait("Page.screencastFrameAck", {"sessionId": params["sessionId"]},
                                      message["sessionId"])
                elif message.get("method") == "Runtime.bindingCalled":
                    params = message.get("params", {})
                    if params.get("name") == "jarriControl":  # a button on the control bar was pressed
                        threading.Thread(target=bar_command, args=(params.get("payload", ""),), daemon=True).start()

    def record(self, message):
        """Keep what the F12 Console and Network tabs show. Headers, cookies and bodies are not kept."""
        method = message.get("method", "")
        session = message.get("sessionId")
        if not session or not method.startswith(("Runtime.", "Log.", "Network.")):
            return
        params = message.get("params", {})
        logs = self.logs.setdefault(session, deque(maxlen=LOG_LIMIT))
        requests = self.network.setdefault(session, deque(maxlen=LOG_LIMIT))
        if method == "Runtime.consoleAPICalled":
            text = " ".join(str(arg.get("value", arg.get("description", ""))) for arg in params.get("args", []))
            logs.append({"level": params.get("type", "log"), "text": text[:500]})
        elif method == "Runtime.exceptionThrown":
            details = params.get("exceptionDetails", {})
            text = (details.get("exception", {}).get("description") or details.get("text", ""))
            logs.append({"level": "error", "text": text[:500]})
        elif method == "Log.entryAdded":
            entry = params.get("entry", {})
            logs.append({"level": entry.get("level", "info"), "text": entry.get("text", "")[:500],
                         "url": entry.get("url", "")[:300]})
        elif method == "Network.requestWillBeSent":
            request = params.get("request", {})
            requests.append({"id": params.get("requestId"), "method": request.get("method", ""),
                             "url": request.get("url", "")[:300], "status": None, "failed": None,
                             "mime": "", "body": None})
        elif method in ("Network.responseReceived", "Network.loadingFailed", "Network.loadingFinished"):
            for item in list(requests):
                if item["id"] == params.get("requestId"):
                    if method == "Network.responseReceived":
                        response = params.get("response", {})
                        item["status"] = response.get("status")
                        item["mime"] = response.get("mimeType", "")
                    elif method == "Network.loadingFailed":
                        item["failed"] = params.get("errorText")
                    # Response bodies are not fetched automatically: on a busy page they flood the pipe
                    # and freeze every request. Status, URL and type are still recorded.

    def fetch_body(self, session, item):
        """Read a finished text response. Runs in its own thread, because the reader must keep reading."""
        try:
            result = self.call("Network.getResponseBody", {"requestId": item["id"]}, session=session)
        except (CdpError, ConnectionError, OSError):
            return
        if not result.get("base64Encoded"):
            item["body"] = redact(result.get("body", ""))

    def _write(self, message):
        if self.closed:
            raise ConnectionError("browser is closed")
        self.outbox.put(json.dumps(message).encode() + b"\0")

    def _writer(self):
        while True:
            data = memoryview(self.outbox.get())
            while data:
                # Never wait forever on a pipe Brave does not read: give up and close instead of freezing.
                _, writable, _ = select.select([], [self.cmd_w], [], TIMEOUT_S)
                if not writable:
                    with self.cond:
                        self.closed = True
                        self.cond.notify_all()
                    return
                try:
                    data = data[os.write(self.cmd_w, data):]
                except OSError:  # Brave is gone
                    with self.cond:
                        self.closed = True
                        self.cond.notify_all()
                    return

    def send_no_wait(self, method, params, session):
        with self.cond:
            self.next_id += 1
            mid = self.next_id
        self._write({"id": mid, "method": method, "params": params, "sessionId": session})

    def call(self, method, params=None, session=None):
        with self.cond:
            if self.closed:
                raise ConnectionError("browser is closed")
            self.next_id += 1
            mid = self.next_id
        message = {"id": mid, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        self._write(message)
        with self.cond:
            end = time.time() + TIMEOUT_S
            while mid not in self.pending:
                left = end - time.time()
                if left <= 0 or self.closed:
                    raise ConnectionError("no answer from browser")
                self.cond.wait(left)
            reply = self.pending.pop(mid)
        if "error" in reply:
            raise CdpError(reply["error"].get("message", "cdp error"))
        return reply.get("result", {})


class Page:
    """One tab, reached through a session on the pipe."""

    def __init__(self, pipe, session):
        self.pipe = pipe
        self.session = session

    def call(self, method, params=None):
        return self.pipe.call(method, params, session=self.session)

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
CONNS = {}      # tab id -> Page
PERMS = {}      # origin -> {"until": epoch seconds | None}
BROWSER = None  # Pipe to the running Brave, or None


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


BROWSER_START = threading.Lock()  # only one request may start Brave at a time


def ensure_browser():
    """Start Brave with the debug pipe if it is not running. Its fds 3 and 4 are the pipe."""
    with BROWSER_START:
        return _start_browser()


def _start_browser():
    global BROWSER
    if BROWSER is not None and not BROWSER.closed:
        return BROWSER
    if PAUSED:  # after Stop, nothing starts again until the user presses Play
        raise ApiError(423, {"error": "paused"})
    if not os.path.exists(BRAVE_BIN):
        raise ApiError(503, {"error": "brave_not_found", "path": BRAVE_BIN})
    cmd_r, cmd_w = os.pipe()
    resp_r, resp_w = os.pipe()

    def child_setup():
        os.dup2(cmd_r, 3)
        os.dup2(resp_w, 4)
        os.set_inheritable(3, True)
        os.set_inheritable(4, True)
        os.closerange(5, 65536)  # the child keeps only stdin, stdout, stderr and the pipe

    os.makedirs(BRAVE_PROFILE, exist_ok=True)
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    with open(os.path.join(STATE_DIR, "brave.log"), "ab") as errors:
        proc = subprocess.Popen(
            [BRAVE_BIN, "--remote-debugging-pipe", f"--user-data-dir={BRAVE_PROFILE}",
             "--no-first-run", "--no-default-browser-check", "--disable-gpu"]
            + (["--headless=new"] if BRAVE_HEADLESS else []) + ["about:blank"],
            close_fds=False, preexec_fn=child_setup,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors,
        )
    os.close(cmd_r)
    os.close(resp_w)
    CONNS.clear()
    BROWSER = Pipe(proc, cmd_w, resp_r)
    log("browser", "Brave started")
    return BROWSER


def stop_browser():
    global BROWSER
    if BROWSER is None:
        return
    try:
        BROWSER.call("Browser.close")
        BROWSER.proc.wait(timeout=10)
    except Exception:
        BROWSER.proc.kill()
    BROWSER = None
    CONNS.clear()
    REFS.clear()
    log("browser", "Brave stopped")


atexit.register(stop_browser)


def bar_text():
    if PAUSED:
        return "Claude is paused"
    intents = [e for e in EVENTS if e["type"] == "intent"]
    return intents[-1]["text"] if intents else "Claude is waiting"


def bar_update():
    text = json.dumps(bar_text())
    for page in list(CONNS.values()):
        try:
            page.evaluate(f"window.__jarriBar && window.__jarriBar.set({text})")
        except (CdpError, ConnectionError, OSError):
            pass


def bar_command(cmd):
    """Runs when a button on the control bar is pressed in Brave."""
    global PAUSED
    if cmd == "stop":
        PAUSED = True
        log("pause", "Stopped from the bar in Brave")
        stop_browser()
        return
    PAUSED = cmd != "play"
    log("pause", "Paused from the bar in Brave" if PAUSED else "Running again from the bar in Brave")
    bar_update()


def page_list():
    pipe = ensure_browser()
    infos = pipe.call("Target.getTargets")["targetInfos"]
    return [t for t in infos if t["type"] == "page"]


def tab_connection(tab_id):
    pipe = ensure_browser()
    pages = page_list()
    if tab_id:
        target = next((t for t in pages if t["targetId"] == tab_id), None)
    else:
        if not pages:  # Brave started without a window: give it an empty tab
            pages = [{"targetId": pipe.call("Target.createTarget", {"url": "about:blank"})["targetId"]}]
        target = pages[0]
    if target is None:
        raise ApiError(404, {"error": "no_such_tab"})
    tid = target["targetId"]
    if tid not in CONNS:
        session = pipe.call("Target.attachToTarget", {"targetId": tid, "flatten": True})["sessionId"]
        page = Page(pipe, session)
        page.call("Page.setDownloadBehavior", {"behavior": "deny"})  # no files leave or land on disk
        for domain in ("Runtime", "Log", "Network"):  # for the console and network reads
            page.call(f"{domain}.enable")
        # Brave sends a frame when the page changes; the panel reads the latest one. Nothing is polled.
        page.call("Page.startScreencast", {"format": "jpeg", "quality": 55, "maxWidth": 960,
                                           "maxHeight": 600, "everyNthFrame": 6})
        page.call("Runtime.addBinding", {"name": "jarriControl"})
        page.call("Page.addScriptToEvaluateOnNewDocument", {"source": BAR_JS})
        page.evaluate(BAR_JS)
        CONNS[tid] = page
    return tid, CONNS[tid]


def current_url(page):
    return page.evaluate("location.href") or ""


def wait_ready(page, timeout=10, first=0.3):
    time.sleep(first)
    end = time.time() + timeout
    while time.time() < end:
        try:
            if page.evaluate("document.readyState") == "complete":
                return
        except CdpError:
            pass
        time.sleep(0.2)


def enforce_after_move(tab_id, page):
    url = current_url(page)
    origin = origin_of(url)
    if granted(origin):
        return
    page.evaluate("history.back()")  # undo the move to a page Claude may not use
    REFS.pop(tab_id, None)
    rid = add_request(origin, url, "access")
    log("blocked", f"Blocked {origin}")
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


def read_page(tab_id, page, limit):
    result = page.evaluate(DIGEST_JS.replace("__LIMIT__", str(limit)))
    REFS[tab_id] = result["items"]
    origin = origin_of(result["url"])
    if result["loginWall"] and origin:
        add_request(origin, result["url"], "login")
        log("login", f"Log in needed on {origin}")
    return {
        "status": "awaiting_login" if result["loginWall"] else "ok",
        "url": result["url"],
        "title": result["title"],
        "loginWall": result["loginWall"],
        "total": result["total"],
        "items": [line(i) for i in result["items"]],
    }


def read_text(tab, chars):
    tab_id, page = tab_connection(tab)
    ensure_granted(current_url(page))
    result = page.evaluate(TEXT_JS.replace("__MAX__", str(chars)))
    return {"url": result["url"], "title": result["title"], "lines": result["lines"],
            "total": result["total"], "truncated": result["truncated"]}


def screenshot(tab):
    """The latest frame of the tab, for a panel only. No MCP tool returns it to Claude."""
    # The panel asks for a picture every half second. Asking must never start Brave, so nothing is
    # started here: with no running Brave there is simply no picture yet.
    if BROWSER is None or BROWSER.closed:
        return {"url": "", "title": "", "image": None}
    tab_id, page = tab_connection(tab)
    frame = BROWSER.frames.get(page.session)
    # URL and title come from the browser's own target list. Running a script in the page here could
    # hang on a slow or consent-blocked page and hold up every other request.
    info = next((t for t in page_list() if t["targetId"] == tab_id), {})
    return {"url": info.get("url", ""), "title": info.get("title", ""),
            "image": "data:image/jpeg;base64," + frame if frame else None}


def user_navigate(body):
    """The user types an address in the panel or the terminal. This is the user, so no origin check."""
    url = body.get("url", "")
    if urlparse(url).scheme not in ("http", "https"):
        raise ApiError(400, {"error": "only http and https"})
    tab_id, page = tab_connection(body.get("tab") or None)
    result = page.call("Page.navigate", {"url": url})
    if result.get("errorText"):
        raise ApiError(502, {"error": "navigation_failed", "detail": result["errorText"]})
    wait_ready(page)
    REFS.pop(tab_id, None)
    log("open", f"You opened {url}")
    return {"ok": True}


def user_back(body):
    _, page = tab_connection(body.get("tab") or None)
    page.evaluate("history.back()")
    return {"ok": True}


KEY_CODES = {"Enter": 13, "Tab": 9, "Escape": 27, "Backspace": 8, "Delete": 46,
             "ArrowLeft": 37, "ArrowUp": 38, "ArrowRight": 39, "ArrowDown": 40}


def user_input(body):
    """Clicks, scrolling, typing and keys from a panel. Positions are 0-1 of the picture."""
    _, page = tab_connection(body.get("tab") or None)
    kind = body.get("type")
    if kind == "mouse":
        size = page.evaluate("({ width: innerWidth, height: innerHeight })")
        x = min(max(float(body["x"]), 0), 1) * size["width"]
        y = min(max(float(body["y"]), 0), 1) * size["height"]
        event = body.get("event")
        if event == "wheel":
            page.call("Input.dispatchMouseEvent", {"type": "mouseWheel", "x": x, "y": y,
                                                  "deltaX": 0, "deltaY": float(body.get("deltaY", 0))})
        elif event == "move":
            page.call("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
        elif event in ("down", "up"):
            kind_name = "mousePressed" if event == "down" else "mouseReleased"
            page.call("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
            page.call("Input.dispatchMouseEvent", {"type": kind_name, "x": x, "y": y,
                                                  "button": "left", "clickCount": 1})
        else:
            raise ApiError(400, {"error": "bad_mouse_event"})
    elif kind == "text":
        value = str(body.get("value", ""))[:200]
        page.call("Input.insertText", {"text": value})
    elif kind == "key":
        key = body.get("key")
        if key not in KEY_CODES:
            raise ApiError(400, {"error": "bad_key"})
        code = KEY_CODES[key]
        base = {"key": key, "code": key, "windowsVirtualKeyCode": code}
        down = {**base, "type": "rawKeyDown"}
        if key == "Enter":
            down["text"] = "\r"
        page.call("Input.dispatchKeyEvent", down)
        page.call("Input.dispatchKeyEvent", {**base, "type": "keyUp"})
    else:
        raise ApiError(400, {"error": "bad_input"})
    return {"ok": True}


def page_log(tab, source, limit):
    """Recent console messages or network requests of a granted tab. Read-only, for Claude and the user."""
    tab_id, page = tab_connection(tab)
    ensure_granted(current_url(page))
    records = BROWSER.logs if source == "console" else BROWSER.network
    return {"url": current_url(page), "items": list(records.get(page.session, []))[-limit:]}


def find_ref(tab_id, ref):
    items = REFS.get(tab_id)
    if items is None:
        raise ApiError(409, {"error": "read_digest_first"})
    item = next((i for i in items if str(i["ref"]) == ref), None)
    if item is None:
        raise ApiError(404, {"error": "unknown_ref"})
    return item


def locate(page, ref):
    pos = page.evaluate(RESOLVE_JS.replace("__REF__", ref))
    if not pos or pos.get("stale"):
        raise ApiError(409, {"error": "stale_ref", "hint": "read the page again"})
    return pos


def status():
    running = BROWSER is not None and not BROWSER.closed
    return {
        "running": running,
        "paused": PAUSED,
        "tabs": len(page_list()) if running else 0,
    }


def tabs():
    if BROWSER is None or BROWSER.closed:
        return []
    return [
        {
            "id": t["targetId"],
            "title": t.get("title", ""),
            "url": t.get("url", ""),
            "origin": origin_of(t.get("url", "")),
            "granted": granted(origin_of(t.get("url", ""))),
        }
        for t in page_list()
    ]


def digest(tab, limit):
    tab_id, page = tab_connection(tab)
    ensure_granted(current_url(page))
    return read_page(tab_id, page, limit)


def open_url(body):
    check_paused()
    url = body.get("url", "")
    if urlparse(url).scheme not in ("http", "https"):
        raise ApiError(400, {"error": "only http and https"})
    ensure_granted(url)
    tab = body.get("tab") or None
    pipe = ensure_browser()
    if tab is None and not page_list():
        tab = pipe.call("Target.createTarget", {"url": "about:blank"})["targetId"]
    tab_id, page = tab_connection(tab)
    result = page.call("Page.navigate", {"url": url})
    if result.get("errorText"):
        raise ApiError(502, {"error": "navigation_failed", "detail": result["errorText"]})
    log("open", f"Opening {url}")
    wait_ready(page)
    enforce_after_move(tab_id, page)
    return read_page(tab_id, page, DEFAULT_LIMIT)


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
    log("approval", f'Waiting for approval: {action} "{label}"')
    raise ApiError(409, {"error": "approval_required", "approvalId": approval_id, "label": label})


def act(body):
    check_paused()
    tab_id, page = tab_connection(body.get("tab") or None)
    ensure_granted(current_url(page))
    action = body.get("action")
    before = REFS.get(tab_id, [])

    if action == "press":
        key = body.get("key")
        if key not in PRESS_KEYS:
            raise ApiError(400, {"error": "bad_key", "allowed": list(PRESS_KEYS)})
        label = f"key {key}"
        if key == "Enter":
            context = page.evaluate(FOCUSED_JS) or ""
            if RISKY.search(context):
                require_approval(tab_id, "", context, "press", body.get("approvalId"))
    elif action in ("click", "type"):
        ref = str(body.get("ref", ""))
        if not ref.isdigit():
            raise ApiError(400, {"error": "bad_ref"})
        item = find_ref(tab_id, ref)
        if item["kind"] == "file":  # file pickers would hand over the user's own photos and files
            raise ApiError(403, {"error": "file_transfer_not_allowed"})
        if action == "type" and item["kind"] not in ("textbox", "textarea"):
            raise ApiError(403, {"error": "not_typeable", "kind": item["kind"]})
        label = f'{item["kind"]} "{item["label"]}"'
        if action == "click" and RISKY.search(item["label"]):
            require_approval(tab_id, ref, item["label"], action, body.get("approvalId"))
    else:
        raise ApiError(400, {"error": "bad_action"})

    log("intent", f"Next: {action} {label}")
    bar_update()
    time.sleep(INTENT_S)
    check_paused()

    if action == "click":
        pos = locate(page, ref)
        for kind in ("mouseMoved", "mousePressed", "mouseReleased"):
            page.call("Input.dispatchMouseEvent", {
                "type": kind, "x": pos["x"], "y": pos["y"], "button": "left", "clickCount": 1,
            })
    elif action == "type":
        value = body.get("value")
        if not isinstance(value, str) or len(value) > 2000:
            raise ApiError(400, {"error": "bad_value"})
        locate(page, ref)
        page.evaluate(FOCUS_JS.replace("__REF__", ref))
        page.call("Input.insertText", {"text": value})
    else:
        code, text = PRESS_KEYS[key]
        base = {"key": key, "code": key, "windowsVirtualKeyCode": code}
        down = {**base, "type": "rawKeyDown"}
        if text:
            down["text"] = text
        page.call("Input.dispatchKeyEvent", down)
        page.call("Input.dispatchKeyEvent", {**base, "type": "keyUp"})

    time.sleep(SETTLE_S)
    wait_ready(page)
    enforce_after_move(tab_id, page)
    after = read_page(tab_id, page, DEFAULT_LIMIT)
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
    log("permission", f"Access granted: {origin}")
    return {"ok": True, "origin": origin}


def revoke(body):
    origin = body.get("origin", "")
    PERMS.pop(origin, None)
    save_permissions()
    log("permission", f"Access removed: {origin}")
    return {"ok": True}


def decide(body):
    approval = APPROVALS.get(body.get("id"))
    if approval is None:
        raise ApiError(404, {"error": "no_such_approval"})
    if body.get("approve"):
        approval["approved"] = True
        log("approval", f'Approved: {approval["action"]} "{approval["label"]}"')
    else:
        del APPROVALS[approval["id"]]
        log("approval", f'Denied: {approval["action"]} "{approval["label"]}"')
    return {"ok": True}


# ---- Formulär och batch: en läsning ger alla fält, och många åtgärder går i ett anrop ----

FORM_JS = """(() => {
  const clean = s => (s || '').replace(/\\s+/g, ' ').trim().slice(0, 120);
  document.querySelectorAll('[data-jarri-name]').forEach(e => e.removeAttribute('data-jarri-name'));
  const shown = el => {
    const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none';
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
      if (ty === 'file') return 'file';
      if (['submit', 'button', 'reset', 'image'].includes(ty)) return 'button';
      if (ty === 'checkbox' || ty === 'radio' || ty === 'range') return ty === 'range' ? 'slider' : ty;
      return 'textbox';
    }
    if (t === 'TEXTAREA') return 'textarea';
    if (t === 'SELECT') return 'select';
    if (t === 'A') return 'link';
    if (el.isContentEditable) return 'textbox';
    if (role === 'checkbox' || role === 'radio' || role === 'switch') return role;
    return role || (t === 'BUTTON' || t === 'SUMMARY' ? 'button' : t.toLowerCase());
  };
  const isChecked = el => el.checked ?? (el.getAttribute('aria-checked') === 'true');
  const valueOf = (el, kind) => {
    if (kind === 'password' || kind === 'file') return null;
    if (kind === 'checkbox' || kind === 'radio' || kind === 'switch') return isChecked(el);
    if (kind === 'textbox' || kind === 'textarea' || kind === 'slider') return clean(el.value ?? el.textContent);
    if (kind === 'select') return clean(el.selectedOptions[0]?.textContent || '');
    return null;
  };
  const SEL = 'input:not([type=hidden]),textarea,select,button,a[href],summary,[contenteditable=true],' +
    '[role=checkbox],[role=radio],[role=switch],[role=combobox],[role=textbox],[role=button],[role=slider],[role=menuitem]';
  const used = {};
  const fields = [];
  for (const el of document.querySelectorAll(SEL)) {
    if (el.closest('[data-jarri-ui]') || !shown(el)) continue;
    if (fields.length >= 300) break;
    const kind = kindOf(el);
    const base = (labelOf(el) || el.getAttribute('name') || kind).toLowerCase().slice(0, 60);
    used[base] = (used[base] || 0) + 1;
    const name = used[base] > 1 ? `${base} #${used[base]}` : base;
    el.setAttribute('data-jarri-name', name);
    const f = { name, kind, label: labelOf(el), required: !!(el.required || el.getAttribute('aria-required') === 'true') };
    if (el.disabled) f.disabled = true;
    if (kind !== 'button' && kind !== 'link') f.value = valueOf(el, kind);
    if (kind === 'select') f.options = [...el.options].map(o => clean(o.text)).slice(0, 40);
    fields.push(f);
  }
  return { url: location.href, title: document.title, total: fields.length, fields };
})()"""

# Finds one field by its stable name. The name is put in as a JSON string.
FIELD_JS = """(() => {
  const name = __NAME__;
  const el = [...document.querySelectorAll('[data-jarri-name]')].find(e => e.getAttribute('data-jarri-name') === name);
  if (!el) return { missing: true };
  if (__SCROLL__) el.scrollIntoView({ block: 'center', inline: 'center' });
  const r = el.getBoundingClientRect();
  return {
    x: r.left + r.width / 2, y: r.top + r.height / 2, w: r.width, h: r.height,
    text: (el.getAttribute('aria-label') || el.innerText || el.value || '').replace(/\\s+/g, ' ').trim().slice(0, 120),
    tag: el.tagName, type: (el.type || '').toLowerCase(), role: el.getAttribute('role') || '',
    checked: !!(el.checked ?? (el.getAttribute('aria-checked') === 'true')), disabled: !!el.disabled,
  };
})()"""

FOCUS_FIELD_JS = """(() => {
  const name = __NAME__;
  const el = [...document.querySelectorAll('[data-jarri-name]')].find(e => e.getAttribute('data-jarri-name') === name);
  if (!el) return { missing: true };
  el.focus();
  if (el.select) el.select();
  else {
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
  return { tag: el.tagName, type: (el.type || '').toLowerCase(), readonly: !!el.readOnly, editable: !!el.isContentEditable };
})()"""

CHOOSE_JS = """(() => {
  const name = __NAME__, want = __WANT__;
  const el = [...document.querySelectorAll('[data-jarri-name]')].find(e => e.getAttribute('data-jarri-name') === name);
  if (!el) return { missing: true };
  if (el.tagName !== 'SELECT') return { notSelect: true };
  const opt = [...el.options].find(o => o.text.trim() === want);
  if (!opt) return { noOption: true, options: [...el.options].map(o => o.text.trim()).slice(0, 40) };
  el.value = opt.value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return { ok: true };
})()"""

VIEWPORT_JS = "[innerWidth / 2, innerHeight / 2]"

BATCH_MAX_STEPS = 50
BATCH_MAX_WAIT_S = 10


def form_snapshot(page):
    return page.evaluate(FORM_JS)


def field(page, name, scroll=True):
    result = page.evaluate(FIELD_JS.replace("__NAME__", json.dumps(name)).replace("__SCROLL__", "true" if scroll else "false"))
    if result.get("missing"):
        raise ApiError(404, {"error": "unknown_field", "name": name, "hint": "read the form again"})
    return result


def field_or_none(page, name):
    result = page.evaluate(FIELD_JS.replace("__NAME__", json.dumps(name)).replace("__SCROLL__", "true"))
    return None if result.get("missing") else result


def stable_field(page, name):
    """Scrolls the field into view and waits until it stops moving, so the click lands where it is."""
    pos = field(page, name)
    for _ in range(12):
        time.sleep(0.08)
        again = field(page, name, scroll=False)
        if abs(again["x"] - pos["x"]) < 1 and abs(again["y"] - pos["y"]) < 1:
            return again
        pos = again
    raise ApiError(409, {"error": "moving", "name": name, "hint": "the element keeps moving, try again"})


def mouse(page, kind, x, y, clicks=0):
    page.call("Input.dispatchMouseEvent", {"type": kind, "x": x, "y": y, "button": "left", "clickCount": clicks})


def click_at(page, x, y):
    mouse(page, "mouseMoved", x, y)
    mouse(page, "mousePressed", x, y, 1)
    mouse(page, "mouseReleased", x, y, 1)


def step_fill(tab_id, page, step):
    name, value = step.get("name", ""), step.get("value")
    if not isinstance(value, str) or len(value) > 2000:
        raise ApiError(400, {"error": "bad_value"})
    info = page.evaluate(FOCUS_FIELD_JS.replace("__NAME__", json.dumps(name)))
    if info.get("missing"):
        raise ApiError(404, {"error": "unknown_field", "name": name})
    if info["type"] == "password":
        raise ApiError(403, {"error": "password_not_allowed"})
    text_input = info["tag"] in ("INPUT", "TEXTAREA") and info["type"] not in ("file", "checkbox", "radio", "button", "submit", "range")
    typeable = text_input or info["editable"]
    if not typeable or info["readonly"]:
        raise ApiError(403, {"error": "not_typeable", "name": name})
    page.call("Input.insertText", {"text": value})
    return {"filled": name, "chars": len(value)}


def step_click(tab_id, page, step):
    name = step.get("name", "")
    pos = stable_field(page, name)
    if pos["disabled"]:
        raise ApiError(409, {"error": "disabled", "name": name})
    label = pos["text"]
    if RISKY.search(label):
        require_approval(tab_id, name, label, "click", step.get("approvalId"))
    click_at(page, pos["x"], pos["y"])
    return {"clicked": name}


def step_check(tab_id, page, step):
    name, want = step.get("name", ""), bool(step.get("value", True))
    pos = stable_field(page, name)
    if pos["type"] not in ("checkbox", "radio") and pos["role"] not in ("checkbox", "radio", "switch"):
        raise ApiError(403, {"error": "not_checkable", "name": name})
    if pos["checked"] != want:
        click_at(page, pos["x"], pos["y"])
    return {"checked": want, "name": name}


def step_choose(tab_id, page, step):
    name, want = step.get("name", ""), step.get("value")
    if not isinstance(want, str):
        raise ApiError(400, {"error": "bad_value"})
    res = page.evaluate(CHOOSE_JS.replace("__NAME__", json.dumps(name)).replace("__WANT__", json.dumps(want)))
    if res.get("missing"):
        raise ApiError(404, {"error": "unknown_field", "name": name})
    if res.get("notSelect"):
        raise ApiError(403, {"error": "not_a_list", "name": name, "hint": "use click for this control"})
    if res.get("noOption"):
        raise ApiError(404, {"error": "no_such_option", "options": res["options"]})
    return {"chose": want, "name": name}


def step_press(tab_id, page, step):
    key = step.get("key")
    if key not in PRESS_KEYS:
        raise ApiError(400, {"error": "bad_key", "allowed": list(PRESS_KEYS)})
    if key == "Enter":
        context = page.evaluate(FOCUSED_JS) or ""
        if RISKY.search(context):
            require_approval(tab_id, "", context, "press", step.get("approvalId"))
    code, text = PRESS_KEYS[key]
    base = {"key": key, "code": key, "windowsVirtualKeyCode": code}
    down = {**base, "type": "rawKeyDown"}
    if text:
        down["text"] = text
    page.call("Input.dispatchKeyEvent", down)
    page.call("Input.dispatchKeyEvent", {**base, "type": "keyUp"})
    return {"pressed": key}


def step_scroll(tab_id, page, step):
    value = step.get("value") or {}
    if "to" in value:
        stable_field(page, value["to"])
        return {"scrolledTo": value["to"]}
    dy = int(value.get("dy", 0))
    vx, vy = page.evaluate(VIEWPORT_JS)
    page.call("Input.dispatchMouseEvent", {"type": "mouseWheel", "x": vx, "y": vy, "deltaX": 0, "deltaY": dy})
    time.sleep(0.15)
    return {"scrolledBy": dy}


def step_drag(tab_id, page, step):
    start = stable_field(page, step.get("name", ""))
    value = step.get("value") or {}
    if "to" in value:
        end = stable_field(page, value["to"])
        ex, ey = end["x"], end["y"]
    else:
        ex, ey = start["x"] + int(value.get("dx", 0)), start["y"] + int(value.get("dy", 0))
    mouse(page, "mouseMoved", start["x"], start["y"])
    mouse(page, "mousePressed", start["x"], start["y"], 1)
    for i in range(1, 11):  # ten small moves, so sliders and sortable lists follow the pointer
        mouse(page, "mouseMoved", start["x"] + (ex - start["x"]) * i / 10, start["y"] + (ey - start["y"]) * i / 10)
        time.sleep(0.02)
    mouse(page, "mouseReleased", ex, ey, 1)
    return {"dragged": step.get("name", "")}


def step_hover(tab_id, page, step):
    pos = stable_field(page, step.get("name", ""))
    mouse(page, "mouseMoved", pos["x"], pos["y"])
    time.sleep(0.15)
    return {"hovered": step.get("name", "")}


def step_wait(tab_id, page, step):
    if "ms" in step:
        time.sleep(min(max(int(step["ms"]), 0), BATCH_MAX_WAIT_S * 1000) / 1000)
        return {"waitedMs": int(step["ms"])}
    name = step.get("name", "")
    timeout = min(float(step.get("timeout", 5)), BATCH_MAX_WAIT_S)
    end = time.time() + timeout
    while time.time() < end:
        found = field_or_none(page, name)
        if found and found["w"] > 0:
            return {"appeared": name}
        time.sleep(0.2)
    raise ApiError(408, {"error": "wait_timeout", "name": name})


# Finds visible list options (custom menus, autocomplete, date lists). Returns the one whose text matches.
PICK_JS = """(() => {
  const want = __WANT__;
  const norm = s => (s || '').replace(/\\s+/g, ' ').trim().toLowerCase();
  const vis = el => {
    const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none';
  };
  const cands = [...document.querySelectorAll('[role=option], [role=menuitem], [role=listbox] li, [id*="-option-"], [class*="-option"]')]
    .filter(vis).filter(el => norm(el.innerText || el.textContent));
  const label = el => (el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 80);
  const options = cands.map(label).slice(0, 60);
  const idx = cands.findIndex(el => norm(el.innerText || el.textContent) === norm(want));
  if (idx < 0) return { found: false, options };
  const r = cands[idx].getBoundingClientRect();
  return { found: true, x: r.left + r.width / 2, y: r.top + r.height / 2, text: label(cands[idx]), options };
})()"""


def step_pick(tab_id, page, step):
    name, want = step.get("name", ""), step.get("value")
    if not isinstance(want, str) or not want:
        raise ApiError(400, {"error": "bad_value"})
    field_pos = stable_field(page, name)
    click_at(page, field_pos["x"], field_pos["y"])  # opens the menu
    end = time.time() + 3
    last = {"found": False, "options": []}
    while time.time() < end:
        time.sleep(0.1)
        last = page.evaluate(PICK_JS.replace("__WANT__", json.dumps(want)))
        if last.get("found"):
            break
    if not last.get("found"):
        raise ApiError(404, {"error": "no_such_option", "name": name, "options": last.get("options", [])})
    if RISKY.search(last["text"]):
        require_approval(tab_id, name, last["text"], "pick", step.get("approvalId"))
    click_at(page, last["x"], last["y"])
    return {"picked": last["text"], "name": name}


STEP_HANDLERS = {
    "fill": step_fill, "click": step_click, "check": step_check, "choose": step_choose,
    "press": step_press, "scroll": step_scroll, "drag": step_drag, "hover": step_hover, "wait": step_wait,
    "pick": step_pick,
}
ACTIONS_THAT_NAVIGATE = {"click", "press", "choose", "check", "pick"}


def batch(body):
    check_paused()
    tab_id, page = tab_connection(body.get("tab") or None)
    ensure_granted(current_url(page))
    steps = body.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > BATCH_MAX_STEPS:
        raise ApiError(400, {"error": "bad_steps", "max": BATCH_MAX_STEPS})
    results = []
    for index, step in enumerate(steps):
        action = step.get("action")
        handler = STEP_HANDLERS.get(action)
        try:
            if handler is None:
                raise ApiError(400, {"error": "bad_action", "allowed": list(STEP_HANDLERS)})
            check_paused()
            log("intent", f"Next: {action} {step.get('name', step.get('key', ''))}")
            bar_update()
            out = handler(tab_id, page, step)
            if action in ACTIONS_THAT_NAVIGATE:
                wait_ready(page, first=0.05)
                enforce_after_move(tab_id, page)
        except ApiError as error:
            raise ApiError(error.status, {**error.body, "stoppedAt": index, "results": results})
        results.append({"i": index, "action": action, **out})
    form = form_snapshot(page)
    return {"ok": True, "results": results, "url": form["url"], "title": form["title"], "total": form["total"], "fields": form["fields"]}



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
        if path in ("/console", "/network"):
            limit = min(max(int(qs.get("limit", [50])[0]), 1), LOG_LIMIT)
            return 200, page_log(qs.get("tab", [None])[0], path[1:], limit)
        if path == "/screenshot":
            return 200, screenshot(qs.get("tab", [None])[0])
        if path == "/text":
            chars = min(max(int(qs.get("chars", [6000])[0]), 500), 20000)
            return 200, read_text(qs.get("tab", [None])[0], chars)
        if path == "/form":
            tab_id, page = tab_connection(qs.get("tab", [None])[0])
            ensure_granted(current_url(page))
            return 200, form_snapshot(page)
        if path == "/events":
            return 200, list(EVENTS)
        if path == "/requests":
            return 200, REQUESTS
        if path == "/approvals":
            return 200, [a for a in APPROVALS.values() if not a["approved"]]
        if path == "/permissions":
            return 200, PERMS
    if method == "POST":
        if path == "/browser/start":
            ensure_browser()
            return 200, status()
        if path == "/navigate":
            return 200, user_navigate(body)
        if path == "/navigate/back":
            return 200, user_back(body)
        if path == "/input":
            return 200, user_input(body)
        if path == "/browser/stop":
            stop_browser()
            return 200, status()
        if path == "/open":
            return 200, open_url(body)
        if path == "/act":
            return 200, act(body)
        if path == "/batch":
            return 200, batch(body)
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
            log("pause", "Paused" if PAUSED else "Running again")
            bar_update()
            return 200, {"paused": PAUSED}
        if path == "/focus":
            tab_id, _ = tab_connection(body.get("tab"))
            ensure_browser().call("Target.activateTarget", {"targetId": tab_id})
            return 200, {"ok": True}
    raise ApiError(404, {"error": "not found"})


class Handler(BaseHTTPRequestHandler):
    server_version = "claude-in-brave"

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
        try:
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the client left before the answer; nothing to do

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
            # Only actions take the lock. Reads (status, events, screenshot...) must not wait behind a
            # slow action, or the panel's requests time out.
            with (STATE_LOCK if method == "POST" else contextlib.nullcontext()):
                body = self._body() if method == "POST" else {}
                status_code, payload = route(method, url.path, parse_qs(url.query), body)
        except ApiError as error:
            return self._send(error.status, error.body)
        except (CdpError, ConnectionError, OSError, ValueError, KeyError, TypeError, IndexError) as error:
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
