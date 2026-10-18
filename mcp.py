"""MCP server that gives Claude the Jarri browser service as tools (stdio, stdlib only).

Claude can read tabs and pages, open pages it may use, act on them, read requests, permissions and
the event log, and pause. Granting access, revoking it and approving actions are for the user only:
those are done in the terminal or in Jarri, never through this server.
"""

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE = f"http://127.0.0.1:{os.environ.get('JARRI_BROWSER_PORT', '8786')}"
PROTOCOL = "2024-11-05"


def call_service(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=60) as reply:
            return reply.status, json.load(reply)
    except HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")
    except URLError:
        return 503, {"error": "browser service not reachable", "hint": "systemctl --user start jarri-browser"}


def as_text(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def digest_text(payload):
    head = f'{payload["status"]} {payload["url"]} | {payload["title"]} | {payload["total"]} elements'
    return "\n".join([head] + payload["items"])


def run_tabs(args):
    return call_service("GET", "/tabs")


def run_digest(args):
    query = f'?limit={int(args.get("limit", 60))}'
    if args.get("tab"):
        query += f'&tab={args["tab"]}'
    return call_service("GET", "/digest" + query)


def run_text(args):
    query = f'?chars={int(args.get("chars", 6000))}'
    if args.get("tab"):
        query += f'&tab={args["tab"]}'
    return call_service("GET", "/text" + query)


def text_text(payload):
    head = f'{payload["title"]} | {payload["url"]} | {payload["total"]} lines' + (" (cut short)" if payload["truncated"] else "")
    return "\n".join([head] + payload["lines"])


def run_console(args):
    return call_service("GET", f'/console?limit={int(args.get("limit", 50))}' + (f'&tab={args["tab"]}' if args.get("tab") else ""))


def run_network(args):
    return call_service("GET", f'/network?limit={int(args.get("limit", 50))}' + (f'&tab={args["tab"]}' if args.get("tab") else ""))


def console_text(payload):
    head = f'{payload["url"]} | {len(payload["items"])} messages'
    return "\n".join([head] + [f'[{i["level"]}] {i["text"]}' for i in payload["items"]])


def network_text(payload):
    head = f'{payload["url"]} | {len(payload["items"])} requests'
    lines = []
    for i in payload["items"]:
        lines.append(f'{i["method"]} {i["status"] or ""} {i["url"]}' + (f' FAILED {i["failed"]}' if i["failed"] else ""))
        if i.get("body"):
            lines.append("  body: " + i["body"])
    return "\n".join([head] + lines)


def run_open(args):
    return call_service("POST", "/open", {"url": args["url"], "tab": args.get("tab")})


def run_act(args):
    body = {key: args[key] for key in ("action", "ref", "value", "key", "tab", "approvalId") if key in args}
    return call_service("POST", "/act", body)


def run_requests(args):
    return call_service("GET", "/requests")


def run_permissions(args):
    return call_service("GET", "/permissions")


def run_events(args):
    return call_service("GET", "/events")


def run_pause(args):
    return call_service("POST", "/pause", {"on": True})


TOOLS = [
    {
        "name": "tabs",
        "description": "List open browser tabs with URL, title, and whether Claude may use the origin.",
        "inputSchema": {"type": "object", "properties": {}},
        "run": run_tabs,
    },
    {
        "name": "digest",
        "description": "Read the page as numbered interactive elements (e.g. '12 button \"Skicka\"'). "
                       "Refs are valid until the next read of the same tab.",
        "inputSchema": {"type": "object", "properties": {
            "tab": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 200}}},
        "run": run_digest,
        "text": digest_text,
    },
    {
        "name": "text",
        "description": "Read the visible text of the page: prices, titles, descriptions. Use this when the digest "
                       "shows links but not the information you need.",
        "inputSchema": {"type": "object", "properties": {
            "tab": {"type": "string"}, "chars": {"type": "integer", "minimum": 500, "maximum": 20000}}},
        "run": run_text,
        "text": text_text,
    },
    {
        "name": "console",
        "description": "Read the F12 Console of a tab: recent messages, warnings and errors. Use it to find out why a page fails.",
        "inputSchema": {"type": "object", "properties": {
            "tab": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 200}}},
        "run": run_console,
        "text": console_text,
    },
    {
        "name": "network",
        "description": "Read the F12 Network list of a tab: recent requests, status codes, failures and text response bodies (cut and redacted). Headers are not shown.",
        "inputSchema": {"type": "object", "properties": {
            "tab": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 200}}},
        "run": run_network,
        "text": network_text,
    },
    {
        "name": "open",
        "description": "Open an http(s) URL. Refused with origin_not_granted unless the user granted the origin.",
        "inputSchema": {"type": "object", "properties": {
            "url": {"type": "string"}, "tab": {"type": "string"}}, "required": ["url"]},
        "run": run_open,
        "text": digest_text,
    },
    {
        "name": "act",
        "description": "Click (ref), type text into a textbox (ref + value), or press Enter, Tab or Escape. "
                       "Returns only what changed. Risky actions return approval_required: stop and tell the user.",
        "inputSchema": {"type": "object", "properties": {
            "action": {"type": "string", "enum": ["click", "type", "press"]},
            "ref": {"type": "string"}, "value": {"type": "string"},
            "key": {"type": "string", "enum": ["Enter", "Tab", "Escape"]},
            "tab": {"type": "string"}, "approvalId": {"type": "string"}}, "required": ["action"]},
        "run": run_act,
    },
    {
        "name": "requests",
        "description": "List what is waiting for the user: access requests and login requests.",
        "inputSchema": {"type": "object", "properties": {}},
        "run": run_requests,
    },
    {
        "name": "permissions",
        "description": "List origins the user has granted, with expiry.",
        "inputSchema": {"type": "object", "properties": {}},
        "run": run_permissions,
    },
    {
        "name": "events",
        "description": "Read the action log: opens, intended actions, approvals, blocks, pauses.",
        "inputSchema": {"type": "object", "properties": {}},
        "run": run_events,
    },
    {
        "name": "pause",
        "description": "Stop all browser actions right away. Only the user can resume.",
        "inputSchema": {"type": "object", "properties": {}},
        "run": run_pause,
    },
]
BY_NAME = {tool["name"]: tool for tool in TOOLS}


def respond(msg_id, result=None, error=None):
    message = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        message["error"] = error
    else:
        message["result"] = result
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def call_tool(name, args):
    tool = BY_NAME[name]
    status, payload = tool["run"](args)
    text = tool["text"](payload) if status < 400 and "text" in tool else as_text(payload)
    return {"content": [{"type": "text", "text": text}], "isError": status >= 400}


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    message = json.loads(line)
    method, msg_id = message.get("method"), message.get("id")
    if msg_id is None:
        continue  # notifications get no reply
    if method == "initialize":
        version = message.get("params", {}).get("protocolVersion", PROTOCOL)
        respond(msg_id, {"protocolVersion": version, "capabilities": {"tools": {}},
                         "serverInfo": {"name": "jarri-browser", "version": "1"}})
    elif method == "tools/list":
        respond(msg_id, {"tools": [{k: t[k] for k in ("name", "description", "inputSchema")} for t in TOOLS]})
    elif method == "tools/call":
        params = message.get("params", {})
        if params.get("name") not in BY_NAME:
            respond(msg_id, error={"code": -32602, "message": "unknown tool"})
        else:
            respond(msg_id, call_tool(params["name"], params.get("arguments", {})))
    elif method == "ping":
        respond(msg_id, {})
    else:
        respond(msg_id, error={"code": -32601, "message": "method not found"})
