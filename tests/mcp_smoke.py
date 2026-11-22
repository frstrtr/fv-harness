"""mcp_smoke.py — stdio smoke test for the lean-lsp MCP server.

    python3 -I tests/mcp_smoke.py [LINE] -- CMD ARGS...   (server command, e.g. ssh $FV_GATE_HOST ...)

LINE is a line of spec/solution/Solution.lean inside a tactic proof (default 6).

Checks: initialize; tools/list contains lean_goal and lean_diagnostic_messages and none of the
remote search tools; lean_diagnostic_messages and lean_goal answer on spec/solution/Solution.lean.
Prints a JSON summary; exit 0 iff every check passed.
"""
import json
import subprocess
import sys
import time

REMOTE = {"lean_leansearch", "lean_loogle", "lean_leanfinder", "lean_hammer_premise"}
cmd = sys.argv[sys.argv.index("--") + 1:]
proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
next_id = 0


def call(method, params=None, timeout=600):
    global next_id
    next_id += 1
    msg = {"jsonrpc": "2.0", "id": next_id, "method": method}
    if params is not None:
        msg["params"] = params
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout")
        try:
            resp = json.loads(line)
        except json.JSONDecodeError:
            continue
        if resp.get("id") == next_id:
            return resp
    raise TimeoutError(method)


def notify(method):
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
    proc.stdin.flush()


def text_of(resp):
    res = resp.get("result", {})
    return "\n".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")


out = {"checks": {}}
try:
    t0 = time.time()
    init = call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "fv-smoke", "version": "1"}})
    out["server"] = init.get("result", {}).get("serverInfo")
    notify("notifications/initialized")
    tools = {t["name"] for t in call("tools/list")["result"]["tools"]}
    out["tools"] = sorted(tools)
    out["checks"]["core_tools_present"] = {"lean_goal", "lean_diagnostic_messages"} <= tools
    out["checks"]["remote_tools_absent"] = not (tools & REMOTE)
    f = "spec/solution/Solution.lean"
    diag = call("tools/call", {"name": "lean_diagnostic_messages", "arguments": {"file_path": f}})
    out["diagnostics"] = text_of(diag)[:1500]
    out["checks"]["diagnostics_answer"] = "error" not in json.dumps(diag.get("error", {})) and bool(out["diagnostics"])
    line = int(sys.argv[1]) if sys.argv[1] != "--" else 6
    goal = call("tools/call", {"name": "lean_goal", "arguments": {"file_path": f, "line": line}})
    out["goal"] = text_of(goal)[:1500]
    out["checks"]["goal_answer"] = "⊢" in out["goal"]
    out["seconds"] = round(time.time() - t0, 1)
except Exception as e:  # noqa: BLE001 - report any failure as a failed smoke test
    out["exception"] = repr(e)
finally:
    proc.stdin.close()
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()

ok = bool(out["checks"]) and all(out["checks"].values()) and "exception" not in out
out["ok"] = ok
print(json.dumps(out, indent=2, ensure_ascii=False))
sys.exit(0 if ok else 1)
