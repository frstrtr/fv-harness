"""tier2_probe.py [BASE_URL] [MODEL] [cot|plain] [N] — N concurrent requests (default 1) for the
fixture's walled leaf `feeOf_le` against a Tier-2 endpoint. Prints per-request throughput
(llama.cpp timings), the finish reason and the last Lean code block, plus the aggregate decode
rate over the wall time."""
import concurrent.futures as cf
import json
import re
import sys
import time
import urllib.request

base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8081/v1"
model = sys.argv[2] if len(sys.argv) > 2 else "goedel-prover-v2-8b"
style = sys.argv[3] if len(sys.argv) > 3 else "cot"
n = int(sys.argv[4]) if len(sys.argv) > 4 else 1
code = """namespace FV

def feeOf (x bps : Nat) : Nat := x * min bps 10000 / 10000

theorem feeOf_le (x bps : Nat) : feeOf x bps ≤ x := by
  sorry

end FV
"""
prompt = "Complete the following Lean 4 code:\n\n```lean4\n" + code + "```"
if style == "cot":
    prompt += ("\n\nBefore producing the Lean 4 code to formally prove the given theorem, provide a detailed proof plan "
               "outlining the main proof steps and strategies.\nThe plan should highlight key ideas, intermediate "
               "lemmas, and proof structures that will guide the construction of the final formal proof.")
body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}],
                   "max_tokens": 6144 if style == "cot" else 1536, "temperature": 0.9, "top_p": 0.95}).encode()


def one(_):
    t0 = time.time()
    req = urllib.request.Request(base.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Content-Type": "application/json"})
    resp = json.load(urllib.request.urlopen(req, timeout=1800))
    text = resp["choices"][0]["message"].get("content") or ""
    blocks = re.findall(r"```(?:lean4|lean)?\s*\n(.*?)```", text, re.S)
    return {"wall_seconds": round(time.time() - t0, 1), "finish_reason": resp["choices"][0].get("finish_reason"),
            "usage": resp.get("usage"),
            "timings": {k: round(v, 2) for k, v in (resp.get("timings") or {}).items() if isinstance(v, (int, float))},
            "reasoning_chars": len(resp["choices"][0]["message"].get("reasoning_content") or ""),
            "content_chars": len(text), "last_code_block": blocks[-1] if blocks else None}


t0 = time.time()
with cf.ThreadPoolExecutor(n) as ex:
    res = list(ex.map(one, range(n)))
wall = time.time() - t0
tok = sum((r["usage"] or {}).get("completion_tokens", 0) for r in res)
print(json.dumps({"endpoint": base, "model": model, "prompt": style, "concurrent": n, "results": res,
                  "aggregate": {"completion_tokens": tok, "wall_seconds": round(wall, 1),
                                "decode_tok_per_s": round(tok / wall, 1)}}, indent=2, ensure_ascii=False))
