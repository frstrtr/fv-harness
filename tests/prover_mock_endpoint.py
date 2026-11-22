"""prover_mock_endpoint.py PORT [fail|vary] — scripted chat-completions-compatible endpoint for testing the
dispatcher and the state machine without a GPU. With `fail`, no reply ever contains code (every
sample fails alike). With `vary`, every reply is code citing a different unknown lemma (every
sample fails differently).

For `feeOf_le` the first reply is a proof that does not compile (omega cannot see through the
nonlinear product); the repair request gets a correct proof. For `transfer_source_le` the first
reply is correct. Anything else gets a reply with no code block.
"""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

BAD_FEE = """theorem feeOf_le (x bps : Nat) : feeOf x bps ≤ x := by
  unfold feeOf
  omega
"""
GOOD_FEE = """theorem feeOf_le (x bps : Nat) : feeOf x bps ≤ x := by
  unfold feeOf
  have h : x * min bps 10000 ≤ x * 10000 := Nat.mul_le_mul_left _ (Nat.min_le_right _ _)
  omega
"""
GOOD_SRC = """theorem transfer_source_le (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).a ≤ l.a := by
  simp only [transfer]
  omega
"""


MODE = sys.argv[2] if len(sys.argv) > 2 else ""
FAIL_ALL = MODE == "fail"  # never produce code: every sample fails alike (same-failure wall)
VARY = MODE == "vary"      # code that fails differently each time: only the budget wall applies
COUNT = [0]


def reply_for(messages):
    if FAIL_ALL:
        return "I could not find a proof."
    if VARY:
        COUNT[0] += 1
        problem = messages[-1]["content"].split("```lean4", 1)[1].split("```", 1)[0]
        stub = re.findall(r"^(theorem\s+\S+[^\n]*(?:\n    [^\n]*)*?) := by", problem, re.M)[-1]
        return ("```lean4\nimport FVSpec.Ledger\nnamespace FV\n" + stub +
                f" := by\n  exact no_such_lemma_{COUNT[0]}\nend FV\n```\n")
    first = messages[-1]["content"]
    repair = "A previous attempt at this proof does not compile" in first
    problem = first.split("```lean4", 1)[1].split("```", 1)[0]
    target = re.findall(r"^theorem\s+(\S+)", problem, re.M)[-1]  # the stub comes last
    if target == "feeOf_le":
        body = GOOD_FEE if repair else BAD_FEE
    elif target == "transfer_source_le":
        body = GOOD_SRC
    else:
        return "I cannot prove this."
    return "Plan: unfold and bound.\n\n```lean4\nimport FVSpec.Ledger\nnamespace FV\n" + body + "end FV\n```\n"


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        text = reply_for(req["messages"])
        out = json.dumps({"choices": [{"message": {"role": "assistant", "content": text}}],
                          "usage": {"completion_tokens": len(text.split())}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
