"""contract_coverage.py — which basic blocks of a contract's runtime code a campaign executed (labels only).

    contract_coverage.py --runtime RUNTIME.bin --solc-output solc-output.json --source NAME --contract NAME
                         --pcs COVERAGE.pcs [--out DIR]

COVERAGE.pcs holds the executed code offsets (pcs) the TRON-TVM reference reported, comma-separated lines,
from every fuzz process of the run. The runtime code (its CBOR metadata trailer excluded) is split into
basic blocks: one starts at offset 0, at every JUMPDEST and after every JUMP, JUMPI, STOP, RETURN,
REVERT, INVALID or SELFDESTRUCT. A block counts as hit when any of its instructions was executed. A block
no control flow can enter (not at offset 0, not a JUMPDEST, and the block before it does not fall
through: it ends in JUMP, STOP, RETURN, REVERT, INVALID or SELFDESTRUCT) is data or dead code: it is
listed apart as UNREACHABLE, never as NOT EXERCISED. Reachable blocks never hit are NOT EXERCISED; with the
compiler's source map each is shown with its source line. The pcs come from the called contract's own
frames, including deeper frames running the same code (this.f(), re-entrancy).
Prints a JSON summary for fuzz.json and writes DIR/contract_coverage.md. It never decides a verdict.
"""
import argparse
import json
import pathlib

TERMINATORS = {0x00, 0x56, 0x57, 0xF3, 0xFD, 0xFE, 0xFF}
NO_FALLTHROUGH = TERMINATORS - {0x57}  # JUMPI falls through


def strip_metadata(code: bytes) -> bytes:
    if len(code) >= 2:
        n = int.from_bytes(code[-2:], "big")
        if n + 2 <= len(code) and 0xA1 <= code[-(n + 2)] <= 0xA5:
            return code[:-(n + 2)]
    return code


def instructions(code: bytes):
    """(pc, opcode, instruction index) for every instruction."""
    out, pc, i = [], 0, 0
    while pc < len(code):
        op = code[pc]
        out.append((pc, op, i))
        pc += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
        i += 1
    return out


def blocks(ins):
    bs, cur = [], []
    for pc, op, i in ins:
        if op == 0x5B and cur:  # JUMPDEST starts a block
            bs.append(cur)
            cur = []
        cur.append((pc, op, i))
        if op in TERMINATORS:
            bs.append(cur)
            cur = []
    if cur:
        bs.append(cur)
    return bs


def source_map(sm: str):
    """Instruction index -> (start, length, file index), decompressing solc's format."""
    out, last = [], [0, 0, 0]
    for entry in sm.split(";"):
        f = entry.split(":")
        for k in range(3):
            if k < len(f) and f[k] != "":
                last[k] = int(f[k])
        out.append(tuple(last))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runtime", required=True)
    ap.add_argument("--solc-output", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--contract", required=True)
    ap.add_argument("--pcs", required=True)
    ap.add_argument("--out")
    a = ap.parse_args()
    code = strip_metadata(pathlib.Path(a.runtime).read_bytes())
    ins = instructions(code)
    bs = blocks(ins)
    hit = set()
    p = pathlib.Path(a.pcs)
    if p.is_file():
        for line in p.read_text().split():
            hit.update(int(x) for x in line.split(",") if x)
    so = json.loads(pathlib.Path(a.solc_output).read_text())
    sm = (so.get("contracts", {}).get(a.source, {}).get(a.contract, {}).get("evm", {})
          .get("deployedBytecode", {}).get("sourceMap", ""))
    smap = source_map(sm) if sm else []
    srcs = {n: s.get("id") for n, s in so.get("sources", {}).items()}
    texts = {}
    for name, sid in srcs.items():
        f = pathlib.Path(a.solc_output).parent / "src" / name
        texts[sid] = f.read_text() if f.is_file() else None

    def where(i):
        if i >= len(smap):
            return None
        s, length, fi = smap[i]
        t = texts.get(fi)
        if fi < 0 or t is None:
            return "compiler-generated"
        line = t.count("\n", 0, s) + 1
        snippet = t[s:s + min(length, 80)].split("\n")[0].strip()
        return f"{[n for n, x in srcs.items() if x == fi][0]}:{line} `{snippet}`"

    rows, prev = [], None
    for b in bs:
        pcs = {pc for pc, _, _ in b}
        entry = b[0][0] == 0 or b[0][1] == 0x5B or (prev is not None and prev[-1][1] not in NO_FALLTHROUGH)
        rows.append({"start": b[0][0], "end": b[-1][0], "hit": bool(pcs & hit), "at": where(b[0][2]),
                     "reachable": entry or bool(pcs & hit)})
        prev = b
    reach = [r for r in rows if r["reachable"]]
    n_hit = sum(r["hit"] for r in reach)
    not_ex = [r for r in reach if not r["hit"]]
    unreach = [r for r in rows if not r["reachable"]]
    summary = {"labels_only": True, "blocks_total": len(reach), "blocks_hit": n_hit,
               "pct_blocks": round(100 * n_hit / len(reach), 1) if reach else 0.0,
               "pcs_executed": len(hit), "code_bytes": len(code), "unreachable_blocks": len(unreach),
               "not_exercised": [{"pc": r["start"], "at": r["at"]} for r in not_ex]}
    if a.out:
        md = ["# Contract coverage (labels only)", "",
              f"{n_hit} of {len(reach)} reachable basic blocks of the runtime code executed "
              f"({summary['pct_blocks']} %), over every fuzz process of the run.", "",
              "## NOT EXERCISED", ""]
        md += [f"- block at pc {r['start']:#x}..{r['end']:#x}: {r['at'] or 'no source mapping'}" for r in not_ex] or ["- none"]
        md += ["", f"## UNREACHABLE (data or dead code, not counted): {len(unreach)} block(s)", ""]
        md += [f"- pc {r['start']:#x}..{r['end']:#x}" for r in unreach[:50]]
        pathlib.Path(a.out, "contract_coverage.md").write_text("\n".join(md) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
