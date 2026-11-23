# fv_tron_tvm.py — harness-owned client of the TRON-TVM reference executor (fuzz/tron-tvm/FvTronTvmDriver.java).
#
# A TRON-TVM binding (fuzz/binding.py, run by the harness's Python loop fuzz/python/fv_diff.py) imports
# this module. fuzz/run_fuzz.sh --lang tron-tvm compiles the contract with the pinned TRON solc and
# the driver against the pinned java-tron, and sets:
#   FV_TRON_TVM_CMD       the driver command (java-tron's TRON-TVM in a JVM, inside a network namespace)
#   FV_TRON_TVM_CREATION  file with the contract's creation bytecode (hex)
#   FV_TRON_TVM_RUNTIME   file with the compiler's runtime bytecode (hex)
#   FV_TRON_TVM_DB        a fresh directory for the node's store
#   FV_TRON_TVM_STATUS    file the client appends what it observed to (JSON lines): "ready" with the driver's
#                    config line and the network interfaces this process sees, and "call" at its first
#                    transaction; run_fuzz.sh requires both before a PASS
#   FV_TRON_TVM_COVERAGE  file the executed contract pcs are appended to
# This module owns what a binding must not be able to weaken:
#   - deployment: the creation code (plus the binding's constructor words) runs once; the code left
#     at the contract address must equal the compiler's runtime bytecode, else the process aborts;
#   - each call's outcome as java-tron reports it: success / revert (with its data) / any other
#     result code as a halt ("halt OUT_OF_ENERGY", "halt TRANSFER_FAILED", ...), the return data
#     and the logs; energy is returned apart from the Outcome, so it is never compared unless a
#     binding compares it on purpose;
#   - the executor failing is never a finding: a driver that will not start, refuses the profile, runs
#     without --debug, dies, answers out of protocol, reports an error or a result code it cannot name
#     (halt UNKNOWN), or the executor's own limits (JVM_STACK_OVER_FLOW, OUT_OF_TIME), ends the process
#     with EXECUTOR_ERROR (87, "fv_tron_tvm: EXECUTOR ERROR: ..."), which
#     run_fuzz.sh reports as ERROR and never keeps as a reproducer; deployed code that differs from the
#     compiler's runtime ends it with DEPLOY_MISMATCH (88), reported as BLOCKED.
# What it does not decide: which storage words and balances are compared and what the oracle's
# state means as an outcome. That is the binding's, which is trusted and human-reviewed.

import os
import subprocess
import sys
from dataclasses import dataclass

TRX_START = 10 ** 15  # sun given to every account the binding creates


@dataclass(frozen=True)
class Log:
    address: bytes  # 20 bytes, as the TRON-TVM reports it
    topics: tuple
    data: bytes


@dataclass(frozen=True)
class Itx:
    """One internal transaction of the VM, as java-tron records it (in order)."""
    note: str        # "call", "create", "suicide", ... as java-tron names it
    sender: bytes    # as java-tron reports it
    to: bytes        # the transfer-to address, b"" if none
    value: int       # TRX (sun)
    tokens: tuple    # ((token id, amount), ...) sorted by id
    rejected: bool


@dataclass(frozen=True)
class Outcome:
    kind: str  # "success", "revert", "halt <RESULT_CODE>" or "invalid <message>"
    data: bytes
    logs: tuple
    internal: tuple = ()  # the internal transactions, an ORDERED tuple of Itx: compared as a whole

    def cls(self, errors=()):
        """The outcome class: success, revert Error(string) "msg", panic 0x.., revert <custom>, halt ..."""
        if self.kind != "revert":
            return self.kind
        d = self.data
        if len(d) < 4:
            return "revert (no data)"
        if d[:4] == bytes.fromhex("08c379a0") and len(d) >= 68:
            n = int.from_bytes(d[36:68], "big")
            return 'revert Error(string) "' + d[68:68 + n].decode("utf-8", "replace") + '"'
        if d[:4] == bytes.fromhex("4e487b71") and len(d) >= 36:
            return "panic 0x%x" % int.from_bytes(d[4:36], "big")
        for e in errors:
            if selector(e) == d[:4]:
                return "revert " + e
        return "revert 0x" + d[:4].hex()

    def show(self, errors=()):
        s = f"{self.cls(errors)} data=0x{self.data.hex()}"
        for lg in self.logs:
            s += f" log[{len(lg.topics)} topic(s), {len(lg.data)} B]"
        for it in self.internal:
            s += (f" itx[{it.note} to=0x{it.to.hex()} trx={it.value} tokens={list(it.tokens)}"
                  f"{' REJECTED' if it.rejected else ''}]")
        return s


SUCCESS = Outcome("success", b"", ())


EXECUTOR_ERROR, DEPLOY_MISMATCH = 87, 88
TX_COUNT = 0  # transactions sent by call() in this process; fv_diff.py requires one per implementation step
# Result codes that are the executor's own failure, never a contract outcome: the JVM's stack, and the
# cpu-time limit (off under --debug, so it must not occur).
EXECUTOR_CODES = ("UNKNOWN", "JVM_STACK_OVER_FLOW", "OUT_OF_TIME")


def _die(msg, kind="EXECUTOR ERROR", code=EXECUTOR_ERROR):
    """Ends the process without a crash report: the executor's failure is not the contract's."""
    sys.stderr.write(f"fv_tron_tvm: {kind}: {msg}\n")
    sys.stderr.flush()
    os._exit(code)


def _status(event, **kw):
    path = os.environ.get("FV_TRON_TVM_STATUS")
    if path:
        import json
        with open(path, "a") as f:
            f.write(json.dumps(dict(event=event, pid=os.getpid(), **kw)) + "\n")


def _net_ifaces():
    try:
        with open("/proc/net/dev") as f:
            return sorted(l.split(":")[0].strip() for l in f.read().splitlines()[2:] if ":" in l)
    except OSError:
        return None


class Tvm:
    def __init__(self):
        cmd, db = os.environ["FV_TRON_TVM_CMD"], os.environ["FV_TRON_TVM_DB"]
        try:
            self.p = subprocess.Popen([cmd, db], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                      bufsize=1)
        except OSError as e:
            _die(f"driver did not start: {e}")
        self.called = False
        ready = self.p.stdout.readline()
        if not ready.startswith("ready"):
            _die(f"driver did not start: {ready!r}")
        self.contract = None
        self.covered = set()
        self.cov_file = os.environ.get("FV_TRON_TVM_COVERAGE")  # executed contract pcs, appended as they appear
        # Determinism: java-tron's per-transaction CPU-time limit must be off (--debug, as its own VM
        # tests run), or a slow execution fails as OUT_OF_TIME and results depend on timing.
        self.config = self._expect("config", "config")
        if "debug=true" not in self.config.split():
            _die("the TRON-TVM's cpu-time limit is not disabled (driver not started with --debug): " + self.config)
        _status("ready", driver=ready.strip(), config=self.config, net_ifaces=_net_ifaces())
        sys.stderr.write(f"fv_tron_tvm: cpu-time limit disabled (--debug), as java-tron's VM tests do; {self.config}\n")

    def _ask(self, line):
        try:
            self.p.stdin.write(line + "\n")
            self.p.stdin.flush()
            ans = self.p.stdout.readline()
        except (BrokenPipeError, OSError) as e:
            _die(f"driver gone: {e}")
        if not ans:
            _die(f"driver gone (no answer to {line.split()[0]})")
        ans = ans.rstrip("\n")
        if ans.startswith("error "):
            _die(f"driver error on {line.split()[0]}: {ans[6:]}")
        return ans

    def _expect(self, line, head):
        ans = self._ask(line)
        if not ans.startswith(head):
            _die(f"unexpected answer to {line.split()[0]}: {ans!r}")
        return ans[len(head):].strip()

    def _cover(self, pcs):
        new = pcs - self.covered
        if new:
            self.covered |= new
            if self.cov_file:
                with open(self.cov_file, "a") as f:
                    f.write(",".join(map(str, sorted(new))) + "\n")

    # accounts, TRC-10 tokens, storage
    def account(self, addr, sun=TRX_START):
        self._expect(f"account {addr.hex()} {sun}", "ok")

    def asset(self):
        return int(self._expect("asset", "asset"))

    def set_token(self, addr, tid, n):
        self._expect(f"settoken {addr.hex()} {tid} {n}", "ok")

    def token(self, addr, tid):
        return int(self._expect(f"token {addr.hex()} {tid}", "token"))

    def exists(self, addr):
        return self._expect(f"exists {addr.hex()}", "exists") == "1"

    def balance(self, addr):
        return int(self._expect(f"balance {addr.hex()}", "balance"))

    def sstore(self, slot, value):
        self._expect(f"sstore {self.contract.hex()} {slot:064x} {value:064x}", "ok")

    def sload(self, slot):
        return int(self._expect(f"sload {self.contract.hex()} {slot:064x}", "value"), 16)

    def keccak(self, b):
        return bytes.fromhex(self._expect(f"keccak {b.hex() or '-'}", "keccak"))

    def deploy(self, creator, ctor_words=()):
        """Deploys the compiled contract once; aborts unless the deployed code is the compiler's runtime."""
        code = open(os.environ["FV_TRON_TVM_CREATION"]).read().strip() + "".join(w.hex() for w in ctor_words)
        runtime = open(os.environ["FV_TRON_TVM_RUNTIME"]).read().strip()
        ans = self._expect(f"deploy {creator.hex()} {code} 0 0 0", "deploy")
        addr, got = ans.split(" ")
        if got != runtime:
            _die(f"the deployed code ({len(got) // 2} B) differs from the compiler's runtime bytecode "
                 f"({len(runtime) // 2} B)", kind="DEPLOYED CODE MISMATCH", code=DEPLOY_MISMATCH)
        self.contract = bytes.fromhex(addr)
        return self.contract

    def call(self, caller, data, value=0, tvalue=0, tid=0):
        """One transaction to the deployed contract -> (Outcome, energy used)."""
        global TX_COUNT
        TX_COUNT += 1
        try:
            return self._call(caller, data, value, tvalue, tid)
        except (ValueError, IndexError, UnicodeDecodeError) as e:  # a malformed answer: the executor's failure
            _die(f"protocol: could not parse the driver's answer to call ({type(e).__name__}: {e})")

    def _call(self, caller, data, value, tvalue, tid):
        ans = self._ask(f"call {caller.hex()} {self.contract.hex()} {data.hex() or '-'} {value} {tvalue} {tid}")
        if not self.called:
            self.called = True
            _status("call")
        if ans.startswith("invalid "):
            return Outcome("invalid " + ans[8:], b"", ()), 0
        f = ans.split(" ")
        if f[0] != "result" or len(f) != 5:
            _die(f"unexpected answer to call: {ans!r}")
        code, ret, energy, n = f[1], f[2], int(f[3]), int(f[4])
        logs = []
        for _ in range(n):
            lf = self.p.stdout.readline().rstrip("\n").split(" ")
            if len(lf) != 4 or lf[0] != "log":
                _die(f"unexpected log line: {lf!r}")
            topics = tuple(bytes.fromhex(t) for t in lf[2].split(",")) if lf[2] != "-" else ()
            logs.append(Log(bytes.fromhex(lf[1]), topics, b"" if lf[3] == "-" else bytes.fromhex(lf[3])))
        il = self.p.stdout.readline().rstrip("\n").split(" ")
        if len(il) != 2 or il[0] != "itxs" or not il[1].isdigit():
            _die(f"unexpected internal-transaction count line: {il!r}")
        itxs = []
        for _ in range(int(il[1])):
            f2 = self.p.stdout.readline().rstrip("\n").split(" ")
            if len(f2) != 7 or f2[0] != "itx" or f2[6] not in ("0", "1") or not f2[4].isdigit():
                _die(f"unexpected internal-transaction line: {f2!r}")
            toks = () if f2[5] == "-" else tuple(sorted((int(k), int(v)) for k, v in (x.split(":") for x in f2[5].split(","))))
            itxs.append(Itx(f2[1], bytes.fromhex(f2[2]), b"" if f2[3] == "-" else bytes.fromhex(f2[3]), int(f2[4]), toks,
                            f2[6] == "1"))
        pl = self.p.stdout.readline().rstrip("\n")
        if not pl.startswith("pcs "):
            _die(f"unexpected coverage line: {pl!r}")
        if pl != "pcs -":
            self._cover({int(x) for x in pl[4:].split(",")})
        if code in EXECUTOR_CODES:
            _die(f"the TRON-TVM returned {code}: an executor failure, not a contract outcome")
        kind = {"SUCCESS": "success", "REVERT": "revert"}.get(code, "halt " + code)
        return Outcome(kind, b"" if ret == "-" else bytes.fromhex(ret), tuple(logs), tuple(itxs)), energy


_T = None


def get():
    """The process's TRON-TVM (started on first use, inside fv_diff's initialisation)."""
    global _T
    if _T is None:
        _T = Tvm()
    return _T


# ABI helpers (Keccak-256 from the reference executor itself, so no extra dependency)
def selector(sig):
    return get().keccak(sig.encode())[:4]


def topic(sig):
    return get().keccak(sig.encode())


def word(v):
    return int(v).to_bytes(32, "big")


def addr_word(a21):
    """An address argument: the 20-byte account id, left-padded (a TRON address is 0x41 + 20 bytes)."""
    return a21[-20:].rjust(32, b"\0")


def calldata(sig, words=()):
    return selector(sig) + b"".join(words)


def error_string(msg):
    """The revert data of require(..., msg): Error(string)."""
    b = msg.encode()
    return (bytes.fromhex("08c379a0") + word(32) + word(len(b)) + b + b"\0" * ((32 - len(b) % 32) % 32))
