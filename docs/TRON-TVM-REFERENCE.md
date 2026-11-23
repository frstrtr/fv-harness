# The TRON Virtual Machine (TVM) reference executor

TRON-TVM contracts are checked against a signed Lean specification on **java-tron's own
TRON-TVM**. java-tron is built from source at a pinned release and runs offline, as a
reference: `fuzz/run_fuzz.sh --lang tron-tvm`. This note records how the reference is built and pinned,
what it covers, and what it does not.

## What runs

- **`fuzz/tron-tvm/FvTronTvmDriver.java`** (harness) runs each transaction through java-tron's
  `TransactionTrace` (init, exec, finalization) with a node context whose store is a temporary
  directory, without a block, as java-tron's VM tests do, but with the trace attached to the
  transaction as `Manager.processTransaction` does (the VM records the caller's energy in that
  receipt). It speaks a line protocol: deploy, calls with a TRX value, a TRC-10 token value and a
  token id, storage, TRC-10 and TRX balances, logs, energy, the executed code offsets, and keccak.
  It also reports each call's internal transactions in order (java-tron's `InternalTransaction`:
  note, sender, recipient, TRX value, tokens, rejected); the client returns them in `Outcome.internal`
  and they are compared as an ordered list. Reads never create an account. Every transaction carries a fresh nonce, so identical requests get
  distinct transaction ids (and identical deploys distinct addresses). Any `Throwable` is reported;
  after an `Error` (e.g. `OutOfMemoryError`) the driver exits. The JVM runs with `-Xmx4g`: java-tron's VM
  trace keeps every executed op with its stack and memory actions for the length of a transaction.
- **The energy-limit fork.** On mainnet `ENERGY_LIMIT_HARD_FORK` is active (java-tron:
  `ReceiptCapsule.checkForEnergyLimit`, latest block ≥ `blockNumForEnergyLimit`, 4,727,890). A fresh
  node has no blocks, so it would be off: nested-call storage would not be deep-copied
  (`RepositoryImpl.getStorage`) and the energy limit would use the pre-fork formula. The driver sets
  `blockNumForEnergyLimit` to 0, and its config line reports `energy_limit_hard_fork=true`.
- **`fuzz/tron-tvm/fv_tron_tvm.py`** (harness) is the client the project's binding imports. Deployed code
  that differs from the compiler's runtime bytecode ends the process with exit 88 (the run is
  BLOCKED). Any executor failure ends it with exit 87 (the run is ERROR, and the input is never kept
  as a reproducer): a driver that will not start or refuses the profile, a node without
  `debug=true`, a driver that dies or answers out of protocol, an `error` answer, or a result the VM
  cannot name (`halt UNKNOWN`). It reports each call's outcome: success, the exact revert data, or the result code
  as a halt (`halt TRANSFER_FAILED`, `halt OUT_OF_ENERGY`, …). The outcome includes the return data
  and logs; energy is kept apart.
- **Network.** The whole fuzz process runs in a network namespace (`bwrap --unshare-net`). There is
  no network at run time.
- **Observed, not assumed.** Each fuzz process appends to `tron-tvm/status.jsonl` what it saw: the
  driver's start line and config (`debug`, `cpu_ms`, `energy_limit_hard_fork`, heap, JVM arguments,
  the sha256 of the node config `config-test.conf`), the network interfaces in its namespace, and
  its first transaction. A PASS needs at least one driver start, `debug=true` in every one, at least
  one process with a transaction, executed contract code in `tron-tvm/coverage.pcs`, and only `lo` in
  every process; otherwise the run is ERROR (a binding that never calls the TRON-TVM cannot pass).
  `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` and `JDK_JAVA_OPTIONS` in the environment are refused.
- **Recorded.** `fuzz.json` → `tron_tvm` records:
  - the java-tron commit; the sha256 of the classpath manifest (every jar, and every class and
    resource directory of java-tron's build by its file manifest, `tron-tvm/classpath.manifest`); the JDK
    and the sha256 of its tree; the driver's and client's sha256; the heap;
  - the chain-parameter profile: name, network, source, fetch time and sha256;
  - the TRON solc sha256;
  - the creation and runtime bytecode, and the runtime with its metadata trailer stripped;
  - as observed: `network`, `cpu_time_limit`, `driver_config` and the number of driver starts and
    processes with a transaction.
- What is enforced before a run, each ERROR otherwise: the java-tron commit and a clean tree; the TRON
  solc sha256; every classpath entry lies under `$FV_TRON_TVM_HOME` and the classpath manifest's sha256 is
  `FV_TRON_TVM_CLASSPATH_SHA256`; the JDK tree's sha256 is `FV_TRON_TVM_JDK_TREE_SHA256`; all three
  build pins are set (`config/pins.env`); no `FV_TVM_*` variable (the names before the rename) and no
  JVM option variable is set. Observed in every driver, else ERROR: offline (only `lo`), `--debug`, the
  energy-limit fork active, and the node config's sha256 equal to `FV_TRON_TVM_NODE_CONFIG_SHA256`.
- What is recorded, not enforced: Gradle. The Gradle distribution below is checksummed when the reference
  is built; what the run checks is the result (the classpath manifest), not the tool that produced it.

## Rules for a binding, and what each failure becomes

- **Every implementation step sends at least one transaction** through `fv_tron_tvm` (the client
  counts them; `fuzz/python/fv_diff.py` checks the count around every `impl_step`). A step that sends
  none, for example one that answers from the oracle, ends the run ERROR (exit 87), never PASS.
- **What is a finding and what is not.** Only a difference between the oracle and the contract's
  observed outcome (or a value outside its declared width) is a finding: FAIL, with the input kept in
  the corpus. Everything else is ERROR (exit 87 from the process, "TRON-TVM reference executor: ..."),
  and the input is not kept:
  - an exception in the binding or the client (the phase is named, and the input is written to
    `artifacts/binding-error-<hash>` for debugging only);
  - a malformed answer from the driver, or the driver gone;
  - a result code that is the executor's own: `UNKNOWN`, `JVM_STACK_OVER_FLOW`, `OUT_OF_TIME`;
  - an input over the per-input timeout (the contract's execution is bounded by energy, so a timeout
    is the executor's time);
  - any driver exception other than `ContractValidateException`.
  Deployed code that is not the compiler's is BLOCKED.
- **"invalid <message>"** is an outcome only for java-tron's `ContractValidateException`: the node
  refused the transaction before the VM. A binding compares it like any other outcome.
- **One value per pin.** Each `FV_TRON_TVM_*_SHA256` (and `FV_JAVA_TRON_COMMIT`, the solc sha256) holds
  exactly one value, the reference build's. Another host's build must reproduce it, or the
  deployment carries its own reviewed `config/pins.env`; there is no list of accepted values.
- The driver's JVM loads only the pinned JDK's own extension directory (`-Djava.ext.dirs`), with
  `LD_PRELOAD` and `LD_LIBRARY_PATH` removed, and the gate refuses a run with either set. Tree hashes
  (classpath directories, the JDK) include every symbolic link's target.

## Pins

| Component | Pin |
|---|---|
| java-tron | GreatVoyage-v4.8.2.4 = commit `4e8389f159d0782f1ebcd9dab2fd88388c0e6fe9`, built from source; the tree must be unmodified (`git status` clean) |
| JDK | Temurin 8u514-b01, `OpenJDK8U-jdk_x64_linux_hotspot_8u514b01.tar.gz` sha256 `27eda854481d20806d918b30cdd417c6bed4fd15882e24f3595dc8ae7fb5d095`; enforced at run time by the tree sha256 `FV_TRON_TVM_JDK_TREE_SHA256` (the directory name alone identifies nothing) |
| Executed build | `FV_TRON_TVM_CLASSPATH_SHA256` (classpath manifest, every entry under the home) and `FV_TRON_TVM_NODE_CONFIG_SHA256` (config-test.conf as loaded): the reference host's values in `config/pins.env`; another host's build must reproduce them or carry its own reviewed values |
| Gradle | 7.6.4 distribution `gradle-7.6.4-bin.zip`, sha256 `bed1da33cca0f557ab13691c77f38bb67388119e4794d113e051039b80af9bb1` (equal to services.gradle.org's published checksum), run directly; checked when building, not at run time |
| TRON solc | 0.5.18 (`tv_0.5.18`, `solidity-linux_0.5.18_Bacon_v4.3.zip`), binary sha256 `27ebd5dcc78f99e60d138cebcf642dc01dcd3cd7d4c7ce24569bbdd136cdbc27` |
| Chain parameters | `fuzz/tron-tvm/profiles/mainnet-20261122.json`: the mainnet `wallet/getchainparameters` answer, byte for byte, sha256 `9012d4a9…0c8f` |

## Building it reproducibly

```sh
T=$FV_ROOT/tron-tvm; mkdir -p "$T/dl" && cd "$T/dl"
# JDK and Gradle: download, then compare with the publishers' checksums
echo "27eda854481d20806d918b30cdd417c6bed4fd15882e24f3595dc8ae7fb5d095  OpenJDK8U-jdk_x64_linux_hotspot_8u514b01.tar.gz" | sha256sum -c
echo "bed1da33cca0f557ab13691c77f38bb67388119e4794d113e051039b80af9bb1  gradle-7.6.4-bin.zip" | sha256sum -c
cd "$T" && git clone --depth 1 --branch GreatVoyage-v4.8.2.4 https://github.com/tronprotocol/java-tron
git -C java-tron rev-parse HEAD     # 4e8389f159d0782f1ebcd9dab2fd88388c0e6fe9
JAVA_HOME=$T/jdk8u514-b01 GRADLE_USER_HOME=$T/gradle-home gradle-7.6.4/bin/gradle --no-daemon \
  --init-script fv-printcp.gradle :framework:fvPrintTestClasspath -x test     # plus the module jars
```

**Two facts about java-tron's Gradle wrapper at this release:**
- `gradle/wrapper/gradle-wrapper.properties` names `gradle-7.6.4-bin.zip` but sets **no
  `distributionSha256Sum`**, so the wrapper as shipped does not verify what it downloads.
- The committed `gradle/wrapper/gradle-wrapper.jar` (sha256 `3dc39ad6…df9f`) is not the 7.6.4
  wrapper jar. It equals Gradle's official wrapper-jar checksum for 5.6–5.6.4: official, but older
  than the distribution it names.

The harness therefore does not run `gradlew`. It runs the 7.6.4 distribution directly, after
checking that distribution's published checksum.

**Dependencies.** java-tron ships `gradle/verification-metadata.xml` (417 components,
`verify-metadata=true`, `verify-signatures=false`). Gradle checks the checksum of every artifact it
fetches. On the reference host the build fetched 311 components (526 files) with no verification
failure. PGP signatures are not checked; that is java-tron's own setting.

## Chain parameters: a profile, applied completely

A fresh java-tron node runs the TRON-TVM with the rules of the network's early proposals, unless the
chain parameters say otherwise. One example: without the multi-sign proposal, the `ADDRESS` opcode
pushes the 21-byte TRON address (`0x41`‖20 bytes). Then `a == address(this)` is false for an
ABI-decoded address, and a contract's self-check is silently skipped.

The reference therefore loads a **pinned profile**: a network's `wallet/getchainparameters` answer.
- It applies the keys in the profile's order. A key that names a java-tron proposal
  (`ProposalUtil.ProposalType`) goes through java-tron's own `ProposalService.process`, one proposal per
  key, so the proposal's side effects happen as on the network. Examples: the adaptive-resource target
  ratio is stored as 24 × 60 × the reported value and derives the energy target limit; Prague deploys
  the TIP-2935 history-storage contract. Any other key goes through its `DynamicPropertiesStore` setter.
- It **refuses** a key it cannot apply.
- It **refuses** a profile that does not round-trip: every parameter this java-tron's own
  `Wallet.getChainParameters` reports (all of them, not only `allow*` and energy ones) must read back
  equal to the profile's value after applying. The exemption list is empty.
- It **refuses** a profile that leaves any `allow*` or energy parameter unset. The exceptions are
  listed in the driver with reasons: chain state such as `TotalEnergyWeight`, and one parameter the
  API does not report.
- A Nile profile fetched on the same day is refused by this release (4.8.2.4), because it carries
  proposals that only newer java-tron knows. A Nile reference needs that newer release.

## What the reference does not cover

- **Time.** The per-transaction CPU-time limit is off (`--debug`, as java-tron's own VM tests run),
  so results do not depend on timing. `OUT_OF_TIME` behaviour is **not covered**. In java-tron's
  source, `--debug` affects only the time checks, not energy accounting.
- **Energy limits** are covered only where a statement or a binding names them.
- **Block context.** Each call runs without a block, as in java-tron's VM tests.
- **Coverage guidance: by the binding only.** The contract runs in the JVM, so libFuzzer sees none of
  it. With no `IMPL_MODULE` (a TRON-TVM binding has none), `fv_diff.py` instruments the binding's own
  functions: the fuzzer is guided over the branches of the binding (its generator and the outcome cases
  it distinguishes), not over the contract's code. A campaign is therefore guided by the binding, and
  only as far as the binding's case split follows the contract (control c51). Guidance from the
  contract's executed code is a planned design item. What the contract executed is still **measured**. The driver reports
  the code offsets java-tron's VM trace records for the called contract's own frame, and for deeper
  frames whose every opcode matches the called contract's code at its offset (the same code entered
  again: `this.f()`, re-entrancy). The run maps them to basic blocks of the runtime code, with source
  lines from the compiler's source map, and lists the reachable blocks never executed as NOT
  EXERCISED. Blocks no control flow can enter (data or dead code) are listed apart as UNREACHABLE
  (`fuzz.json` → `tron_tvm.contract_coverage`, `tron-tvm/contract_coverage.md`; control c41). The coverage file
  is emptied at the start of each run.

## Controls

| Control | What it checks |
|---|---|
| c33 | TRC-10 opcodes against fixed answers: CALLTOKENID, CALLTOKENVALUE, TOKENBALANCE, CALLTOKEN |
| c34 | The capped faucet example on the reference: PASS through the corpus-merge path, with the pins and the observed facts recorded |
| c35 | The faucet's cap test off by one: FAIL |
| c36 | The driver or client refuses a node without `--debug`, an unknown or missing profile parameter, a profile that differs from its record, and another TRON solc; through `run_fuzz.sh`: a refused profile or no `--debug` is ERROR, deployed code that is not the compiler's is BLOCKED, a driver killed mid-run is ERROR with nothing kept, a binding that never calls the TRON-TVM is ERROR, `JAVA_TOOL_OPTIONS` is ERROR |
| c37 | Vendored copies of the client and driver are pinned like the other harness files |
| c41 | A branch the generator cannot reach is reported NOT EXERCISED |
| c51 | With no `IMPL_MODULE` the binding is instrumented: the faucet campaign adds corpus units within 3,000 executions |
| c49 | A faucet whose `withdraw(0)` skips its zero-amount transfer (balances, storage and events unchanged) FAILs on the internal-transaction list |
