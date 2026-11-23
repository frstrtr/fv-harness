// FvTronTvmDriver — harness-owned TRON-TVM reference executor for differential fuzzing (java-tron, offline).
//
// Runs contracts on java-tron's own TRON-TVM through the path its VM tests use (TvmTestUtils ->
// TransactionTrace: init, exec, finalization), with a node context whose store lives in a temporary
// directory. No network is used; fuzz/run_fuzz.sh --lang tron-tvm runs the process in a network
// namespace. It speaks one request per line on stdin and answers on stdout (hex without 0x;
// addresses are 21-byte TRON addresses, 41 + 20 bytes):
//   account A SUN                 create A with SUN of TRX                    -> ok
//   asset                         issue a new TRC-10 token                    -> asset ID
//   settoken A ID N | token A ID  set / read A's balance of token ID          -> ok | token N
//   exists A                      whether account A exists (reads never create one) -> exists 0|1
//   balance A                     A's TRX balance                             -> balance N
//   sstore C SLOT VAL | sload C SLOT   contract storage (32-byte words)       -> ok | value W
//   deploy A CODE VALUE TVALUE TID     create (creation code + constructor args) -> deploy C RUNTIME
//   call A C DATA VALUE TVALUE TID     one transaction                        -> result CODE RET ENERGY N,
//                                 then N lines: log ADDR20 TOPIC,TOPIC,... DATA, then one line
//                                 itxs M, then M lines (the VM's internal transactions, in order):
//                                 itx NOTE SENDER TO TRX_VALUE TOKENS REJECTED (TOKENS: id:amount,...
//                                 sorted by id, or "-"; REJECTED 0|1), then one line
//                                 pcs P,P,... (the contract code offsets executed in the called contract's
//                                 own frame, from java-tron's VM trace; "-" if none)
//   callr A C DATA VALUE TVALUE TID FEELIMIT  the same with the given fee limit (sun), then one line:
//                                 receipt result=R energy_usage_total=N energy_fee=N energy_usage=N
//                                 origin_energy_usage=N net_fee=N
//   config                        the node's settings that decide determinism -> config debug=B cpu_ms=N
//                                 energy_limit_hard_fork=B heap_max=N jvm_args=A,B,.. node_config_sha256=H
//   keccak HEX                    Keccak-256 of the bytes (selectors, topics)  -> keccak H
//   quit
// Errors: "invalid <message>" (java-tron's ContractValidateException: the node refused the transaction
// before the VM) or "error <message>" (any other failure: the executor's, never an outcome); any
// Throwable in the loop (an OutOfMemoryError from the VM trace included) is reported as "error ...",
// and the process exits after an Error. Reads (token, balance) never create an account. Every
// transaction carries a fresh nonce (raw_data.data), so identical requests get distinct ids.
// It decides nothing: the binding compares; this file only executes and reports.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.application.TronApplicationContext;
import org.tron.common.runtime.ProgramResult;
import org.tron.common.runtime.Runtime;
import org.tron.common.runtime.TvmTestUtils;
import org.tron.common.runtime.vm.DataWord;
import org.tron.common.runtime.vm.LogInfo;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.WalletUtil;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.AssetIssueCapsule;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.core.db.Manager;
import org.tron.core.store.DynamicPropertiesStore;
import org.tron.core.store.StoreFactory;
import org.tron.core.vm.repository.Repository;
import org.tron.core.vm.repository.RepositoryImpl;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.contract.AssetIssueContractOuterClass.AssetIssueContract;

public final class FvTronTvmDriver {
  private static final long FEE_LIMIT = 1_000_000_000L;
  private static Manager m;
  private static final byte[] ISSUER = Hex.decode("41" + "1000000000000000000000000000000000000001");
  private static long nonce = 0;

  /** The transaction with a fresh nonce in raw_data.data: identical requests get distinct ids. */
  private static Transaction withNonce(Transaction trx) {
    nonce++;
    return trx.toBuilder().setRawData(trx.getRawData().toBuilder()
        .setData(com.google.protobuf.ByteString.copyFromUtf8("fv-nonce-" + nonce))).build();
  }

  private static String resourceSha(String name) {
    try (java.io.InputStream in = FvTronTvmDriver.class.getClassLoader().getResourceAsStream(name)) {
      if (in == null) {
        return "absent";
      }
      java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
      byte[] buf = new byte[8192];
      for (int n; (n = in.read(buf)) > 0; ) {
        md.update(buf, 0, n);
      }
      return Hex.toHexString(md.digest());
    } catch (Exception e) {
      return "unreadable";
    }
  }

  public static void main(String[] argv) throws Exception {
    // argv[0]: a fresh directory for the node's store; argv[1]: the chain-parameter profile (JSON, the
    // target network's wallet/getchainparameters output); argv[2]: the java-tron test config name.
    // --debug switches off the per-transaction CPU-time limit, as java-tron's own VM tests do: with it
    // on, a slow (e.g. first, not yet compiled) execution fails as OUT_OF_TIME, so results would
    // depend on timing. Everything else is the node's normal TRON-TVM.
    Args.setParam(new String[]{"--output-directory", argv[0], "--debug"},
        argv.length > 2 ? argv[2] : "config-test.conf");
    // The energy-limit hard fork (java-tron: ReceiptCapsule.checkForEnergyLimit, latest block number >=
    // blockNumForEnergyLimit, 4727890 by default) is active on mainnet. A fresh node has no blocks, so
    // without this the fork would be off: storage of nested calls would not be deep-copied
    // (RepositoryImpl.getStorage), unlike mainnet.
    org.tron.common.parameter.CommonParameter.getInstance().blockNumForEnergyLimit = 0L;
    TronApplicationContext ctx = new TronApplicationContext(DefaultConfig.class);
    m = ctx.getBean(Manager.class);
    // Real stdout carries the protocol only; the node's own logging goes to stderr.
    PrintStream out = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true, "UTF-8");
    System.setOut(System.err);
    // Contract coverage: java-tron's own VM trace (every executed op with its pc and call depth),
    // written per transaction to ./vm_trace/<txid>.json; the driver reads and removes it.
    // (ConfigLoader copies the node parameter into VMConfig for every transaction, so set the parameter.)
    org.tron.common.parameter.CommonParameter.getInstance().vmTrace = true;
    String applied;
    try {
      applied = applyProfile(argv.length > 1 ? argv[1] : null, ctx);
    } catch (Throwable e) {
      out.println("error " + oneLine(e));  // the node's threads would keep the JVM alive: exit
      ctx.close();
      System.exit(2);
      return;
    }
    account(ISSUER, 0L);
    BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    out.println("ready java-tron TRON-TVM profile " + applied);
    String line;
    // End of input (the fuzzer exited or died) ends the process.
    while ((line = in.readLine()) != null) {
      String[] t = line.trim().split(" ");
      if (t.length == 0 || t[0].isEmpty()) {
        continue;
      }
      try {
        switch (t[0]) {
          case "quit": out.println("bye"); ctx.close(); System.exit(0); break;
          case "account": account(h(t[1]), Long.parseLong(t[2])); out.println("ok"); break;
          case "asset": out.println("asset " + asset()); break;
          case "config": out.println("config debug=" + org.tron.common.parameter.CommonParameter.getInstance().isDebug()
              + " cpu_ms=" + m.getDynamicPropertiesStore().getMaxCpuTimeOfOneTx()
              + " energy_limit_hard_fork=" + org.tron.core.capsule.ReceiptCapsule.checkForEnergyLimit(m.getDynamicPropertiesStore())
              + " heap_max=" + java.lang.Runtime.getRuntime().maxMemory()
              + " jvm_args=" + String.join(",", java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments())
              + " node_config_sha256=" + resourceSha("config-test.conf")); break;
          case "keccak": out.println("keccak " + Hex.toHexString(org.tron.common.crypto.Hash.sha3(h(t[1])))); break;
          case "settoken": setToken(h(t[1]), t[2], Long.parseLong(t[3])); out.println("ok"); break;
          case "exists": out.println("exists " + (m.getAccountStore().has(h(t[1])) ? 1 : 0)); break;
          case "token": { AccountCapsule c = m.getAccountStore().get(h(t[1])); out.println("token " + (c == null ? 0 : c.getAssetV2(t[2]))); break; }
          case "balance": { AccountCapsule c = m.getAccountStore().get(h(t[1])); out.println("balance " + (c == null ? 0 : c.getBalance())); break; }
          case "sstore": {
            Repository r = RepositoryImpl.createRoot(StoreFactory.getInstance());
            r.putStorageValue(h(t[1]), new DataWord(h(t[2])), new DataWord(h(t[3])));
            r.commit();
            out.println("ok");
            break;
          }
          case "sload": {
            Repository r = RepositoryImpl.createRoot(StoreFactory.getInstance());
            DataWord v = r.getStorageValue(h(t[1]), new DataWord(h(t[2])));
            out.println("value " + Hex.toHexString(v == null ? new byte[32] : v.getData()));
            break;
          }
          case "deploy": out.println(deploy(h(t[1]), t[2], Long.parseLong(t[3]), Long.parseLong(t[4]),
              Long.parseLong(t[5]))); break;
          case "call": call(out, h(t[1]), h(t[2]), h(t[3]), Long.parseLong(t[4]), Long.parseLong(t[5]),
              Long.parseLong(t[6]), FEE_LIMIT, false); break;
          case "callr": call(out, h(t[1]), h(t[2]), h(t[3]), Long.parseLong(t[4]), Long.parseLong(t[5]),
              Long.parseLong(t[6]), Long.parseLong(t[7]), true); break;
          default: out.println("error unknown request " + t[0]);
        }
      } catch (Throwable e) {
        out.println("error " + oneLine(e));
        e.printStackTrace();  // stderr: the driver log
        if (e instanceof Error) {  // OutOfMemoryError, StackOverflowError, ...: the JVM is not to be trusted now
          System.exit(3);
        }
      }
    }
    ctx.close();
    System.exit(0);
  }

  // API key -> DynamicPropertiesStore setter where the names differ (java-tron Wallet.getChainParameters
  // reports these keys from those stores: getAllowOptimizeBlackHole from getAllowBlackHoleOptimization,
  // the two asset-optimisation keys from getAllowAccountAssetOptimization / getAllowAssetOptimization,
  // whose setters are named set...).
  private static final java.util.Map<String, String> ALIAS = new java.util.HashMap<>();
  // allow* / *Energy* setters a profile does not set, with the reason; every other one must be set.
  private static final java.util.Map<String, String> NOT_PARAMETERS = new java.util.LinkedHashMap<>();

  static {
    ALIAS.put("getAllowOptimizeBlackHole", "saveAllowBlackHoleOptimization");
    ALIAS.put("getAllowAccountAssetOptimization", "setAllowAccountAssetOptimization");
    ALIAS.put("getAllowAssetOptimization", "setAllowAssetOptimization");
    NOT_PARAMETERS.put("saveAllowShieldedTransaction", "not reported by getchainparameters (commented out in Wallet)");
    NOT_PARAMETERS.put("saveBlockEnergyUsage", "chain state: energy used in the current block");
    NOT_PARAMETERS.put("saveEnergyPriceHistoryDone", "node bookkeeping flag");
    NOT_PARAMETERS.put("saveTotalEnergyAverageTime", "chain state: energy averaging window position");
    NOT_PARAMETERS.put("saveTotalEnergyLimit2", "legacy setter of TotalEnergyLimit, which the profile sets");
    NOT_PARAMETERS.put("saveTotalEnergyWeight", "chain state: total energy staked");
  }

  // Keys this java-tron's Wallet.getChainParameters reports whose value after applying the profile may
  // legitimately differ from the profile's, with the reason. Empty: every reported key must round-trip.
  private static final java.util.Map<String, String> ROUNDTRIP_EXEMPT = new java.util.LinkedHashMap<>();

  // API key -> java-tron ProposalType name where the upper-snake form of the key differs.
  private static final java.util.Map<String, String> PROPOSAL_ALIAS = new java.util.HashMap<>();

  static {
    PROPOSAL_ALIAS.put("getChangeDelegation", "ALLOW_CHANGE_DELEGATION");
    PROPOSAL_ALIAS.put("getAllowOptimizeBlackHole", "ALLOW_BLACKHOLE_OPTIMIZATION");
  }

  /**
   * Applies every chain parameter of the profile, {"key": "get<Name>", "value": N}, in the profile's
   * order; an entry without a value is 0 (the API omits zeros). A key that names a java-tron proposal
   * (ProposalUtil.ProposalType, by the upper-snake form of its name) is applied through java-tron's own
   * ProposalService.process, one proposal per key, so the proposal's side effects happen as on the
   * network (e.g. ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO stores 24 * 60 x the reported value and derives
   * the energy target limit; ALLOW_TVM_PRAGUE deploys the TIP-2935 history storage contract); any other
   * key through its DynamicPropertiesStore setter. Refuses (a) a key this java-tron cannot apply,
   * (b) any allow* or *Energy* setter the profile leaves unset, except NOT_PARAMETERS, and (c) any
   * parameter this java-tron's own Wallet.getChainParameters reports (every one: allow*, energy, and
   * the others such as getUnfreezeDelayDays, getMaxFeeLimit, getForbidTransferToContract) whose value,
   * read back after applying, differs from the profile's or that the profile does not carry, except
   * ROUNDTRIP_EXEMPT.
   */
  private static String applyProfile(String path, TronApplicationContext ctx) throws Exception {
    if (path == null) {
      throw new IllegalArgumentException("no chain-parameter profile given");
    }
    String text = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path)), StandardCharsets.UTF_8);
    com.google.gson.JsonArray ps = new com.google.gson.JsonParser().parse(text).getAsJsonObject()
        .getAsJsonArray("chainParameter");
    DynamicPropertiesStore d = m.getDynamicPropertiesStore();
    java.util.Map<String, Long> codes = new java.util.HashMap<>();
    for (org.tron.core.utils.ProposalUtil.ProposalType t : org.tron.core.utils.ProposalUtil.ProposalType.values()) {
      codes.put(t.name(), t.getCode());
    }
    java.util.List<String> unknown = new java.util.ArrayList<>();
    java.util.Set<String> applied = new java.util.HashSet<>();
    int viaProposal = 0;
    for (com.google.gson.JsonElement e : ps) {
      com.google.gson.JsonObject o = e.getAsJsonObject();
      String key = o.get("key").getAsString();
      long v = o.has("value") ? o.get("value").getAsLong() : 0L;
      String pname = PROPOSAL_ALIAS.containsKey(key) ? PROPOSAL_ALIAS.get(key)
          : key.startsWith("get") ? key.substring(3).replaceAll("([a-z0-9])([A-Z])", "$1_$2").toUpperCase() : null;
      String setter = ALIAS.containsKey(key) ? ALIAS.get(key) : key.startsWith("get") ? "save" + key.substring(3) : null;
      if (pname != null && codes.containsKey(pname)) {
        org.tron.core.capsule.ProposalCapsule pc = new org.tron.core.capsule.ProposalCapsule(
            com.google.protobuf.ByteString.EMPTY, 0L);
        java.util.Map<Long, Long> one = new java.util.HashMap<>();
        one.put(codes.get(pname), v);
        pc.setParameters(one);
        if (!org.tron.core.consensus.ProposalService.process(m, pc)) {
          unknown.add(key + " (proposal " + pname + " not processed)");
          continue;
        }
        viaProposal++;
        if (setter != null) {
          applied.add(setter.startsWith("set") ? "save" + setter.substring(3) : setter);
        }
        continue;
      }
      try {
        if (setter == null) {
          throw new NoSuchMethodException(key);
        }
        DynamicPropertiesStore.class.getMethod(setter, long.class).invoke(d, v);
        applied.add(setter.startsWith("set") ? "save" + setter.substring(3) : setter);
      } catch (NoSuchMethodException ex) {
        unknown.add(key);
      }
    }
    java.util.List<String> unset = new java.util.ArrayList<>();
    for (java.lang.reflect.Method mt : DynamicPropertiesStore.class.getMethods()) {
      String n = mt.getName();
      boolean relevant = n.startsWith("saveAllow") || (n.startsWith("save") && n.contains("Energy"));
      if (relevant && mt.getParameterCount() == 1 && mt.getParameterTypes()[0] == long.class
          && !applied.contains(n) && !NOT_PARAMETERS.containsKey(n) && !unset.contains(n)) {
        unset.add(n);
      }
    }
    if (!unknown.isEmpty() || !unset.isEmpty()) {
      throw new IllegalArgumentException("chain-parameter profile not applicable to this java-tron: keys it cannot "
          + "apply " + unknown + "; parameters the profile leaves unset " + unset);
    }
    java.util.Map<String, Long> want = new java.util.HashMap<>();
    for (com.google.gson.JsonElement e : ps) {
      com.google.gson.JsonObject o = e.getAsJsonObject();
      want.put(o.get("key").getAsString(), o.has("value") ? o.get("value").getAsLong() : 0L);
    }
    java.util.List<String> differ = new java.util.ArrayList<>();
    int checked = 0;
    for (org.tron.protos.Protocol.ChainParameters.ChainParameter cp
        : ctx.getBean(org.tron.core.Wallet.class).getChainParameters().getChainParameterList()) {
      String k = cp.getKey();
      if (ROUNDTRIP_EXEMPT.containsKey(k)) {
        continue;
      }
      checked++;
      if (!want.containsKey(k)) {
        differ.add(k + " (reported by this java-tron, absent from the profile)");
      } else if (want.get(k) != cp.getValue()) {
        differ.add(k + " = " + cp.getValue() + ", profile " + want.get(k));
      }
    }
    if (!differ.isEmpty()) {
      throw new IllegalArgumentException("chain-parameter profile does not round-trip through this java-tron's "
          + "getChainParameters: " + differ);
    }
    byte[] sha = java.security.MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(
        java.nio.file.Paths.get(path)));
    return applied.size() + " parameters (" + viaProposal + " through ProposalService), " + checked
        + " read back equal, sha256 " + Hex.toHexString(sha);
  }

  /**
   * The pcs the called contract's code executed, read from java-tron's VM trace: every op of the top
   * frame (depth 0), plus the ops of each deeper run of consecutive ops (one depth) whose opcodes all
   * equal the called contract's code at their pcs (the same code entered again: this.f(), re-entrancy).
   * A deeper run whose opcodes differ is another contract's and is not counted.
   */
  private static String framePcs(String txid, byte[] code) {
    java.io.File f = new java.io.File(new java.io.File(System.getProperty("user.dir"), "vm_trace"), txid + ".json");
    if (!f.isFile()) {
      return "-";
    }
    java.util.TreeSet<Integer> pcs = new java.util.TreeSet<>();
    try {
      String text = new String(java.nio.file.Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
      com.google.gson.JsonArray ops = new com.google.gson.JsonParser().parse(text).getAsJsonObject().getAsJsonArray("ops");
      if (ops != null) {
        java.util.List<int[]> run = new java.util.ArrayList<>();  // {pc, opcode} of the current deeper run
        int runDeep = -1;
        for (com.google.gson.JsonElement e : ops) {
          com.google.gson.JsonObject o = e.getAsJsonObject();
          if (!o.has("deep") || !o.has("pc")) {
            continue;
          }
          int deep = o.get("deep").getAsInt(), pc = o.get("pc").getAsInt();
          int op = o.has("code") ? o.get("code").getAsInt() & 0xff : -1;
          if (deep != runDeep) {
            addRun(run, code, pcs);
            run.clear();
            runDeep = deep;
          }
          if (deep == 0) {
            pcs.add(pc);
          } else {
            run.add(new int[]{pc, op});
          }
        }
        addRun(run, code, pcs);
      }
    } catch (Exception e) {
      return "-";
    } finally {
      f.delete();
    }
    StringBuilder b = new StringBuilder();
    for (int pc : pcs) {
      b.append(b.length() == 0 ? "" : ",").append(pc);
    }
    return b.length() == 0 ? "-" : b.toString();
  }

  private static void addRun(java.util.List<int[]> run, byte[] code, java.util.Set<Integer> pcs) {
    if (run.isEmpty() || code == null) {
      return;
    }
    for (int[] r : run) {
      if (r[0] >= code.length || (code[r[0]] & 0xff) != r[1]) {
        return;
      }
    }
    for (int[] r : run) {
      pcs.add(r[0]);
    }
  }

  private static byte[] h(String s) {
    return s.equals("-") ? new byte[0] : Hex.decode(s);
  }

  private static String oneLine(Throwable e) {
    String s = e.getClass().getSimpleName() + ": " + e.getMessage();
    return s.replace('\n', ' ').replace('\r', ' ');
  }

  private static AccountCapsule acct(byte[] a) {
    AccountCapsule c = m.getAccountStore().get(a);
    if (c == null) {
      account(a, 0L);
      c = m.getAccountStore().get(a);
    }
    return c;
  }

  private static void account(byte[] a, long sun) {
    Repository r = RepositoryImpl.createRoot(StoreFactory.getInstance());
    if (r.getAccount(a) == null) {
      r.createAccount(a, AccountType.Normal);
    }
    r.commit();
    AccountCapsule c = m.getAccountStore().get(a);
    c.setBalance(sun);
    m.getAccountStore().put(a, c);
  }

  private static long asset() {
    DynamicPropertiesStore d = m.getDynamicPropertiesStore();
    long id = d.getTokenIdNum() + 1;
    d.saveTokenIdNum(id);
    AssetIssueContract c = AssetIssueContract.newBuilder()
        .setOwnerAddress(com.google.protobuf.ByteString.copyFrom(ISSUER))
        .setName(com.google.protobuf.ByteString.copyFrom(ByteArray.fromString("fvtoken" + id)))
        .setId(Long.toString(id)).setTotalSupply(Long.MAX_VALUE).setTrxNum(1).setNum(1)
        .setStartTime(1).setEndTime(2).build();
    AssetIssueCapsule cap = new AssetIssueCapsule(c);
    m.getAssetIssueV2Store().put(cap.createDbV2Key(), cap);
    return id;
  }

  private static void setToken(byte[] a, String id, long n) {
    AccountCapsule c = acct(a);
    long cur = c.getAssetV2(id);
    byte[] k = ByteArray.fromString(id);
    if (n > cur) {
      c.addAssetAmountV2(k, n - cur, m.getDynamicPropertiesStore(), m.getAssetIssueStore());
    } else if (n < cur) {
      c.reduceAssetAmountV2(k, cur - n, m.getDynamicPropertiesStore(), m.getAssetIssueStore());
    }
    m.getAccountStore().put(a, c);
  }

  private static String deploy(byte[] creator, String code, long value, long tokenValue, long tokenId)
      throws Exception {
    Transaction trx = withNonce(TvmTestUtils.generateDeploySmartContractAndGetTransaction("fv", creator, "[]", code,
        value, FEE_LIMIT, 100, null, FEE_LIMIT, tokenValue, tokenId));
    Runtime rt = run(trx).getRuntime();
    ProgramResult r = rt.getResult();
    if (rt.getRuntimeError() != null || r.isRevert() || r.getException() != null) {
      return "error deploy failed: " + rt.getRuntimeError();
    }
    byte[] addr = WalletUtil.generateContractAddress(trx);
    byte[] runtime = RepositoryImpl.createRoot(StoreFactory.getInstance()).getCode(addr);
    return "deploy " + Hex.toHexString(addr) + " " + (runtime == null ? "-" : Hex.toHexString(runtime));
  }

  /**
   * One transaction through java-tron's TransactionTrace (init, exec, finalization) without a block, as
   * its VM tests do, but with the trace attached to the transaction as Manager.processTransaction does:
   * the VM then records the caller's energy in the receipt and takes the post-fork energy-limit path.
   */
  private static org.tron.core.db.TransactionTrace run(Transaction trx) throws Exception {
    org.tron.core.capsule.TransactionCapsule cap = new org.tron.core.capsule.TransactionCapsule(trx);
    org.tron.core.db.TransactionTrace trace = new org.tron.core.db.TransactionTrace(cap, StoreFactory.getInstance(),
        new org.tron.common.runtime.RuntimeImpl());
    cap.setTrxTrace(trace);
    trace.init(null);
    trace.exec();
    trace.finalization();
    return trace;
  }

  private static void call(PrintStream out, byte[] caller, byte[] contract, byte[] data, long value,
      long tokenValue, long tokenId, long feeLimit, boolean receipt) {
    Runtime rt;
    org.tron.core.capsule.ReceiptCapsule rc;
    String txid;
    try {
      Transaction trx = withNonce(TvmTestUtils.generateTriggerSmartContractAndGetTransaction(caller, contract, data,
          value, feeLimit, tokenValue, tokenId));
      org.tron.core.db.TransactionTrace trace = run(trx);
      rt = trace.getRuntime();
      rc = trace.getReceipt();
      txid = new org.tron.core.capsule.TransactionCapsule(trx).getTransactionId().toString();
    } catch (org.tron.core.exception.ContractValidateException e) {
      out.println("invalid " + oneLine(e));  // the node refused the transaction before the VM
      return;
    } catch (Exception e) {
      out.println("error " + oneLine(e));    // anything else is the executor's failure, not an outcome
      e.printStackTrace();
      return;
    }
    ProgramResult r = rt.getResult();
    byte[] ret = r.getHReturn();
    List<LogInfo> logs = r.getLogInfoList();
    String code = r.getResultCode() == null ? "UNKNOWN" : r.getResultCode().name();
    out.println("result " + code + " " + (ret == null || ret.length == 0 ? "-" : Hex.toHexString(ret)) + " "
        + r.getEnergyUsed() + " " + logs.size());
    for (LogInfo l : logs) {
      StringBuilder ts = new StringBuilder();
      for (DataWord w : l.getTopics()) {
        ts.append(ts.length() == 0 ? "" : ",").append(Hex.toHexString(w.getData()));
      }
      out.println("log " + Hex.toHexString(l.getAddress()) + " " + (ts.length() == 0 ? "-" : ts) + " "
          + (l.getData() == null || l.getData().length == 0 ? "-" : Hex.toHexString(l.getData())));
    }
    List<org.tron.common.runtime.InternalTransaction> itxs = r.getInternalTransactions();
    out.println("itxs " + itxs.size());
    for (org.tron.common.runtime.InternalTransaction it : itxs) {
      StringBuilder tk = new StringBuilder();
      for (java.util.Map.Entry<String, Long> e : new java.util.TreeMap<>(it.getTokenInfo()).entrySet()) {
        tk.append(tk.length() == 0 ? "" : ",").append(e.getKey()).append(':').append(e.getValue());
      }
      byte[] to = it.getTransferToAddress();
      out.println("itx " + (it.getNote() == null || it.getNote().isEmpty() ? "-" : it.getNote()) + " "
          + Hex.toHexString(it.getSender()) + " " + (to == null || to.length == 0 ? "-" : Hex.toHexString(to)) + " "
          + it.getValue() + " " + (tk.length() == 0 ? "-" : tk) + " " + (it.isRejected() ? 1 : 0));
    }
    out.println("pcs " + framePcs(txid, RepositoryImpl.createRoot(StoreFactory.getInstance()).getCode(contract)));
    if (receipt) {
      out.println("receipt result=" + rc.getResult() + " energy_usage_total=" + rc.getEnergyUsageTotal()
          + " energy_fee=" + rc.getEnergyFee() + " energy_usage=" + rc.getEnergyUsage()
          + " origin_energy_usage=" + rc.getOriginEnergyUsage() + " net_fee=" + rc.getNetFee());
    }
  }
}
