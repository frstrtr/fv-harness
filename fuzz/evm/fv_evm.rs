// fv_evm.rs — harness-owned in-process EVM for differential fuzzing of contracts (revm).
//
// An EVM fuzz target is a Rust fuzz target (fuzz/rust/fv_diff.rs drives the loop) whose
// `impl_step` runs the contract here. It includes both harness files:
//   #[macro_use] #[allow(dead_code)] mod fv_diff { include!(env!("FV_DIFF_RS")); }
//   #[allow(dead_code)] mod fv_evm { include!(env!("FV_EVM_RS")); }
// fuzz/run_fuzz.sh --lang evm compiles the contract with the pinned solc and embeds the result
// through build.rs: FV_EVM_CREATION (creation bytecode), FV_EVM_RUNTIME (the compiler's runtime
// bytecode) and FV_EVM_SPEC (the evmVersion it was compiled for).
//
// This file owns what a binding must not be able to weaken:
//   - deployment: the creation code runs once, CREATE from DEPLOYER; the code left at the new
//     address must equal the compiler's runtime bytecode byte for byte, else the process aborts
//     (so a run is tied to exactly the bytecode recorded in fuzz.json);
//   - calls: committed transactions with a fixed gas limit (GAS_LIMIT), in memory: no node, no
//     network, no fork, no keys;
//   - the outcome of each call: success, revert (with its data) or halt (out of gas, invalid
//     opcode, ...), with the return data and the logs. Gas is returned apart from the Outcome,
//     so it is never compared unless a binding compares it on purpose.
// What it does not decide: which storage slots and fields are compared, and what the oracle's
// state means as an outcome. That is the binding's, which is trusted and human-reviewed.

use revm::context::TxEnv;
use revm::context_interface::result::{ExecutionResult, Output};
use revm::database::{CacheDB, EmptyDB};
use revm::database_interface::DatabaseRef;
use revm::primitives::hardfork::SpecId;
use revm::primitives::{keccak256, Address, Bytes, U256};
use revm::state::AccountInfo;
use revm::{Context, ExecuteCommitEvm, MainBuilder, MainContext};
use std::cell::RefCell;

/// The compiler output embedded at build time (see the header).
pub const CREATION: &[u8] = include_bytes!(env!("FV_EVM_CREATION"));
pub const RUNTIME: &[u8] = include_bytes!(env!("FV_EVM_RUNTIME"));
pub const SPEC_NAME: &str = env!("FV_EVM_SPEC");

pub const DEPLOYER: Address = Address::new([0x10; 20]);
/// Default callers, each funded with 10^30 wei.
pub const CALLERS: [Address; 3] = [Address::new([0xA1; 20]), Address::new([0xA2; 20]), Address::new([0xA3; 20])];
pub const GAS_LIMIT: u64 = 30_000_000;

fn spec() -> SpecId {
    match SPEC_NAME {
        "london" => SpecId::LONDON,
        "paris" => SpecId::MERGE,
        "shanghai" => SpecId::SHANGHAI,
        "cancun" => SpecId::CANCUN,
        "prague" => SpecId::PRAGUE,
        "osaka" => SpecId::OSAKA,
        other => panic!("fv_evm: unsupported evmVersion {other:?} (london, paris, shanghai, cancun, prague, osaka)"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Success,
    Revert,
    /// Exceptional halt, all gas spent (out of gas, invalid opcode, stack errors, ...).
    Halt(String),
    /// The transaction was not valid at all (never expected from the harness's own calls).
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// What a call did, as compared by bindings: kind, return (or revert) data and logs. No gas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub kind: Kind,
    pub data: Vec<u8>,
    pub logs: Vec<Log>,
}

const ERROR_STRING: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0]; // Error(string)
const PANIC_UINT: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71]; // Panic(uint256)

impl Outcome {
    /// Success with no data and no logs (also the "nothing happened yet" value).
    pub fn none() -> Self {
        Outcome { kind: Kind::Success, data: Vec::new(), logs: Vec::new() }
    }
    /// The outcome class: "success", "revert Error(string)", "panic 0x11", "revert <custom error>",
    /// "revert 0x<selector>", "revert (no data)", "halt <reason>". `errors` names custom errors
    /// by signature, e.g. ["LimitExceeded()"].
    pub fn class(&self, errors: &[&str]) -> String {
        match &self.kind {
            Kind::Success => "success".into(),
            Kind::Halt(r) => format!("halt {r}"),
            Kind::Invalid(r) => format!("invalid transaction {r}"),
            Kind::Revert => {
                if self.data.len() < 4 {
                    return "revert (no data)".into();
                }
                let sel: [u8; 4] = self.data[..4].try_into().unwrap();
                if sel == ERROR_STRING {
                    return "revert Error(string)".into();
                }
                if sel == PANIC_UINT && self.data.len() >= 36 {
                    let code = U256::from_be_slice(&self.data[4..36]);
                    return format!("panic {code:#x}");
                }
                for e in errors {
                    if selector(e) == sel {
                        return format!("revert {e}");
                    }
                }
                format!("revert 0x{}", hex(&sel))
            }
        }
    }
    pub fn show(&self, errors: &[&str]) -> String {
        let mut s = format!("{} data=0x{}", self.class(errors), hex(&self.data));
        for l in &self.logs {
            s += &format!(" log[{} topic(s), {} B]", l.topics.len(), l.data.len());
        }
        s
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The 4-byte selector of a function or error signature, e.g. "submit(uint64)".
pub fn selector(sig: &str) -> [u8; 4] {
    keccak256(sig.as_bytes())[..4].try_into().unwrap()
}
/// topic0 of an event signature, e.g. "Accepted(uint64)".
pub fn event_topic(sig: &str) -> [u8; 32] {
    keccak256(sig.as_bytes()).0
}
/// One ABI word holding an unsigned integer.
pub fn word(v: u64) -> [u8; 32] {
    U256::from(v).to_be_bytes::<32>()
}
/// Calldata: the selector of `sig`, then static arguments as ABI words.
pub fn calldata(sig: &str, words: &[[u8; 32]]) -> Vec<u8> {
    let mut d = selector(sig).to_vec();
    for w in words {
        d.extend_from_slice(w);
    }
    d
}

type Db = CacheDB<EmptyDB>;
type Inner = revm::handler::MainnetEvm<revm::handler::MainnetContext<Db>>;

pub struct Evm {
    evm: Inner,
    /// The deployed contract.
    pub contract: Address,
}

fn tx(from: Address, to: Option<Address>, value: U256, data: &[u8]) -> TxEnv {
    let b = TxEnv::builder().caller(from).gas_limit(GAS_LIMIT).value(value).data(Bytes::copy_from_slice(data));
    match to {
        Some(a) => b.call(a),
        None => b.create(),
    }
    .build_fill()
}

fn outcome(r: ExecutionResult) -> (Outcome, u64) {
    let gas = r.tx_gas_used();
    let logs = r
        .logs()
        .iter()
        .map(|l| Log {
            address: l.address.0 .0,
            topics: l.data.topics().iter().map(|t| t.0).collect(),
            data: l.data.data.to_vec(),
        })
        .collect();
    let o = match r {
        ExecutionResult::Success { output, .. } => {
            let data = match output {
                Output::Call(b) => b.to_vec(),
                Output::Create(b, _) => b.to_vec(),
            };
            Outcome { kind: Kind::Success, data, logs }
        }
        ExecutionResult::Revert { output, .. } => Outcome { kind: Kind::Revert, data: output.to_vec(), logs },
        ExecutionResult::Halt { reason, .. } => Outcome { kind: Kind::Halt(format!("{reason:?}")), data: Vec::new(), logs },
    };
    (o, gas)
}

impl Evm {
    /// A fresh in-memory chain with the contract deployed from CREATION by DEPLOYER.
    pub fn new() -> Self {
        let mut db = Db::new(EmptyDB::new());
        let rich = AccountInfo::from_balance(U256::from(10u64).pow(U256::from(30u64)));
        db.insert_account_info(DEPLOYER, rich.clone());
        for c in CALLERS {
            db.insert_account_info(c, rich.clone());
        }
        let ctx = Context::mainnet().with_db(db).modify_cfg_chained(|c| {
            c.set_spec_and_mainnet_gas_params(spec());
            c.disable_nonce_check = true;
        });
        let mut evm = ctx.build_mainnet();
        let r = evm.transact_commit(tx(DEPLOYER, None, U256::ZERO, CREATION));
        let contract = match r {
            Ok(ExecutionResult::Success { output: Output::Create(_, Some(a)), .. }) => a,
            other => {
                eprintln!("fv_evm: deployment failed: {other:?}");
                std::process::abort();
            }
        };
        let e = Evm { evm, contract };
        let code = e.code(contract);
        if code != RUNTIME {
            eprintln!("fv_evm: the deployed code ({} B) differs from the compiler's runtime bytecode ({} B)", code.len(), RUNTIME.len());
            std::process::abort();
        }
        e
    }

    fn db(&self) -> &Db {
        &self.evm.ctx.journaled_state.database
    }
    fn db_mut(&mut self) -> &mut Db {
        &mut self.evm.ctx.journaled_state.database
    }

    /// The code at an address.
    pub fn code(&self, a: Address) -> Vec<u8> {
        let info = self.db().basic_ref(a).ok().flatten().unwrap_or_default();
        match info.code {
            Some(c) => c.original_bytes().to_vec(),
            None => self.db().code_by_hash_ref(info.code_hash).map(|c| c.original_bytes().to_vec()).unwrap_or_default(),
        }
    }
    /// One committed call; returns the outcome and the gas used (kept apart from the outcome).
    pub fn call(&mut self, from: Address, value: U256, data: &[u8]) -> (Outcome, u64) {
        let to = self.contract;
        match self.evm.transact_commit(tx(from, Some(to), value, data)) {
            Ok(r) => outcome(r),
            Err(e) => (Outcome { kind: Kind::Invalid(format!("{e:?}")), data: Vec::new(), logs: Vec::new() }, 0),
        }
    }
    pub fn sload(&self, slot: U256) -> U256 {
        self.db().storage_ref(self.contract, slot).unwrap_or_default()
    }
    pub fn sstore(&mut self, slot: U256, value: U256) {
        let c = self.contract;
        self.db_mut().insert_account_storage(c, slot, value).expect("fv_evm: storage write");
    }
}

thread_local! {
    static EVM: RefCell<Option<Evm>> = const { RefCell::new(None) };
}

/// The process's EVM, created (and the contract deployed) on first use. Bindings call this from
/// `warm_up` so the deployment happens inside the LeakSanitizer exemption of fv_diff::init.
pub fn with<R>(f: impl FnOnce(&mut Evm) -> R) -> R {
    EVM.with(|cell| {
        let mut b = cell.borrow_mut();
        f(b.get_or_insert_with(Evm::new))
    })
}
