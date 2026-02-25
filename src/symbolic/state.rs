use alloy::primitives::{keccak256, Address, U256};
use std::collections::{HashMap, HashSet};
use z3::ast::{Array, Ast, Bool, BV};
use z3::{Context, Solver};

use reqwest::Client as HttpClient;

use crate::strategies::storage::{AlgebraicStorage, StorageStrategy};
use crate::symbolic::patterns::{PatternInference, SHA3Trace, StoragePattern};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleType {
    UniV2Reserves,
    ERC4626TotalAssets,
    ChainlinkFeed,
}

pub const MAX_JOURNAL_ENTRIES: usize = 100;

#[derive(Debug, Clone)]
pub struct CallFrame<'ctx> {
    pub stack: SymbolicStack<'ctx>,
    pub memory: Array<'ctx>,
    pub calldata: (Array<'ctx>, BV<'ctx>),
    pub pc: usize,
    pub address: Address,
    pub max_memory_offset: BV<'ctx>,
}

pub const MAX_JOURNAL_DEPTH: usize = 128;
const REENTRANCY_BRANCH_BASE: usize = usize::MAX / 2;

#[derive(Debug, Clone)]
pub struct SymbolicStack<'ctx> {
    pub ctx: &'ctx Context,
    pub stack: Vec<BV<'ctx>>,
    pub underflowed: bool,
}

impl<'ctx> SymbolicStack<'ctx> {
    pub fn new(ctx: &'ctx Context) -> Self {
        Self {
            ctx,
            stack: Vec::new(),
            underflowed: false,
        }
    }
    pub fn push(&mut self, val: BV<'ctx>) {
        self.stack.push(val);
    }
    pub fn pop(&mut self) -> BV<'ctx> {
        match self.stack.pop() {
            Some(v) => v,
            None => {
                // Stack underflow is a semantic EVM error. We mark the stack so the engine can
                // fail-closed the current path (InstructionResult::StackUnderflow).
                self.underflowed = true;
                BV::from_u64(self.ctx, 0, 256)
            }
        }
    }
    pub fn peek(&mut self, offset: usize) -> BV<'ctx> {
        if self.stack.len() <= offset {
            self.underflowed = true;
            return BV::from_u64(self.ctx, 0, 256);
        }
        self.stack[self.stack.len() - 1 - offset].clone()
    }
    pub fn len(&self) -> usize {
        self.stack.len()
    }
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    pub fn take_underflowed(&mut self) -> bool {
        let was = self.underflowed;
        self.underflowed = false;
        was
    }
}

#[derive(Debug, Clone)]
pub struct OracleDep {
    pub source: Address,
    pub target: Address,
    pub slot: U256,
    pub kind: OracleType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookCall {
    pub target: Address,
    pub selector: u32,
    pub call_site_pc: usize,
    pub is_static: bool,
    pub storage_log_len_at_call: usize,
}

#[derive(Debug, Clone)]
pub struct TokenTransferEvent<'ctx> {
    pub token: Address,
    pub from: Address,
    pub to: Address,
    pub requested_amount: BV<'ctx>,
    pub received_amount: BV<'ctx>,
    pub via_transfer_from: bool,
}

#[derive(Debug, Clone)]
pub struct Erc4626VaultState<'ctx> {
    pub initial_assets: BV<'ctx>,
    pub initial_supply: BV<'ctx>,
    pub current_assets: BV<'ctx>,
    pub current_supply: BV<'ctx>,
    pub touched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Create2InitAudit {
    pub declared_len: usize,
    pub analyzed_len: usize,
    pub has_delegatecall: bool,
    pub has_selfdestruct: bool,
    pub has_nested_create2: bool,
    pub has_callcode: bool,
}

impl Create2InitAudit {
    pub fn suspicious(&self) -> bool {
        self.has_delegatecall
            || self.has_selfdestruct
            || self.has_nested_create2
            || self.has_callcode
    }
}

#[derive(Debug, Clone)]
pub struct Create2Deployment<'ctx> {
    pub deployer: Address,
    pub salt: BV<'ctx>,
    pub init_code_hash: BV<'ctx>,
    pub predicted_address: BV<'ctx>,
    pub audit: Create2InitAudit,
}

#[derive(Debug, Clone)]
pub struct PendingKeccakChain<'ctx> {
    pub parent_hash: BV<'ctx>,
    pub child_hash: BV<'ctx>,
    pub parent_index: usize,
    pub arity: usize,
    pub expanded: bool,
}

pub struct SymbolicMachine<'ctx> {
    pub context: &'ctx Context,
    pub solver: &'ctx Solver<'ctx>,
    pub sym_stack: SymbolicStack<'ctx>,
    pub storage_log: Vec<(BV<'ctx>, BV<'ctx>)>,

    pub memory: Array<'ctx>,
    pub storage: HashMap<Address, Array<'ctx>>,
    pub storage_undo_log: Vec<(Address, Option<Array<'ctx>>)>,

    pub keccak: crate::symbolic::z3_ext::KeccakTheory<'ctx>,
    pub calldata: (Array<'ctx>, BV<'ctx>),
    pub sha3_map: Vec<(Vec<BV<'ctx>>, BV<'ctx>)>,
    pub frames: Vec<CallFrame<'ctx>>,
    pub call_value: Option<BV<'ctx>>,
    pub balance_overrides: HashMap<Address, BV<'ctx>>,
    pub token_balances: HashMap<(Address, Address), BV<'ctx>>,
    pub fork_url: Option<String>,
    pub branch_pushes: usize,
    pub last_opcode: u8,
    pub tx_id: usize,
    /// Optional schedule for top-level transaction senders.
    /// When set, `tx_id` selects the active sender (cyclic) to enable multi-sender traces.
    pub tx_sender_schedule: Vec<Address>,
    pub pending_calls: Vec<(BV<'ctx>, BV<'ctx>)>,
    pub last_return_data: (Array<'ctx>, BV<'ctx>),
    pub current_return_data: (Array<'ctx>, BV<'ctx>),
    pub journal: Vec<Vec<(U256, Option<BV<'ctx>>)>>,
    pub reverted: bool,
    pub http_client: HttpClient,
    pub unexplored_branches: Vec<(usize, bool)>,
    pub path_constraints: HashMap<usize, bool>,
    pub has_called_attacker: bool,
    pub reentrancy_detected: bool,
    pub self_destructed: bool,
    pub destroyed_contracts: HashSet<Address>,
    pub ext_code_hash_overrides: HashMap<Address, BV<'ctx>>,
    pub created_contracts: Vec<BV<'ctx>>,
    pub create2_deployments: Vec<Create2Deployment<'ctx>>,

    pub max_memory_offset: BV<'ctx>,
    pub call_path: Vec<Address>,
    pub reentrancy_lock: HashMap<Address, bool>,

    pub visited_pcs: HashMap<usize, usize>,
    pub visited_pcs_undo_log: Vec<(usize, Option<usize>)>,
    pub max_loop_iterations: usize,

    pub gas_remaining: BV<'ctx>,
    pub solver_depth: u32,
    pub next_call_args: Option<(BV<'ctx>, BV<'ctx>)>,
    pub next_call_target: Option<(Address, bool)>, // (target_addr, is_static) for reentrancy detection in Inspector::call
    pub next_call_site_pc: Option<usize>,
    pub call_handled: bool, // Protocol model already handled this call — Inspector::call should short-circuit
    pub delegatecall_depth: usize,
    pub delegatecall_storage_clash_detected: bool,
    pub value_transfer_call_count: usize,
    pub cumulative_call_value_out: BV<'ctx>,
    pub msg_value_loop_guard_triggered: bool,
    pub reentrancy_branch_seq: usize,
    pub active_reentrancy_branch_key: Option<usize>,
    pub reentrancy_invariant_touch: bool,

    pub oracle: crate::symbolic::oracle::KeccakOracle<'ctx>,
    pub pending_keccak_chains: Vec<PendingKeccakChain<'ctx>>,

    // Keccak functions now in self.keccak
    pub read_cache: HashMap<BV<'ctx>, BV<'ctx>>,
    pub oracle_deps: Vec<OracleDep>,
    pub fee_on_transfer_mode: bool,
    pub token_transfer_events: Vec<TokenTransferEvent<'ctx>>,
    pub uniswap_v4_hook_calls: Vec<HookCall>,
    pub erc4626_vaults: HashMap<Address, Erc4626VaultState<'ctx>>,
    pub manipulated_reserves: HashMap<Address, (BV<'ctx>, BV<'ctx>)>,
    pub max_visited_pcs: usize,

    // Pattern Recognition
    pub sha3_trace: Vec<SHA3Trace<'ctx>>,
    pub detected_patterns: HashMap<U256, StoragePattern>,
    pub max_solver_depth: usize,
    pub max_branches: usize,
    pub total_branches: usize,

    pub storage_strategy: Option<Box<dyn StorageStrategy<'ctx> + 'ctx>>,

    /// Dead-end PCs identified by static bytecode analysis.
    /// Branches that land on these PCs are killed immediately in step().
    pub dead_end_pcs: HashSet<usize>,
}

macro_rules! symbolic_snapshot_schema {
    (
        $(
            $field:ident : $ty:ty => {
                capture: |$capture_machine:ident| $capture:expr,
                restore: |$restore_machine:ident, $restore_snap:ident| $restore:block
            }
        ),+ $(,)?
    ) => {
        #[derive(Debug, Clone)]
        pub struct Snapshot<'ctx> {
            $(
                pub $field: $ty,
            )+
        }

        impl<'ctx> SymbolicMachine<'ctx> {
            pub fn snapshot(&self) -> Snapshot<'ctx> {
                Self::assert_snapshot_field_coverage(self);
                Snapshot {
                    $(
                        $field: {
                            let $capture_machine = self;
                            $capture
                        },
                    )+
                }
            }

            pub fn restore(&mut self, snap: &Snapshot<'ctx>) {
                $(
                    {
                        let $restore_machine = &mut *self;
                        let $restore_snap = snap;
                        $restore
                    }
                )+
            }

            fn assert_snapshot_field_coverage(machine: &SymbolicMachine<'ctx>) {
                let &SymbolicMachine {
                    context: _,
                    solver: _,
                    sym_stack: _,
                    storage_log: _,
                    memory: _,
                    storage: _,
                    storage_undo_log: _,
                    keccak: _,
                    calldata: _,
                    sha3_map: _,
                    frames: _,
                    call_value: _,
                    balance_overrides: _,
                    token_balances: _,
                    fork_url: _,
                    branch_pushes: _,
                    last_opcode: _,
                    tx_id: _,
                    tx_sender_schedule: _,
                    pending_calls: _,
                    last_return_data: _,
                    current_return_data: _,
                    journal: _,
                    reverted: _,
                    http_client: _,
                    unexplored_branches: _,
                    path_constraints: _,
                    has_called_attacker: _,
                    reentrancy_detected: _,
                    self_destructed: _,
                    destroyed_contracts: _,
                    ext_code_hash_overrides: _,
                    created_contracts: _,
                    create2_deployments: _,
                    max_memory_offset: _,
                    call_path: _,
                    reentrancy_lock: _,
                    visited_pcs: _,
                    visited_pcs_undo_log: _,
                    max_loop_iterations: _,
                    gas_remaining: _,
                    solver_depth: _,
                    next_call_args: _,
                    next_call_target: _,
                    next_call_site_pc: _,
                    call_handled: _,
                    delegatecall_depth: _,
                    delegatecall_storage_clash_detected: _,
                    value_transfer_call_count: _,
                    cumulative_call_value_out: _,
                    msg_value_loop_guard_triggered: _,
                    reentrancy_branch_seq: _,
                    active_reentrancy_branch_key: _,
                    reentrancy_invariant_touch: _,
                    oracle: _,
                    pending_keccak_chains: _,
                    read_cache: _,
                    oracle_deps: _,
                    fee_on_transfer_mode: _,
                    token_transfer_events: _,
                    uniswap_v4_hook_calls: _,
                    erc4626_vaults: _,
                    manipulated_reserves: _,
                    max_visited_pcs: _,
                    sha3_trace: _,
                    detected_patterns: _,
                    max_solver_depth: _,
                    max_branches: _,
                    total_branches: _,
                    storage_strategy: _,
                    dead_end_pcs: _,
                } = machine;
            }
        }
    };
}

symbolic_snapshot_schema! {
    solver_scope_level: u32 => {
        capture: |machine| machine.solver_depth,
        restore: |machine, snap| {
            if machine.solver_depth > snap.solver_scope_level {
                machine.solver.pop(machine.solver_depth - snap.solver_scope_level);
                machine.solver_depth = snap.solver_scope_level;
            }
        }
    },
    storage_log_len: usize => {
        capture: |machine| machine.storage_log.len(),
        restore: |machine, snap| {
            machine.storage_log.truncate(snap.storage_log_len);
        }
    },
    branch_pushes: usize => {
        capture: |machine| machine.branch_pushes,
        restore: |machine, snap| {
            machine.branch_pushes = snap.branch_pushes;
        }
    },
    has_called_attacker: bool => {
        capture: |machine| machine.has_called_attacker,
        restore: |machine, snap| {
            machine.has_called_attacker = snap.has_called_attacker;
        }
    },
    reentrancy_detected: bool => {
        capture: |machine| machine.reentrancy_detected,
        restore: |machine, snap| {
            machine.reentrancy_detected = snap.reentrancy_detected;
        }
    },
    self_destructed: bool => {
        capture: |machine| machine.self_destructed,
        restore: |machine, snap| {
            machine.self_destructed = snap.self_destructed;
        }
    },
    destroyed_contracts: HashSet<Address> => {
        capture: |machine| machine.destroyed_contracts.clone(),
        restore: |machine, snap| {
            machine.destroyed_contracts = snap.destroyed_contracts.clone();
        }
    },
    ext_code_hash_overrides: HashMap<Address, BV<'ctx>> => {
        capture: |machine| machine.ext_code_hash_overrides.clone(),
        restore: |machine, snap| {
            machine.ext_code_hash_overrides = snap.ext_code_hash_overrides.clone();
        }
    },
    created_contracts_len: usize => {
        capture: |machine| machine.created_contracts.len(),
        restore: |machine, snap| {
            machine.created_contracts.truncate(snap.created_contracts_len);
        }
    },
    create2_deployments_len: usize => {
        capture: |machine| machine.create2_deployments.len(),
        restore: |machine, snap| {
            machine.create2_deployments.truncate(snap.create2_deployments_len);
        }
    },
    memory: Array<'ctx> => {
        capture: |machine| machine.memory.clone(),
        restore: |machine, snap| {
            machine.memory = snap.memory.clone();
        }
    },
    sym_stack: SymbolicStack<'ctx> => {
        capture: |machine| machine.sym_stack.clone(),
        restore: |machine, snap| {
            machine.sym_stack = snap.sym_stack.clone();
        }
    },
    calldata: (Array<'ctx>, BV<'ctx>) => {
        capture: |machine| machine.calldata.clone(),
        restore: |machine, snap| {
            machine.calldata = snap.calldata.clone();
        }
    },
    sha3_map_len: usize => {
        capture: |machine| machine.sha3_map.len(),
        restore: |machine, snap| {
            machine.sha3_map.truncate(snap.sha3_map_len);
        }
    },
    frames: Vec<CallFrame<'ctx>> => {
        capture: |machine| machine.frames.clone(),
        restore: |machine, snap| {
            machine.frames = snap.frames.clone();
        }
    },
    read_cache: HashMap<BV<'ctx>, BV<'ctx>> => {
        capture: |machine| machine.read_cache.clone(),
        restore: |machine, snap| {
            machine.read_cache = snap.read_cache.clone();
        }
    },
    oracle_deps: Vec<OracleDep> => {
        capture: |machine| machine.oracle_deps.clone(),
        restore: |machine, snap| {
            machine.oracle_deps = snap.oracle_deps.clone();
        }
    },
    fee_on_transfer_mode: bool => {
        capture: |machine| machine.fee_on_transfer_mode,
        restore: |machine, snap| {
            machine.fee_on_transfer_mode = snap.fee_on_transfer_mode;
        }
    },
    token_transfer_events: Vec<TokenTransferEvent<'ctx>> => {
        capture: |machine| machine.token_transfer_events.clone(),
        restore: |machine, snap| {
            machine.token_transfer_events = snap.token_transfer_events.clone();
        }
    },
    uniswap_v4_hook_calls: Vec<HookCall> => {
        capture: |machine| machine.uniswap_v4_hook_calls.clone(),
        restore: |machine, snap| {
            machine.uniswap_v4_hook_calls = snap.uniswap_v4_hook_calls.clone();
        }
    },
    erc4626_vaults: HashMap<Address, Erc4626VaultState<'ctx>> => {
        capture: |machine| machine.erc4626_vaults.clone(),
        restore: |machine, snap| {
            machine.erc4626_vaults = snap.erc4626_vaults.clone();
        }
    },
    manipulated_reserves: HashMap<Address, (BV<'ctx>, BV<'ctx>)> => {
        capture: |machine| machine.manipulated_reserves.clone(),
        restore: |machine, snap| {
            machine.manipulated_reserves = snap.manipulated_reserves.clone();
        }
    },
    gas_remaining: BV<'ctx> => {
        capture: |machine| machine.gas_remaining.clone(),
        restore: |machine, snap| {
            machine.gas_remaining = snap.gas_remaining.clone();
        }
    },
    call_path: Vec<Address> => {
        capture: |machine| machine.call_path.clone(),
        restore: |machine, snap| {
            machine.call_path = snap.call_path.clone();
        }
    },
    storage_undo_len: usize => {
        capture: |machine| machine.storage_undo_log.len(),
        restore: |machine, snap| {
            while machine.storage_undo_log.len() > snap.storage_undo_len {
                if let Some((address, previous)) = machine.storage_undo_log.pop() {
                    if let Some(prev_arr) = previous {
                        machine.storage.insert(address, prev_arr);
                    } else {
                        machine.storage.remove(&address);
                    }
                }
            }
        }
    },
    max_memory_offset: BV<'ctx> => {
        capture: |machine| machine.max_memory_offset.clone(),
        restore: |machine, snap| {
            machine.max_memory_offset = snap.max_memory_offset.clone();
        }
    },
    pending_calls: Vec<(BV<'ctx>, BV<'ctx>)> => {
        capture: |machine| machine.pending_calls.clone(),
        restore: |machine, snap| {
            machine.pending_calls = snap.pending_calls.clone();
        }
    },
    tx_sender_schedule: Vec<Address> => {
        capture: |machine| machine.tx_sender_schedule.clone(),
        restore: |machine, snap| {
            machine.tx_sender_schedule = snap.tx_sender_schedule.clone();
        }
    },
    journal_len: usize => {
        capture: |machine| machine.journal.len(),
        restore: |machine, snap| {
            machine.journal.truncate(snap.journal_len);
        }
    },
    journal_depth: usize => {
        capture: |machine| machine.journal.last().map(|v| v.len()).unwrap_or(0),
        restore: |machine, snap| {
            if let Some(journal_last) = machine.journal.last_mut() {
                journal_last.truncate(snap.journal_depth);
            }
        }
    },
    oracle_preimage_map: HashMap<U256, Vec<BV<'ctx>>> => {
        capture: |machine| machine.oracle.preimage_map.clone(),
        restore: |machine, snap| {
            machine.oracle.preimage_map = snap.oracle_preimage_map.clone();
        }
    },
    pending_keccak_chains: Vec<PendingKeccakChain<'ctx>> => {
        capture: |machine| machine.pending_keccak_chains.clone(),
        restore: |machine, snap| {
            machine.pending_keccak_chains = snap.pending_keccak_chains.clone();
        }
    },
    balance_overrides: HashMap<Address, BV<'ctx>> => {
        capture: |machine| machine.balance_overrides.clone(),
        restore: |machine, snap| {
            machine.balance_overrides = snap.balance_overrides.clone();
        }
    },
    token_balances: HashMap<(Address, Address), BV<'ctx>> => {
        capture: |machine| machine.token_balances.clone(),
        restore: |machine, snap| {
            machine.token_balances = snap.token_balances.clone();
        }
    },
    visited_pcs_undo_len: usize => {
        capture: |machine| machine.visited_pcs_undo_log.len(),
        restore: |machine, snap| {
            while machine.visited_pcs_undo_log.len() > snap.visited_pcs_undo_len {
                if let Some((pc, previous)) = machine.visited_pcs_undo_log.pop() {
                    if let Some(prev_count) = previous {
                        machine.visited_pcs.insert(pc, prev_count);
                    } else {
                        machine.visited_pcs.remove(&pc);
                    }
                }
            }
        }
    },
    last_opcode: u8 => {
        capture: |machine| machine.last_opcode,
        restore: |machine, snap| {
            machine.last_opcode = snap.last_opcode;
        }
    },
    tx_id: usize => {
        capture: |machine| machine.tx_id,
        restore: |machine, snap| {
            machine.tx_id = snap.tx_id;
        }
    },
    last_return_data: (Array<'ctx>, BV<'ctx>) => {
        capture: |machine| machine.last_return_data.clone(),
        restore: |machine, snap| {
            machine.last_return_data = snap.last_return_data.clone();
        }
    },
    current_return_data: (Array<'ctx>, BV<'ctx>) => {
        capture: |machine| machine.current_return_data.clone(),
        restore: |machine, snap| {
            machine.current_return_data = snap.current_return_data.clone();
        }
    },
    reverted: bool => {
        capture: |machine| machine.reverted,
        restore: |machine, snap| {
            machine.reverted = snap.reverted;
        }
    },
    path_constraints: HashMap<usize, bool> => {
        capture: |machine| machine.path_constraints.clone(),
        restore: |machine, snap| {
            machine.path_constraints = snap.path_constraints.clone();
        }
    },
    next_call_args: Option<(BV<'ctx>, BV<'ctx>)> => {
        capture: |machine| machine.next_call_args.clone(),
        restore: |machine, snap| {
            machine.next_call_args = snap.next_call_args.clone();
        }
    },
    next_call_target: Option<(Address, bool)> => {
        capture: |machine| machine.next_call_target,
        restore: |machine, snap| {
            machine.next_call_target = snap.next_call_target;
        }
    },
    next_call_site_pc: Option<usize> => {
        capture: |machine| machine.next_call_site_pc,
        restore: |machine, snap| {
            machine.next_call_site_pc = snap.next_call_site_pc;
        }
    },
    max_visited_pcs: usize => {
        capture: |machine| machine.max_visited_pcs,
        restore: |machine, snap| {
            machine.max_visited_pcs = snap.max_visited_pcs;
        }
    },
    sha3_trace_len: usize => {
        capture: |machine| machine.sha3_trace.len(),
        restore: |machine, snap| {
            machine.sha3_trace.truncate(snap.sha3_trace_len);
        }
    },
    detected_patterns: HashMap<U256, StoragePattern> => {
        capture: |machine| machine.detected_patterns.clone(),
        restore: |machine, snap| {
            machine.detected_patterns = snap.detected_patterns.clone();
        }
    },
    total_branches: usize => {
        capture: |machine| machine.total_branches,
        restore: |machine, snap| {
            machine.total_branches = snap.total_branches;
        }
    },
    reentrancy_lock: HashMap<Address, bool> => {
        capture: |machine| machine.reentrancy_lock.clone(),
        restore: |machine, snap| {
            machine.reentrancy_lock = snap.reentrancy_lock.clone();
        }
    },
    call_value: Option<BV<'ctx>> => {
        capture: |machine| machine.call_value.clone(),
        restore: |machine, snap| {
            machine.call_value = snap.call_value.clone();
        }
    },
    call_handled: bool => {
        capture: |machine| machine.call_handled,
        restore: |machine, snap| {
            machine.call_handled = snap.call_handled;
        }
    },
    delegatecall_depth: usize => {
        capture: |machine| machine.delegatecall_depth,
        restore: |machine, snap| {
            machine.delegatecall_depth = snap.delegatecall_depth;
        }
    },
    delegatecall_storage_clash_detected: bool => {
        capture: |machine| machine.delegatecall_storage_clash_detected,
        restore: |machine, snap| {
            machine.delegatecall_storage_clash_detected = snap.delegatecall_storage_clash_detected;
        }
    },
    value_transfer_call_count: usize => {
        capture: |machine| machine.value_transfer_call_count,
        restore: |machine, snap| {
            machine.value_transfer_call_count = snap.value_transfer_call_count;
        }
    },
    cumulative_call_value_out: BV<'ctx> => {
        capture: |machine| machine.cumulative_call_value_out.clone(),
        restore: |machine, snap| {
            machine.cumulative_call_value_out = snap.cumulative_call_value_out.clone();
        }
    },
    msg_value_loop_guard_triggered: bool => {
        capture: |machine| machine.msg_value_loop_guard_triggered,
        restore: |machine, snap| {
            machine.msg_value_loop_guard_triggered = snap.msg_value_loop_guard_triggered;
        }
    },
    reentrancy_branch_seq: usize => {
        capture: |machine| machine.reentrancy_branch_seq,
        restore: |machine, snap| {
            machine.reentrancy_branch_seq = snap.reentrancy_branch_seq;
        }
    },
    active_reentrancy_branch_key: Option<usize> => {
        capture: |machine| machine.active_reentrancy_branch_key,
        restore: |machine, snap| {
            machine.active_reentrancy_branch_key = snap.active_reentrancy_branch_key;
        }
    },
    reentrancy_invariant_touch: bool => {
        capture: |machine| machine.reentrancy_invariant_touch,
        restore: |machine, snap| {
            machine.reentrancy_invariant_touch = snap.reentrancy_invariant_touch;
        }
    },
    storage_strategy: Option<Box<dyn StorageStrategy<'ctx> + 'ctx>> => {
        capture: |machine| machine.storage_strategy.as_ref().map(|strategy| strategy.box_clone()),
        restore: |machine, snap| {
            machine.storage_strategy = snap.storage_strategy.as_ref().map(|strategy| strategy.box_clone());
        }
    },
    dead_end_pcs: HashSet<usize> => {
        capture: |machine| machine.dead_end_pcs.clone(),
        restore: |machine, snap| {
            machine.dead_end_pcs = snap.dead_end_pcs.clone();
        }
    }
}

impl<'ctx> SymbolicMachine<'ctx> {
    pub fn new(
        context: &'ctx Context,
        solver: &'ctx Solver<'ctx>,
        fork_url: Option<String>,
    ) -> Self {
        // Ensure solver is configured (redundant if called from run_with_z3_solver, but safe)
        crate::symbolic::z3_ext::configure_solver(context, solver);

        let domain_addr = z3::Sort::bitvector(context, 256);
        let domain_byte = z3::Sort::bitvector(context, 8);
        let zero_byte = BV::from_u64(context, 0, 8);
        let zero_mem = z3::ast::Array::const_array(context, &domain_addr, &zero_byte);

        let mut machine = Self {
            context,
            solver,
            sym_stack: SymbolicStack::new(context),
            storage_log: Vec::new(),
            memory: zero_mem,
            storage: HashMap::new(),
            storage_undo_log: Vec::new(),
            keccak: crate::symbolic::z3_ext::KeccakTheory::new(context),
            calldata: (
                z3::ast::Array::new_const(context, "calldata", &domain_addr, &domain_byte),
                crate::symbolic::z3_ext::bv_from_u256(context, U256::ZERO),
            ),
            sha3_map: Vec::new(),
            frames: Vec::new(),
            call_value: None,
            balance_overrides: HashMap::new(),
            token_balances: HashMap::new(),
            fork_url,
            branch_pushes: 0,
            last_opcode: 0,
            tx_id: 0,
            tx_sender_schedule: Vec::new(),
            pending_calls: Vec::new(),
            last_return_data: (
                z3::ast::Array::new_const(context, "last_ret_data", &domain_addr, &domain_byte),
                crate::symbolic::z3_ext::bv_from_u256(context, U256::ZERO),
            ),
            current_return_data: (
                z3::ast::Array::new_const(context, "curr_ret_data", &domain_addr, &domain_byte),
                crate::symbolic::z3_ext::bv_from_u256(context, U256::ZERO),
            ),
            journal: vec![Vec::new()],
            reverted: false,
            http_client: HttpClient::new(),
            unexplored_branches: Vec::new(),
            path_constraints: HashMap::new(),
            has_called_attacker: false,
            reentrancy_detected: false,
            self_destructed: false,
            destroyed_contracts: HashSet::new(),
            ext_code_hash_overrides: HashMap::new(),
            created_contracts: Vec::new(),
            create2_deployments: Vec::new(),
            max_memory_offset: crate::symbolic::utils::math::zero(context),
            call_path: Vec::new(),
            reentrancy_lock: HashMap::new(),
            visited_pcs: HashMap::new(),
            visited_pcs_undo_log: Vec::new(),
            max_loop_iterations: 100, // Default
            gas_remaining: crate::symbolic::z3_ext::bv_from_u256(context, U256::from(10_000_000)),
            solver_depth: 0,
            next_call_args: None,
            next_call_target: None,
            next_call_site_pc: None,
            call_handled: false,
            delegatecall_depth: 0,
            delegatecall_storage_clash_detected: false,
            value_transfer_call_count: 0,
            cumulative_call_value_out: crate::symbolic::utils::math::zero(context),
            msg_value_loop_guard_triggered: false,
            reentrancy_branch_seq: 0,
            active_reentrancy_branch_key: None,
            reentrancy_invariant_touch: false,
            oracle: crate::symbolic::oracle::KeccakOracle::new(),
            pending_keccak_chains: Vec::new(),
            read_cache: HashMap::new(),
            oracle_deps: Vec::new(),
            fee_on_transfer_mode: false,
            token_transfer_events: Vec::new(),
            uniswap_v4_hook_calls: Vec::new(),
            erc4626_vaults: HashMap::new(),
            manipulated_reserves: HashMap::new(),
            max_visited_pcs: 10_000,

            sha3_trace: Vec::new(),
            detected_patterns: HashMap::new(),
            max_solver_depth: 64, // Default Depth Limit
            max_branches: 1000,   // Default Branch Limit
            total_branches: 0,

            storage_strategy: Some(Box::new(AlgebraicStorage::new())),
            dead_end_pcs: HashSet::new(),
        };

        machine.oracle.hydrate_from_global_cache(context);

        // AUTO-INIT: Enforce Keccak Axioms
        machine.setup_keccak_axioms();

        machine
    }

    pub fn set_tx_sender_schedule(&mut self, senders: Vec<Address>) {
        self.tx_sender_schedule = senders;
    }

    pub fn sender_for_tx_id(&self, tx_id: usize) -> Option<Address> {
        if self.tx_sender_schedule.is_empty() {
            return None;
        }
        let idx = tx_id % self.tx_sender_schedule.len();
        self.tx_sender_schedule.get(idx).copied()
    }

    pub fn effective_tx_origin(&self, env_origin: Address) -> Address {
        self.sender_for_tx_id(self.tx_id).unwrap_or(env_origin)
    }

    pub fn effective_top_level_msg_sender(&self, env_sender: Address) -> Address {
        self.sender_for_tx_id(self.tx_id).unwrap_or(env_sender)
    }

    pub fn setup_keccak_axioms(&mut self) {
        // We no longer use global quantifiers due to performance (Million-Dollar Bottleneck).
        // Instead, we use "Lazy Injectivity" via record_sha3.
    }

    fn ast_eq(lhs: &BV<'ctx>, rhs: &BV<'ctx>) -> bool {
        lhs._eq(rhs).simplify().as_bool() == Some(true)
    }

    fn next_reentrancy_branch_key(&mut self) -> usize {
        let key = REENTRANCY_BRANCH_BASE.saturating_add(self.reentrancy_branch_seq);
        self.reentrancy_branch_seq = self.reentrancy_branch_seq.saturating_add(1);
        key
    }

    fn is_triple_invariant_slot(&self, slot: &BV<'ctx>) -> bool {
        if let Some(slot_u256) = crate::symbolic::z3_ext::u256_from_bv(slot) {
            if slot_u256 == U256::from(8u64) || self.oracle.common_slots.contains_key(&slot_u256) {
                return true;
            }
        }

        if self
            .sha3_trace
            .iter()
            .any(|trace| Self::ast_eq(&trace.hash, slot))
        {
            return true;
        }

        self.pending_keccak_chains.iter().any(|link| {
            Self::ast_eq(&link.parent_hash, slot) || Self::ast_eq(&link.child_hash, slot)
        })
    }

    /// Forks a reentrancy branch at an external call site.
    /// Returns true when the active path models attacker callback execution.
    pub fn fork_reentrancy_branch(&mut self, call_site_pc: usize) -> bool {
        let branch_key = self.next_reentrancy_branch_key();
        let branch_name = format!(
            "reentrancy_branch_{}_{}_{}",
            self.tx_id, call_site_pc, branch_key
        );
        let reenter = Bool::new_const(self.context, branch_name.as_str());

        let can_reenter = {
            self.solver.push();
            self.solver_depth += 1;
            self.solver.assert(&reenter);
            let sat = self.solver.check() == z3::SatResult::Sat;
            self.solver.pop(1);
            self.solver_depth -= 1;
            sat
        };

        let can_skip = {
            self.solver.push();
            self.solver_depth += 1;
            self.solver.assert(&reenter.not());
            let sat = self.solver.check() == z3::SatResult::Sat;
            self.solver.pop(1);
            self.solver_depth -= 1;
            sat
        };

        let decision = if let Some(&forced) = self.path_constraints.get(&branch_key) {
            forced
        } else if can_reenter && can_skip {
            if (self.solver_depth as usize) >= self.max_solver_depth
                || self.total_branches >= self.max_branches
            {
                false
            } else {
                self.unexplored_branches.push((branch_key, false));
                self.total_branches += 1;
                true
            }
        } else {
            can_reenter
        };

        if can_reenter && can_skip {
            self.solver.push();
            self.solver_depth += 1;
            self.branch_pushes += 1;
        }

        let branch_constraint = if decision { reenter } else { reenter.not() };
        self.solver.assert(&branch_constraint);

        if decision {
            self.active_reentrancy_branch_key = Some(branch_key);
            self.reentrancy_invariant_touch = false;
            self.has_called_attacker = true;
        } else {
            self.active_reentrancy_branch_key = None;
            self.reentrancy_invariant_touch = false;
        }

        decision
    }

    /// Marks SSTORE writes relevant to reentrancy objectives.
    pub fn mark_reentrancy_sstore(&mut self, key: &BV<'ctx>) {
        if !self.has_called_attacker || self.active_reentrancy_branch_key.is_none() {
            return;
        }

        if self.is_triple_invariant_slot(key) {
            self.reentrancy_invariant_touch = true;
            self.reentrancy_detected = true;
        }
    }

    fn is_eip1967_reserved_slot(slot: U256) -> bool {
        let impl_slot = U256::from_be_bytes(crate::utils::constants::EIP1967_IMPL_SLOT);
        let admin_slot = U256::from_be_bytes([
            0xb5, 0x31, 0x27, 0x68, 0x4a, 0x56, 0x8b, 0x31, 0x73, 0xae, 0x13, 0xb9, 0xf8, 0xa6,
            0x01, 0x6e, 0x24, 0x3e, 0x63, 0xb6, 0xe8, 0xee, 0x11, 0x78, 0xd6, 0xa7, 0x17, 0x85,
            0x0b, 0x5d, 0x61, 0x03,
        ]);
        let beacon_slot = U256::from_be_bytes([
            0xa3, 0xf0, 0xad, 0x74, 0xe5, 0x42, 0x3a, 0xeb, 0xfd, 0x80, 0xd3, 0xef, 0x43, 0x46,
            0x57, 0x83, 0x35, 0xa9, 0xa7, 0x2a, 0xea, 0xee, 0x59, 0xff, 0x6c, 0xb3, 0x58, 0x2b,
            0x35, 0x13, 0x3d, 0x50,
        ]);
        slot == impl_slot || slot == admin_slot || slot == beacon_slot
    }

    /// Flags delegatecall storage writes to EIP-1967 reserved proxy slots.
    pub fn mark_delegatecall_sstore(&mut self, key: &BV<'ctx>) {
        if self.delegatecall_depth == 0 {
            return;
        }
        if let Some(slot) = crate::symbolic::z3_ext::u256_from_bv(key) {
            if Self::is_eip1967_reserved_slot(slot) {
                self.delegatecall_storage_clash_detected = true;
            }
        }
    }

    /// Tracks outbound CALL value accumulation and enforces loop-value solvency guard.
    pub fn track_msg_value_loop_guard(&mut self, sender: Address, call_value: &BV<'ctx>) {
        self.value_transfer_call_count = self.value_transfer_call_count.saturating_add(1);

        let next_total = self.cumulative_call_value_out.bvadd(call_value);
        let no_overflow = next_total.bvuge(&self.cumulative_call_value_out);
        self.solver.assert(&no_overflow);
        self.cumulative_call_value_out = next_total;

        if self.value_transfer_call_count > 1 {
            self.msg_value_loop_guard_triggered = true;
            if let Some(sender_balance) = self.balance_overrides.get(&sender) {
                self.solver
                    .assert(&sender_balance.bvuge(&self.cumulative_call_value_out));
            }
        }
    }

    /// Active reentrancy branches must touch invariant-related state to remain explorable.
    pub fn should_prune_reentrancy_path(&self) -> bool {
        self.active_reentrancy_branch_key.is_some() && !self.reentrancy_invariant_touch
    }

    /// Audit CREATE2 init code for high-risk opcodes before deployment.
    pub fn audit_create2_init_code(
        init_code: &[u8],
        declared_len: usize,
        analyzed_len: usize,
    ) -> Create2InitAudit {
        let has_delegatecall = init_code.contains(&0xf4);
        let has_selfdestruct = init_code.contains(&0xff);
        let has_nested_create2 = init_code.contains(&0xf5);
        let has_callcode = init_code.contains(&0xf2);

        Create2InitAudit {
            declared_len,
            analyzed_len,
            has_delegatecall,
            has_selfdestruct,
            has_nested_create2,
            has_callcode,
        }
    }

    /// Predict CREATE2 deployment address.
    /// Uses exact EVM formula when `salt` and `init_code_hash` are concrete, otherwise domain-separated UF.
    pub fn predict_create2_address(
        &self,
        deployer: Address,
        salt: &BV<'ctx>,
        init_code_hash: &BV<'ctx>,
    ) -> BV<'ctx> {
        if let (Some(salt_u256), Some(init_hash_u256)) = (
            crate::symbolic::z3_ext::u256_from_bv(salt),
            crate::symbolic::z3_ext::u256_from_bv(init_code_hash),
        ) {
            let mut preimage = [0u8; 85];
            preimage[0] = 0xff;
            preimage[1..21].copy_from_slice(deployer.as_slice());
            preimage[21..53].copy_from_slice(&salt_u256.to_be_bytes::<32>());
            preimage[53..85].copy_from_slice(&init_hash_u256.to_be_bytes::<32>());

            let digest = keccak256(preimage);
            let mut padded = [0u8; 32];
            padded[12..32].copy_from_slice(&digest.0[12..32]);
            let predicted = U256::from_be_bytes(padded);
            return crate::symbolic::z3_ext::bv_from_u256(self.context, predicted);
        }

        let mut deployer_word_bytes = [0u8; 32];
        deployer_word_bytes[12..].copy_from_slice(deployer.as_slice());
        let deployer_word = crate::symbolic::z3_ext::bv_from_u256(
            self.context,
            U256::from_be_bytes(deployer_word_bytes),
        );
        let create2_tag = BV::from_u64(self.context, 0xff, 256);

        let create2_hash = self.keccak.apply_symbolic(Some(vec![
            create2_tag,
            deployer_word,
            salt.clone(),
            init_code_hash.clone(),
        ]));
        create2_hash.extract(159, 0).zero_ext(96)
    }

    fn enqueue_keccak_chain(
        &mut self,
        parent_hash: BV<'ctx>,
        child_hash: BV<'ctx>,
        parent_index: usize,
        arity: usize,
    ) {
        let already_pending = self.pending_keccak_chains.iter().any(|link| {
            link.parent_index == parent_index
                && link.arity == arity
                && Self::ast_eq(&link.parent_hash, &parent_hash)
                && Self::ast_eq(&link.child_hash, &child_hash)
        });
        if already_pending {
            return;
        }

        self.pending_keccak_chains.push(PendingKeccakChain {
            parent_hash,
            child_hash,
            parent_index,
            arity,
            expanded: false,
        });
    }

    fn expand_pending_keccak_chain(
        &mut self,
        parent_hash: &BV<'ctx>,
        child_hash: &BV<'ctx>,
        parent_index: usize,
        arity: usize,
    ) {
        for trace in &self.sha3_trace {
            if trace.preimage.len() != arity || parent_index >= trace.preimage.len() {
                continue;
            }
            let other_parent = &trace.preimage[parent_index];
            self.keccak.verify_injectivity_chain(
                self.solver,
                parent_hash,
                child_hash,
                other_parent,
                &trace.hash,
            );
        }

        for (concrete_hash, concrete_preimage) in &self.oracle.preimage_map {
            if concrete_preimage.len() != arity || parent_index >= concrete_preimage.len() {
                continue;
            }
            let other_child_hash =
                crate::symbolic::z3_ext::bv_from_u256(self.context, *concrete_hash);
            let other_parent = &concrete_preimage[parent_index];
            self.keccak.verify_injectivity_chain(
                self.solver,
                parent_hash,
                child_hash,
                other_parent,
                &other_child_hash,
            );
        }
    }

    /// Lazily instantiate local chain injectivity only for storage slots that are actively queried.
    pub fn materialize_keccak_chain_for_slot(&mut self, slot: &BV<'ctx>) {
        let mut frontier = vec![slot.clone()];

        loop {
            let to_expand: Vec<usize> = self
                .pending_keccak_chains
                .iter()
                .enumerate()
                .filter(|(_, link)| {
                    !link.expanded
                        && frontier
                            .iter()
                            .any(|candidate| Self::ast_eq(&link.child_hash, candidate))
                })
                .map(|(idx, _)| idx)
                .collect();

            if to_expand.is_empty() {
                break;
            }

            for idx in to_expand {
                let (parent_hash, child_hash, parent_index, arity) = {
                    let link = &self.pending_keccak_chains[idx];
                    (
                        link.parent_hash.clone(),
                        link.child_hash.clone(),
                        link.parent_index,
                        link.arity,
                    )
                };

                self.expand_pending_keccak_chain(&parent_hash, &child_hash, parent_index, arity);

                if let Some(link) = self.pending_keccak_chains.get_mut(idx) {
                    link.expanded = true;
                }
                frontier.push(parent_hash);
            }
        }
    }

    pub fn record_sha3(&mut self, trace: crate::symbolic::patterns::SHA3Trace<'ctx>) {
        // Enforce Lazy Injectivity (Functional Consistency)
        // For every existing trace of same size, assert: hash_match => inputs_match
        let size_u256 = crate::symbolic::z3_ext::u256_from_bv(&trace.size);

        // 1. Check against other Symbolic Traces
        for old_trace in &self.sha3_trace {
            if crate::symbolic::z3_ext::u256_from_bv(&old_trace.size) == size_u256 {
                let hashes_match = old_trace.hash._eq(&trace.hash);

                // Compare preimages
                if old_trace.preimage.len() == trace.preimage.len() {
                    let mut inputs_match = Bool::from_bool(self.context, true);
                    for (b1, b2) in old_trace.preimage.iter().zip(trace.preimage.iter()) {
                        inputs_match = Bool::and(self.context, &[&inputs_match, &b1._eq(b2)]);
                    }

                    self.solver.assert(&hashes_match.implies(&inputs_match));
                }
            }
        }

        // 2. Check against Concrete Oracle Preimages (Partial Quantification)
        // If trace.hash == concrete_hash, then trace.preimage == concrete_preimage
        for (conc_hash, conc_preimage) in &self.oracle.preimage_map {
            // Only check if sizes match (optimization)
            if conc_preimage.len() == trace.preimage.len() {
                let conc_hash_bv = crate::symbolic::z3_ext::bv_from_u256(self.context, *conc_hash);
                let hashes_match = trace.hash._eq(&conc_hash_bv);

                let mut inputs_match = Bool::from_bool(self.context, true);
                for (sym_b, conc_b) in trace.preimage.iter().zip(conc_preimage.iter()) {
                    inputs_match = Bool::and(self.context, &[&inputs_match, &sym_b._eq(conc_b)]);
                }

                self.solver.assert(&hashes_match.implies(&inputs_match));
            }
        }

        // 3. Pattern-Guided Exploration (Hybrid Execution)
        // Infer storage pattern (Mapping, Array, Nested)
        let pattern =
            PatternInference::infer(Some(&self.detected_patterns), &self.sha3_trace, &trace);

        if let Some(p) = pattern {
            // Save detected pattern
            let trace_hash_u256 = crate::symbolic::z3_ext::u256_from_bv(&trace.hash);
            if let Some(h) = trace_hash_u256 {
                self.detected_patterns.insert(h, p.clone());
            }

            // Generate "Deep Projection" Constraints
            // If this hash matches a known concrete hash (from oracle), enforce the path keys match.
            let constraints =
                PatternInference::constrain_deep_projection(self, &trace.hash, &trace, &p);
            for c in constraints {
                self.solver.assert(&c);
            }

            // Generate "Forward Propagation" Constraints
            // Designate validity of the next level if the parent is defined.
            let forward_constraints =
                PatternInference::constrain_forward_propagation(self, &trace, &p);
            for c in forward_constraints {
                self.solver.assert(&c);
            }
        }

        // 4. Incremental Keccak Solving (Lazy Chain Verification)
        // Queue chain links, but only expand injectivity constraints when a relevant slot is queried.
        for (parent_index, potential_parent) in trace.preimage.iter().enumerate() {
            if let Some(parent_trace) = self
                .sha3_trace
                .iter()
                .rev()
                .find(|candidate| Self::ast_eq(&candidate.hash, potential_parent))
            {
                self.enqueue_keccak_chain(
                    parent_trace.hash.clone(),
                    trace.hash.clone(),
                    parent_index,
                    trace.preimage.len(),
                );
            }
        }

        if let Some(trace_hash_u256) = crate::symbolic::z3_ext::u256_from_bv(&trace.hash) {
            self.oracle
                .record_preimage(trace_hash_u256, trace.preimage.clone());
        }

        // Save trace
        self.sha3_trace.push(trace);
    }

    /// Returns a zero-initialized byte-addressed memory array (BV<256> -> BV<8>).
    pub fn zero_memory(&self) -> Array<'ctx> {
        let domain = z3::Sort::bitvector(self.context, 256);
        let zero_byte = BV::from_u64(self.context, 0, 8);
        Array::const_array(self.context, &domain, &zero_byte)
    }

    /// Returns a zero-initialized storage array (BV<256> -> BV<256>).
    pub fn zero_storage(&self) -> Array<'ctx> {
        let domain = z3::Sort::bitvector(self.context, 256);
        let zero_word = BV::from_u64(self.context, 0, 256);
        Array::const_array(self.context, &domain, &zero_word)
    }

    /// Models SELFDESTRUCT as full storage wipe and code-hash reset for metamorphic lifecycle.
    pub fn record_selfdestruct(&mut self, contract: Address) {
        self.self_destructed = true;
        self.set_storage_array(contract, self.zero_storage());
        self.destroyed_contracts.insert(contract);
        self.ext_code_hash_overrides
            .insert(contract, crate::symbolic::utils::math::zero(self.context));
    }

    /// Returns a fresh symbolic byte-addressed array (BV<256> -> BV<8>) with the given name.
    pub fn fresh_byte_array(&self, name: &str) -> Array<'ctx> {
        let domain_addr = z3::Sort::bitvector(self.context, 256);
        let domain_byte = z3::Sort::bitvector(self.context, 8);
        Array::new_const(self.context, name, &domain_addr, &domain_byte)
    }

    pub fn update_max_offset(&mut self, offset: BV<'ctx>) {
        let is_greater = offset.bvugt(&self.max_memory_offset);
        self.max_memory_offset = is_greater.ite(&offset, &self.max_memory_offset);
    }

    pub fn read_word(&mut self, offset: BV<'ctx>) -> BV<'ctx> {
        if let Some(cached) = self.read_cache.get(&offset) {
            return cached.clone();
        }
        let mut word = crate::symbolic::utils::math::zero(self.context);
        for i in 0..32 {
            let idx = offset.bvadd(&crate::symbolic::utils::math::val(self.context, i as u64));
            let byte = self
                .memory
                .select(&idx)
                .as_bv()
                .unwrap_or_else(|| BV::from_u64(self.context, 0, 8));
            let shift = crate::symbolic::z3_ext::bv_from_u256(
                self.context,
                U256::from((31 - i) as u64 * 8),
            );
            let byte_extended = byte.zero_ext(248);
            let shifted = byte_extended.bvshl(&shift);
            word = word.bvor(&shifted);
        }
        self.read_cache.insert(offset.clone(), word.clone());
        word
    }

    pub fn write_word(&mut self, offset: BV<'ctx>, val: BV<'ctx>) {
        self.read_cache.clear();
        for i in 0..32 {
            let idx = offset.bvadd(&crate::symbolic::utils::math::val(self.context, i as u64));
            let shift = crate::symbolic::z3_ext::bv_from_u256(
                self.context,
                U256::from((31 - i) as u64 * 8),
            );
            let byte = val.bvlshr(&shift).extract(7, 0);
            self.memory = self.memory.store(&idx, &byte);
        }
    }

    pub fn read_byte(&mut self, offset: BV<'ctx>) -> BV<'ctx> {
        self.memory
            .select(&offset)
            .as_bv()
            .unwrap_or_else(|| BV::from_u64(self.context, 0, 8))
    }

    pub fn write_byte(&mut self, offset: BV<'ctx>, val: BV<'ctx>) {
        let byte = val.extract(7, 0);
        self.memory = self.memory.store(&offset, &byte);
        self.read_cache.clear();
    }

    pub fn inject_balance_override(&mut self, account: Address, balance: BV<'ctx>) {
        self.balance_overrides.insert(account, balance);
    }

    pub fn reset_calldata(&mut self) {
        self.calldata = (
            self.fresh_byte_array("calldata_root"),
            BV::from_u64(self.context, 0, 256),
        );
    }

    pub fn seed_oracle(&mut self, attacker: Address, target: Option<Address>) {
        self.oracle.precompute_common_slots(attacker, target);

        // Hydrate Preimage Map with BVs from Common Slots
        // We need to clone keys to avoid borrow checker issues if we iterate common_slots directly
        let entries: Vec<(U256, Vec<Vec<u8>>)> = self
            .oracle
            .common_slots
            .iter()
            .map(|(k, v)| (*k, v.inputs.clone()))
            .collect();

        for (hash, inputs_list) in entries {
            // inputs_list is Vec<Vec<u8>>. Usually just one "input blob".
            // We need to convert this blob into Vec<BV> (chunks of 32 bytes).
            // Our KeccakTheory assumes 32-byte word inputs usually.

            for input_bytes in inputs_list {
                let mut bv_chunks = Vec::new();
                // Chunk into 32 bytes
                for chunk in input_bytes.chunks(32) {
                    let mut padded = [0u8; 32];
                    let len = chunk.len().min(32);
                    padded[..len].copy_from_slice(&chunk[..len]);
                    // Z3 BV from bytes
                    let val_u256 = U256::from_be_bytes(padded); // padded at end? No BE bytes means big endian integer.
                                                                // Copy raw bytes to integer.
                                                                // The BV should represent the 32-byte word.
                                                                // If input_bytes was "packed", checking chunks is correct.
                    bv_chunks.push(crate::symbolic::z3_ext::bv_from_u256(
                        self.context,
                        val_u256,
                    ));
                }
                self.oracle.record_preimage(hash, bv_chunks);
            }
        }
    }

    pub fn record_oracle_dependency(&mut self, target: Address, slot: U256, kind: OracleType) {
        self.oracle_deps.push(OracleDep {
            source: target, // The STATICCALL target IS the oracle data source
            target,
            slot,
            kind,
        });
    }

    pub fn record_uniswap_v4_hook_call(
        &mut self,
        target: Address,
        selector: u32,
        call_site_pc: usize,
        is_static: bool,
    ) {
        self.uniswap_v4_hook_calls.push(HookCall {
            target,
            selector,
            call_site_pc,
            is_static,
            storage_log_len_at_call: self.storage_log.len(),
        });
    }

    pub fn erc4626_state(&mut self, vault: Address) -> Option<&mut Erc4626VaultState<'ctx>> {
        if !self.erc4626_vaults.contains_key(&vault) {
            let asset_name = format!("erc4626_assets_init_{}_{}", self.tx_id, vault);
            let supply_name = format!("erc4626_supply_init_{}_{}", self.tx_id, vault);
            let init_assets = BV::new_const(self.context, asset_name.as_str(), 256);
            let init_supply = BV::new_const(self.context, supply_name.as_str(), 256);
            let zero = crate::symbolic::utils::math::zero(self.context);
            self.solver.assert(&init_assets.bvuge(&zero));
            self.solver.assert(&init_supply.bvuge(&zero));

            self.erc4626_vaults.insert(
                vault,
                Erc4626VaultState {
                    initial_assets: init_assets.clone(),
                    initial_supply: init_supply.clone(),
                    current_assets: init_assets,
                    current_supply: init_supply,
                    touched: false,
                },
            );
        }

        self.erc4626_vaults.get_mut(&vault)
    }

    /// Hydrates the symbolic storage array for a specific address.
    pub fn hydrate_storage(&mut self, address: Address, slots: Vec<(U256, U256)>) {
        let storage_arr = self.get_storage(address);
        let mut new_arr = storage_arr;

        for (key, val) in slots {
            let key_bv = crate::symbolic::z3_ext::bv_from_u256(self.context, key);
            let val_bv = crate::symbolic::z3_ext::bv_from_u256(self.context, val);
            new_arr = new_arr.store(&key_bv, &val_bv);
        }
        self.set_storage_array(address, new_arr);
    }

    /// Copy-on-write storage update for snapshot rollback without full map cloning.
    pub fn set_storage_array(&mut self, address: Address, new_storage: Array<'ctx>) {
        let previous = self.storage.insert(address, new_storage);
        self.storage_undo_log.push((address, previous));
    }

    /// Records a visited PC increment with undo information for snapshot rollback.
    pub fn mark_visited_pc(&mut self, pc: usize) -> usize {
        let previous = self.visited_pcs.get(&pc).copied();
        self.visited_pcs_undo_log.push((pc, previous));
        let next = previous.unwrap_or(0).saturating_add(1);
        self.visited_pcs.insert(pc, next);
        next
    }

    /// Clears the visited-PC map while preserving rollback history.
    pub fn clear_visited_pcs(&mut self) {
        if self.visited_pcs.is_empty() {
            return;
        }
        for (&pc, &count) in &self.visited_pcs {
            self.visited_pcs_undo_log.push((pc, Some(count)));
        }
        self.visited_pcs.clear();
    }

    pub fn get_storage(&self, address: Address) -> Array<'ctx> {
        if let Some(arr) = self.storage.get(&address) {
            arr.clone()
        } else {
            // Uninitialized storage defaults to zero.
            // Consider caching this zero array if profiles show repeated allocation cost.
            let domain_addr = z3::Sort::bitvector(self.context, 256);
            let zero_val = crate::symbolic::utils::math::zero(self.context);
            z3::ast::Array::const_array(self.context, &domain_addr, &zero_val)
        }
    }
}
