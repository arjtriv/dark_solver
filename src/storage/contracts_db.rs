use alloy::primitives::{Address, B256};
use anyhow::Context;
use revm::primitives::Bytes;
use revm::primitives::U256 as RU256;
use rusqlite::ffi::ErrorCode;
use rusqlite::{params, Connection, OptionalExtension};
#[cfg(test)]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

const DEFAULT_DB_PATH: &str = "contracts.db";

const DEFAULT_ASYNC_WRITE_QUEUE_CAPACITY: usize = 8_192;
const MAX_ASYNC_WRITE_QUEUE_CAPACITY: usize = 262_144;

static DEFAULT_DB_WRITE_FULL_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_CONTRACTS_DB_NOW_MS: AtomicU64 = AtomicU64::new(1);
#[cfg(not(test))]
static DEFAULT_DB_WRITE_TX: OnceLock<mpsc::Sender<DbWriteOp>> = OnceLock::new();
#[cfg(not(test))]
static DEFAULT_DB_WRITE_INIT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(test)]
static EXTRA_DB_WRITE_TX: OnceLock<Mutex<HashMap<PathBuf, mpsc::Sender<DbWriteOp>>>> =
    OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Queued,
    InProgress,
    Done,
}

impl ScanStatus {
    fn as_str(self) -> &'static str {
        match self {
            ScanStatus::Queued => "queued",
            ScanStatus::InProgress => "in_progress",
            ScanStatus::Done => "done",
        }
    }

    fn from_db(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(Self::Queued),
            "in_progress" => Some(Self::InProgress),
            "done" => Some(Self::Done),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanStatusCounts {
    pub queued: u64,
    pub in_progress: u64,
    pub done: u64,
}

impl ScanStatusCounts {
    pub fn total(self) -> u64 {
        self.queued
            .saturating_add(self.in_progress)
            .saturating_add(self.done)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcomeLabel {
    Included,
    NotIncluded,
    Outbid,
    Late,
    Reverted,
    UnprofitableAfterGas,
    DroppedShadowFail,
    DroppedHoneypot,
    DroppedGasGrief,
    DroppedPreflight,
    DroppedHandshake,
    DroppedStale,
    DroppedPriceConfidence,
    DroppedConditional,
    DroppedSafetyRails,
    SimulatedOnly,
    Unknown,
}

impl ExecutionOutcomeLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionOutcomeLabel::Included => "included",
            ExecutionOutcomeLabel::NotIncluded => "not_included",
            ExecutionOutcomeLabel::Outbid => "outbid",
            ExecutionOutcomeLabel::Late => "late",
            ExecutionOutcomeLabel::Reverted => "reverted",
            ExecutionOutcomeLabel::UnprofitableAfterGas => "unprofitable_after_gas",
            ExecutionOutcomeLabel::DroppedShadowFail => "dropped_shadow_fail",
            ExecutionOutcomeLabel::DroppedHoneypot => "dropped_honeypot",
            ExecutionOutcomeLabel::DroppedGasGrief => "dropped_gas_grief",
            ExecutionOutcomeLabel::DroppedPreflight => "dropped_preflight",
            ExecutionOutcomeLabel::DroppedHandshake => "dropped_handshake",
            ExecutionOutcomeLabel::DroppedStale => "dropped_stale",
            ExecutionOutcomeLabel::DroppedPriceConfidence => "dropped_price_confidence",
            ExecutionOutcomeLabel::DroppedConditional => "dropped_conditional",
            ExecutionOutcomeLabel::DroppedSafetyRails => "dropped_safety_rails",
            ExecutionOutcomeLabel::SimulatedOnly => "simulated_only",
            ExecutionOutcomeLabel::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BuilderAttemptRecord {
    pub builder: String,
    pub accepted: bool,
    pub latency_ms: u64,
    pub rejection_class: Option<String>,
    pub response_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SubmissionAttemptRecord {
    pub target: Address,
    pub objective: String,
    pub solve_block: u64,
    pub solve_duration_ms: u128,
    pub solve_started_ms: u64,
    pub replay_completed_ms: Option<u64>,
    pub send_completed_ms: Option<u64>,
    pub tip_wei: Option<u128>,
    pub max_fee_wei: Option<u128>,
    pub expected_profit_wei: Option<RU256>,
    pub realized_profit_wei: Option<RU256>,
    pub realized_profit_negative: bool,
    pub latency_bucket_ms: Option<u64>,
    pub tip_band_wei: Option<u128>,
    pub chosen_builders: Vec<String>,
    pub outcome_label: ExecutionOutcomeLabel,
    pub included: Option<bool>,
    pub reverted: Option<bool>,
    pub inclusion_block: Option<u64>,
    pub contested: bool,
    pub payload_json: Option<String>,
    pub details_json: Option<String>,
    pub builder_outcomes: Vec<BuilderAttemptRecord>,
}

#[derive(Debug, Clone)]
pub struct BuilderRoutingStats {
    pub builder: String,
    pub attempts: u64,
    pub accepted: u64,
    pub outbid_rejections: u64,
    pub avg_latency_ms: f64,
}

#[derive(Debug, Clone)]
pub struct CalibrationReplayCase {
    pub attempt_id: i64,
    pub target: Address,
    pub solve_block: u64,
    pub payload_json: String,
    pub expected_profit_wei: Option<RU256>,
    pub outcome_label: String,
}

#[derive(Debug, Clone)]
pub struct ContestedBenchmarkRow {
    pub builder: String,
    pub accepted: bool,
    pub outcome_label: String,
    pub latency_ms: u64,
    pub tip_band_wei: Option<u128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytecodeSlice {
    pub selectors: Vec<Bytes>,
    pub nft_callback_selectors: Vec<Bytes>,
    pub dead_end_pcs: std::collections::HashSet<usize>,
}

#[derive(Debug, Clone)]
enum DbWriteOp {
    UpsertStatus {
        address: Address,
        status: ScanStatus,
        bytecode_hash: Option<B256>,
        exploit_found: Option<bool>,
    },
    RecordVulnerableGenome {
        bytecode_hash: B256,
        contract: Address,
    },
    UpsertBytecodeSlice {
        bytecode_hash: B256,
        slice: Box<BytecodeSlice>,
    },
    UpsertBytecodeSimhash {
        bytecode_hash: B256,
        simhash: u64,
        byte_len: usize,
    },
    UpsertProofCache {
        fingerprint_hex: String,
        selector_hex: String,
        result: Box<crate::solver::memo::ProofResult>,
    },
    UpsertHoneypotSieve {
        entry: Box<crate::solver::honeypot::HoneypotEntry>,
    },
    UpsertGasGriefSieve {
        entry: Box<crate::solver::gas_grief::GasGriefEntry>,
    },
    RecordUnknownOpstackTxType {
        block_number: u64,
        tx_hash: Option<B256>,
        stage: String,
        error_class: String,
        error_message: String,
    },
    RecordScannerGapReplay {
        start_block: u64,
        end_block: u64,
        recovered: bool,
        observed_head: u64,
    },
    RecordSubmissionAttempt {
        record: Box<SubmissionAttemptRecord>,
    },
}

fn parse_enabled_env(var: &str, default: bool) -> bool {
    match std::env::var(var) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

#[cfg(not(test))]
fn contracts_db_async_writes_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| parse_enabled_env("CONTRACTS_DB_ASYNC_WRITES_ENABLED", true))
}

#[cfg(test)]
fn contracts_db_async_writes_enabled() -> bool {
    // Tests are hermetic by default: async writes are opt-in so read-after-write tests remain
    // deterministic unless explicitly testing async behavior.
    parse_enabled_env("CONTRACTS_DB_ASYNC_WRITES_TEST", false)
}

fn load_contracts_db_async_write_queue_capacity() -> usize {
    std::env::var("CONTRACTS_DB_WRITE_QUEUE_CAPACITY")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value >= 64)
        .map(|value| value.min(MAX_ASYNC_WRITE_QUEUE_CAPACITY))
        .unwrap_or(DEFAULT_ASYNC_WRITE_QUEUE_CAPACITY)
}

fn spawn_db_write_worker(path: PathBuf) -> anyhow::Result<mpsc::Sender<DbWriteOp>> {
    let capacity = load_contracts_db_async_write_queue_capacity();
    let (tx, mut rx) = mpsc::channel::<DbWriteOp>(capacity);
    std::thread::Builder::new()
        .name(format!("contracts-db-writer({})", path.display()))
        .spawn(move || {
            let db = ContractsDb { path };
            let _ = db.ensure_schema();
            let _ = db.recover_stale_in_progress();
            while let Some(op) = rx.blocking_recv() {
                let _ = match op {
                    DbWriteOp::UpsertStatus {
                        address,
                        status,
                        bytecode_hash,
                        exploit_found,
                    } => db.upsert_status_sync(address, status, bytecode_hash, exploit_found),
                    DbWriteOp::RecordVulnerableGenome {
                        bytecode_hash,
                        contract,
                    } => db.record_vulnerable_genome_sync(bytecode_hash, contract),
                    DbWriteOp::UpsertBytecodeSlice {
                        bytecode_hash,
                        slice,
                    } => db.upsert_bytecode_slice_sync(bytecode_hash, slice.as_ref()),
                    DbWriteOp::UpsertBytecodeSimhash {
                        bytecode_hash,
                        simhash,
                        byte_len,
                    } => db.upsert_bytecode_simhash_sync(bytecode_hash, simhash, byte_len),
                    DbWriteOp::UpsertProofCache {
                        fingerprint_hex,
                        selector_hex,
                        result,
                    } => {
                        db.upsert_proof_cache_sync(&fingerprint_hex, &selector_hex, result.as_ref())
                    }
                    DbWriteOp::UpsertHoneypotSieve { entry } => {
                        db.upsert_honeypot_sieve_sync(entry.as_ref())
                    }
                    DbWriteOp::UpsertGasGriefSieve { entry } => {
                        db.upsert_gas_grief_sieve_sync(entry.as_ref())
                    }
                    DbWriteOp::RecordUnknownOpstackTxType {
                        block_number,
                        tx_hash,
                        stage,
                        error_class,
                        error_message,
                    } => db.record_unknown_opstack_tx_type_sync(
                        block_number,
                        tx_hash,
                        &stage,
                        &error_class,
                        &error_message,
                    ),
                    DbWriteOp::RecordScannerGapReplay {
                        start_block,
                        end_block,
                        recovered,
                        observed_head,
                    } => db.record_scanner_gap_replay_sync(
                        start_block,
                        end_block,
                        recovered,
                        observed_head,
                    ),
                    DbWriteOp::RecordSubmissionAttempt { record } => {
                        db.record_submission_attempt_sync(*record).map(|_| ())
                    }
                };
            }
        })
        .context("failed to spawn sqlite background writer thread")?;
    Ok(tx)
}

#[derive(Debug, Clone)]
pub struct ContractsDb {
    path: PathBuf,
}

impl ContractsDb {
    pub fn open_default() -> anyhow::Result<Self> {
        Self::open(DEFAULT_DB_PATH)
    }

    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let db = Self {
            path: path.as_ref().to_path_buf(),
        };
        db.ensure_schema()?;
        db.recover_stale_in_progress()?;
        if db.should_enqueue_writes() {
            let _ = db.async_write_sender();
        }
        Ok(db)
    }

    fn ensure_schema(&self) -> anyhow::Result<()> {
        self.with_connection("ensure_schema", |conn| {
            conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS contracts (
                    address TEXT PRIMARY KEY NOT NULL,
                    block_deployed INTEGER,
                    bytecode_hash TEXT,
                    scan_status TEXT NOT NULL,
                    exploit_found INTEGER NOT NULL DEFAULT 0,
                    updated_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_contracts_scan_status ON contracts(scan_status);
                CREATE INDEX IF NOT EXISTS idx_contracts_exploit_found ON contracts(exploit_found);

                CREATE TABLE IF NOT EXISTS vulnerable_genomes (
                    bytecode_hash TEXT PRIMARY KEY NOT NULL,
                    first_contract TEXT NOT NULL,
                    first_seen_ms INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS bytecode_slices (
                    bytecode_hash TEXT PRIMARY KEY NOT NULL,
                    selectors TEXT NOT NULL,
                    nft_callback_selectors TEXT NOT NULL,
                    dead_end_pcs TEXT NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS bytecode_simhashes (
                    bytecode_hash TEXT PRIMARY KEY NOT NULL,
                    simhash_hex TEXT NOT NULL,
                    byte_len INTEGER NOT NULL,
                    band0 INTEGER NOT NULL,
                    band1 INTEGER NOT NULL,
                    band2 INTEGER NOT NULL,
                    band3 INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_bytecode_simhash_band0 ON bytecode_simhashes(band0);
                CREATE INDEX IF NOT EXISTS idx_bytecode_simhash_band1 ON bytecode_simhashes(band1);
                CREATE INDEX IF NOT EXISTS idx_bytecode_simhash_band2 ON bytecode_simhashes(band2);
                CREATE INDEX IF NOT EXISTS idx_bytecode_simhash_band3 ON bytecode_simhashes(band3);
                CREATE INDEX IF NOT EXISTS idx_bytecode_simhash_len ON bytecode_simhashes(byte_len);

                CREATE TABLE IF NOT EXISTS proof_cache (
                    fingerprint TEXT NOT NULL,
                    selector TEXT NOT NULL,
                    result TEXT NOT NULL,
                    flash_loan_amount TEXT,
                    expected_profit TEXT,
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (fingerprint, selector)
                );
                CREATE INDEX IF NOT EXISTS idx_proof_cache_result ON proof_cache(result);

                CREATE TABLE IF NOT EXISTS honeypot_sieve (
                    contract TEXT NOT NULL,
                    selector TEXT NOT NULL,
                    class TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    first_seen_ms INTEGER NOT NULL,
                    last_seen_ms INTEGER NOT NULL,
                    PRIMARY KEY (contract, selector)
                );
                CREATE INDEX IF NOT EXISTS idx_honeypot_sieve_contract ON honeypot_sieve(contract);

                CREATE TABLE IF NOT EXISTS gas_grief_sieve (
                    contract TEXT NOT NULL,
                    selector TEXT NOT NULL,
                    class TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    gas_used INTEGER NOT NULL,
                    gas_limit INTEGER NOT NULL,
                    first_seen_ms INTEGER NOT NULL,
                    last_seen_ms INTEGER NOT NULL,
                    PRIMARY KEY (contract, selector)
                );
                CREATE INDEX IF NOT EXISTS idx_gas_grief_sieve_contract ON gas_grief_sieve(contract);

                CREATE TABLE IF NOT EXISTS unknown_opstack_tx_types (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    block_number INTEGER NOT NULL,
                    tx_hash TEXT,
                    stage TEXT NOT NULL,
                    error_class TEXT NOT NULL,
                    error_message TEXT NOT NULL,
                    first_seen_ms INTEGER NOT NULL,
                    last_seen_ms INTEGER NOT NULL,
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(block_number, tx_hash, stage, error_class)
                );
                CREATE INDEX IF NOT EXISTS idx_unknown_opstack_block ON unknown_opstack_tx_types(block_number);

                CREATE TABLE IF NOT EXISTS scanner_gap_replays (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_block INTEGER NOT NULL,
                    end_block INTEGER NOT NULL,
                    recovered INTEGER NOT NULL,
                    observed_head INTEGER NOT NULL,
                    recorded_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scanner_gap_replays_recorded_at ON scanner_gap_replays(recorded_at_ms);

                CREATE TABLE IF NOT EXISTS submission_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    solve_block INTEGER NOT NULL,
                    solve_duration_ms INTEGER NOT NULL,
                    solve_started_ms INTEGER NOT NULL,
                    replay_completed_ms INTEGER,
                    send_completed_ms INTEGER,
                    tip_wei TEXT,
                    max_fee_wei TEXT,
                    expected_profit_wei TEXT,
                    realized_profit_wei TEXT,
                    realized_profit_sign INTEGER NOT NULL DEFAULT 1,
                    latency_bucket_ms INTEGER,
                    tip_band_wei TEXT,
                    chosen_builders TEXT NOT NULL,
                    outcome_label TEXT NOT NULL,
                    included INTEGER,
                    reverted INTEGER,
                    inclusion_block INTEGER,
                    contested INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT,
                    details_json TEXT,
                    created_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_submission_attempts_created_at ON submission_attempts(created_at_ms);
                CREATE INDEX IF NOT EXISTS idx_submission_attempts_outcome ON submission_attempts(outcome_label);
                CREATE INDEX IF NOT EXISTS idx_submission_attempts_contested ON submission_attempts(contested);
                CREATE INDEX IF NOT EXISTS idx_submission_attempts_solve_block ON submission_attempts(solve_block);

                CREATE TABLE IF NOT EXISTS builder_submission_outcomes (
                    attempt_id INTEGER NOT NULL,
                    builder TEXT NOT NULL,
                    accepted INTEGER NOT NULL,
                    latency_ms INTEGER NOT NULL,
                    rejection_class TEXT,
                    response_message TEXT,
                    PRIMARY KEY (attempt_id, builder),
                    FOREIGN KEY (attempt_id) REFERENCES submission_attempts(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_builder_submission_builder ON builder_submission_outcomes(builder);

                CREATE TABLE IF NOT EXISTS pnl_drift_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    expected_profit_wei TEXT NOT NULL,
                    realized_profit_wei TEXT NOT NULL,
                    realized_profit_sign INTEGER NOT NULL,
                    recorded_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_pnl_drift_recorded_at ON pnl_drift_samples(recorded_at_ms);

                -- Proxy resolution cache/telemetry (EIP-1967 / EIP-897 / Diamond facets).
                -- Used to persist discovered implementation/facet addresses for a proxy so the
                -- hydration layer can prewarm code and (optionally) reuse the info.
                CREATE TABLE IF NOT EXISTS proxy_resolutions (
                    proxy_address TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    implementation_address TEXT NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (proxy_address, chain_id, kind, implementation_address)
                );
                CREATE INDEX IF NOT EXISTS idx_proxy_resolutions_proxy_chain
                    ON proxy_resolutions(proxy_address, chain_id);
                "#,
            )?;
            if !table_has_column(conn, "builder_submission_outcomes", "response_message")? {
                conn.execute(
                    "ALTER TABLE builder_submission_outcomes ADD COLUMN response_message TEXT",
                    [],
                )?;
            }
            // Reduce reader/writer contention: the hot-path avoids on-thread writes by routing them
            // through a background worker, and WAL allows reads to proceed concurrently.
            let _ = conn.execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                "#,
            );
            Ok(())
        })
        .map(|_| ())
    }

    fn recover_stale_in_progress(&self) -> anyhow::Result<()> {
        self.with_connection("recover_stale_in_progress", |conn| {
            conn.execute(
                "UPDATE contracts SET scan_status = 'queued' WHERE scan_status = 'in_progress';",
                [],
            )
        })
        .map(|_| ())
    }

    pub fn get_all_high_priority_targets(&self) -> anyhow::Result<Vec<Address>> {
        self.with_connection("get_all_high_priority_targets", |conn| {
            // Prefer addresses with prior signal (findings/proxies/non-done state) before pure recency.
            // We still return the full set, but the ordering is higher-signal than "latest only".
            let mut stmt = conn.prepare(
                r#"
                SELECT c.address
                FROM contracts c
                LEFT JOIN proxy_resolutions pr
                    ON pr.proxy_address = c.address
                LEFT JOIN honeypot_sieve hs
                    ON hs.contract = c.address
                LEFT JOIN gas_grief_sieve gs
                    ON gs.contract = c.address
                GROUP BY c.address, c.exploit_found, c.scan_status, c.updated_at_ms, c.bytecode_hash
                ORDER BY
                    c.exploit_found DESC,
                    CASE c.scan_status
                        WHEN 'queued' THEN 2
                        WHEN 'in_progress' THEN 1
                        ELSE 0
                    END DESC,
                    CASE
                        WHEN c.bytecode_hash IS NULL OR c.bytecode_hash = '' THEN 0
                        ELSE 1
                    END DESC,
                    COUNT(DISTINCT pr.implementation_address) DESC,
                    (COUNT(DISTINCT hs.selector) + COUNT(DISTINCT gs.selector)) ASC,
                    c.updated_at_ms DESC
                "#,
            )?;
            let rows = stmt.query_map([], |row| {
                let addr_str: String = row.get(0)?;
                Address::from_str(&addr_str)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
            })?;

            let mut targets = Vec::new();
            for addr in rows.flatten() {
                targets.push(addr);
            }
            Ok(targets)
        })
    }

    pub fn upsert_bytecode_simhash(
        &self,
        bytecode_hash: B256,
        simhash: u64,
        byte_len: usize,
    ) -> anyhow::Result<()> {
        match self.enqueue_or_return(DbWriteOp::UpsertBytecodeSimhash {
            bytecode_hash,
            simhash,
            byte_len,
        }) {
            Ok(()) => Ok(()),
            Err(DbWriteOp::UpsertBytecodeSimhash {
                bytecode_hash,
                simhash,
                byte_len,
            }) => self.upsert_bytecode_simhash_sync(bytecode_hash, simhash, byte_len),
            Err(_) => Err(anyhow::anyhow!(
                "upsert_bytecode_simhash enqueue failed with mismatched op"
            )),
        }
    }

    fn upsert_bytecode_simhash_sync(
        &self,
        bytecode_hash: B256,
        simhash: u64,
        byte_len: usize,
    ) -> anyhow::Result<()> {
        let hash_hex = format!("{bytecode_hash:#x}");
        let simhash_hex = crate::storage::simhash::simhash_hex(simhash);
        let bands = crate::storage::simhash::simhash_bands16(simhash);
        let now = to_i64(now_ms());
        let byte_len = to_i64(byte_len as u64);
        self.with_connection("upsert_bytecode_simhash", |conn| {
            conn.execute(
                r#"
                INSERT INTO bytecode_simhashes (bytecode_hash, simhash_hex, byte_len, band0, band1, band2, band3, updated_at_ms)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(bytecode_hash) DO UPDATE SET
                    simhash_hex = excluded.simhash_hex,
                    byte_len = excluded.byte_len,
                    band0 = excluded.band0,
                    band1 = excluded.band1,
                    band2 = excluded.band2,
                    band3 = excluded.band3,
                    updated_at_ms = excluded.updated_at_ms
                "#,
                params![
                    hash_hex,
                    simhash_hex,
                    byte_len,
                    bands[0] as i64,
                    bands[1] as i64,
                    bands[2] as i64,
                    bands[3] as i64,
                    now
                ],
            )
        })
        .map(|_| ())
    }

    pub fn lookup_similar_bytecode_slice_by_simhash(
        &self,
        simhash: u64,
        byte_len: usize,
        max_hamming: u32,
        max_len_delta: usize,
        candidate_limit: usize,
    ) -> anyhow::Result<Option<(B256, BytecodeSlice)>> {
        let bands = crate::storage::simhash::simhash_bands16(simhash);
        let min_len = byte_len.saturating_sub(max_len_delta) as i64;
        let max_len = byte_len.saturating_add(max_len_delta) as i64;
        let limit = (candidate_limit as i64).clamp(1, 10_000);

        let rows = self.with_connection("lookup_similar_bytecode_hashes", |conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT bytecode_hash, simhash_hex, byte_len
                FROM bytecode_simhashes
                WHERE (band0 = ?1 OR band1 = ?2 OR band2 = ?3 OR band3 = ?4)
                  AND byte_len BETWEEN ?5 AND ?6
                ORDER BY updated_at_ms DESC
                LIMIT ?7
                "#,
            )?;
            let mut out = Vec::new();
            let mut rows = stmt.query(params![
                bands[0] as i64,
                bands[1] as i64,
                bands[2] as i64,
                bands[3] as i64,
                min_len,
                max_len,
                limit
            ])?;
            while let Some(row) = rows.next()? {
                out.push((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ));
            }
            Ok::<_, rusqlite::Error>(out)
        })?;

        let mut best: Option<(B256, u32)> = None;
        for (hash_raw, simhash_raw, len_raw) in rows {
            let Ok(hash) = B256::from_str(hash_raw.trim()) else {
                continue;
            };
            let Some(candidate_simhash) = crate::storage::simhash::parse_simhash_hex(&simhash_raw)
            else {
                continue;
            };
            let dist = crate::storage::simhash::hamming_distance64(simhash, candidate_simhash);
            if dist > max_hamming {
                continue;
            }
            let _len = len_raw;
            match best {
                None => best = Some((hash, dist)),
                Some((_, best_dist)) if dist < best_dist => best = Some((hash, dist)),
                _ => {}
            }
            if dist == 0 {
                break;
            }
        }

        let Some((best_hash, _)) = best else {
            return Ok(None);
        };
        let Some(slice) = self.lookup_bytecode_slice(best_hash)? else {
            return Ok(None);
        };
        Ok(Some((best_hash, slice)))
    }

    pub fn status_of(&self, address: Address) -> anyhow::Result<Option<ScanStatus>> {
        let address_hex = format!("{address:#x}");
        let status = self
            .with_connection("status_of", |conn| {
                conn.query_row(
                    "SELECT scan_status FROM contracts WHERE address = ?1 LIMIT 1",
                    params![address_hex],
                    |row| row.get::<_, String>(0),
                )
                .optional()
            })?
            .and_then(|raw| ScanStatus::from_db(raw.trim()));
        Ok(status)
    }

    pub fn is_done(&self, address: Address) -> anyhow::Result<bool> {
        Ok(matches!(self.status_of(address)?, Some(ScanStatus::Done)))
    }

    pub fn scan_status_counts(&self) -> anyhow::Result<ScanStatusCounts> {
        self.with_connection("scan_status_counts", |conn| {
            let mut stmt =
                conn.prepare("SELECT scan_status, COUNT(*) FROM contracts GROUP BY scan_status")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;

            let mut counts = ScanStatusCounts::default();
            for row in rows {
                let (status_raw, count_raw) = row?;
                let count = if count_raw <= 0 { 0 } else { count_raw as u64 };
                match ScanStatus::from_db(status_raw.trim()) {
                    Some(ScanStatus::Queued) => counts.queued = count,
                    Some(ScanStatus::InProgress) => counts.in_progress = count,
                    Some(ScanStatus::Done) => counts.done = count,
                    None => {}
                }
            }
            Ok(counts)
        })
    }

    pub fn mark_queued(&self, address: Address) -> anyhow::Result<()> {
        self.upsert_status(address, ScanStatus::Queued, None, None)
    }

    pub fn mark_in_progress(&self, address: Address) -> anyhow::Result<()> {
        self.upsert_status(address, ScanStatus::InProgress, None, None)
    }

    pub fn mark_done(
        &self,
        address: Address,
        bytecode_hash: Option<B256>,
        exploit_found: bool,
    ) -> anyhow::Result<()> {
        self.upsert_status(
            address,
            ScanStatus::Done,
            bytecode_hash,
            Some(exploit_found),
        )
    }

    pub fn record_vulnerable_genome(
        &self,
        bytecode_hash: B256,
        contract: Address,
    ) -> anyhow::Result<()> {
        match self.enqueue_or_return(DbWriteOp::RecordVulnerableGenome {
            bytecode_hash,
            contract,
        }) {
            Ok(()) => Ok(()),
            Err(DbWriteOp::RecordVulnerableGenome {
                bytecode_hash,
                contract,
            }) => self.record_vulnerable_genome_sync(bytecode_hash, contract),
            Err(_) => Err(anyhow::anyhow!(
                "record_vulnerable_genome enqueue failed with mismatched op"
            )),
        }
    }

    fn record_vulnerable_genome_sync(
        &self,
        bytecode_hash: B256,
        contract: Address,
    ) -> anyhow::Result<()> {
        let hash_hex = format!("{bytecode_hash:#x}");
        let contract_hex = format!("{contract:#x}");
        let now = to_i64(now_ms());
        self.with_connection("record_vulnerable_genome", |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO vulnerable_genomes (bytecode_hash, first_contract, first_seen_ms) VALUES (?1, ?2, ?3)",
                params![hash_hex, contract_hex, now],
            )
        })
        .map(|_| ())
    }

    pub fn known_vulnerable_contract_for_genome(
        &self,
        bytecode_hash: B256,
    ) -> anyhow::Result<Option<Address>> {
        let hash_hex = format!("{bytecode_hash:#x}");
        let raw = self.with_connection("known_vulnerable_contract_for_genome", |conn| {
            conn.query_row(
                "SELECT first_contract FROM vulnerable_genomes WHERE bytecode_hash = ?1 LIMIT 1",
                params![hash_hex],
                |row| row.get::<_, String>(0),
            )
            .optional()
        })?;
        Ok(raw.and_then(|value| Address::from_str(value.trim()).ok()))
    }

    pub fn lookup_bytecode_slice(
        &self,
        bytecode_hash: B256,
    ) -> anyhow::Result<Option<BytecodeSlice>> {
        let hash_hex = format!("{bytecode_hash:#x}");
        let row = self.with_connection("lookup_bytecode_slice", |conn| {
            conn.query_row(
                "SELECT selectors, nft_callback_selectors, dead_end_pcs FROM bytecode_slices WHERE bytecode_hash = ?1 LIMIT 1",
                params![hash_hex],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
        })?;

        let Some((selectors_raw, nft_selectors_raw, dead_end_raw)) = row else {
            return Ok(None);
        };

        let selectors = match decode_bytes_csv_strict(&selectors_raw) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    "[WARN] bytecode_slices decode failed for {} selectors: {}; forcing rescan",
                    hash_hex,
                    err
                );
                return Ok(None);
            }
        };
        let nft_callback_selectors = match decode_bytes_csv_strict(&nft_selectors_raw) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    "[WARN] bytecode_slices decode failed for {} nft selectors: {}; forcing rescan",
                    hash_hex,
                    err
                );
                return Ok(None);
            }
        };
        let dead_end_pcs = match decode_usize_csv_strict(&dead_end_raw) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    "[WARN] bytecode_slices decode failed for {} dead-end PCs: {}; forcing rescan",
                    hash_hex,
                    err
                );
                return Ok(None);
            }
        };

        Ok(Some(BytecodeSlice {
            selectors,
            nft_callback_selectors,
            dead_end_pcs,
        }))
    }

    pub fn upsert_bytecode_slice(
        &self,
        bytecode_hash: B256,
        slice: &BytecodeSlice,
    ) -> anyhow::Result<()> {
        match self.enqueue_or_return(DbWriteOp::UpsertBytecodeSlice {
            bytecode_hash,
            slice: Box::new(slice.clone()),
        }) {
            Ok(()) => Ok(()),
            Err(DbWriteOp::UpsertBytecodeSlice {
                bytecode_hash,
                slice,
            }) => self.upsert_bytecode_slice_sync(bytecode_hash, slice.as_ref()),
            Err(_) => Err(anyhow::anyhow!(
                "upsert_bytecode_slice enqueue failed with mismatched op"
            )),
        }
    }

    fn upsert_bytecode_slice_sync(
        &self,
        bytecode_hash: B256,
        slice: &BytecodeSlice,
    ) -> anyhow::Result<()> {
        let hash_hex = format!("{bytecode_hash:#x}");
        let selectors = encode_bytes_csv(&slice.selectors);
        let nft_callback_selectors = encode_bytes_csv(&slice.nft_callback_selectors);
        let dead_end_pcs = encode_usize_csv(&slice.dead_end_pcs);
        let now = to_i64(now_ms());
        self.with_connection("upsert_bytecode_slice", |conn| {
            conn.execute(
                r#"
                INSERT INTO bytecode_slices (bytecode_hash, selectors, nft_callback_selectors, dead_end_pcs, updated_at_ms)
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(bytecode_hash) DO UPDATE SET
                    selectors = excluded.selectors,
                    nft_callback_selectors = excluded.nft_callback_selectors,
                    dead_end_pcs = excluded.dead_end_pcs,
                    updated_at_ms = excluded.updated_at_ms
                "#,
                params![
                    hash_hex,
                    selectors,
                    nft_callback_selectors,
                    dead_end_pcs,
                    now
                ],
            )
        })
        .map(|_| ())
    }

    pub fn lookup_proof_cache(
        &self,
        fingerprint_hex: &str,
        selector_hex: &str,
    ) -> anyhow::Result<Option<crate::solver::memo::ProofResult>> {
        let row = self.with_connection("lookup_proof_cache", |conn| {
            conn.query_row(
                "SELECT result, flash_loan_amount, expected_profit FROM proof_cache WHERE fingerprint = ?1 AND selector = ?2 LIMIT 1",
                params![fingerprint_hex, selector_hex],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
        })?;

        let Some((result_raw, flash_raw, profit_raw)) = row else {
            return Ok(None);
        };

        match result_raw.trim() {
            "unsat" => Ok(Some(crate::solver::memo::ProofResult::Unsat)),
            "timeout" => Ok(Some(crate::solver::memo::ProofResult::Timeout)),
            "sat" => {
                let flash_raw = flash_raw.unwrap_or_default();
                let amount = RU256::from_str(flash_raw.trim()).map_err(|err| {
                    anyhow::anyhow!(
                        "proof_cache decode failed: invalid flash_loan_amount '{}' for fingerprint={} selector={}: {}",
                        flash_raw,
                        fingerprint_hex,
                        selector_hex,
                        err
                    )
                })?;
                let expected_profit = match profit_raw {
                    Some(raw) if !raw.trim().is_empty() => Some(RU256::from_str(raw.trim()).map_err(|err| {
                        anyhow::anyhow!(
                            "proof_cache decode failed: invalid expected_profit '{}' for fingerprint={} selector={}: {}",
                            raw,
                            fingerprint_hex,
                            selector_hex,
                            err
                        )
                    })?),
                    _ => None,
                };
                Ok(Some(crate::solver::memo::ProofResult::Sat {
                    flash_loan_amount: amount,
                    expected_profit,
                }))
            }
            _ => Ok(None),
        }
    }

    pub fn upsert_proof_cache(
        &self,
        fingerprint_hex: &str,
        selector_hex: &str,
        result: &crate::solver::memo::ProofResult,
    ) -> anyhow::Result<()> {
        match self.enqueue_or_return(DbWriteOp::UpsertProofCache {
            fingerprint_hex: fingerprint_hex.to_string(),
            selector_hex: selector_hex.to_string(),
            result: Box::new(result.clone()),
        }) {
            Ok(()) => Ok(()),
            Err(DbWriteOp::UpsertProofCache {
                fingerprint_hex,
                selector_hex,
                result,
            }) => self.upsert_proof_cache_sync(&fingerprint_hex, &selector_hex, result.as_ref()),
            Err(_) => Err(anyhow::anyhow!(
                "upsert_proof_cache enqueue failed with mismatched op"
            )),
        }
    }

    fn upsert_proof_cache_sync(
        &self,
        fingerprint_hex: &str,
        selector_hex: &str,
        result: &crate::solver::memo::ProofResult,
    ) -> anyhow::Result<()> {
        let now = to_i64(now_ms());
        let (result_tag, flash_amount, expected_profit) = match result {
            crate::solver::memo::ProofResult::Unsat => ("unsat".to_string(), None, None),
            crate::solver::memo::ProofResult::Timeout => ("timeout".to_string(), None, None),
            crate::solver::memo::ProofResult::Sat {
                flash_loan_amount,
                expected_profit,
            } => (
                "sat".to_string(),
                Some(flash_loan_amount.to_string()),
                expected_profit.map(|p| p.to_string()),
            ),
        };

        self.with_connection("upsert_proof_cache", |conn| {
            conn.execute(
                r#"
                INSERT INTO proof_cache (fingerprint, selector, result, flash_loan_amount, expected_profit, updated_at_ms)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(fingerprint, selector) DO UPDATE SET
                    result = excluded.result,
                    flash_loan_amount = excluded.flash_loan_amount,
                    expected_profit = excluded.expected_profit,
                    updated_at_ms = excluded.updated_at_ms
                "#,
                params![
                    fingerprint_hex,
                    selector_hex,
                    result_tag,
                    flash_amount,
                    expected_profit,
                    now
                ],
            )
        })
        .map(|_| ())
    }

    pub fn lookup_honeypot_sieve(
        &self,
        contract: Address,
        selector: [u8; 4],
    ) -> anyhow::Result<Option<crate::solver::honeypot::HoneypotEntry>> {
        let contract_hex = format!("{:#x}", contract);
        let selector_hex = format!("0x{}", hex::encode(selector));
        self.with_connection("lookup_honeypot_sieve", |conn| {
            let row: Option<(String, String)> = conn
                .query_row(
                    "SELECT class, reason FROM honeypot_sieve WHERE contract = ?1 AND selector = ?2 LIMIT 1",
                    params![contract_hex, selector_hex],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .optional()?;
            let Some((class_raw, reason)) = row else {
                return Ok(None);
            };
            let Some(class) = crate::solver::honeypot::HoneypotClass::from_str(&class_raw) else {
                return Ok(None);
            };
            Ok(Some(crate::solver::honeypot::HoneypotEntry {
                contract,
                selector,
                class,
                reason,
            }))
        })
    }

    pub fn replace_proxy_resolutions(
        &self,
        proxy: Address,
        chain_id: u64,
        kind: &str,
        implementations: &[Address],
    ) -> anyhow::Result<()> {
        let proxy_hex = format!("{proxy:#x}");
        let chain_id_i64 = to_i64(chain_id);
        let now = to_i64(now_ms());
        self.with_connection("replace_proxy_resolutions", |conn| {
            conn.execute(
                "DELETE FROM proxy_resolutions WHERE proxy_address = ?1 AND chain_id = ?2 AND kind = ?3",
                params![proxy_hex, chain_id_i64, kind],
            )?;
            for addr in implementations {
                let addr_hex = format!("{addr:#x}");
                conn.execute(
                    "INSERT OR REPLACE INTO proxy_resolutions(proxy_address, chain_id, kind, implementation_address, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![proxy_hex, chain_id_i64, kind, addr_hex, now],
                )?;
            }
            Ok(())
        })
        .map(|_| ())
    }

    pub fn proxy_resolutions_for(
        &self,
        proxy: Address,
        chain_id: u64,
    ) -> anyhow::Result<Vec<(String, Address)>> {
        let proxy_hex = format!("{proxy:#x}");
        let chain_id_i64 = to_i64(chain_id);
        self.with_connection("proxy_resolutions_for", |conn| {
            let mut stmt = conn.prepare(
                "SELECT kind, implementation_address FROM proxy_resolutions WHERE proxy_address = ?1 AND chain_id = ?2 ORDER BY updated_at_ms DESC",
            )?;
            let mut rows = stmt.query(params![proxy_hex, chain_id_i64])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                let kind: String = row.get(0)?;
                let addr_hex: String = row.get(1)?;
                let parsed = Address::from_str(addr_hex.trim()).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("invalid address '{addr_hex}': {e}"),
                        )),
                    )
                })?;
                out.push((kind, parsed));
            }
            Ok(out)
        })
    }

    pub fn upsert_honeypot_sieve(
        &self,
        entry: &crate::solver::honeypot::HoneypotEntry,
    ) -> anyhow::Result<()> {
        match self.enqueue_or_return(DbWriteOp::UpsertHoneypotSieve {
            entry: Box::new(entry.clone()),
        }) {
            Ok(()) => Ok(()),
            Err(DbWriteOp::UpsertHoneypotSieve { entry }) => {
                self.upsert_honeypot_sieve_sync(entry.as_ref())
            }
            Err(_) => Err(anyhow::anyhow!(
                "upsert_honeypot_sieve enqueue failed with mismatched op"
            )),
        }
    }

    fn upsert_honeypot_sieve_sync(
        &self,
        entry: &crate::solver::honeypot::HoneypotEntry,
    ) -> anyhow::Result<()> {
        let contract_hex = format!("{:#x}", entry.contract);
        let selector_hex = format!("0x{}", hex::encode(entry.selector));
        let now = to_i64(now_ms());
        let class = entry.class.as_str().to_string();
        let reason = entry.reason.clone();
        self.with_connection("upsert_honeypot_sieve", |conn| {
            conn.execute(
                r#"
                INSERT INTO honeypot_sieve (contract, selector, class, reason, first_seen_ms, last_seen_ms)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(contract, selector) DO UPDATE SET
                    class = excluded.class,
                    reason = excluded.reason,
                    last_seen_ms = excluded.last_seen_ms
                "#,
                params![contract_hex, selector_hex, class, reason, now, now],
            )?;
            Ok(())
        })
    }

    pub fn lookup_gas_grief_sieve(
        &self,
        contract: Address,
        selector: [u8; 4],
    ) -> anyhow::Result<Option<crate::solver::gas_grief::GasGriefEntry>> {
        let contract_hex = format!("{:#x}", contract);
        let selector_hex = format!("0x{}", hex::encode(selector));
        self.with_connection("lookup_gas_grief_sieve", |conn| {
            let row: Option<(String, String, i64, i64)> = conn
                .query_row(
                    "SELECT class, reason, gas_used, gas_limit FROM gas_grief_sieve WHERE contract = ?1 AND selector = ?2 LIMIT 1",
                    params![contract_hex, selector_hex],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, i64>(2)?,
                            r.get::<_, i64>(3)?,
                        ))
                    },
                )
                .optional()?;
            let Some((class_raw, reason, gas_used_raw, gas_limit_raw)) = row else {
                return Ok(None);
            };
            let Some(class) = crate::solver::gas_grief::GasGriefClass::from_str(&class_raw) else {
                return Ok(None);
            };
            Ok(Some(crate::solver::gas_grief::GasGriefEntry {
                contract,
                selector,
                class,
                reason,
                gas_used: gas_used_raw.max(0) as u64,
                gas_limit: gas_limit_raw.max(0) as u64,
            }))
        })
    }

    pub fn upsert_gas_grief_sieve(
        &self,
        entry: &crate::solver::gas_grief::GasGriefEntry,
    ) -> anyhow::Result<()> {
        match self.enqueue_or_return(DbWriteOp::UpsertGasGriefSieve {
            entry: Box::new(entry.clone()),
        }) {
            Ok(()) => Ok(()),
            Err(DbWriteOp::UpsertGasGriefSieve { entry }) => {
                self.upsert_gas_grief_sieve_sync(entry.as_ref())
            }
            Err(_) => Err(anyhow::anyhow!(
                "upsert_gas_grief_sieve enqueue failed with mismatched op"
            )),
        }
    }

    fn upsert_gas_grief_sieve_sync(
        &self,
        entry: &crate::solver::gas_grief::GasGriefEntry,
    ) -> anyhow::Result<()> {
        let contract_hex = format!("{:#x}", entry.contract);
        let selector_hex = format!("0x{}", hex::encode(entry.selector));
        let now = to_i64(now_ms());
        let class = entry.class.as_str().to_string();
        let reason = entry.reason.clone();
        let gas_used = to_i64(entry.gas_used);
        let gas_limit = to_i64(entry.gas_limit);
        self.with_connection("upsert_gas_grief_sieve", |conn| {
            conn.execute(
                r#"
                INSERT INTO gas_grief_sieve (contract, selector, class, reason, gas_used, gas_limit, first_seen_ms, last_seen_ms)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(contract, selector) DO UPDATE SET
                    class = excluded.class,
                    reason = excluded.reason,
                    gas_used = excluded.gas_used,
                    gas_limit = excluded.gas_limit,
                    last_seen_ms = excluded.last_seen_ms
                "#,
                params![
                    contract_hex,
                    selector_hex,
                    class,
                    reason,
                    gas_used,
                    gas_limit,
                    now,
                    now
                ],
            )?;
            Ok(())
        })
    }

    pub fn record_unknown_opstack_tx_type(
        &self,
        block_number: u64,
        tx_hash: Option<B256>,
        stage: &str,
        error_class: &str,
        error_message: &str,
    ) -> anyhow::Result<()> {
        match self.enqueue_or_return(DbWriteOp::RecordUnknownOpstackTxType {
            block_number,
            tx_hash,
            stage: stage.to_string(),
            error_class: error_class.to_string(),
            error_message: error_message.to_string(),
        }) {
            Ok(()) => Ok(()),
            Err(DbWriteOp::RecordUnknownOpstackTxType {
                block_number,
                tx_hash,
                stage,
                error_class,
                error_message,
            }) => self.record_unknown_opstack_tx_type_sync(
                block_number,
                tx_hash,
                &stage,
                &error_class,
                &error_message,
            ),
            Err(_) => Err(anyhow::anyhow!(
                "record_unknown_opstack_tx_type enqueue failed with mismatched op"
            )),
        }
    }

    fn record_unknown_opstack_tx_type_sync(
        &self,
        block_number: u64,
        tx_hash: Option<B256>,
        stage: &str,
        error_class: &str,
        error_message: &str,
    ) -> anyhow::Result<()> {
        let now = to_i64(now_ms());
        let hash = tx_hash.map(|h| format!("{h:#x}"));
        let compact_message = compact_text(error_message, 320);
        self.with_connection("record_unknown_opstack_tx_type", |conn| {
            conn.execute(
                r#"
                INSERT INTO unknown_opstack_tx_types (
                    block_number, tx_hash, stage, error_class, error_message, first_seen_ms, last_seen_ms, occurrences
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1)
                ON CONFLICT(block_number, tx_hash, stage, error_class) DO UPDATE SET
                    error_message = excluded.error_message,
                    last_seen_ms = excluded.last_seen_ms,
                    occurrences = unknown_opstack_tx_types.occurrences + 1
                "#,
                params![
                    to_i64(block_number),
                    hash,
                    stage,
                    error_class,
                    compact_message,
                    now,
                ],
            )
        })
        .map(|_| ())
    }

    pub fn record_scanner_gap_replay(
        &self,
        start_block: u64,
        end_block: u64,
        recovered: bool,
        observed_head: u64,
    ) -> anyhow::Result<()> {
        match self.enqueue_or_return(DbWriteOp::RecordScannerGapReplay {
            start_block,
            end_block,
            recovered,
            observed_head,
        }) {
            Ok(()) => Ok(()),
            Err(DbWriteOp::RecordScannerGapReplay {
                start_block,
                end_block,
                recovered,
                observed_head,
            }) => self.record_scanner_gap_replay_sync(
                start_block,
                end_block,
                recovered,
                observed_head,
            ),
            Err(_) => Err(anyhow::anyhow!(
                "record_scanner_gap_replay enqueue failed with mismatched op"
            )),
        }
    }

    fn record_scanner_gap_replay_sync(
        &self,
        start_block: u64,
        end_block: u64,
        recovered: bool,
        observed_head: u64,
    ) -> anyhow::Result<()> {
        self.with_connection("record_scanner_gap_replay", |conn| {
            conn.execute(
                r#"
                INSERT INTO scanner_gap_replays (start_block, end_block, recovered, observed_head, recorded_at_ms)
                VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    to_i64(start_block),
                    to_i64(end_block),
                    if recovered { 1i64 } else { 0i64 },
                    to_i64(observed_head),
                    to_i64(now_ms()),
                ],
            )
        })
        .map(|_| ())
    }

    pub fn record_submission_attempt(
        &self,
        record: SubmissionAttemptRecord,
    ) -> anyhow::Result<i64> {
        match self.enqueue_or_return(DbWriteOp::RecordSubmissionAttempt {
            record: Box::new(record),
        }) {
            Ok(()) => Ok(0), // The runtime does not use attempt ids; avoid hot-path blocking.
            Err(DbWriteOp::RecordSubmissionAttempt { record }) => {
                self.record_submission_attempt_sync(*record)
            }
            Err(_) => Err(anyhow::anyhow!(
                "record_submission_attempt enqueue failed with mismatched op"
            )),
        }
    }

    fn record_submission_attempt_sync(
        &self,
        record: SubmissionAttemptRecord,
    ) -> anyhow::Result<i64> {
        let SubmissionAttemptRecord {
            target,
            objective,
            solve_block,
            solve_duration_ms,
            solve_started_ms,
            replay_completed_ms,
            send_completed_ms,
            tip_wei,
            max_fee_wei,
            expected_profit_wei,
            realized_profit_wei,
            realized_profit_negative,
            latency_bucket_ms,
            tip_band_wei,
            chosen_builders,
            outcome_label,
            included,
            reverted,
            inclusion_block,
            contested,
            payload_json,
            details_json,
            builder_outcomes,
        } = record;

        let chosen_builders_csv = if chosen_builders.is_empty() {
            "none".to_string()
        } else {
            chosen_builders.join(",")
        };

        let expected_profit_ru256 = expected_profit_wei;
        let realized_profit_ru256 = realized_profit_wei;
        let expected_profit = expected_profit_ru256.map(|v| v.to_string());
        let realized_profit = realized_profit_ru256.map(|v| v.to_string());
        let tip_wei = tip_wei.map(|v| v.to_string());
        let max_fee_wei = max_fee_wei.map(|v| v.to_string());
        let tip_band_wei = tip_band_wei.map(|v| v.to_string());

        self.with_connection("record_submission_attempt", |conn| {
            conn.execute(
                r#"
                INSERT INTO submission_attempts (
                    target,
                    objective,
                    solve_block,
                    solve_duration_ms,
                    solve_started_ms,
                    replay_completed_ms,
                    send_completed_ms,
                    tip_wei,
                    max_fee_wei,
                    expected_profit_wei,
                    realized_profit_wei,
                    realized_profit_sign,
                    latency_bucket_ms,
                    tip_band_wei,
                    chosen_builders,
                    outcome_label,
                    included,
                    reverted,
                    inclusion_block,
                    contested,
                    payload_json,
                    details_json,
                    created_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)
                "#,
                params![
                    format!("{:#x}", target),
                    objective,
                    to_i64(solve_block),
                    to_i64_u128(solve_duration_ms),
                    to_i64(solve_started_ms),
                    replay_completed_ms.map(to_i64),
                    send_completed_ms.map(to_i64),
                    tip_wei,
                    max_fee_wei,
                    expected_profit,
                    realized_profit,
                    if realized_profit_negative { -1i64 } else { 1i64 },
                    latency_bucket_ms.map(to_i64),
                    tip_band_wei,
                    chosen_builders_csv,
                    outcome_label.as_str(),
                    included.map(|v| if v { 1i64 } else { 0i64 }),
                    reverted.map(|v| if v { 1i64 } else { 0i64 }),
                    inclusion_block.map(to_i64),
                    if contested { 1i64 } else { 0i64 },
                    payload_json,
                    details_json,
                    to_i64(now_ms()),
                ],
            )?;

            let attempt_id = conn.last_insert_rowid();
            for outcome in &builder_outcomes {
                conn.execute(
                    r#"
                    INSERT OR REPLACE INTO builder_submission_outcomes (
                        attempt_id,
                        builder,
                        accepted,
                        latency_ms,
                        rejection_class,
                        response_message
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                    "#,
                    params![
                        attempt_id,
                        outcome.builder,
                        if outcome.accepted { 1i64 } else { 0i64 },
                        to_i64(outcome.latency_ms),
                        outcome.rejection_class,
                        outcome.response_message,
                    ],
                )?;
            }

            if let (Some(expected), Some(realized)) = (expected_profit_ru256, realized_profit_ru256)
            {
                conn.execute(
                    r#"
                    INSERT INTO pnl_drift_samples (
                        expected_profit_wei,
                        realized_profit_wei,
                        realized_profit_sign,
                        recorded_at_ms
                    ) VALUES (?1, ?2, ?3, ?4)
                    "#,
                    params![
                        expected.to_string(),
                        realized.to_string(),
                        if realized_profit_negative {
                            -1i64
                        } else {
                            1i64
                        },
                        to_i64(now_ms()),
                    ],
                )?;
            }

            Ok(attempt_id)
        })
    }

    pub fn builder_routing_stats(
        &self,
        sample_limit: usize,
    ) -> anyhow::Result<Vec<BuilderRoutingStats>> {
        let limit = sample_limit.max(1) as i64;
        self.with_connection("builder_routing_stats", |conn| {
            let mut stmt = conn.prepare(
                r#"
                WITH recent_attempts AS (
                    SELECT id
                    FROM submission_attempts
                    ORDER BY id DESC
                    LIMIT ?1
                )
                SELECT
                    b.builder,
                    COUNT(*) AS attempts,
                    SUM(CASE WHEN b.accepted = 1 THEN 1 ELSE 0 END) AS accepted,
                    SUM(CASE WHEN COALESCE(b.rejection_class, '') = 'outbid' THEN 1 ELSE 0 END) AS outbid_rejections,
                    AVG(CAST(b.latency_ms AS REAL)) AS avg_latency
                FROM builder_submission_outcomes b
                INNER JOIN recent_attempts r ON r.id = b.attempt_id
                GROUP BY b.builder
                "#,
            )?;

            let rows = stmt.query_map(params![limit], |row| {
                Ok(BuilderRoutingStats {
                    builder: row.get::<_, String>(0)?,
                    attempts: row.get::<_, i64>(1)? as u64,
                    accepted: row.get::<_, i64>(2)? as u64,
                    outbid_rejections: row.get::<_, i64>(3)? as u64,
                    avg_latency_ms: row.get::<_, f64>(4)?,
                })
            })?;

            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
    }

    pub fn rolling_realized_expected_ratio(
        &self,
        sample_limit: usize,
    ) -> anyhow::Result<Option<f64>> {
        let limit = sample_limit.max(1) as i64;
        let rows: Vec<(String, String, i64)> = self.with_connection("rolling_realized_expected_ratio", |conn| {
            let mut stmt = conn.prepare(
                "SELECT expected_profit_wei, realized_profit_wei, realized_profit_sign FROM pnl_drift_samples ORDER BY id DESC LIMIT ?1",
            )?;
            let mapped = stmt.query_map(params![limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in mapped {
                out.push(row?);
            }
            Ok(out)
        })?;

        if rows.is_empty() {
            return Ok(None);
        }

        let mut expected_sum = 0.0f64;
        let mut realized_sum = 0.0f64;
        for (expected_raw, realized_raw, sign) in rows {
            let Ok(expected) = RU256::from_str(expected_raw.trim()) else {
                tracing::warn!(
                    "[WARN] skipping malformed expected_profit_wei sample: `{}`",
                    compact_text(&expected_raw, 96)
                );
                continue;
            };
            let Ok(realized) = RU256::from_str(realized_raw.trim()) else {
                tracing::warn!(
                    "[WARN] skipping malformed realized_profit_wei sample: `{}`",
                    compact_text(&realized_raw, 96)
                );
                continue;
            };
            let expected_f = u256_to_f64(expected);
            let realized_f = u256_to_f64(realized);
            expected_sum += expected_f;
            if sign >= 0 {
                realized_sum += realized_f;
            }
        }

        if expected_sum <= f64::EPSILON {
            return Ok(None);
        }
        Ok(Some(realized_sum / expected_sum))
    }

    pub fn rolling_drawdown_wei(&self, sample_limit: usize) -> anyhow::Result<RU256> {
        let limit = sample_limit.max(1) as i64;
        let rows: Vec<(String, i64)> = self.with_connection("rolling_drawdown_wei", |conn| {
            let mut stmt = conn.prepare(
                "SELECT realized_profit_wei, realized_profit_sign FROM pnl_drift_samples ORDER BY id DESC LIMIT ?1",
            )?;
            let mapped = stmt.query_map(params![limit], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            let mut out = Vec::new();
            for row in mapped {
                out.push(row?);
            }
            Ok(out)
        })?;

        let mut drawdown = RU256::ZERO;
        for (raw, sign) in rows {
            if sign < 0 {
                if let Ok(v) = RU256::from_str(raw.trim()) {
                    drawdown = drawdown.saturating_add(v);
                }
            }
        }
        Ok(drawdown)
    }

    pub fn realized_loss_for_solve_block(&self, solve_block: u64) -> anyhow::Result<RU256> {
        let rows: Vec<String> = self.with_connection("realized_loss_for_solve_block", |conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT realized_profit_wei
                FROM submission_attempts
                WHERE solve_block = ?1
                  AND realized_profit_sign < 0
                  AND realized_profit_wei IS NOT NULL
                "#,
            )?;
            let mapped =
                stmt.query_map(params![to_i64(solve_block)], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in mapped {
                out.push(row?);
            }
            Ok(out)
        })?;

        let mut loss = RU256::ZERO;
        for raw in rows {
            if let Ok(value) = RU256::from_str(raw.trim()) {
                loss = loss.saturating_add(value);
            }
        }
        Ok(loss)
    }

    pub fn recent_calibration_cases(
        &self,
        limit: usize,
    ) -> anyhow::Result<Vec<CalibrationReplayCase>> {
        let limit = limit.max(1) as i64;
        self.with_connection("recent_calibration_cases", |conn| {
            let mut stmt = conn.prepare(
                r#"
                WITH latest_payloads AS (
                    SELECT MAX(id) AS id
                    FROM submission_attempts
                    WHERE payload_json IS NOT NULL
                    GROUP BY payload_json
                )
                SELECT s.id, s.target, s.solve_block, s.payload_json, s.expected_profit_wei, s.outcome_label
                FROM submission_attempts s
                INNER JOIN latest_payloads l ON l.id = s.id
                ORDER BY s.id DESC
                LIMIT ?1
                "#,
            )?;

            let mapped = stmt.query_map(params![limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?;

            let mut out = Vec::new();
            for row in mapped {
                let (attempt_id, target_raw, solve_block, payload_json, expected_raw, outcome_label) = row?;
                let target = match Address::from_str(target_raw.trim()) {
                    Ok(address) if address != Address::ZERO => address,
                    Ok(_) => {
                        tracing::warn!(
                            "[WARN] dropping calibration case {}: zero target address",
                            attempt_id
                        );
                        continue;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "[WARN] dropping calibration case {}: invalid target `{}` ({})",
                            attempt_id,
                            compact_text(&target_raw, 96),
                            err
                        );
                        continue;
                    }
                };
                let expected_profit_wei = expected_raw.and_then(|raw| match RU256::from_str(raw.trim()) {
                    Ok(v) => Some(v),
                    Err(err) => {
                        tracing::warn!(
                            "[WARN] dropping malformed expected_profit_wei in calibration case {}: {} ({})",
                            attempt_id,
                            compact_text(&raw, 96),
                            err
                        );
                        None
                    }
                });
                out.push(CalibrationReplayCase {
                    attempt_id,
                    target,
                    solve_block,
                    payload_json,
                    expected_profit_wei,
                    outcome_label,
                });
            }
            Ok(out)
        })
    }

    pub fn contested_benchmark_rows(
        &self,
        limit: usize,
    ) -> anyhow::Result<Vec<ContestedBenchmarkRow>> {
        let limit = limit.max(1) as i64;
        self.with_connection("contested_benchmark_rows", |conn| {
            let mut stmt = conn.prepare(
                r#"
                WITH contested_payloads AS (
                    SELECT MAX(id) AS id
                    FROM submission_attempts
                    WHERE contested = 1
                    GROUP BY COALESCE(payload_json, CAST(id AS TEXT))
                    ORDER BY id DESC
                    LIMIT ?1
                )
                SELECT b.builder, b.accepted, c.outcome_label, b.latency_ms, c.tip_band_wei
                FROM builder_submission_outcomes b
                INNER JOIN submission_attempts c ON c.id = b.attempt_id
                INNER JOIN contested_payloads p ON p.id = c.id
                ORDER BY b.attempt_id DESC
                "#,
            )?;

            let mapped = stmt.query_map(params![limit], |row| {
                let tip_band_raw: Option<String> = row.get(4)?;
                let tip_band_wei = tip_band_raw.and_then(|raw| raw.parse::<u128>().ok());
                Ok(ContestedBenchmarkRow {
                    builder: row.get::<_, String>(0)?,
                    accepted: row.get::<_, i64>(1)? == 1,
                    outcome_label: row.get::<_, String>(2)?,
                    latency_ms: row.get::<_, i64>(3)? as u64,
                    tip_band_wei,
                })
            })?;

            let mut out = Vec::new();
            for row in mapped {
                out.push(row?);
            }
            Ok(out)
        })
    }

    fn upsert_status(
        &self,
        address: Address,
        status: ScanStatus,
        bytecode_hash: Option<B256>,
        exploit_found: Option<bool>,
    ) -> anyhow::Result<()> {
        match self.enqueue_or_return(DbWriteOp::UpsertStatus {
            address,
            status,
            bytecode_hash,
            exploit_found,
        }) {
            Ok(()) => Ok(()),
            Err(DbWriteOp::UpsertStatus {
                address,
                status,
                bytecode_hash,
                exploit_found,
            }) => self.upsert_status_sync(address, status, bytecode_hash, exploit_found),
            Err(_) => Err(anyhow::anyhow!(
                "upsert_status enqueue failed with mismatched op"
            )),
        }
    }

    fn upsert_status_sync(
        &self,
        address: Address,
        status: ScanStatus,
        bytecode_hash: Option<B256>,
        exploit_found: Option<bool>,
    ) -> anyhow::Result<()> {
        let address_hex = format!("{address:#x}");
        let hash_hex = bytecode_hash.map(|h| format!("{h:#x}"));
        let now = to_i64(now_ms());
        self.with_connection("upsert_status", |conn| {
            conn.execute(
                r#"
                INSERT INTO contracts (address, block_deployed, bytecode_hash, scan_status, exploit_found, updated_at_ms)
                VALUES (?1, NULL, ?2, ?3, COALESCE(?4, 0), ?5)
                ON CONFLICT(address) DO UPDATE SET
                    bytecode_hash = COALESCE(excluded.bytecode_hash, contracts.bytecode_hash),
                    scan_status = excluded.scan_status,
                    exploit_found = CASE
                        WHEN excluded.exploit_found = 1 THEN 1
                        WHEN ?4 IS NULL THEN contracts.exploit_found
                        ELSE excluded.exploit_found
                    END,
                    updated_at_ms = excluded.updated_at_ms
                "#,
                params![
                    address_hex,
                    hash_hex,
                    status.as_str(),
                    exploit_found.map(|v| if v { 1i64 } else { 0i64 }),
                    now,
                ],
            )
        })
        .map(|_| ())
    }

    fn should_enqueue_writes(&self) -> bool {
        if !contracts_db_async_writes_enabled() {
            return false;
        }
        #[cfg(not(test))]
        {
            self.path.as_path() == Path::new(DEFAULT_DB_PATH)
        }
        #[cfg(test)]
        {
            true
        }
    }

    fn async_write_sender(&self) -> anyhow::Result<mpsc::Sender<DbWriteOp>> {
        #[cfg(not(test))]
        {
            if let Some(tx) = DEFAULT_DB_WRITE_TX.get() {
                return Ok(tx.clone());
            }
            let lock = DEFAULT_DB_WRITE_INIT_LOCK.get_or_init(|| Mutex::new(()));
            let _guard = lock
                .lock()
                .map_err(|_| anyhow::anyhow!("contracts.db async writer init lock poisoned"))?;
            if let Some(tx) = DEFAULT_DB_WRITE_TX.get() {
                return Ok(tx.clone());
            }
            let tx = spawn_db_write_worker(PathBuf::from(DEFAULT_DB_PATH))?;
            let _ = DEFAULT_DB_WRITE_TX.set(tx.clone());
            Ok(tx)
        }
        #[cfg(test)]
        {
            let lock = EXTRA_DB_WRITE_TX.get_or_init(|| Mutex::new(HashMap::new()));
            let mut guard = lock
                .lock()
                .map_err(|_| anyhow::anyhow!("contracts.db async writer map lock poisoned"))?;
            if let Some(tx) = guard.get(&self.path) {
                return Ok(tx.clone());
            }
            let tx = spawn_db_write_worker(self.path.clone())?;
            guard.insert(self.path.clone(), tx.clone());
            Ok(tx)
        }
    }

    fn enqueue_or_return(&self, op: DbWriteOp) -> Result<(), DbWriteOp> {
        if !self.should_enqueue_writes() {
            return Err(op);
        }
        let tx = match self.async_write_sender() {
            Ok(tx) => tx,
            Err(_) => return Err(op),
        };
        match tx.try_send(op) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(op)) => {
                let n = DEFAULT_DB_WRITE_FULL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() {
                    tracing::warn!(
                        "[WARN] contracts.db async write queue full (count={}): falling back to synchronous writes",
                        n
                    );
                }
                Err(op)
            }
            Err(mpsc::error::TrySendError::Closed(op)) => Err(op),
        }
    }

    fn with_connection<T, F>(&self, context: &str, op: F) -> anyhow::Result<T>
    where
        F: Fn(&Connection) -> rusqlite::Result<T>,
    {
        let max_attempts = 6u32;
        let mut last_err = String::new();

        for attempt in 1..=max_attempts {
            let conn = Connection::open(&self.path).with_context(|| {
                format!("failed to open sqlite database {}", self.path.display())
            })?;
            conn.busy_timeout(Duration::from_millis(5_000))
                .context("failed to configure sqlite busy timeout")?;

            match op(&conn) {
                Ok(value) => return Ok(value),
                Err(err) => {
                    last_err = err.to_string();
                    if is_sqlite_locked_error(&err) && attempt < max_attempts {
                        continue;
                    }
                    return Err(anyhow::anyhow!(
                        "{} failed for {}: {}",
                        context,
                        self.path.display(),
                        last_err
                    ));
                }
            }
        }

        Err(anyhow::anyhow!(
            "{} failed for {} after {} attempt(s): {}",
            context,
            self.path.display(),
            max_attempts,
            last_err
        ))
    }
}

pub struct ScanCompletionGuard {
    db: ContractsDb,
    address: Address,
    bytecode_hash: Option<B256>,
    exploit_found: bool,
    finished: bool,
}

impl ScanCompletionGuard {
    pub fn start(db: ContractsDb, address: Address) -> Self {
        let _ = db.mark_in_progress(address);
        Self {
            db,
            address,
            bytecode_hash: None,
            exploit_found: false,
            finished: false,
        }
    }

    pub fn set_bytecode_hash(&mut self, hash: B256) {
        self.bytecode_hash = Some(hash);
    }

    pub fn set_exploit_found(&mut self) {
        self.exploit_found = true;
    }

    pub fn finish(mut self) {
        let _ = self
            .db
            .mark_done(self.address, self.bytecode_hash, self.exploit_found);
        if self.exploit_found {
            if let Some(hash) = self.bytecode_hash {
                let _ = self.db.record_vulnerable_genome(hash, self.address);
            }
        }
        self.finished = true;
    }
}

impl Drop for ScanCompletionGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self
            .db
            .mark_done(self.address, self.bytecode_hash, self.exploit_found);
        if self.exploit_found {
            if let Some(hash) = self.bytecode_hash {
                let _ = self.db.record_vulnerable_genome(hash, self.address);
            }
        }
    }
}

fn is_sqlite_locked_error(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(code, _) => {
            matches!(
                code.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            )
        }
        _ => {
            let msg = err.to_string().to_ascii_lowercase();
            msg.contains("database is locked") || msg.contains("database is busy")
        }
    }
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let pragma = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&pragma)?;
    let mapped = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for name in mapped {
        if name?.trim() == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn now_ms() -> u64 {
    let sample = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64);
    normalize_contracts_db_now_ms(sample)
}

fn normalize_contracts_db_now_ms(sample_ms: Option<u64>) -> u64 {
    let mut prev = LAST_CONTRACTS_DB_NOW_MS.load(Ordering::Relaxed);
    loop {
        let normalized = sample_ms.unwrap_or(prev).max(prev).max(1);
        match LAST_CONTRACTS_DB_NOW_MS.compare_exchange_weak(
            prev,
            normalized,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return normalized,
            Err(actual) => prev = actual,
        }
    }
}

fn to_i64(value: u64) -> i64 {
    if value > i64::MAX as u64 {
        i64::MAX
    } else {
        value as i64
    }
}

fn to_i64_u128(value: u128) -> i64 {
    if value > i64::MAX as u128 {
        i64::MAX
    } else {
        value as i64
    }
}

fn compact_text(input: &str, max_len: usize) -> String {
    if input.chars().count() <= max_len {
        return input.to_string();
    }
    let mut out = String::new();
    for (idx, ch) in input.chars().enumerate() {
        if idx >= max_len {
            break;
        }
        out.push(ch);
    }
    out.push_str("...(truncated)");
    out
}

fn u256_to_f64(value: RU256) -> f64 {
    let as_text = value.to_string();
    as_text.parse::<f64>().unwrap_or(0.0)
}

fn encode_bytes_csv(values: &[Bytes]) -> String {
    values
        .iter()
        .map(|value| format!("0x{}", hex::encode(value.as_ref())))
        .collect::<Vec<_>>()
        .join(",")
}

fn decode_bytes_csv_strict(raw: &str) -> anyhow::Result<Vec<Bytes>> {
    let mut out = Vec::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let normalized = entry.strip_prefix("0x").unwrap_or(entry);
        let bytes = hex::decode(normalized).map_err(|err| {
            anyhow::anyhow!("invalid hex entry `{}`: {}", compact_text(entry, 80), err)
        })?;
        out.push(Bytes::from(bytes));
    }
    Ok(out)
}

fn encode_usize_csv(values: &std::collections::HashSet<usize>) -> String {
    let mut ordered = std::collections::BTreeSet::new();
    for value in values {
        ordered.insert(*value);
    }
    ordered
        .into_iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn decode_usize_csv_strict(raw: &str) -> anyhow::Result<std::collections::HashSet<usize>> {
    let mut out = std::collections::HashSet::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let value = entry.parse::<usize>().map_err(|err| {
            anyhow::anyhow!("invalid usize entry `{}`: {}", compact_text(entry, 80), err)
        })?;
        out.insert(value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_db_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("{}_{}.db", prefix, nanos))
    }

    #[test]
    fn test_contracts_db_status_lifecycle() {
        let path = temp_db_path("contracts_db_lifecycle");
        let db = ContractsDb::open(&path).expect("db open");
        let addr = Address::from([0x11; 20]);

        db.mark_queued(addr).expect("queued");
        assert_eq!(
            db.status_of(addr).expect("status"),
            Some(ScanStatus::Queued)
        );

        db.mark_in_progress(addr).expect("in progress");
        assert_eq!(
            db.status_of(addr).expect("status"),
            Some(ScanStatus::InProgress)
        );

        db.mark_done(addr, None, false).expect("done");
        assert!(db.is_done(addr).expect("is_done"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_scan_completion_guard_marks_done_on_drop() {
        let path = temp_db_path("contracts_db_guard");
        let db = ContractsDb::open(&path).expect("db open");
        let addr = Address::from([0x22; 20]);
        db.mark_queued(addr).expect("queued");

        {
            let mut guard = ScanCompletionGuard::start(db.clone(), addr);
            guard.set_exploit_found();
        }

        assert!(db.is_done(addr).expect("is_done"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_vulnerable_genome_registration_and_lookup() {
        let path = temp_db_path("contracts_db_genome");
        let db = ContractsDb::open(&path).expect("db open");
        let contract = Address::from([0x33; 20]);
        let genome = B256::from([0x44; 32]);

        assert!(db
            .known_vulnerable_contract_for_genome(genome)
            .expect("lookup before insert")
            .is_none());

        db.record_vulnerable_genome(genome, contract)
            .expect("record genome");
        assert_eq!(
            db.known_vulnerable_contract_for_genome(genome)
                .expect("lookup after insert"),
            Some(contract)
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_bytecode_slice_round_trip() {
        let path = temp_db_path("contracts_db_bytecode_slice");
        let db = ContractsDb::open(&path).expect("db open");
        let hash = B256::from([0x55; 32]);
        let slice = BytecodeSlice {
            selectors: vec![Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb])],
            nft_callback_selectors: vec![Bytes::from(vec![0x15, 0x0b, 0x7a, 0x02])],
            dead_end_pcs: [12usize, 24usize].into_iter().collect(),
        };

        assert!(db
            .lookup_bytecode_slice(hash)
            .expect("lookup before insert")
            .is_none());
        db.upsert_bytecode_slice(hash, &slice)
            .expect("insert bytecode slice");
        let round_trip = db
            .lookup_bytecode_slice(hash)
            .expect("lookup after insert")
            .expect("slice exists");

        assert_eq!(round_trip.selectors, slice.selectors);
        assert_eq!(
            round_trip.nft_callback_selectors,
            slice.nft_callback_selectors
        );
        assert_eq!(round_trip.dead_end_pcs, slice.dead_end_pcs);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_submission_attempt_and_builder_stats_round_trip() {
        let path = temp_db_path("contracts_db_submission");
        let db = ContractsDb::open(&path).expect("db open");

        let record = SubmissionAttemptRecord {
            target: Address::from([0xAA; 20]),
            objective: "unit-test".to_string(),
            solve_block: 100,
            solve_duration_ms: 1_250,
            solve_started_ms: 1,
            replay_completed_ms: Some(2),
            send_completed_ms: Some(3),
            tip_wei: Some(1_000_000_000),
            max_fee_wei: Some(2_000_000_000),
            expected_profit_wei: Some(RU256::from(1000u64)),
            realized_profit_wei: Some(RU256::from(900u64)),
            realized_profit_negative: false,
            latency_bucket_ms: Some(1_000),
            tip_band_wei: Some(1_000_000_000),
            chosen_builders: vec!["B1".to_string(), "B2".to_string()],
            outcome_label: ExecutionOutcomeLabel::NotIncluded,
            included: Some(false),
            reverted: Some(false),
            inclusion_block: None,
            contested: true,
            payload_json: Some("{\"v\":1}".to_string()),
            details_json: Some("{}".to_string()),
            builder_outcomes: vec![
                BuilderAttemptRecord {
                    builder: "B1".to_string(),
                    accepted: true,
                    latency_ms: 40,
                    rejection_class: None,
                    response_message: Some(
                        "{\"jsonrpc\":\"2.0\",\"result\":{\"bundleHash\":\"0xabc\"}}".to_string(),
                    ),
                },
                BuilderAttemptRecord {
                    builder: "B2".to_string(),
                    accepted: false,
                    latency_ms: 75,
                    rejection_class: Some("outbid".to_string()),
                    response_message: Some("HTTP 400: outbid".to_string()),
                },
            ],
        };

        let attempt_id = db
            .record_submission_attempt(record.clone())
            .expect("insert attempt");
        assert!(attempt_id > 0);

        let mut negative_record = record.clone();
        negative_record.realized_profit_wei = Some(RU256::from(123u64));
        negative_record.realized_profit_negative = true;
        db.record_submission_attempt(negative_record)
            .expect("insert negative attempt");

        let stats = db.builder_routing_stats(10).expect("routing stats");
        assert_eq!(stats.len(), 2);

        let ratio = db
            .rolling_realized_expected_ratio(10)
            .expect("rolling ratio")
            .expect("ratio exists");
        assert!(ratio > 0.0);

        let cases = db.recent_calibration_cases(5).expect("calibration cases");
        assert_eq!(cases.len(), 1);

        let contested = db.contested_benchmark_rows(5).expect("contested rows");
        assert_eq!(contested.len(), 2);

        let block_loss = db.realized_loss_for_solve_block(100).expect("block loss");
        assert_eq!(block_loss, RU256::from(123u64));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_record_unknown_opstack_tx_type_upserts_occurrence() {
        let path = temp_db_path("contracts_db_unknown_tx");
        let db = ContractsDb::open(&path).expect("db open");
        let hash = B256::from([0x7e; 32]);

        db.record_unknown_opstack_tx_type(
            1,
            Some(hash),
            "block_full",
            "unknown_tx_type",
            "unknown variant `0x7e`",
        )
        .expect("record one");
        db.record_unknown_opstack_tx_type(
            1,
            Some(hash),
            "block_full",
            "unknown_tx_type",
            "unknown variant `0x7e`",
        )
        .expect("record two");

        let rows: Vec<(i64, i64)> = db
            .with_connection("test_read_unknown", |conn| {
                let mut stmt =
                    conn.prepare("SELECT occurrences, block_number FROM unknown_opstack_tx_types")?;
                let mapped =
                    stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
                let mut out = Vec::new();
                for row in mapped {
                    out.push(row?);
                }
                Ok(out)
            })
            .expect("read unknown rows");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_normalize_contracts_db_now_ms_never_returns_zero() {
        super::LAST_CONTRACTS_DB_NOW_MS.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_contracts_db_now_ms(None), 1);
        assert!(super::normalize_contracts_db_now_ms(Some(0)) >= 1);
    }

    #[test]
    fn test_normalize_contracts_db_now_ms_clamps_clock_regressions() {
        super::LAST_CONTRACTS_DB_NOW_MS.store(321, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_contracts_db_now_ms(Some(300)), 321);
        assert_eq!(super::normalize_contracts_db_now_ms(Some(390)), 390);
    }
}
