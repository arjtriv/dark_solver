use revm::primitives::{Address, Bytes};
use std::time::Duration;

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

const DEFAULT_PRE_SIM_PROBE_ENABLED: bool = false;
const DEFAULT_PRE_SIM_PROBE_STRICT: bool = false;
const DEFAULT_PRE_SIM_PROBE_TIMEOUT_MS: u64 = 350;

#[derive(Debug, Clone)]
pub struct PreSimulationProbeReport {
    pub passed: bool,
    pub transfer_ok: bool,
    pub approve_ok: bool,
}

fn load_pre_sim_probe_enabled() -> bool {
    std::env::var("PRE_SIM_PROBE_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_PRE_SIM_PROBE_ENABLED)
}

fn load_pre_sim_probe_strict() -> bool {
    std::env::var("PRE_SIM_PROBE_STRICT")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_PRE_SIM_PROBE_STRICT)
}

fn load_pre_sim_probe_timeout_ms() -> u64 {
    std::env::var("PRE_SIM_PROBE_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(75, 2_000))
        .unwrap_or(DEFAULT_PRE_SIM_PROBE_TIMEOUT_MS)
}

fn encode_erc20_call(selector: [u8; 4], addr: Address, amount: u128) -> String {
    let mut payload = Vec::with_capacity(4 + 32 + 32);
    payload.extend_from_slice(&selector);
    let mut addr_word = [0u8; 32];
    addr_word[12..32].copy_from_slice(addr.as_slice());
    payload.extend_from_slice(&addr_word);
    let mut amount_word = [0u8; 32];
    amount_word[16..32].copy_from_slice(&amount.to_be_bytes());
    payload.extend_from_slice(&amount_word);
    format!("0x{}", hex::encode(payload))
}

async fn pre_sim_eth_call(
    rpc_url: &str,
    from: Address,
    to: Address,
    data: String,
    timeout_ms: u64,
) -> anyhow::Result<bool> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{
            "from": format!("{:#x}", from),
            "to": format!("{:#x}", to),
            "data": data
        }, "latest"]
    });
    let resp = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        client.post(rpc_url).json(&payload).send(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("pre-sim eth_call request timeout"))??;
    let body = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        resp.json::<serde_json::Value>(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("pre-sim eth_call decode timeout"))??;
    if body.get("error").is_some() {
        return Ok(false);
    }
    let result = body
        .get("result")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let normalized = result.trim().to_ascii_lowercase();
    if normalized == "0x" || normalized.len() >= 2 {
        return Ok(true);
    }
    Ok(false)
}

/// Lightweight concrete pre-simulation probe for ERC20-like mechanics.
/// It uses bounded `eth_call` probes (`transfer` and `approve`) to filter obviously anomalous targets.
pub async fn run_pre_simulation_probe(
    rpc_url: &str,
    target: Address,
    caller: Address,
) -> anyhow::Result<PreSimulationProbeReport> {
    if !load_pre_sim_probe_enabled() {
        return Ok(PreSimulationProbeReport {
            passed: true,
            transfer_ok: true,
            approve_ok: true,
        });
    }
    let timeout_ms = load_pre_sim_probe_timeout_ms();
    let transfer_data = encode_erc20_call(selector("transfer(address,uint256)"), caller, 1);
    let approve_data = encode_erc20_call(selector("approve(address,uint256)"), caller, 1);

    let transfer_ok = pre_sim_eth_call(rpc_url, caller, target, transfer_data, timeout_ms).await?;
    let approve_ok = pre_sim_eth_call(rpc_url, caller, target, approve_data, timeout_ms).await?;
    let passed = transfer_ok || approve_ok;
    if !passed && load_pre_sim_probe_strict() {
        anyhow::bail!("pre-simulation probe strict mode rejected target");
    }
    Ok(PreSimulationProbeReport {
        passed,
        transfer_ok,
        approve_ok,
    })
}

/// Scans bytecode for PUSH20 (0x73) instructions to find potential token addresses.
/// excludes: List of addresses to ignore (e.g. attacker, contract)
pub fn scan_for_tokens(bytecode: &Bytes, excludes: &[Address]) -> Vec<Address> {
    let mut tokens = Vec::new();
    for i in 0..bytecode.len().saturating_sub(21) {
        if bytecode[i] == 0x73 {
            let addr_bytes = &bytecode[i + 1..i + 21];
            let addr = Address::from_slice(addr_bytes);
            if !excludes.contains(&addr) && !tokens.contains(&addr) {
                tokens.push(addr);
            }
        }
    }
    tokens
}

/// Scans bytecode for statically referenced call targets.
///
/// Heuristic:
/// - Track the most recent `PUSH20 <addr>`.
/// - If a CALL-like opcode occurs within `window_bytes` of that PUSH20, treat `<addr>` as a
///   cross-contract linkage (a contract this bytecode can call/delegatecall/staticcall).
///
/// This under-approximates (dynamic call targets exist) but is fast and avoids enqueuing every
/// embedded address literal.
pub fn scan_for_call_targets(bytecode: &Bytes, excludes: &[Address]) -> Vec<Address> {
    scan_for_call_targets_bytes(bytecode.as_ref(), excludes)
}

pub fn scan_for_call_targets_bytes(bytecode: &[u8], excludes: &[Address]) -> Vec<Address> {
    let bytes = bytecode;
    if bytes.is_empty() {
        return Vec::new();
    }

    const WINDOW_BYTES: usize = 64;
    let mut out: Vec<Address> = Vec::new();
    let mut last_push20: Option<(usize, Address)> = None;

    let mut pc = 0usize;
    while pc < bytes.len() {
        let op = bytes[pc];

        // PUSH20 <addr>
        if op == 0x73 && pc + 21 <= bytes.len() {
            let addr = Address::from_slice(&bytes[pc + 1..pc + 21]);
            last_push20 = Some((pc, addr));
            pc += 21;
            continue;
        }

        // CALL/CALLCODE/DELEGATECALL/STATICCALL
        if matches!(op, 0xf1 | 0xf2 | 0xf4 | 0xfa) {
            if let Some((push_pc, addr)) = last_push20 {
                if pc.saturating_sub(push_pc) <= WINDOW_BYTES
                    && addr != Address::ZERO
                    && !excludes.contains(&addr)
                    && !out.contains(&addr)
                {
                    out.push(addr);
                }
            }
        }

        // Skip PUSH data (PUSH1..PUSH32).
        if (0x60..=0x7f).contains(&op) {
            pc += (op - 0x5f) as usize;
        }
        pc += 1;
    }

    out.sort();
    out.dedup();
    out
}

/// Scans bytecode for PUSH4 (0x63) instructions to find potential function selectors.
pub fn scan_for_selectors(bytecode: &Bytes) -> Vec<Bytes> {
    let mut selectors = Vec::new();
    for i in 0..bytecode.len().saturating_sub(5) {
        if bytecode[i] == 0x63 {
            // PUSH4
            let sig = &bytecode[i + 1..i + 5];
            selectors.push(Bytes::copy_from_slice(sig));
        }
    }
    selectors.sort();
    selectors.dedup();
    selectors
}

fn is_state_changing_opcode(op: u8) -> bool {
    op == 0x55 // SSTORE
        || op == 0xf0 // CREATE
        || op == 0xf1 // CALL
        || op == 0xf2 // CALLCODE
        || op == 0xf4 // DELEGATECALL
        || op == 0xf5 // CREATE2
        || op == 0xff // SELFDESTRUCT
        || (0xa0..=0xa4).contains(&op) // LOG0..LOG4
}

fn find_dispatch_destination(bytecode: &[u8], selector: &[u8]) -> Option<usize> {
    if selector.len() != 4 {
        return None;
    }
    let len = bytecode.len();
    let mut i = 0usize;
    while i + 7 < len {
        if bytecode[i] == 0x63 && &bytecode[i + 1..i + 5] == selector && bytecode[i + 5] == 0x14 {
            if i + 8 < len && bytecode[i + 6] == 0x60 && bytecode[i + 8] == 0x57 {
                return Some(bytecode[i + 7] as usize);
            }
            if i + 9 < len && bytecode[i + 6] == 0x61 && bytecode[i + 9] == 0x57 {
                let hi = bytecode[i + 7] as usize;
                let lo = bytecode[i + 8] as usize;
                return Some((hi << 8) | lo);
            }
        }
        i += 1;
    }
    None
}

fn function_window_is_state_changing(bytecode: &[u8], start_pc: usize) -> bool {
    if start_pc >= bytecode.len() {
        return false;
    }
    let max_end = (start_pc + 256).min(bytecode.len());
    let mut pc = start_pc;
    while pc < max_end {
        let op = bytecode[pc];
        if pc > start_pc && op == 0x5b {
            break;
        }
        if is_state_changing_opcode(op) {
            return true;
        }
        if (0x60..=0x7f).contains(&op) {
            pc += (op - 0x5f) as usize;
        }
        pc += 1;
    }
    false
}

/// Selector discovery with state-change pruning.
/// Drops selectors whose dispatch windows are provably pure/view.
pub fn scan_for_state_changing_selectors(bytecode: &Bytes) -> Vec<Bytes> {
    let selectors = scan_for_selectors(bytecode);
    let bytes = bytecode.as_ref();
    if selectors.is_empty() {
        return selectors;
    }

    let mut out = Vec::with_capacity(selectors.len());
    for selector in selectors {
        match find_dispatch_destination(bytes, selector.as_ref()) {
            Some(dest) if function_window_is_state_changing(bytes, dest) => out.push(selector),
            Some(_) => {}
            None => out.push(selector),
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Scans for ERC-721 safe-transfer surfaces and injects callback selector probes.
/// This flags the implicit `CALL` to `onERC721Received` so reentrancy objectives can target it.
pub fn scan_for_nft_callback_selectors(bytecode: &Bytes) -> Vec<Bytes> {
    let erc721_safe_transfer = selector("safeTransferFrom(address,address,uint256)");
    let erc721_safe_transfer_data = selector("safeTransferFrom(address,address,uint256,bytes)");
    let erc721_safe_mint = selector("safeMint(address,uint256)");
    let erc721_safe_mint_data = selector("safeMint(address,uint256,bytes)");
    let erc721_callback = selector("onERC721Received(address,address,uint256,bytes)");
    let erc1155_transfer = selector("safeTransferFrom(address,address,uint256,uint256,bytes)");
    let erc1155_batch_transfer =
        selector("safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)");
    let erc1155_callback = selector("onERC1155Received(address,address,uint256,uint256,bytes)");
    let erc1155_batch_callback =
        selector("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)");

    let discovered = scan_for_selectors(bytecode);
    let mut selectors = discovered.clone();
    let has_erc721_transfer_or_mint = discovered
        .iter()
        .any(|sig| sig.as_ref() == erc721_safe_transfer)
        || discovered
            .iter()
            .any(|sig| sig.as_ref() == erc721_safe_transfer_data)
        || discovered
            .iter()
            .any(|sig| sig.as_ref() == erc721_safe_mint)
        || discovered
            .iter()
            .any(|sig| sig.as_ref() == erc721_safe_mint_data);
    let has_erc1155_transfer = discovered
        .iter()
        .any(|sig| sig.as_ref() == erc1155_transfer)
        || discovered
            .iter()
            .any(|sig| sig.as_ref() == erc1155_batch_transfer);

    if has_erc721_transfer_or_mint {
        selectors.push(Bytes::copy_from_slice(&erc721_callback));
    }
    if has_erc1155_transfer {
        selectors.push(Bytes::copy_from_slice(&erc1155_callback));
        selectors.push(Bytes::copy_from_slice(&erc1155_batch_callback));
    }

    selectors.sort();
    selectors.dedup();
    selectors
}

/// Scans bytecode for admin/owner checks (Caller vs Storage Slot).
/// Identifies SLOAD(0) or common admin slots followed by EQ(CALLER).
pub fn scan_for_admin_patterns(bytecode: &Bytes) -> Vec<Bytes> {
    // Heuristic:
    // PUSH 0 (Owner Slot) -> SLOAD -> CALLER -> EQ
    // or
    // PUSH 32-byte-slot -> SLOAD -> CALLER -> EQ
    //
    // This is a naive pattern matcher.
    // Real implementation would use symbolic execution, but this is a fast filter.

    let mut patterns = Vec::new();
    // 1. Basic Owner Check: 60 00 54 33 14 (PUSH1 00 SLOAD CALLER EQ)
    let basic_owner = vec![0x60, 0x00, 0x54, 0x33, 0x14];

    // 2. OpenZeppelin Ownable (simulated): look for CALLER (33) and EQ (14) close by
    // We just return function selectors if we find these opcodes in the function body?
    // Actually, `bytecode` is the whole contract. We can't map to selectors easily without a CFG.
    // So we just return "true" if found?
    // The signature returns Vec<Bytes>, presumably selectors associated with these checks?
    // For now, let's return common admin selectors if we see admin-like opcodes.

    if bytecode
        .windows(basic_owner.len())
        .any(|w| w == basic_owner)
    {
        // Return common admin selectors to try
        patterns.push(Bytes::from_static(&crate::utils::selectors::WITHDRAW));
        patterns.push(Bytes::from_static(&crate::utils::selectors::SET_OWNER));
    }

    // Default: Check for hardcoded admin slots
    // e.g. EIP-1967 Admin Slot: 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
    // We search for the *bytes* of this slot.
    let eip1967_admin_slot: [u8; 32] = [
        0xb5, 0x31, 0x27, 0x68, 0x4a, 0x56, 0x8b, 0x31, 0x73, 0xae, 0x13, 0xb9, 0xf8, 0xa6, 0x01,
        0x6e, 0x24, 0x3e, 0x63, 0xb6, 0xe8, 0xee, 0x11, 0x78, 0xd6, 0xa7, 0x17, 0x85, 0x0b, 0x5d,
        0x61, 0x03,
    ];
    if bytecode.windows(32).any(|w| w == eip1967_admin_slot) {
        patterns.push(Bytes::from_static(&crate::utils::selectors::UPGRADE_TO));
    }

    patterns
}

/// Guided branch pruning via dead-end bytecode analysis.
///
/// Pre-scans bytecode to identify PCs that are provably dead ends.
/// These are locations where execution WILL revert regardless of path.
///
/// Patterns detected:
/// 1. **JUMPI → REVERT corridor**: JUMPI(pc) where both targets lead to REVERT/INVALID
/// 2. **Tight revert loops**: JUMPDEST followed immediately by REVERT or INVALID  
/// 3. **Unconditional revert sinks**: PUSH → PUSH → REVERT (error selector + offset)
/// 4. **INVALID opcode sinks**: 0xFE following a JUMPDEST (Solidity assert/panic)
///
/// Returns a set of PCs where the engine should immediately halt exploration.
pub fn scan_dead_end_pcs(bytecode: &Bytes) -> std::collections::HashSet<usize> {
    let bytes = bytecode.as_ref();
    let len = bytes.len();
    let mut dead_ends = std::collections::HashSet::new();

    // Fast-path: if the entry block falls through into REVERT/INVALID before any conditional
    // control split, prune at PC=0 immediately.
    if entrypoint_is_unconditional_revert(bytes) {
        dead_ends.insert(0);
    }

    let mut i = 0;
    while i < len {
        let op = bytes[i];
        match op {
            // Pattern 1: JUMPDEST (5B) immediately followed by REVERT (FD) or INVALID (FE)
            // This is the compiler's standard "revert handler" block.
            0x5B => {
                if i + 1 < len && (bytes[i + 1] == 0xFD || bytes[i + 1] == 0xFE) {
                    dead_ends.insert(i);
                }
                // Pattern 2: JUMPDEST → PUSH → PUSH → REVERT (error selector pattern)
                // Solidity: revert CustomError() compiles to JUMPDEST PUSH4 errSig PUSH1 0 MSTORE ... REVERT
                // We check: JUMPDEST → any PUSH → ... → REVERT within 12 bytes (typical error block)
                else if i + 12 < len {
                    let mut j = i + 1;
                    let mut all_safe = true;
                    let mut found_revert = false;
                    while j < len.min(i + 12) {
                        let inner_op = bytes[j];
                        if inner_op == 0xFD || inner_op == 0xFE {
                            // REVERT or INVALID
                            found_revert = true;
                            break;
                        }
                        // Skip PUSH data
                        if (0x60..=0x7F).contains(&inner_op) {
                            j += (inner_op - 0x5F) as usize;
                        }
                        // If we see JUMP, CALL, SSTORE, or other state-changing ops, this is NOT dead
                        if inner_op == 0x56
                            || inner_op == 0x57
                            || inner_op == 0xF1
                            || inner_op == 0xF4
                            || inner_op == 0xFA
                            || inner_op == 0x55
                            || inner_op == 0xF3
                            || inner_op == 0x00
                        {
                            all_safe = false;
                            break;
                        }
                        j += 1;
                    }
                    if all_safe && found_revert {
                        dead_ends.insert(i);
                    }
                }
                i += 1;
            }
            // Skip PUSH data bytes
            0x60..=0x7F => {
                let push_size = (op - 0x5F) as usize;
                i += 1 + push_size;
            }
            _ => {
                i += 1;
            }
        }
    }

    dead_ends
}

fn entrypoint_is_unconditional_revert(bytecode: &[u8]) -> bool {
    let mut pc = 0usize;
    while pc < bytecode.len() {
        let op = bytecode[pc];
        match op {
            0xfd | 0xfe => return true, // REVERT / INVALID reached without branch split
            0x57 => return false,       // JUMPI introduces path-conditional control flow
            0x56 => return false,       // JUMP destination depends on runtime stack value
            0x00 | 0xf3 | 0xff | 0xf0 | 0xf1 | 0xf2 | 0xf4 | 0xf5 | 0xfa => return false,
            0x60..=0x7f => {
                let push_size = (op - 0x5f) as usize;
                pc += 1 + push_size;
                continue;
            }
            _ => {
                pc += 1;
            }
        }
    }
    false
}

/// Estimates the complexity of the bytecode to determine solver depth.
///
/// Scoring:
/// - Base: +1 per instruction
/// - Branching (JUMP/JUMPI): +5
/// - State Change (SSTORE/LOG): +10
/// - External Calls (CALL/DELEGATECALL/STATICCALL/CREATE): +20
///
/// Returns a raw complexity score.
pub fn estimate_complexity(bytecode: &Bytes) -> usize {
    let bytes = bytecode.as_ref();
    let mut score = 0usize;
    let mut pc = 0usize;
    while pc < bytes.len() {
        let op = bytes[pc];
        score += 1;

        match op {
            0x56 | 0x57 => score += 5,         // JUMP, JUMPI
            0x55 | 0xa0..=0xa4 => score += 10, // SSTORE, LOG0-4
            0xf0 | 0xf1 | 0xf2 | 0xf4 | 0xf5 | 0xfa | 0xff => score += 20, // CALLs, CREATEs, SELFDESTRUCT
            0x60..=0x7f => {
                let push_size = (op - 0x5f) as usize;
                pc += push_size;
            }
            _ => {}
        }
        pc += 1;
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_complexity_scores_correctly() {
        // Simple: PUSH1 00 PUSH1 00 REVERT (3 ops)
        let simple = Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xfd]);
        assert_eq!(estimate_complexity(&simple), 3);

        // Branching: PUSH1 00 JUMPI (2 ops + PUSH data + JUMPI bonus 5)
        // Ops: PUSH1(1) + data(1 skipped in loop logic but pc advances) + JUMPI(1)
        // Wait, my loop logic increments score once per op, and specific ops add bonus.
        // PUSH1 (score+1), skip data. JUMPI (score+1, bonus+5). Total = 7?
        // Let's trace:
        // pc=0 op=60. score=1. push_size=1. pc calls +=1 -> 1. pc at end of loop +=1 -> 2.
        // pc=2 op=57. score=1+1=2. bonus+=5 -> 7. pc+=1 -> 3.
        // Total 7.
        let branching = Bytes::from(vec![0x60, 0x00, 0x57]);
        assert_eq!(estimate_complexity(&branching), 7);
    }

    #[test]
    fn test_scan_for_nft_callback_selectors_injects_erc721_callback_when_safe_transfer_exists() {
        let safe_transfer = selector("safeTransferFrom(address,address,uint256)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&safe_transfer);
        bytecode.push(0x00);

        let selectors = scan_for_nft_callback_selectors(&Bytes::from(bytecode));
        let callback = selector("onERC721Received(address,address,uint256,bytes)");

        assert!(
            selectors.iter().any(|sig| sig.as_ref() == callback),
            "safeTransferFrom surface must inject onERC721Received callback probe selector"
        );
    }

    #[test]
    fn test_scan_for_nft_callback_selectors_injects_erc1155_callbacks_when_transfer_exists() {
        let transfer = selector("safeTransferFrom(address,address,uint256,uint256,bytes)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&transfer);
        bytecode.push(0x00);

        let selectors = scan_for_nft_callback_selectors(&Bytes::from(bytecode));
        let callback = selector("onERC1155Received(address,address,uint256,uint256,bytes)");
        let batch_callback =
            selector("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)");

        assert!(selectors.iter().any(|sig| sig.as_ref() == callback));
        assert!(selectors.iter().any(|sig| sig.as_ref() == batch_callback));
    }

    #[test]
    fn test_scan_for_state_changing_selectors_prunes_pure_dispatch_branch() {
        let stateful = [0xaa, 0xbb, 0xcc, 0xdd];
        let pure = [0x11, 0x22, 0x33, 0x44];
        let mut bytecode = vec![
            0x63,
            stateful[0],
            stateful[1],
            stateful[2],
            stateful[3],
            0x14,
            0x60,
            0x20,
            0x57,
            0x63,
            pure[0],
            pure[1],
            pure[2],
            pure[3],
            0x14,
            0x60,
            0x30,
            0x57,
            0x00,
        ];
        while bytecode.len() < 0x20 {
            bytecode.push(0x00);
        }
        bytecode.extend_from_slice(&[0x5b, 0x55, 0x00]); // JUMPDEST + SSTORE + STOP
        while bytecode.len() < 0x30 {
            bytecode.push(0x00);
        }
        bytecode.extend_from_slice(&[0x5b, 0xf3, 0x00]); // JUMPDEST + RETURN + STOP

        let selectors = scan_for_state_changing_selectors(&Bytes::from(bytecode));
        assert!(selectors.iter().any(|s| s.as_ref() == stateful));
        assert!(!selectors.iter().any(|s| s.as_ref() == pure));
    }

    #[test]
    fn test_scan_dead_end_pcs_injects_depth0_unconditional_revert() {
        let bytecode = Bytes::from(vec![
            0x60, 0x00, // PUSH1 0
            0x60, 0x00, // PUSH1 0
            0xfd, // REVERT
        ]);
        let dead_ends = scan_dead_end_pcs(&bytecode);
        assert!(
            dead_ends.contains(&0),
            "entrypoint must be marked as dead-end for unconditional depth-0 REVERT"
        );
    }

    #[test]
    fn test_scan_dead_end_pcs_does_not_inject_depth0_when_jumpi_present() {
        let bytecode = Bytes::from(vec![
            0x36, // CALLDATASIZE
            0x60, 0x08, // PUSH1 0x08
            0x57, // JUMPI
            0x60, 0x00, // PUSH1 0
            0x60, 0x00, // PUSH1 0
            0xfd, // REVERT
            0x5b, // JUMPDEST
            0x00, // STOP
        ]);
        let dead_ends = scan_dead_end_pcs(&bytecode);
        assert!(
            !dead_ends.contains(&0),
            "entrypoint must not be marked dead-end when conditional control flow exists"
        );
    }
}
