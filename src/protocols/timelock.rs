use crate::symbolic::utils::math::zero;
use revm::primitives::Bytes;
use z3::ast::{Bool, BV};
use z3::Context;

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

fn bytecode_contains_selector(bytecode: &Bytes, selector: [u8; 4]) -> bool {
    let bytes = bytecode.as_ref();
    for i in 0..bytes.len().saturating_sub(5) {
        if bytes[i] == 0x63 && bytes[i + 1..i + 5] == selector {
            return true;
        }
    }
    false
}

pub fn known_timelock_sniper_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("queueTransaction(address,uint256,string,bytes,uint256)"),
        selector("executeTransaction(address,uint256,string,bytes,uint256)"),
        selector("execute(uint256)"),
        selector("execute(bytes32)"),
        selector("queue(uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn has_timelock_expiry_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let has_queue_selector = bytecode_contains_selector(
        bytecode,
        selector("queueTransaction(address,uint256,string,bytes,uint256)"),
    ) || bytecode_contains_selector(bytecode, selector("queue(uint256)"));
    let has_execute_selector =
        bytecode_contains_selector(
            bytecode,
            selector("executeTransaction(address,uint256,string,bytes,uint256)"),
        ) || bytecode_contains_selector(bytecode, selector("execute(uint256)"))
            || bytecode_contains_selector(bytecode, selector("execute(bytes32)"));

    // TIMESTAMP + comparison op (LT/GT/SLT/SGT) indicates an ETA gate.
    let has_eta_time_gate = bytes.contains(&0x42)
        && (bytes.contains(&0x10)
            || bytes.contains(&0x11)
            || bytes.contains(&0x12)
            || bytes.contains(&0x13));

    has_queue_selector && has_execute_selector && has_eta_time_gate
}

pub fn timelock_window_open<'ctx>(
    ctx: &'ctx Context,
    current_timestamp: &BV<'ctx>,
    eta: &BV<'ctx>,
) -> Bool<'ctx> {
    Bool::and(
        ctx,
        &[
            &current_timestamp.bvugt(&zero(ctx)),
            &eta.bvugt(&zero(ctx)),
            &current_timestamp.bvuge(eta),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_has_timelock_expiry_pattern_detects_queue_execute_and_time_gate() {
        let queue = selector("queueTransaction(address,uint256,string,bytes,uint256)");
        let execute = selector("executeTransaction(address,uint256,string,bytes,uint256)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&queue);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&execute);
        bytecode.extend_from_slice(&[0x42, 0x10, 0x00]); // TIMESTAMP + LT
        assert!(has_timelock_expiry_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_has_timelock_expiry_pattern_rejects_missing_time_gate() {
        let queue = selector("queueTransaction(address,uint256,string,bytes,uint256)");
        let execute = selector("executeTransaction(address,uint256,string,bytes,uint256)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&queue);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&execute);
        bytecode.push(0x00);
        assert!(!has_timelock_expiry_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_timelock_window_open_rejects_pre_eta_timestamp() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let current_timestamp = BV::from_u64(&ctx, 99, 256);
        let eta = BV::from_u64(&ctx, 100, 256);

        solver.assert(&timelock_window_open(&ctx, &current_timestamp, &eta));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
