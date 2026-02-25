use crate::solver::objectives::ExploitParams;
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolCall;
use std::str::FromStr;

alloy::sol! {
    function executePinned(
        address expectedOrigin,
        uint256 expectedBlock,
        address target,
        bytes calldata data
    );
}

fn load_pinning_anchor_address() -> Option<Address> {
    let raw = std::env::var("PINNING_ANCHOR_ADDRESS")
        .ok()
        .map(|v| v.trim().to_string())?;
    if raw.is_empty() {
        return None;
    }
    Address::from_str(&raw).ok()
}

fn load_pinning_anchor_enabled(anchor_present: bool) -> bool {
    match std::env::var("PINNING_ANCHOR_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => anchor_present,
    }
}

fn load_pinning_anchor_strict_block_match() -> bool {
    std::env::var("PINNING_ANCHOR_STRICT_BLOCK_MATCH")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

pub fn pinning_anchor_strict_block_match_enabled() -> bool {
    load_pinning_anchor_strict_block_match()
}

pub fn pinning_anchor_active() -> bool {
    let anchor = load_pinning_anchor_address();
    let enabled = load_pinning_anchor_enabled(anchor.is_some());
    anchor.is_some() && enabled
}

/// Sender + Block Pinning:
/// Wrap the final step calldata in a "pinning anchor" call that enforces:
/// - `tx.origin == expectedOrigin`
/// - `block.number == expectedBlock`
///
/// This requires a deployed on-chain contract at `PINNING_ANCHOR_ADDRESS` that:
/// - validates the predicates and reverts on mismatch
/// - performs the inner call to `target` using `data` (or otherwise executes the intended payload)
///
/// NOTE: Wrapping changes `msg.sender` for the inner call. This is only safe when the final step
/// does not depend on `msg.sender` being the attacker EOA. Keep it opt-in and verify via replay.
pub fn maybe_wrap_with_pinning_anchor(
    mut params: ExploitParams,
    expected_origin: Address,
    expected_block: u64,
) -> ExploitParams {
    let anchor = load_pinning_anchor_address();
    let enabled = load_pinning_anchor_enabled(anchor.is_some());
    let Some(anchor) = anchor else {
        return params;
    };
    if !enabled {
        return params;
    }
    if params.steps.is_empty() {
        return params;
    }

    // Avoid breaking conditional bundle execution semantics: execute_if predicates are keyed to
    // the tx target; wrapping would incorrectly apply them to the pinning anchor contract address.
    let last_has_execute_if = params
        .steps
        .last()
        .and_then(|s| s.execute_if.as_ref())
        .is_some();
    if last_has_execute_if {
        return params;
    }

    // Do not wrap the only step when it is a flash-loan callback receiver call; the provider
    // expects a specific receiver interface.
    if params.steps.len() == 1 && params.flash_loan_provider != Address::ZERO {
        return params;
    }

    if let Some(last) = params.steps.last_mut() {
        let inner_target = last.target;
        let inner_data = last.call_data.clone();
        let wrapped = executePinnedCall {
            expectedOrigin: expected_origin,
            expectedBlock: U256::from(expected_block),
            target: inner_target,
            data: inner_data,
        }
        .abi_encode();
        last.target = anchor;
        last.call_data = Bytes::from(wrapped);
    }

    params
}
