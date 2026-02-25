use crate::solver::objectives::ExploitParams;
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolCall;
use std::str::FromStr;

alloy::sol! {
    function executeInvariantAnchor(
        address profitToken,
        uint256 minDelta,
        address target,
        bytes calldata data
    );
}

fn load_anchor_address() -> Option<Address> {
    let raw = std::env::var("INVARIANT_ANCHOR_ADDRESS")
        .ok()
        .map(|v| v.trim().to_string())?;
    if raw.is_empty() {
        return None;
    }
    Address::from_str(&raw).ok()
}

fn load_anchor_enabled(anchor_present: bool) -> bool {
    match std::env::var("INVARIANT_ANCHOR_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => anchor_present,
    }
}

fn load_anchor_min_delta() -> U256 {
    // Interpreted in raw token units (not ETH-wei unless the profit token uses 18 decimals).
    std::env::var("INVARIANT_ANCHOR_MIN_DELTA")
        .ok()
        .and_then(|raw| U256::from_str(raw.trim()).ok())
        .filter(|v| !v.is_zero())
        .unwrap_or(U256::from(1u64))
}

fn choose_profit_token(params: &ExploitParams, chain_id: u64) -> Address {
    if params.flash_loan_token != Address::ZERO {
        return params.flash_loan_token;
    }
    // Fallback: chain WETH is a reasonable "profit proxy" in most paths that end by wrapping.
    crate::config::chains::ChainConfig::get(chain_id).weth
}

/// Atomic Invariant Anchors:
/// Wrap the final step calldata in an "invariant anchor" call that enforces
/// `balance_after >= balance_before + minDelta` for a chosen profit token.
///
/// This requires a deployed on-chain contract at `INVARIANT_ANCHOR_ADDRESS` that:
/// - restricts execution to our sender (e.g., `msg.sender == owner`)
/// - performs the inner call to `target` using `data`
/// - checks the token balance delta for `msg.sender` and reverts on failure
pub fn maybe_wrap_with_atomic_invariant_anchor(
    mut params: ExploitParams,
    chain_id: u64,
) -> ExploitParams {
    let anchor = load_anchor_address();
    let enabled = load_anchor_enabled(anchor.is_some());
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
    // the tx target; wrapping would incorrectly apply them to the anchor contract address.
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

    let profit_token = choose_profit_token(&params, chain_id);
    let min_delta = load_anchor_min_delta();

    if let Some(last) = params.steps.last_mut() {
        let inner_target = last.target;
        let inner_data = last.call_data.clone();

        let wrapped = executeInvariantAnchorCall {
            profitToken: profit_token,
            minDelta: min_delta,
            target: inner_target,
            data: inner_data,
        }
        .abi_encode();

        last.target = anchor;
        last.call_data = Bytes::from(wrapped);
    }

    params
}

pub fn decode_anchor_call_data(bytes: &Bytes) -> Option<(Address, U256, Address, Bytes)> {
    let decoded = executeInvariantAnchorCall::abi_decode(bytes.as_ref(), true).ok()?;
    Some((
        decoded.profitToken,
        decoded.minDelta,
        decoded.target,
        Bytes::from(decoded.data.to_vec()),
    ))
}
