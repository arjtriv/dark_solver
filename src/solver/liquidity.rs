use crate::solver::objectives::ExploitParams;
use alloy::primitives::aliases::U24;
use alloy::primitives::{Address, U160, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use serde_json::Value;
use std::str::FromStr;
use std::time::Duration;

alloy::sol! {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(ExactInputSingleParams calldata params)
        external
        payable
        returns (uint256 amountOut);

    function quoteExactInputSingle(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        uint256 amountIn,
        uint160 sqrtPriceLimitX96
    ) external returns (uint256 amountOut);
}

#[derive(Clone, Copy, Debug)]
struct ExactInputSingleQuoteRequest {
    token_in: Address,
    token_out: Address,
    fee: U24,
    amount_in: U256,
    amount_out_minimum: U256,
    sqrt_price_limit_x96: U160,
}

#[derive(Clone, Copy, Debug)]
pub struct SlippageCheckResult {
    pub required_min_out: U256,
    pub quoted_out: U256,
    pub passed: bool,
}

fn slippage_oracle_enabled() -> bool {
    std::env::var("SLIPPAGE_ORACLE_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

pub fn slippage_solver_constraint_enabled() -> bool {
    std::env::var("SLIPPAGE_SOLVER_CONSTRAINT_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

pub fn slippage_oracle_strict() -> bool {
    std::env::var("SLIPPAGE_ORACLE_STRICT")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn slippage_oracle_timeout_ms() -> u64 {
    std::env::var("SLIPPAGE_ORACLE_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(1_200)
}

fn decode_u256_word(data: &[u8], offset: usize) -> Option<U256> {
    if data.len() < offset.saturating_add(32) {
        return None;
    }
    let mut word = [0u8; 32];
    word.copy_from_slice(&data[offset..offset + 32]);
    Some(U256::from_be_bytes(word))
}

fn decode_hex_payload(payload: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = payload.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    Ok(hex::decode(hex_part)?)
}

fn slippage_oracle_quoter(chain_id: u64) -> Option<Address> {
    let key = format!("SLIPPAGE_ORACLE_QUOTER_{chain_id}");
    if let Ok(raw) = std::env::var(key) {
        if let Ok(addr) = Address::from_str(raw.trim()) {
            return Some(addr);
        }
    }
    std::env::var("SLIPPAGE_ORACLE_QUOTER")
        .ok()
        .and_then(|raw| Address::from_str(raw.trim()).ok())
}

fn extract_exact_input_single_quote_request(
    params: &ExploitParams,
) -> Option<ExactInputSingleQuoteRequest> {
    for step in &params.steps {
        let Ok(decoded) = exactInputSingleCall::abi_decode(step.call_data.as_ref(), true) else {
            continue;
        };

        return Some(ExactInputSingleQuoteRequest {
            token_in: decoded.params.tokenIn,
            token_out: decoded.params.tokenOut,
            fee: decoded.params.fee,
            amount_in: decoded.params.amountIn,
            amount_out_minimum: decoded.params.amountOutMinimum,
            sqrt_price_limit_x96: decoded.params.sqrtPriceLimitX96,
        });
    }
    None
}

fn build_quote_call_data(request: ExactInputSingleQuoteRequest) -> Vec<u8> {
    quoteExactInputSingleCall {
        tokenIn: request.token_in,
        tokenOut: request.token_out,
        fee: request.fee,
        amountIn: request.amount_in,
        sqrtPriceLimitX96: request.sqrt_price_limit_x96,
    }
    .abi_encode()
}

fn parse_quote_result(
    payload: &[u8],
    request: ExactInputSingleQuoteRequest,
) -> anyhow::Result<SlippageCheckResult> {
    let quoted_out = decode_u256_word(payload, 0).ok_or_else(|| {
        anyhow::anyhow!(
            "slippage oracle returned malformed quote payload: expected >= 32 bytes, got {}",
            payload.len()
        )
    })?;
    Ok(SlippageCheckResult {
        required_min_out: request.amount_out_minimum,
        quoted_out,
        passed: quoted_out >= request.amount_out_minimum,
    })
}

fn perform_eth_call_blocking(
    rpc_url: &str,
    to: Address,
    call_data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(slippage_oracle_timeout_ms()))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new());
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1u64,
        "method": "eth_call",
        "params": [
            {
                "to": format!("{:#x}", to),
                "data": format!("0x{}", hex::encode(call_data))
            },
            "latest"
        ]
    });

    let response = client.post(rpc_url).json(&payload).send()?;
    let body: Value = response.json()?;
    if let Some(err) = body.get("error") {
        return Err(anyhow::anyhow!("slippage oracle eth_call error: {err}"));
    }
    let result_hex = body
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("slippage oracle eth_call missing result field"))?;
    decode_hex_payload(result_hex)
}

pub async fn verify_exact_input_single_liquidity<P, T>(
    provider: &P,
    chain_id: u64,
    params: &ExploitParams,
) -> anyhow::Result<Option<SlippageCheckResult>>
where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    if !slippage_oracle_enabled() {
        return Ok(None);
    }

    let Some(quoter) = slippage_oracle_quoter(chain_id) else {
        return Ok(None);
    };
    let Some(request) = extract_exact_input_single_quote_request(params) else {
        return Ok(None);
    };

    let call_data = build_quote_call_data(request);
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(quoter)
        .input(alloy::rpc::types::TransactionInput::new(call_data.into()));

    let raw = provider.call(&tx).await?;
    Ok(Some(parse_quote_result(raw.as_ref(), request)?))
}

/// Solve-phase slippage gate that can run from synchronous objective code.
///
/// This keeps fake-liquidity paths out of SAT candidate returns before execution.
pub fn verify_exact_input_single_liquidity_blocking(
    chain_id: u64,
    rpc_url: &str,
    params: &ExploitParams,
) -> anyhow::Result<Option<SlippageCheckResult>> {
    if !slippage_oracle_enabled() {
        return Ok(None);
    }
    let Some(quoter) = slippage_oracle_quoter(chain_id) else {
        return Ok(None);
    };
    let Some(request) = extract_exact_input_single_quote_request(params) else {
        return Ok(None);
    };

    let call_data = build_quote_call_data(request);
    let payload = perform_eth_call_blocking(rpc_url, quoter, &call_data)?;
    Ok(Some(parse_quote_result(&payload, request)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_u256_word_rejects_short_payload() {
        assert!(decode_u256_word(&[0u8; 31], 0).is_none());
    }

    #[test]
    fn test_decode_u256_word_reads_first_word_big_endian() {
        let mut buf = [0u8; 64];
        buf[31] = 0x2a;
        assert_eq!(decode_u256_word(&buf, 0), Some(U256::from(42u64)));
    }

    #[test]
    fn test_decode_hex_payload_accepts_prefixed_and_plain() {
        assert_eq!(decode_hex_payload("0x2a").expect("hex"), vec![0x2a]);
        assert_eq!(decode_hex_payload("2a").expect("hex"), vec![0x2a]);
    }
}
