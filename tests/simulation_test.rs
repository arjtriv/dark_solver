use dark_solver::solver::objectives::{ExploitObjective, GenericProfitObjective};
use revm::primitives::hex::FromHex;
use revm::primitives::Bytes;

async fn rpc_supports_debug_storage_range_at(rpc_url: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "debug_storageRangeAt",
        "params": [
            "latest",
            0,
            "0x0000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            1
        ]
    });

    let response = match client.post(rpc_url).json(&payload).send().await {
        Ok(r) => r,
        Err(_) => return false,
    };

    let body: serde_json::Value = match response.json().await {
        Ok(v) => v,
        Err(_) => return false,
    };

    if body.get("result").is_some() {
        return true;
    }

    match body
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64())
    {
        Some(-32601) => false,
        Some(_) => true,
        None => false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invariant_breach_candidate_detection() {
    println!("Running invariant breach candidate detection test...");

    dark_solver::solver::memo::clear_cache();
    dark_solver::solver::soundness::clear_false_positive_lemmas();

    let rpc_url = "http://localhost:8545";
    let strict_assertions = rpc_supports_debug_storage_range_at(rpc_url).await;

    // Scenario: synthetic profitable branch used as a deterministic solver fixture.
    let code_hex = "3331670de0b6b3a764000001";
    let bytecode = Bytes::from_hex(code_hex).unwrap();

    let strategy = GenericProfitObjective {
        rpc_url: rpc_url.to_string(),
        chain_id: 1,
    };
    let res = strategy.execute(&bytecode);

    if let Some(params) = res {
        println!("Invariant breach candidate found.");
        println!("Suggested Flash Loan: {}", params.flash_loan_amount);
        if let Some(profit) = params.expected_profit {
            println!("Expected Profit: {} wei", profit);
        }
    } else if strict_assertions {
        panic!("expected invariant breach candidate");
    } else {
        println!(
            "Skipping strict candidate assertion: local RPC does not support debug_storageRangeAt."
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_multistep_logical_candidate_detection() {
    println!("Running multi-step logical candidate detection test...");

    dark_solver::solver::memo::clear_cache();
    dark_solver::solver::soundness::clear_false_positive_lemmas();

    let rpc_url = "http://localhost:8545";
    let strict_assertions = rpc_supports_debug_storage_range_at(rpc_url).await;

    // Scenario: Two-Step Logic Gate.
    // Selector 1: withdraw() [0x3ccfd604] -> sets storage[0] = 1
    // Selector 2: claim() [0x4ebb5844] -> if storage[0] == 1, set storage[0] = 100 ETH
    let code_hex = "60003560e01c633ccfd6041460205760003560e01c634ebb58441460275700005b6001600055005b600054600114603257005b67056bc75e2d63100060005500";
    let bytecode = Bytes::from_hex(code_hex).unwrap();

    let strategy = GenericProfitObjective {
        rpc_url: rpc_url.to_string(),
        chain_id: 1,
    };
    let res = strategy.execute(&bytecode);

    if let Some(params) = res {
        println!("Multi-step logical candidate found.");
        println!("Steps Found: {}", params.steps.len());
        for (i, step) in params.steps.iter().enumerate() {
            println!("  Step {}: Data={:?}", i + 1, step.call_data);
        }
        assert!(
            params.steps.len() >= 2,
            "Should have found at least 2 steps"
        );
    } else if strict_assertions {
        panic!("expected multi-step candidate");
    } else {
        println!(
            "Skipping strict multi-step assertion: local RPC does not support debug_storageRangeAt."
        );
    }
}
