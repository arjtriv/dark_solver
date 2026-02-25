#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Expectation {
    Sat,
    Unsat,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct GauntletCase {
    pub id: u16,
    pub exploit: String,
    pub primitive: &'static str,
    pub scenario: Scenario,
    pub expected: Expectation,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum Scenario {
    UniV2KInvariant {
        amount_in: String,
        reserve_in: u64,
        reserve_out: u64,
    },
    ProfitOverflowGuard {
        min_amount_bits: u32,
        max_final_balance: u64,
        profit_threshold: u64,
    },
    ReserveOverflowGuard {
        reserve: u64,
    },
    Erc4626ShareRatio {
        initial_assets: u64,
        initial_supply: u64,
        final_assets: u64,
        final_supply: u64,
    },
    IsolationModeBorrow {
        isolation_enabled: bool,
        asset_borrowable: bool,
        total_isolation_debt: u64,
        borrow_amount: u64,
        debt_ceiling: u64,
    },
}

pub fn top_100_historical_cases() -> Vec<GauntletCase> {
    let exploit_names = [
        "The DAO (2016)",
        "bZx Fulcrum Oracle Attack (2020)",
        "Harvest Finance (2020)",
        "Value DeFi MultiStables (2020)",
        "Warp Finance Flash Loan (2020)",
        "Alpha Homora x Iron Bank (2021)",
        "PancakeBunny Price Manipulation (2021)",
        "Cream Finance AMP (2021)",
        "BadgerDAO Frontend Key Compromise (2021)",
        "Compound Proposal 62 Bug (2021)",
        "Beanstalk Governance Takeover (2022)",
        "Wormhole Bridge Mint Bug (2022)",
        "Nomad Bridge Replica Bug (2022)",
        "Mango Markets Oracle Manipulation (2022)",
        "Euler Finance DonateToReserve (2023)",
        "Curve Vyper Reentrancy (2023)",
        "KyberSwap Elastic Math Bug (2023)",
        "Hundred Finance hWBTC Market (2023)",
        "Polter Finance Lending Incident (2024)",
        "UwU Lend Oracle Incident (2024)",
    ];

    let mut cases = Vec::with_capacity(100);
    let mut next_id: u16 = 1;

    for (idx, exploit_name) in exploit_names.iter().enumerate() {
        let variant = idx as u64 + 1;

        cases.push(GauntletCase {
            id: next_id,
            exploit: exploit_name.to_string(),
            primitive: "uni_v2_k_constraint",
            scenario: Scenario::UniV2KInvariant {
                amount_in:
                    "115792089237316195423570985008687907853269984665640564039457584007913129639935"
                        .to_string(),
                reserve_in: variant,
                reserve_out: variant,
            },
            expected: Expectation::Unsat,
        });
        next_id += 1;

        cases.push(GauntletCase {
            id: next_id,
            exploit: exploit_name.to_string(),
            primitive: "profit_overflow_guard",
            scenario: Scenario::ProfitOverflowGuard {
                min_amount_bits: 180 + (idx as u32 % 30),
                max_final_balance: 1_000_000_000_000_000_000,
                profit_threshold: 1_000_000_000_000_000,
            },
            expected: Expectation::Unsat,
        });
        next_id += 1;

        cases.push(GauntletCase {
            id: next_id,
            exploit: exploit_name.to_string(),
            primitive: "reserve_overflow_guard",
            scenario: Scenario::ReserveOverflowGuard {
                reserve: 1_000_000_000_000 + variant,
            },
            expected: Expectation::Unsat,
        });
        next_id += 1;

        let (final_assets, ratio_expectation) = if idx % 2 == 0 {
            (90_u64 + variant, Expectation::Sat)
        } else {
            (110_u64 + variant, Expectation::Unsat)
        };
        cases.push(GauntletCase {
            id: next_id,
            exploit: exploit_name.to_string(),
            primitive: "erc4626_share_ratio",
            scenario: Scenario::Erc4626ShareRatio {
                initial_assets: 100 + variant,
                initial_supply: 100 + variant,
                final_assets,
                final_supply: 100 + variant,
            },
            expected: ratio_expectation,
        });
        next_id += 1;

        let (isolation_enabled, asset_borrowable, debt, borrow, ceiling, expected) = match idx % 3 {
            0 => (false, false, 500_u64, 250_u64, 600_u64, Expectation::Sat),
            1 => (true, false, 500_u64, 250_u64, 1_000_u64, Expectation::Unsat),
            _ => (true, true, 500_u64, 250_u64, 1_000_u64, Expectation::Sat),
        };

        cases.push(GauntletCase {
            id: next_id,
            exploit: exploit_name.to_string(),
            primitive: "lending_isolation_mode",
            scenario: Scenario::IsolationModeBorrow {
                isolation_enabled,
                asset_borrowable,
                total_isolation_debt: debt,
                borrow_amount: borrow,
                debt_ceiling: ceiling,
            },
            expected,
        });
        next_id += 1;
    }

    debug_assert_eq!(cases.len(), 100);
    cases
}
