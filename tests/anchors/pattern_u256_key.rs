use dark_solver::symbolic::patterns::{PatternInference, SHA3Trace, StoragePattern};
use dark_solver::symbolic::z3_ext::bv_from_u256;
use revm::primitives::U256;
use z3::ast::BV;
use z3::{Config, Context};

#[test]
fn test_u256_key_inference_full_width() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);

    let key = (U256::from(1) << 200) + U256::from(0xdead_beef_u64);
    let key_bv = bv_from_u256(&ctx, key);
    let slot = BV::from_u64(&ctx, 0, 256);

    let trace = SHA3Trace {
        preimage: vec![key_bv, slot],
        hash: BV::new_const(&ctx, "hash", 256),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 0,
    };

    let pattern = PatternInference::infer(None, &[], &trace);

    match pattern {
        Some(StoragePattern::FlatMapping(base, Some(concrete_key))) => {
            assert_eq!(base, U256::ZERO);
            assert_eq!(concrete_key, key);
        }
        _ => panic!("Expected FlatMapping with concrete key, got {:?}", pattern),
    }
}

#[test]
fn test_u256_key_inference_fuzz_loop() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);

    let mut seed = 0x9e3779b97f4a7c15u64;
    for i in 0..32u64 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let a = seed;
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let b = seed;
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let c = seed;
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let d = seed;

        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&a.to_be_bytes());
        bytes[8..16].copy_from_slice(&b.to_be_bytes());
        bytes[16..24].copy_from_slice(&c.to_be_bytes());
        bytes[24..32].copy_from_slice(&d.to_be_bytes());

        let key = U256::from_be_bytes(bytes);
        let key_bv = bv_from_u256(&ctx, key);
        let slot = BV::from_u64(&ctx, i % 2, 256);

        let name = format!("hash_{i}");
        let trace = SHA3Trace {
            preimage: vec![key_bv, slot],
            hash: BV::new_const(&ctx, name.as_str(), 256),
            size: BV::from_u64(&ctx, 64, 256),
            pc: i as usize,
        };

        let pattern = PatternInference::infer(None, &[], &trace);
        match pattern {
            Some(StoragePattern::FlatMapping(_, Some(concrete_key))) => {
                assert_eq!(concrete_key, key);
            }
            _ => panic!("Fuzz iteration {i} failed: {:?}", pattern),
        }
    }
}
