use dark_solver::symbolic::z3_ext::bv_from_u256;
use revm::primitives::U256;
use z3::ast::Ast;
use z3::{Config, Context};

#[test]
fn test_bv_from_u256_is_total_and_bit_exact() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);

    let cases = [
        U256::ZERO,
        U256::from(1u64),
        U256::from(0xfeed_beefu64),
        U256::from(1u64) << 255,
        U256::MAX,
        U256::from_be_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65,
            0x43, 0x21, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x10, 0x20, 0x30, 0x40,
            0x50, 0x60, 0x70, 0x80,
        ]),
    ];

    for val in cases {
        let bv = bv_from_u256(&ctx, val);
        assert_eq!(bv.get_size(), 256);

        // Validate all 4 64-bit limbs match the U256 big-endian bytes exactly.
        let bytes = val.to_be_bytes::<32>();
        for limb in 0..4u32 {
            let byte_off = (limb as usize) * 8;
            let expected = u64::from_be_bytes([
                bytes[byte_off],
                bytes[byte_off + 1],
                bytes[byte_off + 2],
                bytes[byte_off + 3],
                bytes[byte_off + 4],
                bytes[byte_off + 5],
                bytes[byte_off + 6],
                bytes[byte_off + 7],
            ]);

            let high = 255 - limb * 64;
            let low = high - 63;
            let chunk = bv.extract(high, low);
            let got = chunk
                .simplify()
                .as_u64()
                .expect("64-bit extract must be a concrete numeral");
            assert_eq!(got, expected, "limb {limb} mismatch for {val:?}");
        }
    }
}
