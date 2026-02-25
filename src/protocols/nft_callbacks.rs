use revm::primitives::Bytes;
use z3::ast::{Ast, Bool, BV};
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

pub fn known_erc721_callback_reentrancy_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("safeTransferFrom(address,address,uint256)"),
        selector("safeTransferFrom(address,address,uint256,bytes)"),
        selector("onERC721Received(address,address,uint256,bytes)"),
        selector("withdraw()"),
        selector("claim()"),
        selector("buy(uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn known_erc1155_callback_reentrancy_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("safeTransferFrom(address,address,uint256,uint256,bytes)"),
        selector("safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)"),
        selector("onERC1155Received(address,address,uint256,uint256,bytes)"),
        selector("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"),
        selector("withdraw()"),
        selector("claim()"),
        selector("buy(uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn known_erc721_mint_callback_drain_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("mint(uint256)"),
        selector("mint(address,uint256)"),
        selector("safeMint(address,uint256)"),
        selector("safeMint(address,uint256,bytes)"),
        selector("onERC721Received(address,address,uint256,bytes)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn known_erc721_approval_hijack_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("safeTransferFrom(address,address,uint256)"),
        selector("safeTransferFrom(address,address,uint256,bytes)"),
        selector("onERC721Received(address,address,uint256,bytes)"),
        selector("setApprovalForAll(address,bool)"),
        selector("isApprovedForAll(address,address)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn has_erc721_callback_reentrancy_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let has_safe_transfer_selector = bytecode_contains_selector(
        bytecode,
        selector("safeTransferFrom(address,address,uint256)"),
    ) || bytecode_contains_selector(
        bytecode,
        selector("safeTransferFrom(address,address,uint256,bytes)"),
    );
    let has_callback_selector = bytecode_contains_selector(
        bytecode,
        selector("onERC721Received(address,address,uint256,bytes)"),
    );
    let has_external_call = bytes.contains(&0xf1); // CALL
    let has_state_write = bytes.contains(&0x55); // SSTORE

    has_safe_transfer_selector && has_callback_selector && has_external_call && has_state_write
}

pub fn has_erc1155_callback_reentrancy_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let has_transfer_selector = bytecode_contains_selector(
        bytecode,
        selector("safeTransferFrom(address,address,uint256,uint256,bytes)"),
    ) || bytecode_contains_selector(
        bytecode,
        selector("safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)"),
    );
    let has_callback_selector = bytecode_contains_selector(
        bytecode,
        selector("onERC1155Received(address,address,uint256,uint256,bytes)"),
    ) || bytecode_contains_selector(
        bytecode,
        selector("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"),
    );
    let has_external_call = bytes.contains(&0xf1); // CALL
    let has_state_write = bytes.contains(&0x55); // SSTORE

    has_transfer_selector && has_callback_selector && has_external_call && has_state_write
}

pub fn has_erc721_mint_callback_drain_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let has_mint_selector = bytecode_contains_selector(bytecode, selector("mint(uint256)"))
        || bytecode_contains_selector(bytecode, selector("mint(address,uint256)"))
        || bytecode_contains_selector(bytecode, selector("safeMint(address,uint256)"))
        || bytecode_contains_selector(bytecode, selector("safeMint(address,uint256,bytes)"));
    let has_callback_selector = bytecode_contains_selector(
        bytecode,
        selector("onERC721Received(address,address,uint256,bytes)"),
    );
    let has_external_call = bytes.contains(&0xf1); // CALL
    let has_state_write = bytes.contains(&0x55); // SSTORE

    has_mint_selector && has_callback_selector && has_external_call && has_state_write
}

pub fn has_erc721_approval_hijack_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let has_transfer_selector = bytecode_contains_selector(
        bytecode,
        selector("safeTransferFrom(address,address,uint256)"),
    ) || bytecode_contains_selector(
        bytecode,
        selector("safeTransferFrom(address,address,uint256,bytes)"),
    );
    let has_callback_selector = bytecode_contains_selector(
        bytecode,
        selector("onERC721Received(address,address,uint256,bytes)"),
    );
    let has_approval_selector =
        bytecode_contains_selector(bytecode, selector("setApprovalForAll(address,bool)"))
            || bytecode_contains_selector(bytecode, selector("isApprovedForAll(address,address)"));
    let has_external_call = bytes.contains(&0xf1); // CALL
    let has_state_write = bytes.contains(&0x55); // SSTORE

    has_transfer_selector
        && has_callback_selector
        && has_approval_selector
        && has_external_call
        && has_state_write
}

pub fn approval_hijack_succeeds<'ctx>(
    ctx: &'ctx Context,
    victim_word: &BV<'ctx>,
    operator_word: &BV<'ctx>,
    attacker_word: &BV<'ctx>,
    approved_after: &Bool<'ctx>,
) -> Bool<'ctx> {
    Bool::and(
        ctx,
        &[
            &victim_word._eq(attacker_word).not(),
            &operator_word._eq(attacker_word),
            approved_after,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_has_erc721_callback_reentrancy_pattern_detects_safe_transfer_and_callback_surface() {
        let safe_transfer = selector("safeTransferFrom(address,address,uint256)");
        let callback = selector("onERC721Received(address,address,uint256,bytes)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&safe_transfer);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&callback);
        bytecode.extend_from_slice(&[0xf1, 0x55, 0x00]); // CALL + SSTORE
        assert!(has_erc721_callback_reentrancy_pattern(&Bytes::from(
            bytecode
        )));
    }

    #[test]
    fn test_has_erc721_callback_reentrancy_pattern_rejects_missing_callback_selector() {
        let safe_transfer = selector("safeTransferFrom(address,address,uint256)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&safe_transfer);
        bytecode.extend_from_slice(&[0xf1, 0x55, 0x00]);
        assert!(!has_erc721_callback_reentrancy_pattern(&Bytes::from(
            bytecode
        )));
    }

    #[test]
    fn test_has_erc1155_callback_reentrancy_pattern_detects_transfer_and_callback_surface() {
        let transfer = selector("safeTransferFrom(address,address,uint256,uint256,bytes)");
        let callback = selector("onERC1155Received(address,address,uint256,uint256,bytes)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&transfer);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&callback);
        bytecode.extend_from_slice(&[0xf1, 0x55, 0x00]);
        assert!(has_erc1155_callback_reentrancy_pattern(&Bytes::from(
            bytecode
        )));
    }

    #[test]
    fn test_has_erc721_mint_callback_drain_pattern_detects_safe_mint_and_callback_surface() {
        let safe_mint = selector("safeMint(address,uint256)");
        let callback = selector("onERC721Received(address,address,uint256,bytes)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&safe_mint);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&callback);
        bytecode.extend_from_slice(&[0xf1, 0x55, 0x00]);
        assert!(has_erc721_mint_callback_drain_pattern(&Bytes::from(
            bytecode
        )));
    }

    #[test]
    fn test_has_erc721_approval_hijack_pattern_detects_callback_and_approval_surface() {
        let safe_transfer = selector("safeTransferFrom(address,address,uint256)");
        let callback = selector("onERC721Received(address,address,uint256,bytes)");
        let approval = selector("setApprovalForAll(address,bool)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&safe_transfer);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&callback);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&approval);
        bytecode.extend_from_slice(&[0xf1, 0x55, 0x00]);
        assert!(has_erc721_approval_hijack_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_approval_hijack_succeeds_rejects_victim_equals_attacker() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let attacker_word = BV::from_u64(&ctx, 7, 256);
        let victim_word = BV::from_u64(&ctx, 7, 256);
        let operator_word = BV::from_u64(&ctx, 7, 256);
        let approved_after = Bool::from_bool(&ctx, true);

        solver.assert(&approval_hijack_succeeds(
            &ctx,
            &victim_word,
            &operator_word,
            &attacker_word,
            &approved_after,
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
