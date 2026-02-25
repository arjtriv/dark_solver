use revm::primitives::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Groth16AuditIssue {
    MissingPublicInputBinding,
}

fn has_push1(bytecode: &Bytes, value: u8) -> bool {
    bytecode
        .as_ref()
        .windows(2)
        .any(|w| w[0] == 0x60 && w[1] == value)
}

fn has_groth16_bn254_precompile_surface(bytecode: &Bytes) -> bool {
    // Groth16 verifiers on EVM typically use these BN254 precompiles:
    // 0x06 (add), 0x07 (mul), 0x08 (pairing).
    has_push1(bytecode, 0x06) && has_push1(bytecode, 0x07) && has_push1(bytecode, 0x08)
}

fn parse_push_immediate_u64(opcode: u8, bytes: &[u8]) -> Option<(u64, usize)> {
    if !(0x60..=0x7f).contains(&opcode) {
        return None;
    }
    let n = (opcode - 0x5f) as usize;
    if bytes.len() < 1 + n {
        return None;
    }
    let imm = &bytes[1..1 + n];
    let take = imm.len().min(8);
    let mut buf = [0u8; 8];
    buf[8 - take..].copy_from_slice(&imm[imm.len() - take..]);
    Some((u64::from_be_bytes(buf), 1 + n))
}

fn max_constant_calldata_load_offset(bytecode: &Bytes) -> Option<u64> {
    // Conservative scan for `PUSHn <off>; CALLDATALOAD`.
    // If verifiers never load beyond the proof header region (~0x80), they are likely not binding
    // public inputs into their linear combination.
    let mut i = 0usize;
    let code = bytecode.as_ref();
    let mut saw = false;
    let mut max_off = 0u64;
    while i < code.len() {
        let op = code[i];
        if let Some((imm, advance)) = parse_push_immediate_u64(op, &code[i..]) {
            let next = i + advance;
            if next < code.len() && code[next] == 0x35 {
                // CALLDATALOAD
                saw = true;
                if imm > max_off {
                    max_off = imm;
                }
            }
            i = i.saturating_add(advance);
            continue;
        }
        i = i.saturating_add(1);
    }
    if saw {
        Some(max_off)
    } else {
        None
    }
}

pub fn audit_groth16_verifier(bytecode: &Bytes) -> Option<Groth16AuditIssue> {
    if !has_groth16_bn254_precompile_surface(bytecode) {
        return None;
    }

    // Heuristic: public inputs begin after proof parameters. For common Groth16 ABIs this is >= 0x80.
    // If the verifier never CALLDATALOAD's past this region via constant offsets, it likely ignores inputs.
    let max_off = max_constant_calldata_load_offset(bytecode).unwrap_or(0);
    if max_off < 0x80 {
        return Some(Groth16AuditIssue::MissingPublicInputBinding);
    }

    None
}
