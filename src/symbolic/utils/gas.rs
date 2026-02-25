pub fn get_opcode_gas(opcode: u8) -> u64 {
    match opcode {
        0x00 => 0,                   // STOP
        0x01..=0x0b => 3,            // Arithmetic
        0x20 => 30,                  // SHA3 (base)
        0x30..=0x3f => 2,            // Context
        0x51 => 3,                   // MLOAD
        0x52 => 3,                   // MSTORE
        0x53 => 3,                   // MSTORE8
        0x54 => 100,                 // SLOAD (warm approx)
        0x55 => 22100,               // SSTORE (dirty init approx)
        0x56 | 0x57 => 8,            // JUMP/JUMPI
        0xf0 | 0xf5 | 0xfa => 32000, // CREATE/CALL variants
        _ => 10,                     // Base default
    }
}
