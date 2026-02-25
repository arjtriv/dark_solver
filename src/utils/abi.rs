use alloy::primitives::{Address, U256};
use anyhow::{anyhow, Result};

pub fn decode_abi_usize_at(bytes: &[u8], start: usize, context: &str) -> Result<usize> {
    let end = start
        .checked_add(32)
        .ok_or_else(|| anyhow!("{context}: ABI word offset overflow"))?;
    let word = bytes
        .get(start..end)
        .ok_or_else(|| anyhow!("{context}: missing 32-byte ABI word at byte offset {start}"))?;
    let value = U256::from_be_slice(word);
    usize::try_from(value).map_err(|_| anyhow!("{context}: ABI word does not fit into usize"))
}

pub fn decode_abi_address_array(bytes: &[u8], context: &str) -> Result<Vec<Address>> {
    let offset_context = format!("{context} offset");
    let offset = decode_abi_usize_at(bytes, 0, &offset_context)?;
    if offset != 32 {
        return Err(anyhow!("{context}: expected ABI offset 32, got {offset}"));
    }

    let length_context = format!("{context} length");
    let len = decode_abi_usize_at(bytes, offset, &length_context)?;
    let data_start = offset
        .checked_add(32)
        .ok_or_else(|| anyhow!("{context}: ABI data start overflow"))?;
    let data_len = len
        .checked_mul(32)
        .ok_or_else(|| anyhow!("{context}: ABI array length overflow"))?;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or_else(|| anyhow!("{context}: ABI data end overflow"))?;
    let data = bytes.get(data_start..data_end).ok_or_else(|| {
        anyhow!(
            "{context}: declared {len} addresses but only {} bytes are available",
            bytes.len().saturating_sub(data_start)
        )
    })?;

    let mut addrs = Vec::with_capacity(len);
    for chunk in data.chunks_exact(32) {
        let addr = Address::from_slice(&chunk[12..32]);
        if !addr.is_zero() {
            addrs.push(addr);
        }
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::{decode_abi_address_array, decode_abi_usize_at};
    use alloy::primitives::Address;

    #[test]
    fn decode_abi_usize_at_rejects_oversized_value() {
        let word = [0xffu8; 32];
        let err = decode_abi_usize_at(&word, 0, "oversized").expect_err("must reject overflow");
        assert!(err.to_string().contains("does not fit into usize"));
    }

    #[test]
    fn decode_abi_address_array_rejects_unexpected_offset() {
        let mut payload = vec![0u8; 96];
        payload[31] = 0x40;
        payload[63] = 0x01;

        let err = decode_abi_address_array(&payload, "array").expect_err("must reject bad offset");
        assert!(err.to_string().contains("expected ABI offset 32"));
    }

    #[test]
    fn decode_abi_address_array_decodes_addresses() {
        let addr_a: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .expect("address a");
        let addr_b: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .expect("address b");

        let mut payload = vec![0u8; 128];
        payload[31] = 0x20;
        payload[63] = 0x02;
        payload[76..96].copy_from_slice(addr_a.as_slice());
        payload[108..128].copy_from_slice(addr_b.as_slice());

        let decoded = decode_abi_address_array(&payload, "array").expect("decode addresses");
        assert_eq!(decoded, vec![addr_a, addr_b]);
    }
}
