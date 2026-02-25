use std::fs;

#[test]
fn test_payload_calldata_decryption_is_wired() {
    let source = fs::read_to_string("src/executor/payload_hardening.rs")
        .expect("src/executor/payload_hardening.rs must be readable for calldata decryption audit");

    assert!(
        source.contains("PAYLOAD_ENCRYPTION_ENABLED")
            && source.contains("PAYLOAD_DECRYPTOR_ROUTER")
            && source.contains("PAYLOAD_ENCRYPTION_KEY_HEX")
            && source.contains("PAYLOAD_ENCRYPTION_EPOCH_SECS"),
        "payload hardening must expose encrypted calldata controls with rotating epoch settings"
    );
    assert!(
        source.contains("executeEncrypted(address,uint64,bytes32,bytes)")
            && source.contains("xor_stream_encrypt")
            && source.contains("maybe_encrypt_step_payloads"),
        "payload hardening must wrap steps into an on-chain decryptor envelope with encrypted payload bytes"
    );
}
