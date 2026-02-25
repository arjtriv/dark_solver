//! Anchor Test: secure private-RPC handshake blocks public endpoint routing.

#[test]
fn test_private_rpc_handshake_transport_guard() {
    let private_ok = dark_solver::executor::builders::verify_private_transport_url(
        "https://rpc.beaverbuild.org",
    );
    assert!(
        private_ok.is_ok(),
        "known private builder should be accepted"
    );

    let public_rpc = dark_solver::executor::builders::verify_private_transport_url(
        "https://eth-mainnet.g.alchemy.com/v2/demo",
    );
    assert!(public_rpc.is_err(), "public RPC endpoint must be rejected");

    let plaintext =
        dark_solver::executor::builders::verify_private_transport_url("http://relay.flashbots.net");
    assert!(plaintext.is_err(), "non-HTTPS endpoint must be rejected");
}
