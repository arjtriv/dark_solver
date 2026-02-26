use std::fs;

#[test]
fn deep_sniper_cli_arg_surface_is_wired() {
    let source = fs::read_to_string("src/bin/deep_sniper.rs").expect("read deep_sniper.rs");
    assert!(
        source.contains("fn parse_args_from_iter"),
        "deep_sniper should parse args through a testable iterator path"
    );
    assert!(
        source.contains("ETH_RPC_URL") && source.contains("RPC_URL"),
        "deep_sniper should preserve RPC env fallbacks"
    );
    assert!(
        source.contains("inspect_err(|_| print_usage())"),
        "deep_sniper should print usage on parse failures"
    );
}
