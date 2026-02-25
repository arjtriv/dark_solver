//! Anchor: private-rpc hint sniper detects competition hints even when some builders accept,
//! and extracts "Bundle Received" acknowledgements.

use dark_solver::executor::{
    builder_outcomes_have_competition_hint, bundle_received_builders, is_bundle_received_hint,
    BuilderDispatchOutcome,
};

#[test]
fn private_rpc_hint_sniper_detects_any_competition_hint() {
    let outcomes = vec![
        BuilderDispatchOutcome {
            builder: "A".to_string(),
            accepted: true,
            latency_ms: 5,
            rejection_class: None,
            response_message: Some("{\"result\":\"ok\"}".to_string()),
        },
        BuilderDispatchOutcome {
            builder: "B".to_string(),
            accepted: false,
            latency_ms: 6,
            rejection_class: Some("outbid".to_string()),
            response_message: Some("bundle already imported".to_string()),
        },
    ];
    assert!(builder_outcomes_have_competition_hint(&outcomes));
}

#[test]
fn private_rpc_hint_sniper_extracts_bundle_received_builders() {
    assert!(is_bundle_received_hint("Bundle Received"));
    let outcomes = vec![
        BuilderDispatchOutcome {
            builder: "BeaverBuild".to_string(),
            accepted: true,
            latency_ms: 5,
            rejection_class: None,
            response_message: Some("{\"result\":\"Bundle Received\"}".to_string()),
        },
        BuilderDispatchOutcome {
            builder: "Titan".to_string(),
            accepted: true,
            latency_ms: 5,
            rejection_class: None,
            response_message: Some("{\"result\":\"ok\"}".to_string()),
        },
    ];
    assert_eq!(
        bundle_received_builders(&outcomes),
        vec!["BeaverBuild".to_string()]
    );
}
