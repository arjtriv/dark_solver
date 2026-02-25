use crate::runtime::{DiscoveryMode, DiscoveryModeReport, DynamicProfileReport, RuntimeArgs};

pub fn emit_runtime_profile_status(
    runtime_args: &RuntimeArgs,
    profile: &DynamicProfileReport,
    discovery: &DiscoveryModeReport,
) {
    let target_mode = if let Some(target) = runtime_args.manual_target {
        format!("dashboard-target:{target:#x}")
    } else {
        match discovery.effective {
            DiscoveryMode::Scanner => "scanner".to_string(),
            DiscoveryMode::Hybrid => "scanner+feeds".to_string(),
            DiscoveryMode::Defillama => "feed:defillama".to_string(),
            DiscoveryMode::Basescan => "feed:basescan".to_string(),
            DiscoveryMode::Auto => "auto".to_string(),
        }
    };
    tracing::info!(
        "[OPS] Runtime profile resolved: requested={} effective={} chain={}({}) fast_chain={} cpu_parallelism={} target_mode={}",
        profile.requested.as_str(),
        profile.effective.as_str(),
        profile.chain_id,
        profile.chain_name,
        profile.fast_chain,
        profile.cpu_parallelism,
        target_mode
    );

    if profile.injected_defaults.is_empty() {
        tracing::info!(
            "[OPS] Dynamic defaults: none injected (explicit environment already provides all tuned keys)."
        );
        return;
    }

    let mut entries = profile
        .injected_defaults
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>();
    entries.sort();
    let preview_count = entries.len().min(10);
    let preview = entries[..preview_count].join(", ");
    if entries.len() > preview_count {
        tracing::info!(
            "[OPS] Dynamic defaults injected ({} keys): {} (+{} more)",
            entries.len(),
            preview,
            entries.len() - preview_count
        );
    } else {
        tracing::info!(
            "[OPS] Dynamic defaults injected ({} keys): {}",
            entries.len(),
            preview
        );
    }
}

pub fn emit_discovery_mode_status(discovery: &DiscoveryModeReport) {
    tracing::info!(
        "[OPS] Discovery mode resolved: requested={} effective={}",
        discovery.requested.as_str(),
        discovery.effective.as_str()
    );
    let mode_matrix = match discovery.effective {
        DiscoveryMode::Auto => "scanner=auto defillama=auto basescan=auto",
        DiscoveryMode::Scanner => "scanner=ON defillama=OFF basescan=OFF",
        DiscoveryMode::Defillama => "scanner=OFF defillama=ON basescan=OFF",
        DiscoveryMode::Basescan => "scanner=OFF defillama=OFF basescan=ON",
        DiscoveryMode::Hybrid => "scanner=ON defillama=ON basescan=ON",
    };
    tracing::info!("[OPS] Discovery module map: {}", mode_matrix);

    if discovery.injected_defaults.is_empty() {
        tracing::info!(
            "[OPS] Discovery defaults: none injected (explicit environment already provides feeder/scanner toggles)."
        );
        return;
    }

    let mut entries = discovery
        .injected_defaults
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>();
    entries.sort();
    tracing::info!(
        "[OPS] Discovery defaults injected ({} keys): {}",
        entries.len(),
        entries.join(", ")
    );
}
