use std::fs;
use std::path::Path;

fn write_minimal_env_template(file: &mut fs::File) -> std::io::Result<()> {
    use std::io::Write;
    writeln!(file, "# Dark Solver (simulation-only) configuration")?;
    writeln!(file)?;
    writeln!(file, "ETH_RPC_URL=\"https://mainnet.infura.io/v3/CHANGE_ME\"")?;
    writeln!(file, "CHAIN_ID=\"1\"")?;
    writeln!(file)?;
    writeln!(file, "RUST_LOG=\"info,dark_solver::solver=info\"")?;
    writeln!(file, "VERIFICATION_TELEMETRY_DIR=\"./telemetry\"")?;
    Ok(())
}

fn load_dot_env() {
    let path = Path::new(".env");
    if !path.exists() {
        return;
    }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ENV] Failed to read .env: {}", e);
            return;
        }
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };

        if std::env::var_os(key.trim()).is_some() {
            continue;
        }

        let value_no_comment = value.split('#').next().unwrap_or("").trim();
        let parsed = if value_no_comment.len() >= 2
            && ((value_no_comment.starts_with('"') && value_no_comment.ends_with('"'))
                || (value_no_comment.starts_with('\'') && value_no_comment.ends_with('\'')))
        {
            &value_no_comment[1..value_no_comment.len() - 1]
        } else {
            value_no_comment
        };

        std::env::set_var(key.trim(), parsed);
    }
}

fn ensure_env_files_exist() {
    let env_example = Path::new(".env.example");
    if !env_example.exists() {
        if let Ok(mut file) = fs::File::create(env_example) {
            let _ = write_minimal_env_template(&mut file);
        }
    }

    let env_path = Path::new(".env");
    if !env_path.exists() {
        if let Ok(mut file) = fs::File::create(env_path) {
            let _ = write_minimal_env_template(&mut file);
        }
    }
}

pub fn harden_env_setup() {
    ensure_env_files_exist();
    load_dot_env();
    if std::env::var("ETH_RPC_URL").is_err() {
        eprintln!("[ENV] WARN: ETH_RPC_URL is not set");
    }
    if std::env::var("CHAIN_ID").is_err() {
        eprintln!("[ENV] WARN: CHAIN_ID is not set");
    }
}
