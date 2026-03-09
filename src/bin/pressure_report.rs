use dark_solver::solver::verification::{
    evaluate_memory_profile_window, evaluate_solve_rate_window,
};
use dark_solver::utils::cli::parse_u64_flag;

#[derive(Debug, PartialEq)]
struct Args {
    window_secs: u64,
    json: bool,
    telemetry_dir: Option<String>,
}

fn parse_u64_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn print_usage() {
    eprintln!(
        "usage: pressure_report [--window-secs <n>] [--json] [--telemetry-dir <path>]\n\
         env fallback: PRESSURE_REPORT_WINDOW_SECS and VERIFICATION_TELEMETRY_DIR"
    );
}

fn parse_args_from_iter<I, S>(iter: I) -> anyhow::Result<Args>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut window_secs = parse_u64_env("PRESSURE_REPORT_WINDOW_SECS", 3600);
    let mut json = false;
    let mut telemetry_dir = std::env::var("VERIFICATION_TELEMETRY_DIR").ok();

    let mut iter = iter.into_iter().map(Into::into);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--window-secs" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))?;
                window_secs = parse_u64_flag(&raw, "window")?;
            }
            "--json" => {
                json = true;
            }
            "--telemetry-dir" => {
                telemetry_dir = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))?,
                );
            }
            other => return Err(anyhow::anyhow!("unknown argument '{other}'")),
        }
    }

    Ok(Args {
        window_secs,
        json,
        telemetry_dir,
    })
}

fn parse_args() -> anyhow::Result<Args> {
    parse_args_from_iter(std::env::args().skip(1))
}

fn main() {
    let args = parse_args().inspect_err(|_| print_usage()).unwrap_or_else(|_| {
        std::process::exit(2);
    });
    if let Some(dir) = &args.telemetry_dir {
        std::env::set_var("VERIFICATION_TELEMETRY_DIR", dir);
    }
    let window_ms = args.window_secs.saturating_mul(1000);

    let memory = match evaluate_memory_profile_window(window_ms) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("[PRESSURE] memory report failed: {err}");
            std::process::exit(2);
        }
    };

    let solve_rate = match evaluate_solve_rate_window(window_ms) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("[PRESSURE] solve-rate report failed: {err}");
            std::process::exit(2);
        }
    };

    if args.json {
        let payload = serde_json::json!({
            "window_secs": args.window_secs,
            "telemetry_dir": args.telemetry_dir,
            "memory": memory,
            "solve_rate": solve_rate,
        });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string()));
    } else {
        println!(
            "[PRESSURE] window_secs={} memory{{pass={} enough_window={} samples={} start_rss_mb={:.2} end_rss_mb={:.2} delta_mb={:.2} max_rss_mb={:.2}}} solve_rate{{pass={} enough_window={} samples={} within_budget={} ratio={:.3}}}",
            args.window_secs,
            memory.pass,
            memory.enough_window,
            memory.samples,
            memory.start_rss_mb,
            memory.end_rss_mb,
            memory.delta_mb,
            memory.max_rss_mb,
            solve_rate.pass,
            solve_rate.enough_window,
            solve_rate.samples,
            solve_rate.within_budget,
            solve_rate.ratio,
        );
    }

    if memory.pass && solve_rate.pass {
        std::process::exit(0);
    }
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::{parse_args_from_iter, Args};
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_env() {
        std::env::remove_var("PRESSURE_REPORT_WINDOW_SECS");
        std::env::remove_var("VERIFICATION_TELEMETRY_DIR");
    }

    #[test]
    fn parse_args_from_iter_uses_env_defaults() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();
        std::env::set_var("PRESSURE_REPORT_WINDOW_SECS", "900");
        std::env::set_var("VERIFICATION_TELEMETRY_DIR", "/tmp/telemetry");

        let args = parse_args_from_iter(Vec::<String>::new()).expect("parse");
        assert_eq!(
            args,
            Args {
                window_secs: 900,
                json: false,
                telemetry_dir: Some("/tmp/telemetry".to_string()),
            }
        );

        clear_env();
    }

    #[test]
    fn parse_args_from_iter_accepts_named_flags() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();

        let args = parse_args_from_iter([
            "--window-secs",
            "1800",
            "--json",
            "--telemetry-dir",
            "/var/tmp/dark",
        ])
        .expect("parse");

        assert_eq!(
            args,
            Args {
                window_secs: 1800,
                json: true,
                telemetry_dir: Some("/var/tmp/dark".to_string()),
            }
        );
    }
}
