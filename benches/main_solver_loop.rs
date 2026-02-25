use dark_solver::solver::objectives::{run_with_z3_solver, ExploitObjective, ExploitParams};
use dark_solver::solver::runner::run_objectives_parallel;
use revm::primitives::Bytes;
use std::time::Instant;
use z3::ast::BV;

const PERF_BUDGET_MS: u128 = 1_800;
const BENCH_ROUNDS: usize = 7;
const OBJECTIVE_FANOUT: usize = 4;

struct SolverLoopProbeObjective {
    id: usize,
}

impl ExploitObjective for SolverLoopProbeObjective {
    fn name(&self) -> &str {
        "SolverLoopProbeObjective"
    }

    fn execute(&self, _bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let sym = BV::new_const(ctx, format!("solver_loop_probe_{}", self.id), 256);
            let floor = BV::from_u64(ctx, (self.id as u64 % 1024) + 1, 256);
            let ceiling = BV::from_u64(ctx, 10_000_000, 256);

            solver.assert(&sym.bvugt(&floor));
            solver.assert(&sym.bvult(&ceiling));

            // Overflow-safe arithmetic guard: preserve solvency-style monotonicity.
            let sum = sym.bvadd(&floor);
            solver.assert(&sum.bvuge(&sym));

            let _ = solver.check();
            None
        })
    }
}

fn median_ms(mut samples: Vec<u128>) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

async fn run_single_round(round: usize) -> u128 {
    let objectives: Vec<Box<dyn ExploitObjective>> = (0..OBJECTIVE_FANOUT)
        .map(|idx| {
            Box::new(SolverLoopProbeObjective {
                id: (round * OBJECTIVE_FANOUT) + idx,
            }) as Box<dyn ExploitObjective>
        })
        .collect();

    let bytecode = Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0x56]);
    let started = Instant::now();
    let _ = run_objectives_parallel(objectives, &bytecode, None).await;
    started.elapsed().as_millis()
}

fn main() {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("[BENCH][FAIL] failed to construct Tokio runtime: {err}");
            std::process::exit(1);
        }
    };

    let mut rounds = Vec::with_capacity(BENCH_ROUNDS);
    for round in 0..BENCH_ROUNDS {
        let elapsed_ms = runtime.block_on(run_single_round(round));
        rounds.push(elapsed_ms);
    }

    let median = median_ms(rounds.clone());
    println!(
        "[BENCH] main_solver_loop rounds_ms={:?} median_ms={} budget_ms={}",
        rounds, median, PERF_BUDGET_MS
    );

    if median > PERF_BUDGET_MS {
        eprintln!(
            "[BENCH][FAIL] main solver loop median {}ms exceeded {}ms budget",
            median, PERF_BUDGET_MS
        );
        std::process::exit(1);
    }

    println!(
        "[BENCH][PASS] main solver loop median {}ms within {}ms budget",
        median, PERF_BUDGET_MS
    );
}
