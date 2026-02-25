//! Anchor Test: Parallel Multi-Context Solver
//!
//! Proves that objectives run in parallel, not sequentially.
//! Two 1-second objectives MUST complete in < 1.5s.

use dark_solver::solver::objectives::{ExploitObjective, ExploitParams};
use revm::primitives::Bytes;
use std::time::{Duration, Instant};

/// A test objective that sleeps for a fixed duration.
/// Used to measure parallelism without touching Z3.
struct SleepObjective {
    id: u32,
    duration: Duration,
}

impl ExploitObjective for SleepObjective {
    fn name(&self) -> &str {
        Box::leak(format!("SleepObjective_{}", self.id).into_boxed_str())
    }
    fn execute(&self, _bytecode: &Bytes) -> Option<ExploitParams> {
        std::thread::sleep(self.duration);
        None
    }
}

#[tokio::test]
async fn test_parallel_execution_speed() {
    let start = Instant::now();

    let objectives: Vec<Box<dyn ExploitObjective>> = vec![
        Box::new(SleepObjective {
            id: 1,
            duration: Duration::from_secs(1),
        }),
        Box::new(SleepObjective {
            id: 2,
            duration: Duration::from_secs(1),
        }),
        Box::new(SleepObjective {
            id: 3,
            duration: Duration::from_secs(1),
        }),
    ];

    // Parallel: 3 x 1s objectives should complete in ~1s, not 3s
    let _findings =
        dark_solver::solver::runner::run_objectives_parallel(objectives, &Bytes::new(), None).await;

    let elapsed = start.elapsed();
    println!("Parallel execution elapsed: {:?}", elapsed);

    // Assert it took less than 1.5s (proving all 3 ran in parallel)
    assert!(
        elapsed.as_millis() < 1500,
        "PARALLEL FAILURE: 3x1s objectives took {:?} (expected < 1.5s). They ran sequentially!",
        elapsed
    );
}

#[tokio::test]
async fn test_sequential_execution_is_slow() {
    let start = Instant::now();

    let objectives: Vec<Box<dyn ExploitObjective>> = vec![
        Box::new(SleepObjective {
            id: 1,
            duration: Duration::from_millis(200),
        }),
        Box::new(SleepObjective {
            id: 2,
            duration: Duration::from_millis(200),
        }),
    ];

    // Sequential: 2 x 200ms should take >= 400ms
    let _findings =
        dark_solver::solver::runner::run_objectives_sequential(objectives, &Bytes::new(), None)
            .await;

    let elapsed = start.elapsed();
    println!("Sequential execution elapsed: {:?}", elapsed);

    assert!(
        elapsed.as_millis() >= 350,
        "Sequential runner completed too fast ({:?}). It might be running in parallel?",
        elapsed
    );
}
