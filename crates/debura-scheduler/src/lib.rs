//! Task prioritization and the autonomous loop (PROJECT.md S24, S27) -- M6.
//!
//! `run` is `debura run <project>`'s engine: it seeds work from whatever
//! the knowledge graph doesn't have hypotheses for yet, executes the
//! highest-priority task, enqueues whatever follows from it, and repeats
//! until the queue empties or a budget trips.

mod fingerprint;
mod priority;
mod queue;
mod report;
mod run;
mod seed;
mod task;

// Re-exported for existing callers (the CLI's `stats` command) --
// classification lives in debura-knowledge itself now so debura-recovery
// can reuse it too, without an awkward recovery-depends-on-scheduler edge.
pub use debura_knowledge::{claim_breakdown, classify_subject, ClaimBreakdown, ClaimClass};
pub use fingerprint::fingerprint;
pub use queue::Scheduler;
pub use report::{investigation_report, InvestigationReport, TaskTypeStats};
pub use run::{run, run_with_concurrency, RunBudget, RunSummary, StopReason};
pub use seed::seed_initial_tasks;
pub use task::Task;
