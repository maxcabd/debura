use anyhow::Result;

use crate::result::InvestigationResult;
use crate::task::AnalyzeFunctionTask;

/// Debura is not architected around one particular model (PROJECT.md S4 /
/// S15): every reasoning backend implements this trait. The harness (and
/// everything above it) only ever talks to `dyn AgentProvider` -- it has no
/// idea whether a given implementation calls a real API, a local model, or
/// (as with `mock::EchoProvider`) nothing at all.
pub trait AgentProvider {
    fn investigate(&self, task: &AnalyzeFunctionTask) -> Result<InvestigationResult>;
}
