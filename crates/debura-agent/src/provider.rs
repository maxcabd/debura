use anyhow::Result;

use crate::challenge::{ChallengeHypothesisTask, ChallengeResult};
use crate::resolution::{ResolutionResult, ResolveContradictionTask};
use crate::result::InvestigationResult;
use crate::task::AnalyzeFunctionTask;

/// Debura is not architected around one particular model (PROJECT.md S4 /
/// S15): every reasoning backend implements this trait. The harness (and
/// everything above it) only ever talks to `dyn AgentProvider` -- it has no
/// idea whether a given implementation calls a real API, a local model, or
/// (as with `mock::EchoProvider`) nothing at all.
///
/// One method per bounded task type (PROJECT.md S28): `investigate` for
/// AnalyzeFunction (M4), `challenge` for ChallengeHypothesis and
/// `resolve_contradiction` for ResolveContradiction (both M5).
pub trait AgentProvider {
    fn investigate(&self, task: &AnalyzeFunctionTask) -> Result<InvestigationResult>;
    fn challenge(&self, task: &ChallengeHypothesisTask) -> Result<ChallengeResult>;
    fn resolve_contradiction(&self, task: &ResolveContradictionTask) -> Result<ResolutionResult>;
}
