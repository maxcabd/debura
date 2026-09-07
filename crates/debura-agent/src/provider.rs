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

    /// PROJECT.md M10: AnalyzeFunction is the one task type whose context
    /// is genuinely independent per-subject *and* small enough that
    /// several fit in one model call -- unlike ChallengeHypothesis/
    /// ResolveContradiction, which reason adversarially about one
    /// hypothesis at a time and risk conflating unrelated reasoning if
    /// batched. Returns one `Result` per entry of `tasks`, same order,
    /// same length -- a real provider that sends one network request for
    /// the whole batch can still fail individual subjects independently
    /// (the model omitted one, say) without losing the rest.
    ///
    /// Default implementation calls `investigate` once per task, so
    /// every existing provider (including test doubles) keeps working
    /// unchanged; only a provider that actually benefits from fewer,
    /// larger requests (a real network-backed one) needs to override
    /// this.
    fn investigate_batch(&self, tasks: &[AnalyzeFunctionTask]) -> Vec<Result<InvestigationResult>> {
        tasks.iter().map(|task| self.investigate(task)).collect()
    }
}
