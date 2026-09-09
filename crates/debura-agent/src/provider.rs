use anyhow::Result;

use crate::challenge::{ChallengeHypothesisTask, ChallengeResult};
use crate::field_task::{ProposeFieldNameTask, ProposeFieldSemanticRoleTask, SemanticRoleResult};
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

    /// PROJECT.md, "Field-level semantic naming": proposes a name for one
    /// struct/stack field, reusing `InvestigationResult`/
    /// `ProposedHypothesis` exactly as `investigate` does (predicate
    /// `"field_semantic_name"` rather than `"semantic_role"`) -- the
    /// harness's existing `commit_hypothesis` needs no changes to accept
    /// either. Defaults to a clear error rather than requiring every
    /// existing provider (including every test double across this
    /// workspace) to implement a task type it doesn't care about -- only
    /// a provider that actually supports field naming needs to override
    /// this.
    fn propose_field_name(&self, _task: &ProposeFieldNameTask) -> Result<InvestigationResult> {
        Err(anyhow::anyhow!("this provider does not support field-name proposals"))
    }

    /// PROJECT.md, "Two-stage semantic reasoning": proposes what a field
    /// *means* -- forced to trace the tracked value through the supplied
    /// evidence and cite a `decisive_sink`, never an identifier -- before
    /// `propose_field_name` is ever asked to spell it. Defaults to a
    /// clear error, same reasoning as `propose_field_name`'s own default.
    fn propose_field_semantic_role(&self, _task: &ProposeFieldSemanticRoleTask) -> Result<SemanticRoleResult> {
        Err(anyhow::anyhow!("this provider does not support field-semantic-role proposals"))
    }

    /// PROJECT.md M10: every task type here reasons about strictly
    /// per-subject/per-hypothesis context (S23) and so is safe to batch
    /// in principle -- the real risk with ChallengeHypothesis/
    /// ResolveContradiction specifically is adversarial reasoning about
    /// one hypothesis bleeding into another's (a contradiction found for
    /// hypothesis A getting inappropriately reused against B). A real
    /// provider's batched prompt must say so explicitly, the same way
    /// `investigate_batch`'s already does for AnalyzeFunction, rather
    /// than assuming the model infers it. Returns one `Result` per entry
    /// of `tasks`, same order, same length -- a real provider that sends
    /// one network request for the whole batch can still fail individual
    /// subjects independently (the model omitted one, say) without
    /// losing the rest.
    ///
    /// Default implementation calls `investigate` once per task, so
    /// every existing provider (including test doubles) keeps working
    /// unchanged; only a provider that actually benefits from fewer,
    /// larger requests (a real network-backed one) needs to override
    /// this.
    fn investigate_batch(&self, tasks: &[AnalyzeFunctionTask]) -> Vec<Result<InvestigationResult>> {
        tasks.iter().map(|task| self.investigate(task)).collect()
    }

    /// See `investigate_batch`'s doc comment -- same batching rationale
    /// and the same per-hypothesis isolation requirement, applied to
    /// ChallengeHypothesis. A real run showed why this matters even
    /// though AnalyzeFunction was clustered first: ChallengeHypothesis
    /// and ResolveContradiction together made up 72% of that run's
    /// request volume (1296 of 1794 iterations), each paying a full
    /// system-prompt-and-schema request on its own -- the single
    /// largest source of avoidable per-request overhead in the whole
    /// loop.
    fn challenge_batch(&self, tasks: &[ChallengeHypothesisTask]) -> Vec<Result<ChallengeResult>> {
        tasks.iter().map(|task| self.challenge(task)).collect()
    }

    /// See `challenge_batch`'s doc comment; applied to ResolveContradiction.
    fn resolve_batch(&self, tasks: &[ResolveContradictionTask]) -> Vec<Result<ResolutionResult>> {
        tasks.iter().map(|task| self.resolve_contradiction(task)).collect()
    }
}
