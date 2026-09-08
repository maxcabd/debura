use debura_knowledge::{Evidence, Hypothesis, KnowledgeGraph, Observation};
use serde::{Deserialize, Serialize};

use crate::call_context::{self, CallSequenceNeighbor};
use crate::evidence_view;
use crate::result::ProposedHypothesis;

/// PROJECT.md S12: an adversarial pass. The objective is not to find more
/// evidence that a hypothesis is right, it's to actively try to prove it
/// wrong -- so the challenger gets the full evidence trail behind the
/// hypothesis, plus every other observation known about the same subject
/// (not just the slice the original investigation happened to look at).
#[derive(Debug, Clone)]
pub struct ChallengeHypothesisTask {
    pub hypothesis: Hypothesis,
    pub supporting_evidence: Vec<(Evidence, Observation)>,
    pub other_observations: Vec<Observation>,
    /// PROJECT.md M17: the same raw ensemble evidence (caller-sequence
    /// neighbors' mechanics/reachable API names, this subject's own
    /// reachable API names) AnalyzeFunction saw -- without this, a
    /// challenge on a phase-inferred semantic_role would only ever see the
    /// hypothesis's own text and this subject's own observations, with no
    /// way to judge whether the ensemble it cites actually supports it or
    /// was overstated.
    pub call_sequence: Vec<CallSequenceNeighbor>,
    pub reachable_api_hints: Vec<String>,
}

impl ChallengeHypothesisTask {
    pub fn build(graph: &KnowledgeGraph, hypothesis: &Hypothesis) -> Self {
        Self {
            supporting_evidence: evidence_view::resolve(graph, &hypothesis.supporting_evidence),
            // Excludes `agent_flagged_contradiction`: that's this
            // subject's own past-contradiction bookkeeping (harness.rs's
            // `commit_contradiction`), unbounded and purely historical --
            // a fresh challenge needs the subject's real facts, not a
            // growing transcript of every previous verdict against it.
            //
            // Reads `active_observations()`, not `observations()`: a real
            // run found a challenger re-rejecting a reconsidered hypothesis
            // partly because it was still reading a `provenance_gate_rejected`
            // observation as live evidence, even though a later observation
            // on the same subject had already recorded that its premise no
            // longer held (PROJECT.md M18 -- `reconsider_stale_provenance_rejections`
            // now supersedes that old observation instead of leaving it to
            // look current forever). Superseded/Retracted facts stay on the
            // record for history; they just don't get to argue with fresh
            // reasoning.
            other_observations: graph
                .active_observations()
                .filter(|o| o.subject == hypothesis.subject)
                .filter(|o| o.predicate != "agent_flagged_contradiction")
                .cloned()
                .collect(),
            call_sequence: call_context::call_sequence_neighbors(graph, &hypothesis.subject),
            reachable_api_hints: call_context::reachable_api_hints(graph, &hypothesis.subject),
            hypothesis: hypothesis.clone(),
        }
    }
}

/// What a challenge produced. None of the three findings are mutually
/// exclusive -- a challenger could, in principle, both flag a contradiction
/// and propose a better alternative.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChallengeResult {
    /// A reason the hypothesis should be considered contradicted, if the
    /// challenger found one.
    pub contradiction: Option<String>,
    /// A more plausible or more general interpretation of the same
    /// subject (S12's PlayerCharacter::TakeDamage -> Character::ApplyDamage
    /// example), if the challenger found one.
    pub alternative: Option<ProposedHypothesis>,
    /// The challenger's recommended confidence for the *original*
    /// hypothesis, having genuinely tried to break it. Ignored if a
    /// contradiction was also reported -- CONTESTED takes precedence over
    /// any confidence number until ResolveContradiction settles it.
    pub confidence_recommendation: Option<f64>,
    pub reasoning: String,
}
