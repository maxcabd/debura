use debura_knowledge::{Evidence, Hypothesis, KnowledgeGraph, Observation};
use serde::{Deserialize, Serialize};

use crate::call_context::{self, CallSequenceNeighbor};
use crate::evidence_view;
use crate::field_task::{ProposeFieldNameTask, ProposeFieldSemanticRoleTask, SemanticRoleResult};
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

/// PROJECT.md, "Predicate-aware challenge": the field-semantic-role
/// analog of `ChallengeHypothesisTask` -- a real, confirmed gap found
/// while verifying the previous round: the generic task above carries
/// `call_sequence`/`reachable_api_hints`, both naturally, permanently
/// empty for a field subject (those are function-only concepts), and
/// `other_observations`/`supporting_evidence` are *also* empty for a
/// field hypothesis, since `commit_hypothesis` never attaches Evidence
/// records to it. The generic challenger, given nothing else to reason
/// from, said so honestly -- *"no API context or caller information to
/// support what role this field plays"* -- and rejected a hypothesis
/// that was, in fact, correctly evidence-backed. This task instead
/// carries the exact same rich field context
/// `ProposeFieldSemanticRoleTask` itself was given, plus the proposal's
/// own claimed trace/sink/evidence, so the challenger can actually
/// re-derive whether the citation holds up -- never just "was there
/// anything here at all."
#[derive(Debug, Clone)]
pub struct ChallengeFieldSemanticRoleTask {
    pub subject: String,
    pub proposed_role: String,
    pub decisive_sink: Option<String>,
    pub propagation_chain: Vec<String>,
    pub evidence: Vec<String>,
    pub competing_interpretations: Vec<String>,
    pub function_display_name: String,
    pub function_decompilation: String,
    pub base: String,
    pub offset: i64,
    pub width: u32,
    pub declared_type: String,
    pub sibling_fields: Vec<String>,
    pub value_consumers: Vec<String>,
    pub relevant_data_references: Vec<String>,
    pub display_associations: Vec<String>,
    pub known_sinks: Vec<String>,
}

impl ChallengeFieldSemanticRoleTask {
    /// Built directly from the same task and result the proposal stage
    /// already produced -- nothing here is re-derived or re-fetched from
    /// the graph, since none of it was ever stored there as durable
    /// observations in the first place (a real, separate gap; the
    /// proposal's own evidence lives only in this one request's memory
    /// today).
    pub fn build(proposal_task: &ProposeFieldSemanticRoleTask, proposal_result: &SemanticRoleResult) -> Self {
        Self {
            subject: proposal_task.subject.clone(),
            proposed_role: proposal_result.semantic_role.clone().unwrap_or_default(),
            decisive_sink: proposal_result.decisive_sink.clone(),
            propagation_chain: proposal_result.propagation_chain.clone(),
            evidence: proposal_result.evidence.clone(),
            competing_interpretations: proposal_result.competing_interpretations.clone(),
            function_display_name: proposal_task.function_display_name.clone(),
            function_decompilation: proposal_task.function_decompilation.clone(),
            base: proposal_task.base.clone(),
            offset: proposal_task.offset,
            width: proposal_task.width,
            declared_type: proposal_task.declared_type.clone(),
            sibling_fields: proposal_task.sibling_fields.clone(),
            value_consumers: proposal_task.value_consumers.clone(),
            relevant_data_references: proposal_task.relevant_data_references.clone(),
            display_associations: proposal_task.display_associations.clone(),
            known_sinks: proposal_task.known_sinks.clone(),
        }
    }
}

/// PROJECT.md, "Predicate-aware challenge": the field-semantic-name
/// analog, for the exact same reason `ChallengeFieldSemanticRoleTask`
/// exists -- a real run showed the generic challenger applies the same
/// "no caller/API context" critique to a proposed *name* too, even
/// though by this stage the semantic question is already settled
/// (`established_role` is an ACCEPTED hypothesis). This task's job is
/// narrower than the role challenge's: not "is this concept right" (that
/// was already adversarially checked), but "does this spelling still
/// faithfully express the already-accepted concept" -- a downstream
/// predicate inheriting upstream accepted semantics rather than
/// re-proving them from raw evidence.
#[derive(Debug, Clone)]
pub struct ChallengeFieldSemanticNameTask {
    pub subject: String,
    pub established_role: String,
    pub proposed_name: String,
    pub function_display_name: String,
    pub function_decompilation: String,
    pub base: String,
    pub offset: i64,
    pub width: u32,
    pub declared_type: String,
    pub sibling_fields: Vec<String>,
    pub value_consumers: Vec<String>,
    pub relevant_data_references: Vec<String>,
}

impl ChallengeFieldSemanticNameTask {
    /// Built from the same task the naming proposal itself used, plus the
    /// name it actually proposed -- there is no separate structured
    /// result type for field naming the way `SemanticRoleResult` exists
    /// for roles (`propose_field_name` reuses the flat
    /// `InvestigationResult`/`ProposedHypothesis` shape), so the proposed
    /// value is passed directly.
    pub fn build(proposal_task: &ProposeFieldNameTask, proposed_name: &str) -> Self {
        Self {
            subject: proposal_task.subject.clone(),
            established_role: proposal_task.established_role.clone(),
            proposed_name: proposed_name.to_string(),
            function_display_name: proposal_task.function_display_name.clone(),
            function_decompilation: proposal_task.function_decompilation.clone(),
            base: proposal_task.base.clone(),
            offset: proposal_task.offset,
            width: proposal_task.width,
            declared_type: proposal_task.declared_type.clone(),
            sibling_fields: proposal_task.sibling_fields.clone(),
            value_consumers: proposal_task.value_consumers.clone(),
            relevant_data_references: proposal_task.relevant_data_references.clone(),
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
