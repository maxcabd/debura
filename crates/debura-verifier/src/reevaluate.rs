use debura_agent::commit_contradiction;
use debura_knowledge::{
    classify_provenance, HypothesisId, HypothesisStatus, KnowledgeGraph, Provenance,
    RejectionReason,
};

use crate::mechanical_shape::mechanically_shaped_reason;
use crate::policy::VerificationPolicy;
use crate::vtable_propagation::propagate_vtable_slot_role;

/// Deterministic status transition (PROJECT.md S10, M5) -- no model call.
/// Per S2.3, don't spend a token on a question software can already
/// answer: whether a confidence number and a verification timestamp clear
/// a configured bar is exactly that kind of question.
///
/// CONTESTED and REJECTED are left untouched -- resolving those is
/// `resolve_contradiction`'s job, not a threshold check. Returns `None`
/// only if `id` doesn't exist.
pub fn reevaluate_hypothesis(
    graph: &mut KnowledgeGraph,
    id: HypothesisId,
    policy: &VerificationPolicy,
) -> Option<HypothesisStatus> {
    let h = graph.hypothesis(id)?;

    if matches!(
        h.status,
        HypothesisStatus::Contested | HypothesisStatus::Rejected
    ) {
        return Some(h.status);
    }

    let old_status = h.status;
    let predicate = h.predicate.clone();
    let subject = h.subject.clone();
    let value = h.value.clone();
    let verified = h.last_verified_at.is_some();
    let confidence = h.confidence;

    let new_status = if verified && confidence >= policy.acceptance_threshold {
        HypothesisStatus::Accepted
    } else if confidence >= policy.support_threshold {
        HypothesisStatus::Supported
    } else {
        HypothesisStatus::Proposed
    };

    if new_status == HypothesisStatus::Accepted
        && predicate == "semantic_role"
        && classify_provenance(graph, &subject) != Provenance::Application
    {
        // PROJECT.md M17: a real audit found 10 of 37 ACCEPTED
        // semantic_role claims were library/CRT internals
        // (std::vector::_M_erase_at_end, MinGW's own
        // _pei386_runtime_relocator) that earned application-sounding
        // names and made it all the way into the recovered .cpp output --
        // because the old two-state Provenance defaulted "no name-shape
        // signal" to Application, which on a genuinely stripped binary is
        // nearly always the case. This is a hard structural exclusion,
        // not a debatable naming judgment: a subject whose provenance
        // isn't Application shouldn't carry an application semantic_role
        // at all, so -- unlike `mechanically_shaped_reason` below, which
        // flags something ChallengeHypothesis/ResolveContradiction should
        // actually weigh -- this goes straight to REJECTED rather than
        // through CONTESTED. The subject can still be recovered/recognized
        // structurally; it just doesn't get to claim application meaning.
        let _ = graph.reject_with_reason(id, RejectionReason::ProvenanceNotApplication);
        graph.add_observation(
            subject,
            "provenance_gate_rejected",
            format!("semantic_role '{value}' rejected: subject's provenance is not Application"),
            0.5,
            "debura:provenance_gate",
            None,
        );
        return Some(HypothesisStatus::Rejected);
    }

    if new_status == HypothesisStatus::Accepted {
        if let Some(reason) = mechanically_shaped_reason(graph, id) {
            // PROJECT.md M17: caught in practice -- three sibling classes'
            // semantic_role of "iteratesGrid" all reached here with a
            // qualifying confidence and verification stamp, restating each
            // subject's own mechanical_behavior word-for-word, and
            // CHALLENGE_SYSTEM's free-form side-effect question missed all
            // three. Don't let this one silently coast to ACCEPTED just
            // because the number-crunching above cleared the bar -- push it
            // through the same CONTESTED -> ResolveContradiction path any
            // other contradiction takes (commit_contradiction sets the
            // status), so a human-legible reason and the normal adversarial
            // pass still decide it, rather than this check silently
            // vetoing it on its own.
            commit_contradiction(graph, id, &reason, "debura:mechanical_shape_check");
            return graph.hypothesis(id).map(|h| h.status);
        }
    }

    if new_status != old_status {
        let _ = graph.set_status(id, new_status);
        if new_status == HypothesisStatus::Accepted {
            // PROJECT.md M17: this is the single choke point every path
            // that can newly accept a hypothesis passes through, so
            // vtable-slot propagation is triggered from here rather
            // than duplicated at each of reevaluate_hypothesis's own
            // several call sites.
            propagate_vtable_slot_role(graph, id);
        }
    }

    Some(new_status)
}
