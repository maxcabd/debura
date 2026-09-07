use debura_knowledge::{HypothesisId, HypothesisStatus, KnowledgeGraph};

use crate::policy::VerificationPolicy;

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

    let verified = h.last_verified_at.is_some();
    let confidence = h.confidence;

    let new_status = if verified && confidence >= policy.acceptance_threshold {
        HypothesisStatus::Accepted
    } else if confidence >= policy.support_threshold {
        HypothesisStatus::Supported
    } else {
        HypothesisStatus::Proposed
    };

    if new_status != h.status {
        let _ = graph.set_status(id, new_status);
    }

    Some(new_status)
}
