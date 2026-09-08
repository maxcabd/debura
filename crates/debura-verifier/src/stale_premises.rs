use debura_knowledge::{classify_provenance, HypothesisId, HypothesisStatus, KnowledgeGraph, Provenance, RejectionReason};

/// PROJECT.md M18: `reevaluate_hypothesis`'s provenance gate REJECTs a
/// `semantic_role` hypothesis whenever `classify_provenance` says the
/// subject isn't Application -- a hard structural exclusion, correctly
/// terminal against the generic dependency cascade. But `classify_provenance`
/// itself gained a new signal this milestone (own-state field access +
/// thunk-to-import), so a real rejection recorded under the *old*
/// classifier can now be wrong: its premise ("this subject's provenance
/// isn't Application") no longer holds, yet nothing re-examines a REJECTED
/// hypothesis on its own.
///
/// This is a deliberate, narrow exception, not a generalized "recheck
/// everything" cascade: it only looks at hypotheses REJECTED for exactly
/// `RejectionReason::ProvenanceNotApplication`, and only moves them to
/// STALE (eligible for the normal investigate/challenge pipeline to
/// re-decide) -- never straight back to ACCEPTED. Returns the hypotheses
/// it moved, so a caller can requeue investigation for them.
///
/// A real project's persisted graph can hold REJECTED semantic_role
/// hypotheses from before `rejection_reason` existed at all -- the gate
/// still recorded a `provenance_gate_rejected` observation each time, so
/// that legacy free-text record is used to backfill the structured reason
/// first (never fabricated: it's read from the gate's own prior record),
/// then treated exactly the same as a freshly-structured rejection below.
pub fn reconsider_stale_provenance_rejections(graph: &mut KnowledgeGraph) -> Vec<HypothesisId> {
    let unbackfilled: Vec<(HypothesisId, String, String)> = graph
        .hypotheses()
        .filter(|h| h.status == HypothesisStatus::Rejected && h.rejection_reason.is_none() && h.predicate == "semantic_role")
        .map(|h| (h.id, h.subject.clone(), h.value.clone()))
        .collect();
    for (id, subject, value) in unbackfilled {
        if legacy_provenance_gate_rejection(graph, &subject, &value) {
            graph.backfill_rejection_reason(id, RejectionReason::ProvenanceNotApplication);
        }
    }

    let candidates: Vec<(HypothesisId, String, String)> = graph
        .hypotheses()
        .filter(|h| {
            h.status == HypothesisStatus::Rejected
                && h.rejection_reason == Some(RejectionReason::ProvenanceNotApplication)
        })
        .map(|h| (h.id, h.subject.clone(), h.value.clone()))
        .collect();

    let mut reconsidered = Vec::new();
    for (id, subject, value) in candidates {
        if classify_provenance(graph, &subject) != Provenance::Application {
            continue;
        }
        if graph.reconsider_rejected(id, &RejectionReason::ProvenanceNotApplication) {
            graph.add_observation(
                subject,
                "rejection_premise_invalidated",
                format!(
                    "semantic_role '{value}' was rejected when this subject's provenance \
                     wasn't Application; provenance now classifies as Application, so the \
                     rejection's premise no longer holds -- marked STALE for reevaluation"
                ),
                0.5,
                "debura:premise_reconsideration",
                None,
            );
            reconsidered.push(id);
        }
    }
    reconsidered
}

/// Whether `reevaluate_hypothesis`'s provenance gate really did reject
/// this exact `semantic_role` value on this exact subject, per its own
/// prior `provenance_gate_rejected` observation -- the free-text record
/// left behind before `RejectionReason` existed. Matches the literal
/// message `reevaluate_hypothesis` writes, so a change to that wording
/// would need a matching change here (same coupling `mechanical_shape`'s
/// own text-matching checks already accept elsewhere in this crate).
fn legacy_provenance_gate_rejection(graph: &KnowledgeGraph, subject: &str, value: &str) -> bool {
    let needle = format!("semantic_role '{value}' rejected: subject's provenance is not Application");
    graph
        .observations()
        .any(|o| o.subject == subject && o.predicate == "provenance_gate_rejected" && o.value == needle)
}

#[cfg(test)]
mod tests {
    use debura_knowledge::KnowledgeGraph;

    use super::*;

    #[test]
    fn a_rejection_whose_provenance_premise_is_still_false_is_left_alone() {
        let mut graph = KnowledgeGraph::new();
        // No name-shape, no method_owner anchor, no own-state signal, no
        // thunk resolution -- this subject stays Unknown, never Application.
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        let id = graph.propose_hypothesis("0x1", "semantic_role", "renderFrame", 0.9, None);
        graph
            .reject_with_reason(id, RejectionReason::ProvenanceNotApplication)
            .unwrap();

        let reconsidered = reconsider_stale_provenance_rejections(&mut graph);

        assert!(reconsidered.is_empty());
        assert_eq!(graph.hypothesis(id).unwrap().status, HypothesisStatus::Rejected);
    }

    #[test]
    fn a_rejection_whose_provenance_premise_flipped_to_application_is_marked_stale() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        graph.add_observation(
            "0x1",
            "decompiles_to",
            "void FUN_1(longlong param_1)\n\n{\n  *(int *)(param_1 + 4) = 0;\n  *(int *)(param_1 + 8) = 1;\n  FUN_2(*(void **)param_1);\n  return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        // The own-state signal also requires a direct callee that
        // thunk-resolves to a real import -- without this, the same
        // two-field-touching body stays Unknown (see the STL-internal
        // false positive this signal was built to keep excluded).
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "imports", "SDL_DestroyWindow", 0.95, "ghidra:import", None);
        let id = graph.propose_hypothesis("0x1", "semantic_role", "renderFrame", 0.9, None);
        graph
            .reject_with_reason(id, RejectionReason::ProvenanceNotApplication)
            .unwrap();

        // Sanity: the up-to-date classifier really does call this
        // Application now (own-state access + a thunk-shaped import call),
        // which is exactly the scenario this function exists for.
        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::Application);

        let reconsidered = reconsider_stale_provenance_rejections(&mut graph);

        assert_eq!(reconsidered, vec![id]);
        let h = graph.hypothesis(id).unwrap();
        assert_eq!(h.status, HypothesisStatus::Stale);
        assert_eq!(h.rejection_reason, None);
    }

    #[test]
    fn a_legacy_rejection_with_no_structured_reason_is_backfilled_from_its_own_prior_observation() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        graph.add_observation(
            "0x1",
            "decompiles_to",
            "void FUN_1(longlong param_1)\n\n{\n  *(int *)(param_1 + 4) = 0;\n  *(int *)(param_1 + 8) = 1;\n  FUN_2(*(void **)param_1);\n  return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "imports", "SDL_DestroyWindow", 0.95, "ghidra:import", None);
        let id = graph.propose_hypothesis("0x1", "semantic_role", "renderFrame", 0.9, None);
        // Predates `RejectionReason`: a plain status flip plus the gate's
        // own free-text observation, exactly what a real pre-M18 project
        // database holds -- no `reject_with_reason` call at all.
        graph.set_status(id, HypothesisStatus::Rejected).unwrap();
        graph.add_observation(
            "0x1",
            "provenance_gate_rejected",
            "semantic_role 'renderFrame' rejected: subject's provenance is not Application",
            0.5,
            "debura:provenance_gate",
            None,
        );

        let reconsidered = reconsider_stale_provenance_rejections(&mut graph);

        assert_eq!(reconsidered, vec![id]);
        assert_eq!(graph.hypothesis(id).unwrap().status, HypothesisStatus::Stale);
    }

    #[test]
    fn a_rejection_for_a_different_reason_is_never_touched() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        let id = graph.propose_hypothesis("0x1", "semantic_role", "renderFrame", 0.9, None);
        graph
            .reject_with_reason(id, RejectionReason::InsufficientEvidence)
            .unwrap();

        let reconsidered = reconsider_stale_provenance_rejections(&mut graph);

        assert!(reconsidered.is_empty());
        assert_eq!(graph.hypothesis(id).unwrap().status, HypothesisStatus::Rejected);
    }
}
