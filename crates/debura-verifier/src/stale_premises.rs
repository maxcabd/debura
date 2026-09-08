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
pub fn reconsider_stale_provenance_rejections(graph: &mut KnowledgeGraph) -> Vec<HypothesisId> {
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
