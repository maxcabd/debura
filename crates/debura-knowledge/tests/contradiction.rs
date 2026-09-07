use debura_knowledge::{DependencyKind, HypothesisId, HypothesisStatus, KnowledgeError, KnowledgeGraph};

/// PROJECT.md S9: new evidence contradicting a hypothesis moves it to
/// CONTESTED (a verification pass decides ACCEPTED/REJECTED later -- M5),
/// and dependents cascade to STALE. Confidence itself is left untouched:
/// recalculating it is a verification decision, not something M2 automates.
#[test]
fn contradicting_evidence_contests_a_hypothesis_and_cascades_stale() {
    let mut kg = KnowledgeGraph::new();

    let obs = kg.add_observation(
        "PlayerCharacter+0x138",
        "referenced_by",
        "HUD element labeled Health",
        0.95,
        "static_analysis",
        None,
    );
    let contradicting_evidence = kg
        .add_evidence(
            obs,
            "field is displayed as Health in the HUD",
            "AnalyzeField",
            None,
            None,
        )
        .unwrap();

    let stamina_hypothesis =
        kg.propose_hypothesis("PlayerCharacter+0x138", "semantic_role", "stamina", 0.64, None);
    kg.set_status(stamina_hypothesis, HypothesisStatus::Supported)
        .unwrap();

    let dependent = kg.propose_hypothesis("F193", "modifies", "stamina", 0.5, None);
    kg.add_dependency(dependent, stamina_hypothesis, DependencyKind::DependsOn)
        .unwrap();

    let newly_stale = kg
        .attach_contradicting_evidence(stamina_hypothesis, contradicting_evidence)
        .unwrap();

    let h = kg.hypothesis(stamina_hypothesis).unwrap();
    assert_eq!(h.status, HypothesisStatus::Contested);
    assert_eq!(h.confidence, 0.64);
    assert_eq!(h.contradicting_evidence, vec![contradicting_evidence]);

    assert_eq!(newly_stale, vec![dependent]);
    assert_eq!(
        kg.hypothesis(dependent).unwrap().status,
        HypothesisStatus::Stale
    );
}

/// PROJECT.md S4: rejected hypotheses are never silently deleted, and new
/// contradicting evidence against one is a no-op on status (already
/// terminal) while still being recorded for provenance.
#[test]
fn contradicting_evidence_does_not_move_a_rejected_hypothesis() {
    let mut kg = KnowledgeGraph::new();

    let obs = kg.add_observation("s", "p", "v", 0.9, "src", None);
    let evidence = kg.add_evidence(obs, "r", "src", None, None).unwrap();

    let h = kg.propose_hypothesis("s", "p", "v", 0.2, None);
    kg.set_status(h, HypothesisStatus::Rejected).unwrap();

    kg.attach_contradicting_evidence(h, evidence).unwrap();

    assert_eq!(kg.hypothesis(h).unwrap().status, HypothesisStatus::Rejected);
    assert_eq!(kg.hypothesis(h).unwrap().contradicting_evidence, vec![evidence]);
}

#[test]
fn attaching_evidence_to_unknown_hypothesis_is_an_error() {
    let mut kg = KnowledgeGraph::new();
    let obs = kg.add_observation("s", "p", "v", 1.0, "src", None);
    let evidence = kg.add_evidence(obs, "r", "src", None, None).unwrap();

    let bogus = HypothesisId(999);
    let err = kg
        .attach_contradicting_evidence(bogus, evidence)
        .unwrap_err();
    assert_eq!(err, KnowledgeError::UnknownHypothesis(bogus));
}
