use debura_knowledge::{DependencyKind, HypothesisStatus, KnowledgeGraph};

/// PROJECT.md S8: H4 DEPENDS_ON H3 DEPENDS_ON H2 DEPENDS_ON H1.
/// Rejecting H1 must cascade STALE through H2, H3 and H4.
#[test]
fn rejecting_a_hypothesis_marks_its_dependents_stale() {
    let mut kg = KnowledgeGraph::new();

    let h1 = kg.propose_hypothesis("PlayerCharacter+0x138", "semantic_role", "health", 0.91, None);
    let h2 = kg.propose_hypothesis("F193", "modifies", "health", 0.85, None);
    let h3 = kg.propose_hypothesis("F193", "semantic_role", "TakeDamage", 0.82, None);
    let h4 = kg.propose_hypothesis("F193", "member_of", "PlayerCharacter", 0.78, None);

    for h in [h1, h2, h3, h4] {
        kg.set_status(h, HypothesisStatus::Accepted).unwrap();
    }

    kg.add_dependency(h2, h1, DependencyKind::DependsOn).unwrap();
    kg.add_dependency(h3, h2, DependencyKind::DependsOn).unwrap();
    kg.add_dependency(h4, h3, DependencyKind::DependsOn).unwrap();

    let mut newly_stale = kg.set_status(h1, HypothesisStatus::Rejected).unwrap();
    newly_stale.sort();

    assert_eq!(
        kg.hypothesis(h1).unwrap().status,
        HypothesisStatus::Rejected
    );
    assert_eq!(kg.hypothesis(h2).unwrap().status, HypothesisStatus::Stale);
    assert_eq!(kg.hypothesis(h3).unwrap().status, HypothesisStatus::Stale);
    assert_eq!(kg.hypothesis(h4).unwrap().status, HypothesisStatus::Stale);

    let mut expected = vec![h2, h3, h4];
    expected.sort();
    assert_eq!(newly_stale, expected);
}

/// PROJECT.md S4: REJECTED is terminal. A hypothesis that depends on
/// something whose confidence later drops must not un-reject.
#[test]
fn rejected_hypotheses_are_never_resurrected_by_cascade() {
    let mut kg = KnowledgeGraph::new();

    let target = kg.propose_hypothesis("subject", "pred", "value", 0.5, None);
    let dependent = kg.propose_hypothesis("subject2", "pred2", "value2", 0.5, None);

    kg.set_status(dependent, HypothesisStatus::Rejected).unwrap();
    kg.add_dependency(dependent, target, DependencyKind::DependsOn)
        .unwrap();

    kg.set_confidence(target, 0.1).unwrap();

    assert_eq!(
        kg.hypothesis(dependent).unwrap().status,
        HypothesisStatus::Rejected
    );
}

/// A cyclic dependency graph must not hang the propagation traversal.
#[test]
fn cyclic_dependencies_do_not_infinite_loop() {
    let mut kg = KnowledgeGraph::new();

    let a = kg.propose_hypothesis("a", "p", "v", 0.5, None);
    let b = kg.propose_hypothesis("b", "p", "v", 0.5, None);

    kg.add_dependency(a, b, DependencyKind::DependsOn).unwrap();
    kg.add_dependency(b, a, DependencyKind::DependsOn).unwrap();

    let stale = kg.set_confidence(a, 0.1).unwrap();

    assert_eq!(kg.hypothesis(b).unwrap().status, HypothesisStatus::Stale);
    assert_eq!(stale, vec![b]);
}
