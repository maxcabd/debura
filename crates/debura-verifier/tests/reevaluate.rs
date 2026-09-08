use chrono::Utc;
use debura_knowledge::{HypothesisStatus, KnowledgeGraph};
use debura_verifier::{reevaluate_hypothesis, VerificationPolicy};

/// PROJECT.md M5's central requirement, isolated from any provider: no
/// amount of raw confidence promotes a hypothesis to ACCEPTED without an
/// actual verification attempt on record.
#[test]
fn high_confidence_without_verification_stays_supported() {
    let mut graph = KnowledgeGraph::new();
    let h = graph.propose_hypothesis("0x1", "semantic_role", "TakeDamage", 0.95, None);

    let status = reevaluate_hypothesis(&mut graph, h, &VerificationPolicy::default()).unwrap();

    assert_eq!(status, HypothesisStatus::Supported);
    assert_eq!(graph.hypothesis(h).unwrap().status, HypothesisStatus::Supported);
}

#[test]
fn high_confidence_with_verification_reaches_accepted() {
    let mut graph = KnowledgeGraph::new();
    // PROJECT.md M17: a bare subject with no other observations has no
    // provenance signal at all and is correctly Unknown, not Application
    // -- give it a real application class so this test exercises the
    // threshold logic it's actually about, not the provenance gate.
    graph.add_observation("0x1", "is_method_of", "Wall", 0.95, "ghidra:function", None);
    let h = graph.propose_hypothesis("0x1", "semantic_role", "TakeDamage", 0.95, None);
    graph.mark_verified(h, Utc::now()).unwrap();

    let status = reevaluate_hypothesis(&mut graph, h, &VerificationPolicy::default()).unwrap();

    assert_eq!(status, HypothesisStatus::Accepted);
}

#[test]
fn low_confidence_stays_proposed_even_if_verified() {
    let mut graph = KnowledgeGraph::new();
    let h = graph.propose_hypothesis("0x1", "semantic_role", "guess", 0.3, None);
    graph.mark_verified(h, Utc::now()).unwrap();

    let status = reevaluate_hypothesis(&mut graph, h, &VerificationPolicy::default()).unwrap();

    assert_eq!(status, HypothesisStatus::Proposed);
}

#[test]
fn contested_and_rejected_are_left_alone() {
    let mut graph = KnowledgeGraph::new();
    let policy = VerificationPolicy::default();

    let contested = graph.propose_hypothesis("0x1", "p", "v", 0.99, None);
    graph.mark_verified(contested, Utc::now()).unwrap();
    graph
        .set_status(contested, HypothesisStatus::Contested)
        .unwrap();
    assert_eq!(
        reevaluate_hypothesis(&mut graph, contested, &policy),
        Some(HypothesisStatus::Contested)
    );

    let rejected = graph.propose_hypothesis("0x2", "p", "v", 0.99, None);
    graph.mark_verified(rejected, Utc::now()).unwrap();
    graph
        .set_status(rejected, HypothesisStatus::Rejected)
        .unwrap();
    assert_eq!(
        reevaluate_hypothesis(&mut graph, rejected, &policy),
        Some(HypothesisStatus::Rejected)
    );
}

/// PROJECT.md M17: the provenance gate. A semantic_role that would
/// otherwise clear the acceptance threshold must still be rejected if the
/// subject's provenance isn't Application -- the exact bug a real audit
/// found (library/CRT internals earning application-sounding names)
/// happening because nothing enforced this at the acceptance gate.
#[test]
fn a_semantic_role_on_a_non_application_subject_is_rejected_even_at_high_confidence() {
    let mut graph = KnowledgeGraph::new();
    // No is_method_of, no calls, no name beyond the implicit raw
    // placeholder -- exactly the "genuinely stripped, no signal either
    // way" shape that must resolve Unknown, not Application.
    let h = graph.propose_hypothesis("0x1", "semantic_role", "invokeAnotherFunction", 0.95, None);
    graph.mark_verified(h, Utc::now()).unwrap();

    let status = reevaluate_hypothesis(&mut graph, h, &VerificationPolicy::default()).unwrap();

    assert_eq!(status, HypothesisStatus::Rejected);
    assert_eq!(graph.hypothesis(h).unwrap().status, HypothesisStatus::Rejected);
}

/// The gate is specific to semantic_role -- a mechanical_behavior claim
/// about a non-Application subject is still real, useful knowledge (the
/// user's own point: "you can still recover or recognize the function
/// structurally") and must not be blocked by this check.
#[test]
fn the_provenance_gate_does_not_touch_mechanical_behavior() {
    let mut graph = KnowledgeGraph::new();
    let h = graph.propose_hypothesis("0x1", "mechanical_behavior", "callsOneFunction", 0.95, None);
    graph.mark_verified(h, Utc::now()).unwrap();

    let status = reevaluate_hypothesis(&mut graph, h, &VerificationPolicy::default()).unwrap();

    assert_eq!(status, HypothesisStatus::Accepted);
}

#[test]
fn unknown_hypothesis_returns_none() {
    let mut graph = KnowledgeGraph::new();
    let bogus = debura_knowledge::HypothesisId(999);
    assert_eq!(
        reevaluate_hypothesis(&mut graph, bogus, &VerificationPolicy::default()),
        None
    );
}
