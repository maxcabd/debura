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

#[test]
fn unknown_hypothesis_returns_none() {
    let mut graph = KnowledgeGraph::new();
    let bogus = debura_knowledge::HypothesisId(999);
    assert_eq!(
        reevaluate_hypothesis(&mut graph, bogus, &VerificationPolicy::default()),
        None
    );
}
