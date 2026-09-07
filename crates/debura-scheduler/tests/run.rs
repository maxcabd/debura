use std::time::Duration;

use debura_agent::mock::EchoProvider;
use debura_agent::{
    AgentProvider, AnalyzeFunctionTask, ChallengeHypothesisTask, ChallengeResult,
    InvestigationResult, ProposedHypothesis, Resolution, ResolutionResult,
    ResolveContradictionTask,
};
use debura_knowledge::{HypothesisStatus, KnowledgeGraph};
use debura_scheduler::{run, RunBudget, StopReason};
use debura_verifier::VerificationPolicy;

fn seeded_graph() -> KnowledgeGraph {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "compute", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "has_name", "add", 0.95, "ghidra:function", None);
    graph
}

#[test]
fn runs_to_completion_with_the_echo_provider() {
    let mut graph = seeded_graph();

    let summary = run(
        &mut graph,
        &EchoProvider,
        &VerificationPolicy::default(),
        &RunBudget::default(),
        |_, _, _| {},
    );

    assert_eq!(summary.stopped_because, StopReason::QueueEmpty);
    // AnalyzeFunction + ChallengeHypothesis per function; EchoProvider
    // never contradicts or proposes alternatives, so nothing else follows.
    assert_eq!(summary.iterations, 4);
    assert_eq!(graph.hypotheses().count(), 2);
    for h in graph.hypotheses() {
        assert!(h.last_verified_at.is_some());
    }
}

#[test]
fn max_iterations_stops_early_even_with_work_left() {
    let mut graph = seeded_graph();
    let budget = RunBudget {
        max_iterations: Some(1),
        ..Default::default()
    };

    let summary = run(
        &mut graph,
        &EchoProvider,
        &VerificationPolicy::default(),
        &budget,
        |_, _, _| {},
    );

    assert_eq!(summary.stopped_because, StopReason::MaxIterations);
    assert_eq!(summary.iterations, 1);
}

#[test]
fn zero_time_budget_stops_before_any_iteration() {
    let mut graph = seeded_graph();
    let budget = RunBudget {
        time_budget: Some(Duration::ZERO),
        ..Default::default()
    };

    let summary = run(
        &mut graph,
        &EchoProvider,
        &VerificationPolicy::default(),
        &budget,
        |_, _, _| {},
    );

    assert_eq!(summary.stopped_because, StopReason::TimeBudget);
    assert_eq!(summary.iterations, 0);
}

/// A provider that always finds a contradiction on challenge, so every
/// hypothesis's followups exercise ResolveContradiction too, not just
/// ChallengeHypothesis.
struct AlwaysContradicts;

impl AgentProvider for AlwaysContradicts {
    fn investigate(&self, task: &AnalyzeFunctionTask) -> anyhow::Result<InvestigationResult> {
        EchoProvider.investigate(task)
    }

    fn challenge(&self, _task: &ChallengeHypothesisTask) -> anyhow::Result<ChallengeResult> {
        Ok(ChallengeResult {
            contradiction: Some("scripted contradiction".to_string()),
            reasoning: "test".to_string(),
            ..Default::default()
        })
    }

    fn resolve_contradiction(
        &self,
        _task: &ResolveContradictionTask,
    ) -> anyhow::Result<ResolutionResult> {
        Ok(ResolutionResult {
            resolution: Resolution::Survives { confidence: 0.95 },
            reasoning: "test".to_string(),
        })
    }
}

#[test]
fn contested_hypotheses_get_a_resolve_contradiction_followup() {
    let mut graph = seeded_graph();

    let summary = run(
        &mut graph,
        &AlwaysContradicts,
        &VerificationPolicy::default(),
        &RunBudget::default(),
        |_, _, _| {},
    );

    assert_eq!(summary.stopped_because, StopReason::QueueEmpty);
    // AnalyzeFunction + ChallengeHypothesis + ResolveContradiction, per function.
    assert_eq!(summary.iterations, 6);
    for h in graph.hypotheses() {
        assert_eq!(
            h.status,
            HypothesisStatus::Accepted,
            "Survives at 0.95 + verified should clear both M5 gates"
        );
    }
}

/// A provider that always proposes the same claim, always finds a
/// (fabricated) contradiction on challenge, and always rejects on
/// resolution -- i.e. never converges. Stands in for a provider that keeps
/// making the same mistake, to prove the retry loop actually stops instead
/// of spending forever.
struct NeverConverges;

impl AgentProvider for NeverConverges {
    fn investigate(&self, _task: &AnalyzeFunctionTask) -> anyhow::Result<InvestigationResult> {
        Ok(InvestigationResult {
            hypotheses: vec![ProposedHypothesis {
                predicate: "is_a".to_string(),
                value: "GameEntity".to_string(),
                confidence: 0.9,
                depends_on: Vec::new(),
            }],
            ..Default::default()
        })
    }

    fn challenge(&self, _task: &ChallengeHypothesisTask) -> anyhow::Result<ChallengeResult> {
        Ok(ChallengeResult {
            contradiction: Some("fabricated claim, no such evidence".to_string()),
            reasoning: "test".to_string(),
            ..Default::default()
        })
    }

    fn resolve_contradiction(
        &self,
        _task: &ResolveContradictionTask,
    ) -> anyhow::Result<ResolutionResult> {
        Ok(ResolutionResult {
            resolution: Resolution::Rejected,
            reasoning: "test".to_string(),
        })
    }
}

#[test]
fn retries_after_rejection_are_bounded_not_infinite() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "mystery", 0.95, "ghidra:function", None);

    let summary = run(
        &mut graph,
        &NeverConverges,
        &VerificationPolicy::default(),
        &RunBudget::default(),
        |_, _, _| {},
    );

    assert_eq!(summary.stopped_because, StopReason::QueueEmpty);
    // 3 attempts x (AnalyzeFunction + ChallengeHypothesis + ResolveContradiction)
    assert_eq!(summary.iterations, 9);

    let attempts = graph
        .investigations()
        .filter(|i| i.task == "AnalyzeFunction" && i.target == "0x1")
        .count();
    assert_eq!(attempts, 3, "must stop retrying after the bounded max");

    let rejected = graph
        .hypotheses()
        .filter(|h| h.subject == "0x1" && h.status == HypothesisStatus::Rejected)
        .count();
    assert_eq!(rejected, 3, "every attempt's hypothesis was rejected");
}
