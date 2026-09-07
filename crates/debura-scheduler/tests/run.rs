use std::time::Duration;

use debura_agent::mock::EchoProvider;
use debura_agent::{
    AgentProvider, AnalyzeFunctionTask, ChallengeHypothesisTask, ChallengeResult,
    InvestigationResult, ProposedHypothesis, Resolution, ResolutionResult,
    ResolveContradictionTask,
};
use debura_knowledge::{HypothesisStatus, KnowledgeGraph};
use debura_scheduler::{run, run_with_concurrency, RunBudget, StopReason};
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

/// The parallel loop (M10: real binaries are too big for one-at-a-time
/// network round trips to be practical) must reach the same end state as
/// the sequential one for the same provider -- concurrency changes wall
/// clock time, not the outcome.
#[test]
fn parallel_run_reaches_the_same_outcome_as_sequential() {
    let mut graph = seeded_graph();

    let summary = run_with_concurrency(
        &mut graph,
        &EchoProvider,
        &VerificationPolicy::default(),
        &RunBudget::default(),
        4,
        |_, _, _| {},
    );

    assert_eq!(summary.stopped_because, StopReason::QueueEmpty);
    assert_eq!(summary.iterations, 4);
    assert_eq!(graph.hypotheses().count(), 2);
    for h in graph.hypotheses() {
        assert!(h.last_verified_at.is_some());
    }
}

#[test]
fn parallel_run_still_bounds_retries_after_rejection() {
    let mut graph = seeded_graph();

    let summary = run_with_concurrency(
        &mut graph,
        &NeverConverges,
        &VerificationPolicy::default(),
        &RunBudget::default(),
        4,
        |_, _, _| {},
    );

    assert_eq!(summary.stopped_because, StopReason::QueueEmpty);
    // Two subjects this time (both seeded), same 3-attempt cap each.
    for subject in ["0x1", "0x2"] {
        let attempts = graph
            .investigations()
            .filter(|i| i.task == "AnalyzeFunction" && i.target == subject)
            .count();
        assert_eq!(attempts, 3, "must stop retrying after the bounded max");
    }
}

/// A single AnalyzeFunction call that proposes several competing
/// hypotheses on the same subject at once, all of which get contradicted
/// and rejected together. Real run against the Snake fixture hit this:
/// with multiple live hypotheses sharing a subject, several rejections
/// can land in the same commit batch, each reading the same
/// not-yet-incremented persisted attempt count and each deciding to
/// retry -- one subject reached 10 AnalyzeFunction attempts against a
/// cap of 3 before the scheduler deduplicated identical waiting tasks.
struct NeverConvergesWithCompetingHypotheses;

impl AgentProvider for NeverConvergesWithCompetingHypotheses {
    fn investigate(&self, _task: &AnalyzeFunctionTask) -> anyhow::Result<InvestigationResult> {
        Ok(InvestigationResult {
            hypotheses: (0..3)
                .map(|i| ProposedHypothesis {
                    predicate: "is_a".to_string(),
                    value: format!("GameEntity{i}"),
                    confidence: 0.9,
                    depends_on: Vec::new(),
                })
                .collect(),
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
fn parallel_run_bounds_retries_even_when_multiple_hypotheses_share_a_subject() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "mystery", 0.95, "ghidra:function", None);

    let summary = run_with_concurrency(
        &mut graph,
        &NeverConvergesWithCompetingHypotheses,
        &VerificationPolicy::default(),
        &RunBudget::default(),
        4,
        |_, _, _| {},
    );

    assert_eq!(summary.stopped_because, StopReason::QueueEmpty);

    let attempts = graph
        .investigations()
        .filter(|i| i.task == "AnalyzeFunction" && i.target == "0x1")
        .count();
    assert_eq!(
        attempts, 3,
        "must stay bounded even when several hypotheses on the same subject are rejected together"
    );
}

#[test]
fn parallel_run_respects_max_iterations() {
    let mut graph = seeded_graph();
    let budget = RunBudget {
        max_iterations: Some(3),
        ..Default::default()
    };

    let summary = run_with_concurrency(
        &mut graph,
        &EchoProvider,
        &VerificationPolicy::default(),
        &budget,
        4,
        |_, _, _| {},
    );

    assert_eq!(summary.stopped_because, StopReason::MaxIterations);
    assert_eq!(summary.iterations, 3);
}
