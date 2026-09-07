use std::time::Duration;

use chrono::Utc;
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
    assert_eq!(summary.resolved_subjects, 2);
    assert_eq!(summary.total_subjects, 2);
}

/// PROJECT.md M10: stop once enough of the binary is explained, instead
/// of always grinding the queue to empty -- useful on a binary large
/// enough that the last stragglers cost more than they're worth.
#[test]
fn coverage_target_stops_before_the_queue_empties() {
    let mut graph = seeded_graph();
    let budget = RunBudget {
        coverage_target: Some(0.5),
        ..Default::default()
    };

    let summary = run(&mut graph, &EchoProvider, &VerificationPolicy::default(), &budget, |_, _, _| {});

    assert_eq!(summary.stopped_because, StopReason::CoverageReached);
    // Full completion takes 4 iterations (see the unbounded test above);
    // reaching 50% coverage (1 of 2 subjects resolved) must stop short of that.
    assert!(summary.iterations < 4, "should stop once coverage is reached, not run to completion");
    assert_eq!(summary.total_subjects, 2);
    assert!(summary.resolved_subjects * 2 >= summary.total_subjects, "at least 50% must be resolved");
}

/// PROJECT.md M10: a subject whose decompiled body exactly matches
/// (after Ghidra-address normalization) an already-solved subject
/// should reuse that answer instead of spending another AnalyzeFunction
/// call on code we've already investigated once.
#[test]
fn a_structurally_identical_subject_reuses_the_accepted_answer_without_a_fresh_investigation() {
    let mut graph = KnowledgeGraph::new();

    graph.add_observation("0x1", "has_name", "resetLevel", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "void resetLevel(void) { score = DAT_140009070; return; }",
        0.95,
        "ghidra:decompiler",
        None,
    );
    let h = graph.propose_hypothesis("0x1", "semantic_role", "resetLevel", 0.9, None);
    graph.mark_verified(h, Utc::now()).unwrap();
    graph.set_status(h, HypothesisStatus::Accepted).unwrap();

    // Same shape, different embedded address -- the case a real re-run
    // of the same source at another address (or a duplicate/COMDAT-folded
    // copy) actually looks like.
    graph.add_observation("0x2", "has_name", "FUN_dead", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x2",
        "decompiles_to",
        "void resetLevel(void) { score = DAT_1400091a0; return; }",
        0.95,
        "ghidra:decompiler",
        None,
    );

    let summary = run(&mut graph, &EchoProvider, &VerificationPolicy::default(), &RunBudget::default(), |_, _, _| {});

    assert_eq!(summary.stopped_because, StopReason::QueueEmpty);

    let analyzed_0x2 = graph
        .investigations()
        .filter(|i| i.task == "AnalyzeFunction" && i.target == "0x2")
        .count();
    assert_eq!(analyzed_0x2, 0, "a fingerprint match must skip the model call entirely");

    let semantic_role = graph
        .hypotheses()
        .find(|h| h.subject == "0x2" && h.predicate == "semantic_role")
        .expect("the cloned hypothesis should exist");
    assert_eq!(semantic_role.value, "resetLevel");
    assert_eq!(semantic_role.status, HypothesisStatus::Accepted);

    assert!(
        graph
            .observations()
            .any(|o| o.subject == "0x2" && o.predicate == "fingerprint_cache_source" && o.value == "0x1"),
        "the reused answer's provenance must be traceable back to its source subject"
    );
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

/// A provider that records how many subjects/hypotheses it was asked to
/// handle in each batch call, so a test can prove clustering actually
/// happened rather than the default one-at-a-time fallback.
struct RecordingBatchProvider {
    batch_sizes: std::sync::Mutex<Vec<usize>>,
    challenge_batch_sizes: std::sync::Mutex<Vec<usize>>,
    resolve_batch_sizes: std::sync::Mutex<Vec<usize>>,
}

impl RecordingBatchProvider {
    fn new() -> Self {
        Self {
            batch_sizes: std::sync::Mutex::new(Vec::new()),
            challenge_batch_sizes: std::sync::Mutex::new(Vec::new()),
            resolve_batch_sizes: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl AgentProvider for RecordingBatchProvider {
    fn investigate(&self, task: &AnalyzeFunctionTask) -> anyhow::Result<InvestigationResult> {
        EchoProvider.investigate(task)
    }

    // Unlike EchoProvider, always reports a contradiction -- so a test
    // built on this provider can also exercise ResolveContradiction
    // clustering, which only ever gets queued as a real follow-up of a
    // challenge that actually found something (PROJECT.md: seed_initial_tasks
    // never seeds ResolveContradiction for a pre-existing CONTESTED
    // hypothesis on its own).
    fn challenge(&self, _task: &ChallengeHypothesisTask) -> anyhow::Result<ChallengeResult> {
        Ok(ChallengeResult {
            contradiction: Some("RecordingBatchProvider always contradicts, for testing".to_string()),
            ..Default::default()
        })
    }

    fn resolve_contradiction(&self, task: &ResolveContradictionTask) -> anyhow::Result<ResolutionResult> {
        EchoProvider.resolve_contradiction(task)
    }

    fn investigate_batch(&self, tasks: &[AnalyzeFunctionTask]) -> Vec<anyhow::Result<InvestigationResult>> {
        self.batch_sizes.lock().unwrap().push(tasks.len());
        tasks.iter().map(|t| self.investigate(t)).collect()
    }

    fn challenge_batch(&self, tasks: &[ChallengeHypothesisTask]) -> Vec<anyhow::Result<ChallengeResult>> {
        self.challenge_batch_sizes.lock().unwrap().push(tasks.len());
        tasks.iter().map(|t| self.challenge(t)).collect()
    }

    fn resolve_batch(&self, tasks: &[ResolveContradictionTask]) -> Vec<anyhow::Result<ResolutionResult>> {
        self.resolve_batch_sizes.lock().unwrap().push(tasks.len());
        tasks.iter().map(|t| self.resolve_contradiction(t)).collect()
    }
}

/// PROJECT.md M10: several AnalyzeFunction subjects ready in the same
/// wave must go through one investigate_batch call, not one investigate
/// call each -- that's the entire point of clustering.
#[test]
fn parallel_run_clusters_analyze_function_into_batches() {
    let mut graph = KnowledgeGraph::new();
    for i in 1..=6 {
        graph.add_observation(
            format!("0x{i}"),
            "has_name",
            format!("fn{i}"),
            0.95,
            "ghidra:function",
            None,
        );
    }
    let provider = RecordingBatchProvider::new();

    let summary = run_with_concurrency(
        &mut graph,
        &provider,
        &VerificationPolicy::default(),
        &RunBudget::default(),
        8, // >= 6, so all 6 seeded subjects land in the first wave together
        |_, _, _| {},
    );

    assert_eq!(summary.stopped_because, StopReason::QueueEmpty);
    assert_eq!(summary.total_subjects, 6);

    let batch_sizes = provider.batch_sizes.into_inner().unwrap();
    assert!(
        batch_sizes.iter().any(|&size| size > 1),
        "expected at least one clustered call, got batch sizes {batch_sizes:?}"
    );
    assert_eq!(
        batch_sizes.iter().sum::<usize>(),
        6,
        "every seeded subject must still be covered exactly once across all batches"
    );
}

/// PROJECT.md M10: a real run showed ChallengeHypothesis and
/// ResolveContradiction together made up 72% of that run's request
/// volume, each going through the provider one hypothesis at a time --
/// the same clustering AnalyzeFunction already gets must apply to both.
/// This drives one seeded graph all the way through AnalyzeFunction (6
/// hypotheses proposed) -> ChallengeHypothesis (RecordingBatchProvider
/// always contradicts, so all 6 become CONTESTED) -> ResolveContradiction,
/// checking both stages actually clustered rather than falling back to
/// one call per hypothesis.
#[test]
fn parallel_run_clusters_challenge_and_resolve_into_batches() {
    let mut graph = KnowledgeGraph::new();
    for i in 1..=6 {
        graph.add_observation(
            format!("0x{i}"),
            "has_name",
            format!("fn{i}"),
            0.95,
            "ghidra:function",
            None,
        );
    }
    let provider = RecordingBatchProvider::new();

    let summary = run_with_concurrency(
        &mut graph,
        &provider,
        &VerificationPolicy::default(),
        &RunBudget::default(),
        8, // >= 6, so each stage's 6 tasks land in one wave together
        |_, _, _| {},
    );

    assert_eq!(summary.stopped_because, StopReason::QueueEmpty);

    let challenge_sizes = provider.challenge_batch_sizes.into_inner().unwrap();
    assert!(
        challenge_sizes.iter().any(|&size| size > 1),
        "expected at least one clustered challenge call, got sizes {challenge_sizes:?}"
    );
    assert_eq!(
        challenge_sizes.iter().sum::<usize>(),
        6,
        "every hypothesis must still be challenged exactly once across all batches"
    );

    let resolve_sizes = provider.resolve_batch_sizes.into_inner().unwrap();
    assert!(
        resolve_sizes.iter().any(|&size| size > 1),
        "expected at least one clustered resolve call, got sizes {resolve_sizes:?}"
    );
    assert_eq!(
        resolve_sizes.iter().sum::<usize>(),
        6,
        "every contested hypothesis must still be resolved exactly once across all batches"
    );
}
