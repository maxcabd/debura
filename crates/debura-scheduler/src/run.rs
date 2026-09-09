use std::time::{Duration, Instant};

use debura_agent::{
    AnalyzeFunctionTask, ChallengeHypothesisTask, ChallengeResult, InvestigationResult,
    ResolutionResult, ResolveContradictionTask,
};
use debura_agent::AgentProvider;
use debura_knowledge::{HypothesisId, HypothesisStatus, KnowledgeGraph};
use debura_verifier::VerificationPolicy;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::queue::Scheduler;
use crate::seed::seed_initial_tasks;
use crate::task::Task;

/// How many times AnalyzeFunction will be re-run for the same subject after
/// its hypothesis gets REJECTED, before giving up on it. Bounded so a
/// provider that never converges on a subject can't loop (and spend)
/// forever -- counted from persisted Investigation records (survives a
/// restart mid-run), not an in-memory counter.
const MAX_ANALYSIS_ATTEMPTS: usize = 3;

fn analysis_attempt_count(graph: &KnowledgeGraph, subject: &str) -> usize {
    graph
        .investigations()
        .filter(|i| i.task == "AnalyzeFunction" && i.target == subject)
        .count()
}

/// A subject the scheduler has no more automatic work queued for right
/// now: it has an ACCEPTED hypothesis (regardless of any other sibling's
/// state), or every hypothesis on it has settled into a status the
/// scheduler doesn't act on -- SUPPORTED, REJECTED, STALE, or a
/// PROPOSED hypothesis that's already been through ChallengeHypothesis
/// (`last_verified_at.is_some()`) but stayed PROPOSED because its
/// confidence never reached `support_threshold` (M5's reevaluate_hypothesis)
/// -- rather than one still awaiting a challenge/resolve step (an
/// unverified PROPOSED, INVESTIGATING, or CONTESTED). A subject whose
/// only hypothesis was *just* rejected and has a retry already queued
/// for the next wave briefly counts as resolved here too -- it corrects
/// itself once that retry's fresh hypothesis lands a wave later, so this
/// is an approximate, reporting-grade signal, not a scheduler-state
/// guarantee.
fn is_resolved(graph: &KnowledgeGraph, subject: &str) -> bool {
    let mut has_any = false;
    let mut has_pending = false;
    for h in graph.hypotheses().filter(|h| h.subject == subject) {
        has_any = true;
        if h.status == HypothesisStatus::Accepted {
            return true;
        }
        let awaiting_first_challenge =
            h.status == HypothesisStatus::Proposed && h.last_verified_at.is_none();
        if awaiting_first_challenge
            || matches!(h.status, HypothesisStatus::Investigating | HypothesisStatus::Contested)
        {
            has_pending = true;
        }
    }
    has_any && !has_pending
}

/// `resolved`/`total` over every subject `seed_initial_tasks` proposed at
/// the start of the run -- PROJECT.md M10's "how much of the binary did
/// we actually explain," as an alternative to "is the queue empty" for
/// deciding when a run has done enough. `total` is fixed at seed time
/// (subjects already analyzed before this run started aren't included --
/// same scope `seed_initial_tasks` itself uses); `resolved` is
/// recomputed fresh each call.
fn coverage(graph: &KnowledgeGraph, seeded_subjects: &[String]) -> (usize, usize) {
    let resolved = seeded_subjects.iter().filter(|s| is_resolved(graph, s)).count();
    (resolved, seeded_subjects.len())
}

fn seeded_subjects(graph: &KnowledgeGraph) -> Vec<String> {
    seed_initial_tasks(graph)
        .into_iter()
        .map(|task| match task {
            Task::AnalyzeFunction { subject } => subject,
            // seed_initial_tasks only ever proposes AnalyzeFunction (seed.rs).
            _ => unreachable!("seed_initial_tasks only produces AnalyzeFunction tasks"),
        })
        .collect()
}

/// After a ResolveContradiction, decide whether the (now REJECTED)
/// subject is worth another AnalyzeFunction attempt. Shared by the
/// sequential and parallel loops so the retry cap can't drift between them.
fn retry_after_rejection(graph: &KnowledgeGraph, hypothesis: HypothesisId) -> Vec<Task> {
    let Some(h) = graph.hypothesis(hypothesis) else {
        return Vec::new();
    };
    if h.status != HypothesisStatus::Rejected {
        return Vec::new();
    }
    let subject = h.subject.clone();

    let attempts = analysis_attempt_count(graph, &subject);
    if attempts < MAX_ANALYSIS_ATTEMPTS {
        vec![Task::AnalyzeFunction { subject }]
    } else {
        tracing::info!(
            %subject,
            attempts,
            "giving up on subject after max AnalyzeFunction attempts"
        );
        Vec::new()
    }
}

/// PROJECT.md M6's four stopping conditions. `token_budget`/`cost_budget`
/// are accepted but not yet enforced: no `AgentProvider` implementation
/// (real or mock) reports usage yet, so there's nothing to check them
/// against. `max_iterations` and `time_budget` need no cooperation from the
/// provider and are enforced for real.
#[derive(Debug, Clone, Default)]
pub struct RunBudget {
    pub max_iterations: Option<u64>,
    pub time_budget: Option<Duration>,
    pub token_budget: Option<u64>,
    pub cost_budget: Option<f64>,
    /// Stop once `resolved/total` (see `coverage`) reaches this fraction,
    /// even with tasks still queued -- trading completeness for cost on
    /// a binary large enough that grinding out every last retry-capped
    /// straggler isn't worth it. `None` means uncapped (today's
    /// behavior: run to QueueEmpty or another budget).
    pub coverage_target: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    QueueEmpty,
    MaxIterations,
    TimeBudget,
    CoverageReached,
}

#[derive(Debug)]
pub struct RunSummary {
    pub iterations: u64,
    pub stopped_because: StopReason,
    /// Wall-clock time from seeding to the stop condition tripping. Not
    /// the same as token/cost spend (still unenforced -- no provider
    /// reports usage yet), but it's the one cost dimension free to
    /// measure without provider cooperation.
    pub elapsed: Duration,
    /// How many of `total_subjects` (everything seeded at the start of
    /// this run) reached a state the scheduler considers settled (see
    /// `is_resolved`), as of whenever the run stopped -- computed
    /// regardless of *why* it stopped, so this is meaningful even for
    /// `QueueEmpty` (should be 100%) as well as an early exit.
    pub resolved_subjects: usize,
    pub total_subjects: usize,
}

/// Runs the autonomous loop (PROJECT.md S24) until the task queue empties
/// or a budget trips, one task at a time. Ghidra feedback
/// (`ghidra.apply(...)` in S24's pseudocode) isn't wired in -- that's M8,
/// invoked separately via `debura apply`. `on_iteration` is called after
/// each task so the caller can checkpoint to storage and report progress
/// without this crate knowing anything about SQLite or a terminal.
///
/// For a large binary, most of the wall-clock time here is a real model
/// waiting on a network round trip -- and different subjects'/hypotheses'
/// task context is always scoped to their own data (PROJECT.md S23), so
/// those round trips don't actually depend on each other. `run_with_concurrency`
/// runs the same loop but overlaps that waiting across several tasks at
/// once; use this one when strict single-task-at-a-time ordering matters
/// more than throughput (e.g. tests).
pub fn run(
    graph: &mut KnowledgeGraph,
    provider: &dyn AgentProvider,
    policy: &VerificationPolicy,
    budget: &RunBudget,
    mut on_iteration: impl FnMut(u64, &Task, &KnowledgeGraph),
) -> RunSummary {
    // `seeded` (the coverage denominator) is captured before the
    // fingerprint cache can mutate the graph, so subjects it fast-paths
    // still count as part of the binary that needed handling.
    let seeded = seeded_subjects(graph);
    let cache_followups = crate::fingerprint::apply_fingerprint_cache(graph, &seeded);

    let mut scheduler = Scheduler::new();
    for task in seed_initial_tasks(graph) {
        scheduler.enqueue(graph, task);
    }
    for followup in cache_followups {
        scheduler.enqueue(graph, followup);
    }

    let start = Instant::now();
    let mut iterations = 0u64;

    let stopped_because = loop {
        if budget.max_iterations.is_some_and(|max| iterations >= max) {
            break StopReason::MaxIterations;
        }
        if budget.time_budget.is_some_and(|limit| start.elapsed() >= limit) {
            break StopReason::TimeBudget;
        }
        if budget
            .coverage_target
            .is_some_and(|target| coverage(graph, &seeded).0 as f64 / seeded.len().max(1) as f64 >= target)
        {
            break StopReason::CoverageReached;
        }

        let Some(task) = scheduler.pop() else {
            break StopReason::QueueEmpty;
        };

        for followup in execute(graph, provider, policy, &task) {
            scheduler.enqueue(graph, followup);
        }

        iterations += 1;
        on_iteration(iterations, &task, graph);
    };

    let (resolved_subjects, total_subjects) = coverage(graph, &seeded);
    RunSummary {
        iterations,
        stopped_because,
        elapsed: start.elapsed(),
        resolved_subjects,
        total_subjects,
    }
}

fn execute(
    graph: &mut KnowledgeGraph,
    provider: &dyn AgentProvider,
    policy: &VerificationPolicy,
    task: &Task,
) -> Vec<Task> {
    match task {
        Task::AnalyzeFunction { subject } => {
            match debura_agent::analyze_function(graph, provider, subject) {
                Ok(investigation_id) => {
                    let created = graph
                        .investigation(investigation_id)
                        .map(|i| i.hypotheses_created.clone())
                        .unwrap_or_default();

                    for id in &created {
                        debura_verifier::reevaluate_hypothesis(graph, *id, policy);
                    }

                    created
                        .into_iter()
                        .map(|hypothesis| Task::ChallengeHypothesis { hypothesis })
                        .collect()
                }
                Err(error) => {
                    tracing::warn!(%subject, %error, "AnalyzeFunction failed");
                    Vec::new()
                }
            }
        }

        Task::ChallengeHypothesis { hypothesis } => {
            match debura_verifier::challenge_hypothesis(graph, provider, *hypothesis, policy) {
                Ok(investigation_id) => {
                    let mut followups: Vec<Task> = graph
                        .investigation(investigation_id)
                        .map(|i| i.hypotheses_created.clone())
                        .unwrap_or_default()
                        .into_iter()
                        .map(|alternative| Task::ChallengeHypothesis {
                            hypothesis: alternative,
                        })
                        .collect();

                    if graph.hypothesis(*hypothesis).map(|h| h.status)
                        == Some(HypothesisStatus::Contested)
                    {
                        followups.push(Task::ResolveContradiction {
                            hypothesis: *hypothesis,
                        });
                    }

                    followups
                }
                Err(error) => {
                    tracing::warn!(%hypothesis, %error, "ChallengeHypothesis failed");
                    Vec::new()
                }
            }
        }

        Task::ResolveContradiction { hypothesis } => {
            match debura_verifier::resolve_contradiction(graph, provider, *hypothesis, policy) {
                Ok(_) => retry_after_rejection(graph, *hypothesis),
                Err(error) => {
                    tracing::warn!(%hypothesis, %error, "ResolveContradiction failed");
                    Vec::new()
                }
            }
        }
    }
}

/// The result of the non-mutating (build task + call provider) half of one
/// task, computed off the main thread. Mirrors `Task`'s three variants.
enum PendingOutcome {
    AnalyzeFunction {
        subject: String,
        outcome: anyhow::Result<(AnalyzeFunctionTask, InvestigationResult)>,
    },
    ChallengeHypothesis {
        hypothesis: HypothesisId,
        outcome: anyhow::Result<(ChallengeHypothesisTask, ChallengeResult)>,
    },
    ResolveContradiction {
        hypothesis: HypothesisId,
        outcome: anyhow::Result<(ResolveContradictionTask, ResolutionResult)>,
    },
}

/// How many AnalyzeFunction subjects go into one investigate_batch call.
/// Bounded well below a wave's full `concurrency`: an unbounded cluster
/// would turn one oversized, slow, all-or-nothing-on-parse-failure
/// request into the very bottleneck concurrency was meant to remove.
const MAX_CLUSTER_SIZE: usize = 5;

/// The parallel-safe half of a cluster of AnalyzeFunction subjects: builds
/// each one's context (safe to do concurrently -- PROJECT.md S23), then
/// makes one `investigate_batch` call covering all of them.
fn resolve_analyze_cluster(
    graph: &KnowledgeGraph,
    provider: &(dyn AgentProvider + Sync),
    subjects: &[String],
) -> Vec<(Task, PendingOutcome)> {
    let built: Vec<AnalyzeFunctionTask> =
        subjects.iter().map(|s| AnalyzeFunctionTask::build(graph, s)).collect();
    let results = provider.investigate_batch(&built);

    built
        .into_iter()
        .zip(results)
        .map(|(task, outcome)| {
            let subject = task.subject.clone();
            (
                Task::AnalyzeFunction { subject: subject.clone() },
                PendingOutcome::AnalyzeFunction {
                    subject,
                    outcome: outcome.map(|r| (task, r)),
                },
            )
        })
        .collect()
}

/// The parallel-safe half of a cluster of ChallengeHypothesis tasks:
/// builds each hypothesis's context, then makes one `challenge_batch`
/// call covering all of them. A hypothesis whose task fails to build
/// (already gone, say) reports that failure on its own without losing
/// the rest of the cluster.
fn resolve_challenge_cluster(
    graph: &KnowledgeGraph,
    provider: &(dyn AgentProvider + Sync),
    hypotheses: &[HypothesisId],
) -> Vec<(Task, PendingOutcome)> {
    let mut built = Vec::new();
    let mut build_failures = Vec::new();
    for &hypothesis in hypotheses {
        match debura_verifier::build_challenge_task(graph, hypothesis) {
            Ok(task) => built.push(task),
            Err(error) => build_failures.push((hypothesis, error)),
        }
    }

    let results = provider.challenge_batch(&built);

    let mut outcomes: Vec<(Task, PendingOutcome)> = built
        .into_iter()
        .zip(results)
        .map(|(task, outcome)| {
            let hypothesis = task.hypothesis.id;
            (
                Task::ChallengeHypothesis { hypothesis },
                PendingOutcome::ChallengeHypothesis {
                    hypothesis,
                    outcome: outcome.map(|r| (task, r)),
                },
            )
        })
        .collect();

    for (hypothesis, error) in build_failures {
        outcomes.push((
            Task::ChallengeHypothesis { hypothesis },
            PendingOutcome::ChallengeHypothesis { hypothesis, outcome: Err(error) },
        ));
    }
    outcomes
}

/// Same shape as `resolve_challenge_cluster`, for ResolveContradiction.
fn resolve_resolution_cluster(
    graph: &KnowledgeGraph,
    provider: &(dyn AgentProvider + Sync),
    hypotheses: &[HypothesisId],
) -> Vec<(Task, PendingOutcome)> {
    let mut built = Vec::new();
    let mut build_failures = Vec::new();
    for &hypothesis in hypotheses {
        match debura_verifier::build_resolve_task(graph, hypothesis) {
            Ok(task) => built.push(task),
            Err(error) => build_failures.push((hypothesis, error)),
        }
    }

    let results = provider.resolve_batch(&built);

    let mut outcomes: Vec<(Task, PendingOutcome)> = built
        .into_iter()
        .zip(results)
        .map(|(task, outcome)| {
            let hypothesis = task.hypothesis.id;
            (
                Task::ResolveContradiction { hypothesis },
                PendingOutcome::ResolveContradiction {
                    hypothesis,
                    outcome: outcome.map(|r| (task, r)),
                },
            )
        })
        .collect();

    for (hypothesis, error) in build_failures {
        outcomes.push((
            Task::ResolveContradiction { hypothesis },
            PendingOutcome::ResolveContradiction { hypothesis, outcome: Err(error) },
        ));
    }
    outcomes
}

/// The mutating half: commits whatever a cluster resolver produced. Always
/// called on the main thread, one outcome at a time -- this is the only
/// part of a wave that touches `&mut KnowledgeGraph`.
fn commit_one(graph: &mut KnowledgeGraph, policy: &VerificationPolicy, outcome: PendingOutcome) -> Vec<Task> {
    match outcome {
        PendingOutcome::AnalyzeFunction { subject, outcome } => match outcome {
            Ok((task, result)) => {
                let investigation_id = debura_agent::commit_investigation(graph, &task, result);
                let created = graph
                    .investigation(investigation_id)
                    .map(|i| i.hypotheses_created.clone())
                    .unwrap_or_default();
                for id in &created {
                    debura_verifier::reevaluate_hypothesis(graph, *id, policy);
                }
                created
                    .into_iter()
                    .map(|hypothesis| Task::ChallengeHypothesis { hypothesis })
                    .collect()
            }
            Err(error) => {
                tracing::warn!(%subject, %error, "AnalyzeFunction failed");
                Vec::new()
            }
        },

        PendingOutcome::ChallengeHypothesis { hypothesis, outcome } => match outcome {
            Ok((task, result)) => {
                let context_snapshot = format!(
                    "{} supporting evidence, {} other observations",
                    task.supporting_evidence.len(),
                    task.other_observations.len()
                );
                match debura_verifier::commit_challenge(graph, hypothesis, &context_snapshot, result, policy) {
                    Ok(investigation_id) => {
                        let mut followups: Vec<Task> = graph
                            .investigation(investigation_id)
                            .map(|i| i.hypotheses_created.clone())
                            .unwrap_or_default()
                            .into_iter()
                            .map(|alternative| Task::ChallengeHypothesis {
                                hypothesis: alternative,
                            })
                            .collect();

                        if graph.hypothesis(hypothesis).map(|h| h.status)
                            == Some(HypothesisStatus::Contested)
                        {
                            followups.push(Task::ResolveContradiction { hypothesis });
                        }
                        followups
                    }
                    Err(error) => {
                        tracing::warn!(%hypothesis, %error, "commit_challenge failed");
                        Vec::new()
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%hypothesis, %error, "ChallengeHypothesis failed");
                Vec::new()
            }
        },

        PendingOutcome::ResolveContradiction { hypothesis, outcome } => match outcome {
            Ok((task, result)) => {
                match debura_verifier::commit_resolution(graph, hypothesis, &task, result, policy) {
                    Ok(_) => retry_after_rejection(graph, hypothesis),
                    Err(error) => {
                        tracing::warn!(%hypothesis, %error, "commit_resolution failed");
                        Vec::new()
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%hypothesis, %error, "ResolveContradiction failed");
                Vec::new()
            }
        },
    }
}

/// Same loop as `run`, but processes up to `concurrency` tasks per wave:
/// building each task's context and calling the provider run in parallel
/// (both touch the graph only through `&KnowledgeGraph` -- PROJECT.md S23
/// guarantees task context never crosses subjects, so this never races),
/// then every result in the wave is committed one at a time on the calling
/// thread. Uses a dedicated thread pool sized for `concurrency` rather than
/// rayon's CPU-count default, since the work here is waiting on network
/// I/O, not computing -- there's no reason to cap it at core count.
pub fn run_with_concurrency(
    graph: &mut KnowledgeGraph,
    provider: &(dyn AgentProvider + Sync),
    policy: &VerificationPolicy,
    budget: &RunBudget,
    concurrency: usize,
    mut on_iteration: impl FnMut(u64, &Task, &KnowledgeGraph),
) -> RunSummary {
    let concurrency = concurrency.max(1);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(concurrency)
        .build()
        .expect("failed to build thread pool");

    // `seeded` (the coverage denominator) is captured before the
    // fingerprint cache can mutate the graph, so subjects it fast-paths
    // still count as part of the binary that needed handling.
    let seeded = seeded_subjects(graph);
    let cache_followups = crate::fingerprint::apply_fingerprint_cache(graph, &seeded);

    let mut scheduler = Scheduler::new();
    for task in seed_initial_tasks(graph) {
        scheduler.enqueue(graph, task);
    }
    for followup in cache_followups {
        scheduler.enqueue(graph, followup);
    }

    let start = Instant::now();
    let mut iterations = 0u64;

    let stopped_because = loop {
        if budget.max_iterations.is_some_and(|max| iterations >= max) {
            break StopReason::MaxIterations;
        }
        if budget.time_budget.is_some_and(|limit| start.elapsed() >= limit) {
            break StopReason::TimeBudget;
        }
        if budget
            .coverage_target
            .is_some_and(|target| coverage(graph, &seeded).0 as f64 / seeded.len().max(1) as f64 >= target)
        {
            break StopReason::CoverageReached;
        }

        let mut batch = Vec::new();
        while batch.len() < concurrency {
            if budget
                .max_iterations
                .is_some_and(|max| iterations + batch.len() as u64 >= max)
            {
                break;
            }
            match scheduler.pop() {
                Some(task) => batch.push(task),
                None => break,
            }
        }
        if batch.is_empty() {
            break StopReason::QueueEmpty;
        }

        // Every task type in this wave is clustered into groups of up to
        // MAX_CLUSTER_SIZE and sent through its provider's batch method,
        // one model call per group instead of one per subject/hypothesis
        // -- a real run showed why this matters for all three, not just
        // AnalyzeFunction: ChallengeHypothesis and ResolveContradiction
        // together made up 72% of that run's request volume, each paying
        // a full system-prompt-and-schema request on its own. The three
        // groups run in parallel with each other via the same thread pool.
        let mut analyze_subjects = Vec::new();
        let mut challenge_hypotheses = Vec::new();
        let mut resolve_hypotheses = Vec::new();
        for task in batch {
            match task {
                Task::AnalyzeFunction { subject } => analyze_subjects.push(subject),
                Task::ChallengeHypothesis { hypothesis } => challenge_hypotheses.push(hypothesis),
                Task::ResolveContradiction { hypothesis } => resolve_hypotheses.push(hypothesis),
            }
        }
        let analyze_chunks: Vec<&[String]> = analyze_subjects.chunks(MAX_CLUSTER_SIZE).collect();
        let challenge_chunks: Vec<&[HypothesisId]> =
            challenge_hypotheses.chunks(MAX_CLUSTER_SIZE).collect();
        let resolve_chunks: Vec<&[HypothesisId]> =
            resolve_hypotheses.chunks(MAX_CLUSTER_SIZE).collect();

        let graph_ref: &KnowledgeGraph = graph;
        let (analyze_outcomes, (challenge_outcomes, resolve_outcomes)): (
            Vec<Vec<(Task, PendingOutcome)>>,
            (Vec<Vec<(Task, PendingOutcome)>>, Vec<Vec<(Task, PendingOutcome)>>),
        ) = pool.install(|| {
            rayon::join(
                || {
                    analyze_chunks
                        .into_par_iter()
                        .map(|chunk| resolve_analyze_cluster(graph_ref, provider, chunk))
                        .collect()
                },
                || {
                    rayon::join(
                        || {
                            challenge_chunks
                                .into_par_iter()
                                .map(|chunk| resolve_challenge_cluster(graph_ref, provider, chunk))
                                .collect()
                        },
                        || {
                            resolve_chunks
                                .into_par_iter()
                                .map(|chunk| resolve_resolution_cluster(graph_ref, provider, chunk))
                                .collect()
                        },
                    )
                },
            )
        });

        let all_outcomes = analyze_outcomes
            .into_iter()
            .flatten()
            .chain(challenge_outcomes.into_iter().flatten())
            .chain(resolve_outcomes.into_iter().flatten());
        for (task, outcome) in all_outcomes {
            for followup in commit_one(graph, policy, outcome) {
                scheduler.enqueue(graph, followup);
            }
            iterations += 1;
            on_iteration(iterations, &task, graph);
        }
    };

    let (resolved_subjects, total_subjects) = coverage(graph, &seeded);
    RunSummary {
        iterations,
        stopped_because,
        elapsed: start.elapsed(),
        resolved_subjects,
        total_subjects,
    }
}
