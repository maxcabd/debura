use anyhow::{bail, Context, Result};
use chrono::Utc;
use debura_agent::{
    commit_contradiction, commit_hypothesis, AgentProvider, ChallengeHypothesisTask,
    ChallengeResult, Resolution, ResolutionResult, ResolveContradictionTask,
};
use debura_knowledge::{
    DependencyKind, HypothesisId, HypothesisStatus, Investigation, InvestigationId, KnowledgeGraph,
};

use crate::policy::VerificationPolicy;
use crate::reevaluate::reevaluate_hypothesis;

/// The non-mutating half of `challenge_hypothesis`: builds the task and
/// calls the provider, touching the graph only through `&KnowledgeGraph`.
/// Task context is always scoped to one hypothesis's own subject
/// (PROJECT.md S23), so this is safe to run concurrently across different
/// hypotheses (M10) -- only `commit_challenge` needs exclusive access.
pub fn challenge(
    graph: &KnowledgeGraph,
    provider: &dyn AgentProvider,
    hypothesis: HypothesisId,
) -> Result<(ChallengeHypothesisTask, ChallengeResult)> {
    let target = graph
        .hypothesis(hypothesis)
        .with_context(|| format!("unknown hypothesis: {hypothesis}"))?
        .clone();

    let task = ChallengeHypothesisTask::build(graph, &target);
    let result = provider.challenge(&task)?;
    Ok((task, result))
}

/// The mutating half of `challenge_hypothesis` -- call with exclusive
/// access after `challenge` returns (from any thread).
pub fn commit_challenge(
    graph: &mut KnowledgeGraph,
    hypothesis: HypothesisId,
    task: &ChallengeHypothesisTask,
    result: ChallengeResult,
    policy: &VerificationPolicy,
) -> Result<InvestigationId> {
    let investigation_id = graph.record_investigation(Investigation {
        id: InvestigationId(0),
        task: "ChallengeHypothesis".to_string(),
        target: hypothesis.to_string(),
        context_snapshot: format!(
            "{} supporting evidence, {} other observations",
            task.supporting_evidence.len(),
            task.other_observations.len()
        ),
        tool_calls: Vec::new(),
        observations: Vec::new(),
        hypotheses_created: Vec::new(),
        hypotheses_modified: vec![hypothesis],
        evidence_created: Vec::new(),
        result: result.reasoning.clone(),
        followup_tasks: Vec::new(),
        created_at: Utc::now(),
    });

    let mut evidence_created = Vec::new();
    if let Some(reason) = &result.contradiction {
        if let Some(evidence_id) =
            commit_contradiction(graph, hypothesis, reason, "agent:ChallengeHypothesis")
        {
            evidence_created.push(evidence_id);
        }
    }

    let mut hypotheses_created = Vec::new();
    if let Some(alternative) = &result.alternative {
        let subject = graph
            .hypothesis(hypothesis)
            .map(|h| h.subject.clone())
            .unwrap_or_default();
        let alt_id = commit_hypothesis(graph, &subject, alternative, Some(investigation_id));
        let _ = graph.add_dependency(alt_id, hypothesis, DependencyKind::Contradicts);
        reevaluate_hypothesis(graph, alt_id, policy);
        hypotheses_created.push(alt_id);
    }

    // A contradiction takes precedence: don't let a confidence bump paper
    // over a finding that just moved this hypothesis to CONTESTED.
    if result.contradiction.is_none() {
        if let Some(confidence) = result.confidence_recommendation {
            let _ = graph.set_confidence(hypothesis, confidence);
        }
    }

    graph.mark_verified(hypothesis, Utc::now())?;
    reevaluate_hypothesis(graph, hypothesis, policy);

    if let Some(investigation) = graph.investigation_mut(investigation_id) {
        investigation.evidence_created = evidence_created;
        investigation.hypotheses_created = hypotheses_created;
    }

    Ok(investigation_id)
}

/// PROJECT.md S12: actively try to falsify `hypothesis`. Always stamps
/// `last_verified_at` when it finishes, regardless of verdict -- an
/// attempt was made, which is what "verified" means for M5's acceptance
/// gate. If a contradiction is found, CONTESTED wins over any confidence
/// recommendation the challenger also returned; reaching ACCEPTED still
/// requires clearing that via `resolve_contradiction`.
pub fn challenge_hypothesis(
    graph: &mut KnowledgeGraph,
    provider: &dyn AgentProvider,
    hypothesis: HypothesisId,
    policy: &VerificationPolicy,
) -> Result<InvestigationId> {
    let (task, result) = challenge(graph, provider, hypothesis)?;
    commit_challenge(graph, hypothesis, &task, result, policy)
}

/// The non-mutating half of `resolve_contradiction`. See `challenge` --
/// same shape, same concurrency guarantee.
pub fn resolve(
    graph: &KnowledgeGraph,
    provider: &dyn AgentProvider,
    hypothesis: HypothesisId,
) -> Result<(ResolveContradictionTask, ResolutionResult)> {
    let target = graph
        .hypothesis(hypothesis)
        .with_context(|| format!("unknown hypothesis: {hypothesis}"))?
        .clone();

    if target.status != HypothesisStatus::Contested {
        bail!(
            "hypothesis {hypothesis} is not CONTESTED (status: {:?})",
            target.status
        );
    }

    let task = ResolveContradictionTask::build(graph, &target);
    let result = provider.resolve_contradiction(&task)?;
    Ok((task, result))
}

/// The mutating half of `resolve_contradiction` -- call with exclusive
/// access after `resolve` returns (from any thread).
pub fn commit_resolution(
    graph: &mut KnowledgeGraph,
    hypothesis: HypothesisId,
    task: &ResolveContradictionTask,
    result: ResolutionResult,
    policy: &VerificationPolicy,
) -> Result<InvestigationId> {
    let investigation_id = graph.record_investigation(Investigation {
        id: InvestigationId(0),
        task: "ResolveContradiction".to_string(),
        target: hypothesis.to_string(),
        context_snapshot: format!(
            "{} supporting, {} contradicting evidence",
            task.supporting_evidence.len(),
            task.contradicting_evidence.len()
        ),
        tool_calls: Vec::new(),
        observations: Vec::new(),
        hypotheses_created: Vec::new(),
        hypotheses_modified: vec![hypothesis],
        evidence_created: Vec::new(),
        result: result.reasoning.clone(),
        followup_tasks: Vec::new(),
        created_at: Utc::now(),
    });

    match result.resolution {
        Resolution::Survives { confidence } => {
            // Move off CONTESTED first so reevaluate's normal threshold
            // logic (which refuses to touch CONTESTED/REJECTED) can run.
            let _ = graph.set_status(hypothesis, HypothesisStatus::Proposed);
            let _ = graph.set_confidence(hypothesis, confidence);
            graph.mark_verified(hypothesis, Utc::now())?;
            reevaluate_hypothesis(graph, hypothesis, policy);
        }
        Resolution::Rejected => {
            let _ = graph.set_status(hypothesis, HypothesisStatus::Rejected);
        }
    }

    Ok(investigation_id)
}

/// PROJECT.md S28: given a CONTESTED hypothesis, decide whether the
/// contradiction actually holds up. `Survives` clears CONTESTED and
/// re-runs it through the same threshold logic as any other verification
/// pass (S10) -- surviving a challenge doesn't mean ACCEPTED, it means
/// eligible to be judged on confidence and verification like anything
/// else. `Rejected` is terminal, same as everywhere else in the graph (S4).
pub fn resolve_contradiction(
    graph: &mut KnowledgeGraph,
    provider: &dyn AgentProvider,
    hypothesis: HypothesisId,
    policy: &VerificationPolicy,
) -> Result<InvestigationId> {
    let (task, result) = resolve(graph, provider, hypothesis)?;
    commit_resolution(graph, hypothesis, &task, result, policy)
}
