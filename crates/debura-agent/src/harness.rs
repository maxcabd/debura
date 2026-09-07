use chrono::Utc;
use debura_knowledge::{
    DependencyKind, EvidenceId, HypothesisId, Investigation, InvestigationId, KnowledgeGraph,
};

use crate::provider::AgentProvider;
use crate::result::{InvestigationResult, ProposedHypothesis};
use crate::task::AnalyzeFunctionTask;

/// Runs one bounded AnalyzeFunction investigation and commits whatever of
/// its result validates cleanly. Debura is the controller here (PROJECT.md
/// S2.5): the provider only answers a bounded question, it never writes to
/// the graph directly.
pub fn analyze_function(
    graph: &mut KnowledgeGraph,
    provider: &dyn AgentProvider,
    subject: &str,
) -> anyhow::Result<InvestigationId> {
    let (task, result) = investigate(graph, provider, subject);
    Ok(commit_investigation(graph, &task, result?))
}

/// The non-mutating half of `analyze_function`: builds the task and calls
/// the provider, touching the graph only through `&KnowledgeGraph`. Task
/// context is always scoped to one subject's own data (PROJECT.md S23), so
/// this is safe to run concurrently across different subjects (M10) --
/// only `commit_investigation` needs exclusive access.
pub fn investigate(
    graph: &KnowledgeGraph,
    provider: &dyn AgentProvider,
    subject: &str,
) -> (AnalyzeFunctionTask, anyhow::Result<InvestigationResult>) {
    let task = AnalyzeFunctionTask::build(graph, subject);
    let result = provider.investigate(&task);
    (task, result)
}

/// The mutating half of `analyze_function` -- call with exclusive access
/// after `investigate` returns (from any thread).
pub fn commit_investigation(
    graph: &mut KnowledgeGraph,
    task: &AnalyzeFunctionTask,
    result: InvestigationResult,
) -> InvestigationId {
    commit(graph, task, result)
}

/// Commits one proposed hypothesis onto `subject`, wiring any DEPENDS_ON
/// edges it names. Shared by AnalyzeFunction's commit path and
/// ChallengeHypothesis's "propose a better alternative" path (M5) so both
/// validate dangling dependencies the same way.
pub fn commit_hypothesis(
    graph: &mut KnowledgeGraph,
    subject: &str,
    proposed: &ProposedHypothesis,
    created_by: Option<InvestigationId>,
) -> HypothesisId {
    let id = graph.propose_hypothesis(
        subject.to_string(),
        proposed.predicate.clone(),
        proposed.value.clone(),
        proposed.confidence,
        created_by,
    );

    for target in &proposed.depends_on {
        if graph.hypothesis(*target).is_none() {
            tracing::warn!(
                hypothesis = %id,
                missing = %target,
                "dropping dependency on unknown hypothesis"
            );
            continue;
        }
        let _ = graph.add_dependency(id, *target, DependencyKind::DependsOn);
    }

    id
}

/// Turns a contradiction claim into a provenance-tracked Observation +
/// Evidence pair (S7) and attaches it, moving `hypothesis` to CONTESTED
/// (S4) -- rather than an untraceable side effect on its status. Shared by
/// AnalyzeFunction's and ChallengeHypothesis's (M5) contradiction handling.
/// Returns `None` (and logs) if `hypothesis` doesn't exist.
pub fn commit_contradiction(
    graph: &mut KnowledgeGraph,
    hypothesis: HypothesisId,
    reason: &str,
    source: &str,
) -> Option<EvidenceId> {
    let Some(target) = graph.hypothesis(hypothesis) else {
        tracing::warn!(%hypothesis, "contradiction against unknown hypothesis, skipping");
        return None;
    };
    let subject = target.subject.clone();

    let obs_id = graph.add_observation(
        subject,
        "agent_flagged_contradiction",
        reason,
        0.5,
        source,
        None,
    );

    let evidence_id = graph
        .add_evidence(obs_id, reason, source, None, None)
        .expect("observation was just created above");

    let _ = graph.attach_contradicting_evidence(hypothesis, evidence_id);
    Some(evidence_id)
}

/// PROJECT.md S11: "the harness validates this result before committing
/// anything." Anything referencing a hypothesis id that doesn't actually
/// exist in the graph is dropped (with a warning) rather than committed or
/// treated as a hard failure -- a real provider's output shouldn't be
/// trusted any more than that.
fn commit(
    graph: &mut KnowledgeGraph,
    task: &AnalyzeFunctionTask,
    result: InvestigationResult,
) -> InvestigationId {
    // Reserve the investigation's id now; its outcome fields are filled in
    // once we know what actually got committed.
    let investigation_id = graph.record_investigation(Investigation {
        id: InvestigationId(0),
        task: "AnalyzeFunction".to_string(),
        target: task.subject.clone(),
        context_snapshot: format!(
            "{} observations, {} existing hypotheses",
            task.observations.len(),
            task.existing_hypotheses.len()
        ),
        tool_calls: Vec::new(),
        observations: Vec::new(),
        hypotheses_created: Vec::new(),
        hypotheses_modified: Vec::new(),
        evidence_created: Vec::new(),
        result: String::new(),
        followup_tasks: result.followup_tasks.clone(),
        created_at: Utc::now(),
    });

    let mut new_observations = Vec::new();
    for obs in &result.observations {
        let id = graph.add_observation(
            obs.subject.clone(),
            obs.predicate.clone(),
            obs.value.clone(),
            obs.confidence,
            obs.source.clone(),
            None,
        );
        new_observations.push(id);
    }

    let mut hypotheses_created = Vec::new();
    for proposed in &result.hypotheses {
        hypotheses_created.push(commit_hypothesis(
            graph,
            &task.subject,
            proposed,
            Some(investigation_id),
        ));
    }

    let mut hypotheses_modified = Vec::new();
    for update in &result.confidence_updates {
        if graph.hypothesis(update.hypothesis).is_none() {
            tracing::warn!(
                hypothesis = %update.hypothesis,
                "confidence update for unknown hypothesis, skipping"
            );
            continue;
        }
        let _ = graph.set_confidence(update.hypothesis, update.confidence);
        hypotheses_modified.push(update.hypothesis);
    }

    let mut evidence_created = Vec::new();
    for contradiction in &result.contradictions {
        if let Some(evidence_id) = commit_contradiction(
            graph,
            contradiction.hypothesis,
            &contradiction.reason,
            "agent:AnalyzeFunction",
        ) {
            evidence_created.push(evidence_id);
            hypotheses_modified.push(contradiction.hypothesis);
        }
    }

    if let Some(investigation) = graph.investigation_mut(investigation_id) {
        investigation.observations = new_observations;
        investigation.hypotheses_created = hypotheses_created;
        investigation.hypotheses_modified = hypotheses_modified;
        investigation.evidence_created = evidence_created;
        investigation.result = "committed".to_string();
    }

    investigation_id
}
