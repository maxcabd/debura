use chrono::Utc;
use debura_knowledge::{DependencyKind, Investigation, InvestigationId, KnowledgeGraph};

use crate::provider::AgentProvider;
use crate::result::InvestigationResult;
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
    let task = AnalyzeFunctionTask::build(graph, subject);
    let result = provider.investigate(&task)?;
    Ok(commit(graph, &task, result))
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
        let id = graph.propose_hypothesis(
            task.subject.clone(),
            proposed.predicate.clone(),
            proposed.value.clone(),
            proposed.confidence,
            Some(investigation_id),
        );
        hypotheses_created.push(id);

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
        let Some(target) = graph.hypothesis(contradiction.hypothesis) else {
            tracing::warn!(
                hypothesis = %contradiction.hypothesis,
                "contradiction against unknown hypothesis, skipping"
            );
            continue;
        };

        // The agent's own claim becomes a provenance-tracked Observation +
        // Evidence pair (S7), not an untraceable side effect on the
        // hypothesis's status.
        let obs_id = graph.add_observation(
            target.subject.clone(),
            "agent_flagged_contradiction",
            contradiction.reason.clone(),
            0.5,
            "agent:AnalyzeFunction",
            None,
        );
        new_observations.push(obs_id);

        let evidence_id = graph
            .add_evidence(
                obs_id,
                contradiction.reason.clone(),
                "agent:AnalyzeFunction",
                None,
                None,
            )
            .expect("observation was just created above");
        evidence_created.push(evidence_id);

        let _ = graph.attach_contradicting_evidence(contradiction.hypothesis, evidence_id);
        hypotheses_modified.push(contradiction.hypothesis);
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
