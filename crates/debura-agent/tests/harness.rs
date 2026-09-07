use debura_agent::{
    analyze_function, mock::EchoProvider, AgentProvider, AnalyzeFunctionTask,
    ChallengeHypothesisTask, ChallengeResult, ConfidenceUpdate, InvestigationResult,
    ProposedContradiction, ProposedHypothesis, ProposedObservation, Resolution, ResolutionResult,
    ResolveContradictionTask,
};
use debura_knowledge::{HypothesisId, HypothesisStatus, KnowledgeGraph};

/// A provider that always returns a fixed, caller-supplied AnalyzeFunction
/// result -- standing in for whatever a real provider might say, so the
/// harness's commit/validation logic can be tested independently of any
/// actual reasoning. challenge/resolve_contradiction aren't exercised by
/// these tests (that's debura-verifier's job) so they're neutral no-ops.
struct ScriptedProvider(InvestigationResult);

impl AgentProvider for ScriptedProvider {
    fn investigate(&self, _task: &AnalyzeFunctionTask) -> anyhow::Result<InvestigationResult> {
        Ok(self.0.clone())
    }

    fn challenge(&self, _task: &ChallengeHypothesisTask) -> anyhow::Result<ChallengeResult> {
        Ok(ChallengeResult::default())
    }

    fn resolve_contradiction(
        &self,
        task: &ResolveContradictionTask,
    ) -> anyhow::Result<ResolutionResult> {
        Ok(ResolutionResult {
            resolution: Resolution::Survives {
                confidence: task.hypothesis.confidence,
            },
            reasoning: String::new(),
        })
    }
}

#[test]
fn task_context_is_scoped_to_its_own_subject() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "compute", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "has_name", "add", 0.95, "ghidra:function", None);
    graph.propose_hypothesis("0x1", "semantic_role", "guess", 0.4, None);

    let task = AnalyzeFunctionTask::build(&graph, "0x1");

    assert_eq!(task.observations.len(), 1);
    assert_eq!(task.observations[0].value, "compute");
    assert_eq!(task.existing_hypotheses.len(), 1);
}

#[test]
fn echo_provider_proposes_semantic_role_from_ghidra_name() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation(
        "0x1400016e4",
        "has_name",
        "compute",
        0.95,
        "ghidra:function",
        None,
    );

    let investigation_id = analyze_function(&mut graph, &EchoProvider, "0x1400016e4").unwrap();

    let created: Vec<_> = graph
        .hypotheses()
        .filter(|h| h.subject == "0x1400016e4")
        .collect();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].predicate, "semantic_role");
    assert_eq!(created[0].value, "compute");
    assert_eq!(created[0].created_by, Some(investigation_id));

    let investigation = graph.investigation(investigation_id).unwrap();
    assert_eq!(investigation.hypotheses_created, vec![created[0].id]);
    assert_eq!(investigation.result, "committed");
}

#[test]
fn echo_provider_reports_a_followup_when_the_function_has_no_name() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "size_bytes", "12", 0.95, "ghidra:function", None);

    let investigation_id = analyze_function(&mut graph, &EchoProvider, "0x1").unwrap();

    assert_eq!(graph.hypotheses().count(), 0);
    let investigation = graph.investigation(investigation_id).unwrap();
    assert_eq!(investigation.followup_tasks.len(), 1);
}

#[test]
fn proposed_hypothesis_dependency_on_existing_hypothesis_is_wired() {
    let mut graph = KnowledgeGraph::new();
    let field_hypothesis = graph.propose_hypothesis("0x138", "semantic_role", "health", 0.9, None);

    let provider = ScriptedProvider(InvestigationResult {
        hypotheses: vec![ProposedHypothesis {
            predicate: "semantic_role".to_string(),
            value: "TakeDamage".to_string(),
            confidence: 0.7,
            depends_on: vec![field_hypothesis],
        }],
        ..Default::default()
    });

    analyze_function(&mut graph, &provider, "0xF193").unwrap();

    let created = graph
        .hypotheses()
        .find(|h| h.subject == "0xF193")
        .unwrap();
    assert_eq!(created.dependencies, vec![field_hypothesis]);
}

#[test]
fn dependency_on_unknown_hypothesis_is_dropped_not_fatal() {
    let mut graph = KnowledgeGraph::new();
    let bogus = HypothesisId(9999);

    let provider = ScriptedProvider(InvestigationResult {
        hypotheses: vec![ProposedHypothesis {
            predicate: "semantic_role".to_string(),
            value: "TakeDamage".to_string(),
            confidence: 0.7,
            depends_on: vec![bogus],
        }],
        ..Default::default()
    });

    analyze_function(&mut graph, &provider, "0xF193").unwrap();

    let created = graph
        .hypotheses()
        .find(|h| h.subject == "0xF193")
        .unwrap();
    assert!(created.dependencies.is_empty());
}

#[test]
fn confidence_update_applies_and_cascades_stale() {
    let mut graph = KnowledgeGraph::new();
    let target = graph.propose_hypothesis("0x138", "semantic_role", "health", 0.9, None);
    graph.set_status(target, HypothesisStatus::Accepted).unwrap();
    let dependent = graph.propose_hypothesis("0xF193", "semantic_role", "TakeDamage", 0.8, None);
    graph.set_status(dependent, HypothesisStatus::Accepted).unwrap();
    graph
        .add_dependency(dependent, target, debura_knowledge::DependencyKind::DependsOn)
        .unwrap();

    let provider = ScriptedProvider(InvestigationResult {
        confidence_updates: vec![ConfidenceUpdate {
            hypothesis: target,
            confidence: 0.2,
        }],
        ..Default::default()
    });

    analyze_function(&mut graph, &provider, "0x138").unwrap();

    assert_eq!(graph.hypothesis(target).unwrap().confidence, 0.2);
    assert_eq!(
        graph.hypothesis(dependent).unwrap().status,
        HypothesisStatus::Stale
    );
}

#[test]
fn contradiction_creates_provenance_and_contests_the_hypothesis() {
    let mut graph = KnowledgeGraph::new();
    let target = graph.propose_hypothesis("0x138", "semantic_role", "stamina", 0.6, None);
    graph.set_status(target, HypothesisStatus::Supported).unwrap();

    let provider = ScriptedProvider(InvestigationResult {
        contradictions: vec![ProposedContradiction {
            hypothesis: target,
            reason: "HUD labels this field Health".to_string(),
        }],
        ..Default::default()
    });

    let investigation_id = analyze_function(&mut graph, &provider, "0x138").unwrap();

    let h = graph.hypothesis(target).unwrap();
    assert_eq!(h.status, HypothesisStatus::Contested);
    assert_eq!(h.contradicting_evidence.len(), 1);

    let evidence = graph.evidence(h.contradicting_evidence[0]).unwrap();
    let observation = graph.observation(evidence.observation_id).unwrap();
    assert_eq!(observation.value, "HUD labels this field Health");
    assert_eq!(observation.source, "agent:AnalyzeFunction");

    let investigation = graph.investigation(investigation_id).unwrap();
    assert_eq!(investigation.evidence_created.len(), 1);
    assert_eq!(investigation.hypotheses_modified, vec![target]);
}

#[test]
fn agent_proposed_observations_are_committed() {
    let mut graph = KnowledgeGraph::new();

    let provider = ScriptedProvider(InvestigationResult {
        observations: vec![ProposedObservation {
            subject: "0x140".to_string(),
            predicate: "reads_offset".to_string(),
            value: "0x20".to_string(),
            confidence: 0.9,
            source: "agent:tool_call".to_string(),
        }],
        ..Default::default()
    });

    analyze_function(&mut graph, &provider, "0x140").unwrap();

    assert_eq!(graph.observations().count(), 1);
    let obs = graph.observations().next().unwrap();
    assert_eq!(obs.predicate, "reads_offset");
}
