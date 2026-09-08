use std::cell::RefCell;

use debura_agent::{
    AgentProvider, AnalyzeFunctionTask, ChallengeHypothesisTask, ChallengeResult,
    InvestigationResult, ProposedHypothesis, Resolution, ResolutionResult, ResolveContradictionTask,
};
use debura_knowledge::{DependencyKind, HypothesisStatus, KnowledgeGraph};
use debura_verifier::{challenge_hypothesis, reevaluate_hypothesis, resolve_contradiction, VerificationPolicy};

/// Returns whatever `ChallengeResult`/`ResolutionResult` the test configured,
/// so challenge_hypothesis/resolve_contradiction's commit logic can be
/// tested against precise, controlled verdicts.
struct ScriptedProvider {
    challenge: RefCell<Option<ChallengeResult>>,
    resolution: RefCell<Option<ResolutionResult>>,
}

impl ScriptedProvider {
    fn challenge(result: ChallengeResult) -> Self {
        Self {
            challenge: RefCell::new(Some(result)),
            resolution: RefCell::new(None),
        }
    }

    fn resolution(result: ResolutionResult) -> Self {
        Self {
            challenge: RefCell::new(None),
            resolution: RefCell::new(Some(result)),
        }
    }
}

impl AgentProvider for ScriptedProvider {
    fn investigate(&self, _task: &AnalyzeFunctionTask) -> anyhow::Result<InvestigationResult> {
        unimplemented!("not exercised by these tests")
    }

    fn challenge(&self, _task: &ChallengeHypothesisTask) -> anyhow::Result<ChallengeResult> {
        Ok(self.challenge.borrow_mut().take().expect("challenge scripted"))
    }

    fn resolve_contradiction(
        &self,
        _task: &ResolveContradictionTask,
    ) -> anyhow::Result<ResolutionResult> {
        Ok(self.resolution.borrow_mut().take().expect("resolution scripted"))
    }
}

#[test]
fn challenge_with_no_findings_marks_verified_and_can_reach_accepted() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "is_method_of", "Wall", 0.95, "ghidra:function", None);
    let h = graph.propose_hypothesis("0x1", "semantic_role", "TakeDamage", 0.9, None);

    let provider = ScriptedProvider::challenge(ChallengeResult {
        reasoning: "nothing found".to_string(),
        ..Default::default()
    });

    challenge_hypothesis(&mut graph, &provider, h, &VerificationPolicy::default()).unwrap();

    let result = graph.hypothesis(h).unwrap();
    assert!(result.last_verified_at.is_some());
    assert_eq!(result.status, HypothesisStatus::Accepted);
}

#[test]
fn challenge_with_contradiction_contests_instead_of_accepting() {
    let mut graph = KnowledgeGraph::new();
    let h = graph.propose_hypothesis("0x1", "semantic_role", "TakeDamage", 0.95, None);

    let provider = ScriptedProvider::challenge(ChallengeResult {
        contradiction: Some("also called on non-player objects".to_string()),
        confidence_recommendation: Some(0.99), // must be ignored -- contradiction wins
        reasoning: "found a counterexample".to_string(),
        ..Default::default()
    });

    let investigation_id =
        challenge_hypothesis(&mut graph, &provider, h, &VerificationPolicy::default()).unwrap();

    let result = graph.hypothesis(h).unwrap();
    assert_eq!(result.status, HypothesisStatus::Contested);
    assert_eq!(result.confidence, 0.95, "contradiction must block the confidence bump");
    assert_eq!(result.contradicting_evidence.len(), 1);

    let investigation = graph.investigation(investigation_id).unwrap();
    assert_eq!(investigation.evidence_created.len(), 1);
}

#[test]
fn challenge_with_alternative_proposes_a_competing_hypothesis() {
    let mut graph = KnowledgeGraph::new();
    let h = graph.propose_hypothesis("0xF193", "semantic_role", "PlayerCharacter::TakeDamage", 0.8, None);

    let provider = ScriptedProvider::challenge(ChallengeResult {
        alternative: Some(ProposedHypothesis {
            predicate: "semantic_role".to_string(),
            value: "Character::ApplyDamage".to_string(),
            confidence: 0.75,
            depends_on: Vec::new(),
        }),
        reasoning: "also called for EnemyCharacter and NPCCharacter".to_string(),
        ..Default::default()
    });

    challenge_hypothesis(&mut graph, &provider, h, &VerificationPolicy::default()).unwrap();

    let alternative = graph
        .hypotheses()
        .find(|other| other.id != h && other.subject == "0xF193")
        .expect("alternative hypothesis was created");
    assert_eq!(alternative.value, "Character::ApplyDamage");

    let contradicts = graph
        .dependencies()
        .iter()
        .find(|d| d.source == alternative.id && d.target == h);
    assert!(matches!(
        contradicts,
        Some(d) if d.kind == DependencyKind::Contradicts
    ));
}

#[test]
fn resolve_contradiction_requires_contested_status() {
    let mut graph = KnowledgeGraph::new();
    let h = graph.propose_hypothesis("0x1", "p", "v", 0.5, None);
    let provider = ScriptedProvider::resolution(ResolutionResult {
        resolution: Resolution::Survives { confidence: 0.5 },
        reasoning: String::new(),
    });

    let err = resolve_contradiction(&mut graph, &provider, h, &VerificationPolicy::default())
        .unwrap_err();
    assert!(err.to_string().contains("not CONTESTED"));
}

#[test]
fn resolve_contradiction_survives_clears_contested_and_can_be_reevaluated() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "is_method_of", "Wall", 0.95, "ghidra:function", None);
    let h = graph.propose_hypothesis("0x1", "semantic_role", "health", 0.6, None);
    graph.set_status(h, HypothesisStatus::Contested).unwrap();

    let provider = ScriptedProvider::resolution(ResolutionResult {
        resolution: Resolution::Survives { confidence: 0.9 },
        reasoning: "the contradicting field is unrelated".to_string(),
    });

    resolve_contradiction(&mut graph, &provider, h, &VerificationPolicy::default()).unwrap();

    let result = graph.hypothesis(h).unwrap();
    assert_eq!(result.confidence, 0.9);
    assert!(result.last_verified_at.is_some());
    // Verified + above acceptance threshold: reevaluate_hypothesis (called
    // internally by resolve_contradiction) should have promoted it.
    assert_eq!(result.status, HypothesisStatus::Accepted);
}

#[test]
fn resolve_contradiction_rejected_is_terminal_and_cascades_stale() {
    let mut graph = KnowledgeGraph::new();
    let h = graph.propose_hypothesis("0x1", "semantic_role", "stamina", 0.6, None);
    graph.set_status(h, HypothesisStatus::Contested).unwrap();

    let dependent = graph.propose_hypothesis("0x2", "p", "v", 0.7, None);
    graph.set_status(dependent, HypothesisStatus::Accepted).unwrap();
    graph
        .add_dependency(dependent, h, DependencyKind::DependsOn)
        .unwrap();

    let provider = ScriptedProvider::resolution(ResolutionResult {
        resolution: Resolution::Rejected,
        reasoning: "HUD clearly labels it Health".to_string(),
    });

    resolve_contradiction(&mut graph, &provider, h, &VerificationPolicy::default()).unwrap();

    assert_eq!(graph.hypothesis(h).unwrap().status, HypothesisStatus::Rejected);
    assert_eq!(
        graph.hypothesis(dependent).unwrap().status,
        HypothesisStatus::Stale
    );
}

/// The full loop the M5 milestone description is actually about: a
/// hypothesis cannot become ACCEPTED by confidence alone, but can once it's
/// gone through a real (even if here, mocked) challenge.
#[test]
fn end_to_end_acceptance_requires_a_challenge() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "is_method_of", "Wall", 0.95, "ghidra:function", None);
    let policy = VerificationPolicy::default();
    let h = graph.propose_hypothesis("0x1", "semantic_role", "TakeDamage", 0.95, None);

    assert_eq!(
        reevaluate_hypothesis(&mut graph, h, &policy),
        Some(HypothesisStatus::Supported)
    );

    let provider = ScriptedProvider::challenge(ChallengeResult::default());
    challenge_hypothesis(&mut graph, &provider, h, &policy).unwrap();

    assert_eq!(graph.hypothesis(h).unwrap().status, HypothesisStatus::Accepted);
}

/// PROJECT.md M18: a real run found a fresh challenge re-rejecting a
/// reconsidered hypothesis partly because it was still reading a now-
/// outdated observation as if it were current. A Superseded observation
/// must stay on the record (for history/audit) but must not reach a fresh
/// challenge's context as if it were live evidence.
#[test]
fn build_challenge_task_excludes_superseded_observations() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "is_method_of", "Wall", 0.95, "ghidra:function", None);
    let old = graph.add_observation(
        "0x1",
        "provenance_gate_rejected",
        "semantic_role 'renderFrame' rejected: subject's provenance is not Application",
        0.5,
        "debura:provenance_gate",
        None,
    );
    let new = graph.add_observation(
        "0x1",
        "rejection_premise_invalidated",
        "provenance now classifies as Application",
        0.5,
        "debura:premise_reconsideration",
        None,
    );
    graph.supersede_observation(old, new).unwrap();

    let h = graph.propose_hypothesis("0x1", "semantic_role", "renderFrame", 0.9, None);

    let task = debura_verifier::build_challenge_task(&graph, h).unwrap();

    assert!(
        task.other_observations.iter().all(|o| o.id != old),
        "superseded observation leaked into a fresh challenge's context: {:?}",
        task.other_observations
    );
    assert!(task.other_observations.iter().any(|o| o.id == new));
}
