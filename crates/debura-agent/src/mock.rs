//! Deterministic test doubles for `AgentProvider`. No network calls, no
//! API key, no real reasoning -- these exist to prove the harness's context
//! building, validation and commit logic without depending on (or paying
//! for) a real model. A real provider (Anthropic, OpenAI, ...) is a later
//! addition behind the same trait.

use anyhow::Result;

use crate::challenge::{ChallengeHypothesisTask, ChallengeResult};
use crate::field_task::{ProposeFieldNameTask, ProposeFieldSemanticRoleTask, SemanticRoleResult};
use crate::resolution::{Resolution, ResolutionResult, ResolveContradictionTask};
use crate::result::{InvestigationResult, ProposedHypothesis};
use crate::task::AnalyzeFunctionTask;
use crate::AgentProvider;

/// For AnalyzeFunction, proposes `semantic_role = <name>` at low confidence
/// using whatever name Ghidra already assigned -- useful only for
/// exercising the harness's plumbing, since it doesn't interpret anything.
///
/// For ChallengeHypothesis and ResolveContradiction it makes no real
/// judgment at all: it reports "nothing found" and "survives unchanged"
/// respectively. A hypothesis can therefore be marked as *having gone
/// through* verification via this provider, but will never be genuinely
/// scrutinized by it -- that's the honest line between "the plumbing
/// works" and "the reasoning is real."
pub struct EchoProvider;

impl AgentProvider for EchoProvider {
    fn investigate(&self, task: &AnalyzeFunctionTask) -> Result<InvestigationResult> {
        let Some(name_observation) = task
            .observations
            .iter()
            .find(|o| o.predicate == "has_name")
        else {
            return Ok(InvestigationResult {
                followup_tasks: vec![format!(
                    "no has_name observation for {}; re-run analysis",
                    task.subject
                )],
                ..Default::default()
            });
        };

        Ok(InvestigationResult {
            hypotheses: vec![ProposedHypothesis {
                predicate: "semantic_role".to_string(),
                value: name_observation.value.clone(),
                confidence: 0.5,
                depends_on: Vec::new(),
            }],
            ..Default::default()
        })
    }

    fn challenge(&self, _task: &ChallengeHypothesisTask) -> Result<ChallengeResult> {
        Ok(ChallengeResult {
            reasoning: "EchoProvider performs no real adversarial reasoning".to_string(),
            ..Default::default()
        })
    }

    fn resolve_contradiction(&self, task: &ResolveContradictionTask) -> Result<ResolutionResult> {
        Ok(ResolutionResult {
            resolution: Resolution::Survives {
                confidence: task.hypothesis.confidence,
            },
            reasoning: "EchoProvider performs no real adversarial reasoning".to_string(),
        })
    }

    /// Echoes the mechanical `field_{offset}` name back at low confidence
    /// -- same honest "exercises the plumbing, interprets nothing" line
    /// as `investigate` above.
    fn propose_field_name(&self, task: &ProposeFieldNameTask) -> Result<InvestigationResult> {
        Ok(InvestigationResult {
            hypotheses: vec![ProposedHypothesis {
                predicate: "field_semantic_name".to_string(),
                value: format!("field_0x{:x}", task.offset),
                confidence: 0.3,
                depends_on: Vec::new(),
            }],
            ..Default::default()
        })
    }

    /// Same honest "exercises the plumbing, interprets nothing" line as
    /// `investigate`/`propose_field_name` above -- proposes a mechanical
    /// placeholder role but deliberately cites no `decisive_sink` at all
    /// (it did no real tracing), so `debura_confidence_for_role` always
    /// rejects it before anything gets committed. That's the correct,
    /// honest behavior for a provider that does no real reasoning, not a
    /// bug in the gate.
    fn propose_field_semantic_role(&self, task: &ProposeFieldSemanticRoleTask) -> Result<SemanticRoleResult> {
        Ok(SemanticRoleResult {
            tracked_value: format!("{} + 0x{:x}", task.base, task.offset),
            propagation_chain: Vec::new(),
            decisive_sink: None,
            semantic_role: Some(format!("field_0x{:x}", task.offset)),
            evidence: Vec::new(),
            competing_interpretations: Vec::new(),
            confidence: 0.3,
        })
    }
}
