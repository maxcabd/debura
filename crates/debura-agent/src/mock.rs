//! Deterministic test doubles for `AgentProvider`. No network calls, no
//! API key, no real reasoning -- these exist to prove the harness's context
//! building, validation and commit logic without depending on (or paying
//! for) a real model. A real provider (Anthropic, OpenAI, ...) is a later
//! addition behind the same trait.

use anyhow::Result;

use crate::result::{InvestigationResult, ProposedHypothesis};
use crate::task::AnalyzeFunctionTask;
use crate::AgentProvider;

/// Proposes `semantic_role = <name>` at low confidence, using whatever
/// name Ghidra already assigned (the task's `has_name` observation). Useful
/// only for exercising the harness's plumbing end-to-end -- it doesn't
/// interpret anything, it just echoes back a fact that's already known.
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
}
