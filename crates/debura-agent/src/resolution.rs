use debura_knowledge::{Evidence, Hypothesis, KnowledgeGraph, Observation};
use serde::{Deserialize, Serialize};

use crate::evidence_view;

/// PROJECT.md S28: given a CONTESTED hypothesis, decide whether the
/// contradiction actually holds up or can be explained away. Both sides of
/// the evidence are handed over -- a resolution that only saw the
/// contradicting evidence couldn't judge whether it actually outweighs
/// what the hypothesis already had going for it.
#[derive(Debug, Clone)]
pub struct ResolveContradictionTask {
    pub hypothesis: Hypothesis,
    pub supporting_evidence: Vec<(Evidence, Observation)>,
    pub contradicting_evidence: Vec<(Evidence, Observation)>,
}

impl ResolveContradictionTask {
    pub fn build(graph: &KnowledgeGraph, hypothesis: &Hypothesis) -> Self {
        Self {
            supporting_evidence: evidence_view::resolve(graph, &hypothesis.supporting_evidence),
            contradicting_evidence: evidence_view::resolve(graph, &hypothesis.contradicting_evidence),
            hypothesis: hypothesis.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Resolution {
    /// The contradiction doesn't hold up; the hypothesis survives, at this
    /// (possibly revised) confidence.
    Survives { confidence: f64 },
    /// The contradiction wins.
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionResult {
    pub resolution: Resolution,
    pub reasoning: String,
}
