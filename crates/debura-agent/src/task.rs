use std::collections::HashMap;

use debura_knowledge::{Hypothesis, HypothesisId, HypothesisStatus, KnowledgeGraph, Observation};

use crate::evidence_view;

/// Debura's first bounded investigation task (PROJECT.md M4, S23):
/// "determine the likely semantic role of this function/field/etc."
///
/// Context is scoped to exactly this subject's own observations and
/// hypotheses -- no whole-graph dump (S13, S25). Following relationships
/// to pull in related subjects (callers, callees, the type they belong to)
/// is real context-retrieval work for the scheduler (M6); this is the
/// simplest honest starting point.
#[derive(Debug, Clone)]
pub struct AnalyzeFunctionTask {
    pub subject: String,
    pub observations: Vec<Observation>,
    pub existing_hypotheses: Vec<Hypothesis>,
    /// Why each REJECTED/CONTESTED existing hypothesis didn't hold up, so a
    /// retry after rejection (the scheduler's bounded re-investigation)
    /// doesn't just repeat the same mistake blindly. Keyed by hypothesis id;
    /// only hypotheses with recorded contradicting evidence appear here.
    pub rejection_reasons: HashMap<HypothesisId, Vec<String>>,
}

impl AnalyzeFunctionTask {
    pub fn build(graph: &KnowledgeGraph, subject: &str) -> Self {
        let existing_hypotheses: Vec<Hypothesis> = graph
            .hypotheses()
            .filter(|h| h.subject == subject)
            .cloned()
            .collect();

        let mut rejection_reasons = HashMap::new();
        for h in &existing_hypotheses {
            let unresolved = matches!(
                h.status,
                HypothesisStatus::Rejected | HypothesisStatus::Contested
            );
            if unresolved && !h.contradicting_evidence.is_empty() {
                let reasons = evidence_view::resolve(graph, &h.contradicting_evidence)
                    .into_iter()
                    .map(|(_, observation)| observation.value)
                    .collect();
                rejection_reasons.insert(h.id, reasons);
            }
        }

        Self {
            subject: subject.to_string(),
            observations: graph
                .observations()
                .filter(|o| o.subject == subject)
                .cloned()
                .collect(),
            existing_hypotheses,
            rejection_reasons,
        }
    }
}
