use debura_knowledge::{Hypothesis, KnowledgeGraph, Observation};

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
}

impl AnalyzeFunctionTask {
    pub fn build(graph: &KnowledgeGraph, subject: &str) -> Self {
        Self {
            subject: subject.to_string(),
            observations: graph
                .observations()
                .filter(|o| o.subject == subject)
                .cloned()
                .collect(),
            existing_hypotheses: graph
                .hypotheses()
                .filter(|h| h.subject == subject)
                .cloned()
                .collect(),
        }
    }
}
