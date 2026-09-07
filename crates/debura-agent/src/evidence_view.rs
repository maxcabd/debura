use debura_knowledge::{Evidence, EvidenceId, KnowledgeGraph, Observation};

/// Resolves evidence ids to their full (Evidence, Observation) content, for
/// building task context. Silently drops any id that no longer resolves --
/// evidence/observations are never deleted (S4), so this should never
/// happen, but a task builder has no business panicking over it.
pub(crate) fn resolve(graph: &KnowledgeGraph, ids: &[EvidenceId]) -> Vec<(Evidence, Observation)> {
    ids.iter()
        .filter_map(|id| {
            let evidence = graph.evidence(*id)?;
            let observation = graph.observation(evidence.observation_id)?;
            Some((evidence.clone(), observation.clone()))
        })
        .collect()
}
