use std::collections::HashSet;

use debura_knowledge::KnowledgeGraph;

use crate::task::Task;

/// Finds every known function (a subject with a `has_name` observation --
/// M1/M3's deterministic extraction) that has no hypothesis yet, and
/// proposes AnalyzeFunction for it. This is the only source of brand-new
/// work; everything else the scheduler ever runs is a follow-up produced
/// by a task that already ran (PROJECT.md S24's `enqueue_followups`).
pub fn seed_initial_tasks(graph: &KnowledgeGraph) -> Vec<Task> {
    let already_analyzed: HashSet<&str> =
        graph.hypotheses().map(|h| h.subject.as_str()).collect();

    let mut subjects: Vec<&str> = graph
        .observations()
        .filter(|o| o.predicate == "has_name")
        .map(|o| o.subject.as_str())
        .collect();
    subjects.sort_unstable();
    subjects.dedup();

    subjects
        .into_iter()
        .filter(|subject| !already_analyzed.contains(subject))
        .map(|subject| Task::AnalyzeFunction {
            subject: subject.to_string(),
        })
        .collect()
}
