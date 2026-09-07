use debura_knowledge::KnowledgeGraph;
use debura_scheduler::{seed_initial_tasks, Task};

#[test]
fn seeds_analyze_function_for_unanalyzed_subjects_only() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "compute", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "has_name", "add", 0.95, "ghidra:function", None);
    graph.propose_hypothesis("0x2", "semantic_role", "add", 0.5, None);

    let tasks = seed_initial_tasks(&graph);

    assert_eq!(
        tasks,
        vec![Task::AnalyzeFunction {
            subject: "0x1".to_string()
        }]
    );
}

#[test]
fn ignores_observations_that_are_not_has_name() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "contains_string", "hello", 0.95, "ghidra:strings", None);

    assert!(seed_initial_tasks(&graph).is_empty());
}
