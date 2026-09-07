use debura_knowledge::KnowledgeGraph;
use debura_scheduler::{Scheduler, Task};

#[test]
fn pops_highest_priority_first() {
    let mut graph = KnowledgeGraph::new();
    let h = graph.propose_hypothesis("0x1", "p", "v", 0.9, None);

    let mut scheduler = Scheduler::new();
    scheduler.enqueue(
        &graph,
        Task::AnalyzeFunction {
            subject: "0x2".to_string(),
        },
    );
    scheduler.enqueue(&graph, Task::ResolveContradiction { hypothesis: h });
    scheduler.enqueue(&graph, Task::ChallengeHypothesis { hypothesis: h });

    assert_eq!(scheduler.len(), 3);
    assert_eq!(
        scheduler.pop(),
        Some(Task::ResolveContradiction { hypothesis: h })
    );
    assert_eq!(
        scheduler.pop(),
        Some(Task::ChallengeHypothesis { hypothesis: h })
    );
    assert_eq!(
        scheduler.pop(),
        Some(Task::AnalyzeFunction {
            subject: "0x2".to_string()
        })
    );
    assert_eq!(scheduler.pop(), None);
    assert!(scheduler.is_empty());
}
