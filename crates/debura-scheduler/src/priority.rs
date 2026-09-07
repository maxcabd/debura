use debura_knowledge::KnowledgeGraph;

use crate::task::Task;

/// A first-cut scoring function (PROJECT.md S27). It only uses signals that
/// actually exist today -- a hypothesis's own confidence and how many
/// other hypotheses depend on it -- not graph centrality, architectural
/// relevance, or real cost, since none of those are computed anywhere yet.
/// This is deliberately simple and should be expected to change once M9's
/// evaluation against ground-truth binaries gives real signal on whether
/// it's actually picking good tasks.
pub fn priority(graph: &KnowledgeGraph, task: &Task) -> f64 {
    match task {
        // A function nobody has looked at yet: worth investigating, but
        // below anything that's already close to a real conclusion.
        Task::AnalyzeFunction { .. } => 0.5,

        // Verifying a hypothesis is worth more the closer it already is to
        // useful (higher confidence) and the more that resolving it would
        // unblock (S15: "resolving one central type may improve hundreds
        // of functions simultaneously").
        Task::ChallengeHypothesis { hypothesis } => {
            let confidence = graph.hypothesis(*hypothesis).map_or(0.0, |h| h.confidence);
            let dependents = graph.dependent_count(*hypothesis) as f64;
            0.6 + confidence * 0.3 + dependents * 0.05
        }

        // A CONTESTED hypothesis actively blocks every dependent from ever
        // reaching ACCEPTED (S9-10's cascade already marked them STALE) --
        // resolving it is close to always worth doing first.
        Task::ResolveContradiction { hypothesis } => {
            let dependents = graph.dependent_count(*hypothesis) as f64;
            0.9 + dependents * 0.05
        }
    }
}

#[cfg(test)]
mod tests {
    use debura_knowledge::{DependencyKind, KnowledgeGraph};

    use super::*;

    #[test]
    fn resolve_contradiction_outranks_challenge_and_analyze() {
        let mut graph = KnowledgeGraph::new();
        let h = graph.propose_hypothesis("0x1", "p", "v", 0.9, None);

        let analyze = Task::AnalyzeFunction {
            subject: "0x2".to_string(),
        };
        let challenge = Task::ChallengeHypothesis { hypothesis: h };
        let resolve = Task::ResolveContradiction { hypothesis: h };

        assert!(priority(&graph, &resolve) > priority(&graph, &challenge));
        assert!(priority(&graph, &challenge) > priority(&graph, &analyze));
    }

    #[test]
    fn higher_confidence_challenge_outranks_lower_confidence() {
        let mut graph = KnowledgeGraph::new();
        let high = graph.propose_hypothesis("0x1", "p", "v", 0.9, None);
        let low = graph.propose_hypothesis("0x2", "p", "v", 0.2, None);

        let high_task = Task::ChallengeHypothesis { hypothesis: high };
        let low_task = Task::ChallengeHypothesis { hypothesis: low };

        assert!(priority(&graph, &high_task) > priority(&graph, &low_task));
    }

    #[test]
    fn more_dependents_outranks_fewer_for_the_same_task_kind() {
        let mut graph = KnowledgeGraph::new();
        let popular = graph.propose_hypothesis("0x1", "p", "v", 0.7, None);
        let lonely = graph.propose_hypothesis("0x2", "p", "v", 0.7, None);
        let dependent = graph.propose_hypothesis("0x3", "p", "v", 0.5, None);
        graph
            .add_dependency(dependent, popular, DependencyKind::DependsOn)
            .unwrap();

        let popular_task = Task::ChallengeHypothesis { hypothesis: popular };
        let lonely_task = Task::ChallengeHypothesis { hypothesis: lonely };

        assert!(priority(&graph, &popular_task) > priority(&graph, &lonely_task));
    }
}
