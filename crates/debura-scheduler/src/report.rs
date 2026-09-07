use std::collections::BTreeMap;

use debura_knowledge::{HypothesisStatus, KnowledgeGraph};

/// One task type's slice of a run's investigations (PROJECT.md M15:
/// "instrument investigations by task type" instead of only reporting a
/// raw count). `no_op` and productivity are judged by whether an
/// investigation added anything new to the graph -- a fresh hypothesis
/// or fresh evidence -- not by `hypotheses_modified`: both
/// ChallengeHypothesis and ResolveContradiction always record the
/// hypothesis under review there (verifying it touches
/// `last_verified_at`/status regardless of outcome), so that field alone
/// can't tell a confirming challenge apart from a genuinely inert one.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TaskTypeStats {
    pub task: String,
    pub executed: usize,
    pub hypotheses_created: usize,
    pub hypotheses_modified: usize,
    pub evidence_created: usize,
    /// Of this task type's own `hypotheses_created`, how many hold
    /// ACCEPTED status as of now -- a proxy for "knowledge this task
    /// type produced that actually held up," not a guarantee that
    /// *this* investigation is solely why (a later investigation could
    /// have moved the same hypothesis further).
    pub accepted_from_created: usize,
    /// Neither a new hypothesis nor new evidence came out of it.
    pub no_op: usize,
}

impl TaskTypeStats {
    pub fn productive(&self) -> usize {
        self.executed - self.no_op
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct InvestigationReport {
    pub by_task: Vec<TaskTypeStats>,
    /// Subjects served from `apply_fingerprint_cache` instead of a real
    /// AnalyzeFunction call -- these never become an Investigation at
    /// all, so they're invisible to `by_task` and counted separately.
    pub fingerprint_cache_hits: usize,
    pub total_investigations: usize,
    pub productive_investigations: usize,
}

impl InvestigationReport {
    /// PROJECT.md M15: "investigations that materially change knowledge
    /// / total investigations" -- the number worth tracking once a run
    /// is fast enough that raw wall-clock time stops being the
    /// bottleneck question.
    pub fn productive_rate(&self) -> f64 {
        if self.total_investigations == 0 {
            0.0
        } else {
            self.productive_investigations as f64 / self.total_investigations as f64
        }
    }
}

/// Builds the report from whatever's persisted in `graph` -- no new
/// tracking to add, `Investigation` already records everything needed
/// (PROJECT.md S19); this only groups and summarizes it.
pub fn investigation_report(graph: &KnowledgeGraph) -> InvestigationReport {
    let mut by_task: BTreeMap<String, TaskTypeStats> = BTreeMap::new();
    let mut total = 0usize;
    let mut productive = 0usize;

    for inv in graph.investigations() {
        total += 1;
        let entry = by_task.entry(inv.task.clone()).or_insert_with(|| TaskTypeStats {
            task: inv.task.clone(),
            ..Default::default()
        });

        entry.executed += 1;
        entry.hypotheses_created += inv.hypotheses_created.len();
        entry.hypotheses_modified += inv.hypotheses_modified.len();
        entry.evidence_created += inv.evidence_created.len();
        entry.accepted_from_created += inv
            .hypotheses_created
            .iter()
            .filter(|id| graph.hypothesis(**id).map(|h| h.status) == Some(HypothesisStatus::Accepted))
            .count();

        // ResolveContradiction never creates a hypothesis or evidence --
        // by design (it consumes the evidence a challenge already
        // produced) -- but it's never inert either: every call decides
        // whether the contested hypothesis survives or is REJECTED,
        // which is exactly the kind of state change this is meant to
        // measure. Judging it by the same "new hypothesis/evidence"
        // signal as the other two task types would make 100% of it look
        // like a no-op, which isn't true; it's productive by definition.
        let is_no_op = inv.task != "ResolveContradiction"
            && inv.hypotheses_created.is_empty()
            && inv.evidence_created.is_empty();
        if is_no_op {
            entry.no_op += 1;
        } else {
            productive += 1;
        }
    }

    let fingerprint_cache_hits = graph
        .observations()
        .filter(|o| o.predicate == "fingerprint_cache_source")
        .count();

    InvestigationReport {
        by_task: by_task.into_values().collect(),
        fingerprint_cache_hits,
        total_investigations: total,
        productive_investigations: productive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use debura_knowledge::{Investigation, InvestigationId, HypothesisId};

    fn investigation(task: &str, created: Vec<HypothesisId>, evidence_len: usize) -> Investigation {
        use debura_knowledge::EvidenceId;
        Investigation {
            id: InvestigationId(0),
            task: task.to_string(),
            target: "0x1".to_string(),
            context_snapshot: String::new(),
            tool_calls: Vec::new(),
            observations: Vec::new(),
            hypotheses_created: created,
            hypotheses_modified: Vec::new(),
            evidence_created: (0..evidence_len).map(|i| EvidenceId(i as u64)).collect(),
            result: String::new(),
            followup_tasks: Vec::new(),
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn groups_by_task_and_flags_no_ops() {
        let mut graph = KnowledgeGraph::new();
        let h1 = graph.propose_hypothesis("0x1", "semantic_role", "compute", 0.9, None);
        graph.record_investigation(investigation("AnalyzeFunction", vec![h1], 0));
        // A challenge that found nothing new: no new hypothesis, no new
        // evidence -- a no-op despite always touching the hypothesis via
        // hypotheses_modified in real usage.
        graph.record_investigation(investigation("ChallengeHypothesis", vec![], 0));
        // A challenge that DID find a contradiction: new evidence, so
        // productive even with no new hypothesis.
        graph.record_investigation(investigation("ChallengeHypothesis", vec![], 1));

        let report = investigation_report(&graph);

        let analyze = report.by_task.iter().find(|t| t.task == "AnalyzeFunction").unwrap();
        assert_eq!(analyze.executed, 1);
        assert_eq!(analyze.no_op, 0);

        let challenge = report.by_task.iter().find(|t| t.task == "ChallengeHypothesis").unwrap();
        assert_eq!(challenge.executed, 2);
        assert_eq!(challenge.no_op, 1);
        assert_eq!(challenge.productive(), 1);

        assert_eq!(report.total_investigations, 3);
        assert_eq!(report.productive_investigations, 2);
        assert!((report.productive_rate() - (2.0 / 3.0)).abs() < 1e-9);
    }

    #[test]
    fn attributes_accepted_hypotheses_to_the_task_type_that_created_them() {
        let mut graph = KnowledgeGraph::new();
        let h1 = graph.propose_hypothesis("0x1", "semantic_role", "compute", 0.95, None);
        graph.mark_verified(h1, chrono::Utc::now()).unwrap();
        graph.set_status(h1, HypothesisStatus::Accepted).unwrap();
        graph.record_investigation(investigation("AnalyzeFunction", vec![h1], 0));

        let report = investigation_report(&graph);
        let analyze = report.by_task.iter().find(|t| t.task == "AnalyzeFunction").unwrap();
        assert_eq!(analyze.accepted_from_created, 1);
    }

    /// A real run showed this matters: ResolveContradiction never
    /// creates a hypothesis or evidence by design, so judging it by the
    /// same signal as the other task types made every single one of 143
    /// real resolutions look like a no-op, when each one actually
    /// decided whether a contested hypothesis survived or was rejected.
    #[test]
    fn resolve_contradiction_is_never_counted_as_a_no_op() {
        let mut graph = KnowledgeGraph::new();
        graph.record_investigation(investigation("ResolveContradiction", vec![], 0));

        let report = investigation_report(&graph);
        let resolve = report.by_task.iter().find(|t| t.task == "ResolveContradiction").unwrap();
        assert_eq!(resolve.no_op, 0);
        assert_eq!(resolve.productive(), 1);
        assert_eq!(report.productive_investigations, 1);
    }

    #[test]
    fn fingerprint_cache_hits_are_counted_separately_from_investigations() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x2", "fingerprint_cache_source", "0x1", 1.0, "debura:fingerprint_cache", None);

        let report = investigation_report(&graph);
        assert_eq!(report.fingerprint_cache_hits, 1);
        assert_eq!(report.total_investigations, 0);
    }
}
