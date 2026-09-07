use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{EvidenceId, HypothesisId, InvestigationId, ObservationId};

/// A record of what an agent actually did (PROJECT.md S19). Nothing
/// populates this until M4 (Agent Harness) -- the type exists now so the
/// knowledge graph's provenance fields (Hypothesis::created_by) have
/// somewhere to point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Investigation {
    pub id: InvestigationId,
    pub task: String,
    pub target: String,
    pub context_snapshot: String,
    pub tool_calls: Vec<String>,
    pub observations: Vec<ObservationId>,
    pub hypotheses_created: Vec<HypothesisId>,
    pub hypotheses_modified: Vec<HypothesisId>,
    pub evidence_created: Vec<EvidenceId>,
    pub result: String,
    pub followup_tasks: Vec<String>,
    pub created_at: DateTime<Utc>,
}
