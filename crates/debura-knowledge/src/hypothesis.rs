use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{EvidenceId, HypothesisId, InvestigationId};

/// PROJECT.md S4. REJECTED is terminal: a rejected hypothesis is never
/// silently deleted or resurrected by cascading staleness from something
/// it once depended on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HypothesisStatus {
    Proposed,
    Investigating,
    Supported,
    Accepted,
    Contested,
    Stale,
    Rejected,
}

/// An interpretation of one or more observations (PROJECT.md S3.2).
/// Confidence and status describe Debura's *current* belief, not ground
/// truth -- both can change as evidence and dependencies change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: HypothesisId,
    pub subject: String,
    pub predicate: String,
    pub value: String,
    pub confidence: f64,
    pub status: HypothesisStatus,
    pub supporting_evidence: Vec<EvidenceId>,
    pub contradicting_evidence: Vec<EvidenceId>,
    pub dependencies: Vec<HypothesisId>,
    pub created_by: Option<InvestigationId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_verified_at: Option<DateTime<Utc>>,
}
