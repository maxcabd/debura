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

/// Why a hypothesis was REJECTED, as a machine-checkable premise rather
/// than only the free-text observation a rejecting pass may also record
/// (PROJECT.md M18: a real audit found the provenance gate's REJECTED
/// semantic_role hypotheses over `Screen`/`Snake` had become wrong the
/// moment M18's own-state provenance signal shipped, but nothing noticed
/// because REJECTED is otherwise terminal and no generic cascade is
/// allowed to touch it -- see `KnowledgeGraph::mark_stale_dependents`).
/// This lets a *specific, deliberate* recheck of exactly this premise --
/// never the generic dependency cascade -- decide whether the rejection
/// still holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectionReason {
    ProvenanceNotApplication,
    InsufficientEvidence,
    ContradictedBy(HypothesisId),
    Other(String),
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
    /// Set only when `status == Rejected` by a pass that rejected against
    /// a specific, later-rechecked premise. `None` for a rejection with no
    /// such structured premise (e.g. `ChallengeHypothesis`'s free-form
    /// contradiction path) -- those remain terminal with no reconsideration
    /// path, same as before this field existed.
    pub rejection_reason: Option<RejectionReason>,
}
