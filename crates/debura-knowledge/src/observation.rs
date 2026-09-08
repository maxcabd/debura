use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::ObservationId;

/// An observation's lifecycle state (PROJECT.md M18): a real run found a
/// model re-rejecting a reconsidered hypothesis partly because it was
/// still reading a now-outdated `provenance_gate_rejected` observation as
/// if it were live evidence, even though a later observation on the same
/// subject had already recorded that its premise no longer held. Historical
/// observations must stay on the record -- nothing here is ever deleted --
/// but they should stop feeding new reasoning once something supersedes
/// them. Generalizes beyond provenance: a later, stronger field-type
/// inference, a corrected class-ownership call, a re-resolved thunk
/// target, or an improved decompilation's mechanical-behavior read are all
/// the same shape (an old fact a newer one corrects), not a special case
/// of this one predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationStatus {
    /// Live evidence -- the default, and the only status new reasoning
    /// (e.g. `ChallengeHypothesisTask`'s context) should see.
    Active,
    /// Corrected or replaced by a specific later observation
    /// (`superseded_by`), not merely doubted -- still real history, just
    /// no longer current.
    Superseded,
    /// Withdrawn outright (e.g. found to be a genuine extraction error),
    /// with no replacement fact taking its place.
    Retracted,
}

/// Something directly derived from the binary or deterministic analysis
/// (PROJECT.md S3.1). Not a semantic interpretation -- observations should
/// generally sit at very high confidence because nothing here was guessed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub id: ObservationId,
    pub subject: String,
    pub predicate: String,
    pub value: String,
    pub confidence: f64,
    pub source: String,
    pub artifact: Option<String>,
    pub created_at: DateTime<Utc>,
    pub status: ObservationStatus,
    /// Set only when `status == Superseded`: the observation that corrects
    /// this one. `None` for `Active`/`Retracted`.
    pub superseded_by: Option<ObservationId>,
}
