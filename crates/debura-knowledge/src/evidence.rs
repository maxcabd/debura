use serde::{Deserialize, Serialize};

use crate::ids::{EvidenceId, ObservationId};

/// A pointer from an Observation to how/why it was gathered as evidence
/// (PROJECT.md S19). Whether it supports or contradicts a given hypothesis
/// is recorded on the Hypothesis itself (`supporting_evidence` /
/// `contradicting_evidence`), not here -- the same observation could in
/// principle be cited by more than one hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub observation_id: ObservationId,
    pub relevance: String,
    pub source: String,
    pub location: Option<String>,
    pub artifact_reference: Option<String>,
}
