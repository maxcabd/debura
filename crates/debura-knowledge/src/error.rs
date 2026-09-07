use thiserror::Error;

use crate::ids::{EvidenceId, HypothesisId, ObservationId};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KnowledgeError {
    #[error("unknown observation: {0}")]
    UnknownObservation(ObservationId),
    #[error("unknown evidence: {0}")]
    UnknownEvidence(EvidenceId),
    #[error("unknown hypothesis: {0}")]
    UnknownHypothesis(HypothesisId),
}
