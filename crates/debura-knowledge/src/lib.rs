//! The epistemic model: Observation, Evidence, Hypothesis, Dependency,
//! Investigation, ProgramModel (PROJECT.md S3, S19) -- M2.
//!
//! Everything here is in-memory hot state (PROJECT.md S16). SQLite backing
//! for this graph is M3; the agent that actually populates it is M4.

mod claims;
mod dependency;
mod error;
mod evidence;
mod graph;
mod hypothesis;
mod ids;
mod investigation;
mod observation;
mod program_model;

pub use claims::{
    claim_breakdown, classify_provenance, classify_subject, is_reserved_identifier,
    library_callee_ratio, ClaimBreakdown, ClaimClass, Provenance,
};
pub use dependency::{Dependency, DependencyKind};
pub use error::KnowledgeError;
pub use evidence::Evidence;
pub use graph::KnowledgeGraph;
pub use hypothesis::{Hypothesis, HypothesisStatus, RejectionReason};
pub use ids::{EvidenceId, HypothesisId, InvestigationId, ObservationId};
pub use investigation::Investigation;
pub use observation::Observation;
pub use program_model::ProgramModel;
