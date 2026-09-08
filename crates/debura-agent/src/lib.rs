//! `AgentProvider` trait and the bounded-investigation harness (PROJECT.md
//! S23) -- M4/M5.
//!
//! This crate is called by the engine -- it never controls Debura's
//! lifecycle (S2.5: engine owns truth, agent is a worker). A provider only
//! answers one bounded question at a time; the harness decides what of
//! that answer is trustworthy enough to commit.

mod call_context;
mod challenge;
mod evidence_view;
mod harness;
mod provider;
mod resolution;
mod result;
mod task;

pub mod mock;
#[cfg(feature = "openai")]
pub mod openai;

pub use call_context::{call_sequence_neighbors, CallSequenceNeighbor, SequencedCall};
pub use challenge::{ChallengeHypothesisTask, ChallengeResult};
pub use harness::{
    analyze_function, commit_contradiction, commit_hypothesis, commit_investigation, investigate,
};
pub use provider::AgentProvider;
pub use resolution::{Resolution, ResolutionResult, ResolveContradictionTask};
pub use result::{
    ConfidenceUpdate, InvestigationResult, ProposedContradiction, ProposedHypothesis,
    ProposedObservation,
};
pub use task::AnalyzeFunctionTask;
