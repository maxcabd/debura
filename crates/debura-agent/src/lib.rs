//! `AgentProvider` trait and the bounded-investigation harness (PROJECT.md
//! S23) -- M4.
//!
//! This crate is called by the engine -- it never controls Debura's
//! lifecycle (S2.5: engine owns truth, agent is a worker). A provider only
//! answers one bounded question (`AnalyzeFunctionTask -> InvestigationResult`);
//! the harness decides what of that answer is trustworthy enough to commit.

mod harness;
mod provider;
mod result;
mod task;

pub mod mock;

pub use harness::analyze_function;
pub use provider::AgentProvider;
pub use result::{
    ConfidenceUpdate, InvestigationResult, ProposedContradiction, ProposedHypothesis,
    ProposedObservation,
};
pub use task::AnalyzeFunctionTask;
