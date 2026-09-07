//! `AgentProvider` trait and the bounded-investigation harness (PROJECT.md §23).
//!
//! This crate is called by the engine — it never controls Debura's lifecycle
//! (PROJECT.md §2.5 / arch decision: engine owns truth, agent is a worker).
//!
//! Implementation begins at M4 — Agent Harness.
