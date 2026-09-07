//! C++ source generation from the accepted program model (PROJECT.md S31)
//! -- M9.
//!
//! Combines two different kinds of trust (S5): structural facts (vtables,
//! inheritance, field offsets) are deterministic Ghidra observations,
//! already trustworthy without going through verification; member *names*
//! are only used when backed by an ACCEPTED hypothesis (M5's gate), never
//! a merely PROPOSED one -- otherwise Ghidra's own raw name is kept and
//! marked as such. Every recovered name says which of the two it is.

mod compat;
mod extract;
mod model;
mod render;
mod symbols;
mod write;

pub use compat::{GHIDRA_COMPAT_HEADER, GHIDRA_COMPAT_HEADER_NAME};
pub use extract::extract;
pub use model::{
    NameSource, RecoveredClass, RecoveredField, RecoveredFunction, RecoveredMethod,
    RecoveredProgram,
};
pub use render::{render_functions_source, render_header, render_source};
pub use symbols::{render_ghidra_symbols_header, GHIDRA_SYMBOLS_HEADER_NAME};
pub use write::{write_to_disk, RecoverySummary};

use std::path::Path;

use anyhow::Result;
use debura_knowledge::KnowledgeGraph;

/// Extracts and writes in one call -- the convenience entry point for the
/// CLI (`debura recover`).
pub fn recover(graph: &KnowledgeGraph, project_root: &Path) -> Result<RecoverySummary> {
    let program = extract::extract(graph);
    write::write_to_disk(project_root, &program)
}
