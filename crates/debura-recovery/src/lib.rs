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
mod crt_boundary;
mod data_symbols;
mod disposition;
mod extract;
mod field_naming;
mod forwarding_thunk;
mod frontier;
mod model;
mod phantom_local;
mod render;
mod return_forwarding;
mod stack_object;
mod symbols;
mod symtab;
mod write;

pub use compat::{render_ghidra_compat_header, GHIDRA_COMPAT_HEADER_NAME};
pub use crt_boundary::{crt_startup_only_addresses, find_main_equivalent};
pub use data_symbols::{
    classify_data_symbols, find_constructor_string_literals, DataResolution, DataSymbolKind, VtableSlotTarget,
};
pub use disposition::{classify_recovery_disposition, DispositionEntry, RecoveryDisposition};
pub use extract::{extract, extract_with_options, extract_with_required_runtime_bodies};
pub use field_naming::NamesMode;
pub use frontier::{classify_frontier, parse_undefined_symbols, reachable_from, FrontierBucket, FrontierEntry, UnresolvedSymbol};
pub use model::{
    NameSource, RecoveredClass, RecoveredField, RecoveredFunction, RecoveredMethod,
    RecoveredProgram, VtableTrampoline,
};
pub use render::{render_functions_source, render_header, render_source};
pub use stack_object::{find_field_value_consumers, DiscoveredField, FieldValueConsumer};
pub use symtab::{build_symbol_table, SymbolTable};
pub use symbols::{
    render_function_declarations, render_ghidra_symbols_header, render_ghidra_symbols_header_resolved,
    GHIDRA_SYMBOLS_HEADER_NAME,
};
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
