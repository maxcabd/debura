//! Stable abstraction over Ghidra (PROJECT.md S22).
//!
//! M1 implements the read-only, deterministic side: importing a binary into
//! headless Ghidra and extracting facts. Mutation operations (rename,
//! retype, apply_type, ...) arrive with Ghidra feedback at M8.

mod headless;
mod mutation;
pub mod model;

pub use headless::{analyze, reextract};
pub use model::{
    AnalysisResult, DataObjectFact, ExportFact, FieldFact, FunctionFact, ImportFact,
    InheritanceFact, StringFact, VirtualMethodFact, VtableFact, XrefFact,
};
pub use mutation::{apply_renames, is_valid_symbol_name, RenameOutcome, RenameRequest};
