//! Stable abstraction over Ghidra (PROJECT.md S22).
//!
//! M1 implements the read-only, deterministic side: importing a binary into
//! headless Ghidra and extracting facts. Mutation operations (rename,
//! retype, apply_type, ...) arrive with Ghidra feedback at M8.

mod headless;
pub mod model;

pub use headless::analyze;
pub use model::{
    AnalysisResult, ExportFact, FieldFact, FunctionFact, ImportFact, InheritanceFact, StringFact,
    VirtualMethodFact, VtableFact, XrefFact,
};
