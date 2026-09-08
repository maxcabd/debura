use serde::{Deserialize, Serialize};

/// A deterministic fact about one function, as observed by Ghidra.
///
/// Nothing here is a semantic claim (PROJECT.md S3.1) -- `name` is whatever
/// Ghidra assigned (e.g. `FUN_140271330`), not an inferred identity.
/// `owner_class`/`is_constructor`/`is_destructor` come from recognizing a
/// `this` parameter and matching Ghidra's own (demangled) function name
/// against it (M7) -- not from any inference of our own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionFact {
    pub address: String,
    pub name: String,
    pub size: u64,
    pub signature: String,
    pub calling_convention: String,
    pub callers: Vec<String>,
    pub callees: Vec<String>,
    pub decompilation: String,
    pub owner_class: Option<String>,
    pub is_constructor: bool,
    pub is_destructor: bool,
    /// Set when this function stores its owner class's own vtable pointer
    /// into `this` early in its body -- the Itanium ABI idiom every
    /// constructor and destructor performs, but which one isn't
    /// distinguished (M7's structural discovery can find the pattern
    /// without being able to tell the two apart -- see ExtractFacts.py's
    /// module-level comment). `None` when the owner class (if any) came
    /// from Ghidra's own symbol-based demangling instead, where
    /// `is_constructor`/`is_destructor` already answer this more
    /// precisely.
    pub installs_vtable_of: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringFact {
    pub address: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportFact {
    pub name: String,
    pub namespace: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportFact {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefFact {
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub kind: String,
}

/// A class's vtable address (PROJECT.md M7). Itanium C++ ABI only --
/// see ExtractFacts.py's module comment for what that excludes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtableFact {
    pub class_name: String,
    pub address: String,
}

/// One virtual method slot, read directly out of a class's vtable. Slot
/// numbers include inherited (non-overridden) methods, since Itanium
/// vtables always list the full flattened set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualMethodFact {
    pub class_name: String,
    pub slot: u32,
    pub function_address: String,
}

/// `derived` has exactly one non-virtual public base, `base` (read from
/// the Itanium RTTI record's base-typeinfo pointer). Multiple/virtual
/// inheritance isn't extracted -- see ExtractFacts.py.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InheritanceFact {
    pub derived: String,
    pub base: String,
}

/// A candidate field, found by pattern-matching `*(TYPE *)(this + OFFSET)`
/// in a method's decompilation (M7) -- a regex over already-decompiled
/// text, not real data-flow analysis. Refining this to walk p-code
/// directly is a natural improvement once field-offset accuracy is
/// actually being measured (M9).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldFact {
    pub class_name: String,
    pub offset: String,
    #[serde(rename = "type")]
    pub field_type: String,
}

/// A deterministic fact about one address recovered code references that
/// isn't itself a known function entry point (PROJECT.md M18.2) --
/// exactly the shape a `DAT_*`/`PTR_*`/`LAB_*` linker placeholder is.
/// Every field here is Ghidra's own observation, never an interpretation
/// of it: `size`/`bytes_hex` are only ever set from a real, bounded
/// extent (a defined Data object, or a next symbol close enough to trust
/// as a bound), never guessed from a name shape; `pointee_address` is
/// only set when Ghidra's own reference analysis found one, or a
/// bounds-checked raw 8-byte read resolves to a real in-program address
/// (`pointee_source` says which). Deriving a semantic kind (mutable
/// global vs. constant, pointer-to-function vs. pointer-to-import, ...)
/// from these is `debura-analysis`'s/the recovery layer's job, not this
/// crate's -- see `ExtractFacts.py`'s own `extract_data_objects`
/// docstring for the full reasoning (a real, deliberate design
/// correction: an earlier draft classified `kind` directly in the
/// extraction script itself, exactly the premature semantic claim this
/// whole project's own discipline exists to avoid).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataObjectFact {
    pub address: String,
    pub symbol_name: Option<String>,
    pub section: Option<String>,
    pub readable: Option<bool>,
    pub writable: Option<bool>,
    pub executable: Option<bool>,
    pub initialized: Option<bool>,
    pub data_type: Option<String>,
    pub size: Option<u64>,
    /// `false` when `size` was only estimated from a next-symbol
    /// distance (not a real Ghidra-defined Data object's own length) --
    /// still bounded/sane, but not authoritative the way a defined
    /// type's length is.
    pub size_confident: bool,
    /// Only ever populated when `size` is both known and small enough
    /// to be worth reading (`ExtractFacts.py`'s own bounded cap) --
    /// `None` otherwise, deliberately never an unbounded/guessed read.
    pub bytes_hex: Option<String>,
    /// The containing function's own entry-point address, if this
    /// address falls inside one -- the concrete, checkable answer to
    /// "is this actually a code label taken as a value, not real data".
    pub inside_function: Option<String>,
    pub pointee_address: Option<String>,
    /// `"reference"` (Ghidra's own reference analysis) or
    /// `"raw_bytes"` (a bounds-checked reinterpretation of this
    /// address's own 8 raw bytes) -- `None` alongside a `None`
    /// `pointee_address`.
    pub pointee_source: Option<String>,
    pub referenced_from: Vec<String>,
}

/// The full set of deterministic observations extracted from one program
/// (PROJECT.md S21, M1/M7). Raw material for M2's Observation/Evidence
/// model -- this crate does not interpret any of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub program: String,
    pub functions: Vec<FunctionFact>,
    pub strings: Vec<StringFact>,
    pub imports: Vec<ImportFact>,
    pub exports: Vec<ExportFact>,
    pub xrefs: Vec<XrefFact>,
    pub vtables: Vec<VtableFact>,
    pub virtual_methods: Vec<VirtualMethodFact>,
    pub inheritance: Vec<InheritanceFact>,
    pub fields: Vec<FieldFact>,
    pub data_objects: Vec<DataObjectFact>,
}
