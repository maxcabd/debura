use debura_knowledge::HypothesisId;

/// Where a recovered name came from -- so generated source can say so
/// (PROJECT.md S31: recovered source retains a link back to the
/// hypothesis/evidence that produced it).
#[derive(Debug, Clone)]
pub enum NameSource {
    /// An ACCEPTED hypothesis (PROJECT.md M5's gate has already been
    /// cleared for it).
    Accepted {
        hypothesis: HypothesisId,
        confidence: f64,
    },
    /// No accepted hypothesis exists yet -- this is Ghidra's own name,
    /// carrying no semantic confidence at all.
    Raw,
}

#[derive(Debug, Clone)]
pub struct RecoveredField {
    pub offset: String,
    /// Every distinct candidate type observed at this offset (M7's
    /// field-offset heuristic can disagree with itself, e.g. `int` vs
    /// `uint` from different call sites). The first is used in the
    /// declaration; the rest are noted, not silently dropped.
    pub candidate_types: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RecoveredMethod {
    pub address: String,
    pub raw_name: String,
    pub display_name: String,
    pub name_source: NameSource,
    pub return_type: String,
    pub params: String,
    pub is_constructor: bool,
    pub is_destructor: bool,
    /// A local-variable declaration to splice into the body's first
    /// statement, re-binding a structurally-discovered method's own raw
    /// receiver name (`param_1`, never recognized by Ghidra's own type
    /// system as `this`) back to the real, implicit `this` -- `None` for
    /// a method Ghidra did recognize (nothing to re-bind: the body's own
    /// uses of the identifier `this` already resolve correctly once it's
    /// dropped from the declared params) or a standalone function (no
    /// receiver at all). Deliberately NOT already spliced into
    /// `decompilation`: this text contains the literal keyword `this`,
    /// and `render.rs`'s `patch_known_idioms` separately renames a
    /// *different*, unrelated local variable Ghidra's decompiler
    /// sometimes names that exact way (`rename_this_local_variable`) --
    /// splicing this in before that rename ran corrupted this alias's
    /// own use of the keyword right along with it (a real regression,
    /// caught immediately by a real compile). `render.rs` inserts this
    /// itself, after that rename has already run.
    pub receiver_alias: Option<String>,
    /// Ghidra's decompiled body (PROJECT.md S31 doesn't specify how
    /// faithful the recovered body must be -- this is annotated decompiler
    /// output, not hand-lifted C++, and says so where it's rendered).
    pub decompilation: String,
}

#[derive(Debug, Clone)]
pub struct RecoveredClass {
    pub name: String,
    pub base: Option<String>,
    pub vtable_address: String,
    pub fields: Vec<RecoveredField>,
    pub methods: Vec<RecoveredMethod>,
    /// Other recovered classes this one's own method/field signatures
    /// name (e.g. `Food::draw(Screen *)`), excluding `base` (already
    /// its own `#include`). A real compile of this output hit the
    /// referenced-but-never-declared case for exactly this reason.
    pub references: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RecoveredFunction {
    pub address: String,
    pub raw_name: String,
    pub display_name: String,
    pub name_source: NameSource,
    pub return_type: String,
    pub params: String,
    pub decompilation: String,
}

/// Everything Debura currently has enough grounds to recover (PROJECT.md
/// M9). Only functions with a real recovered (ACCEPTED) name are included
/// as standalone recovered functions -- dumping every unnamed `FUN_xxx` in
/// the binary wouldn't be "recovered" anything.
#[derive(Debug, Clone, Default)]
pub struct RecoveredProgram {
    pub classes: Vec<RecoveredClass>,
    pub functions: Vec<RecoveredFunction>,
    /// Recovered classes any standalone function's signature or (M15
    /// symbol-resolved) body mentions -- `functions.cpp`'s own
    /// `#include` list, the same reasoning as `RecoveredClass::references`.
    pub function_references: Vec<String>,
    /// Ghidra's own auto-generated data-symbol names (`DAT_...`,
    /// `PTR_...`, `_refptr_...`) referenced somewhere in a recovered
    /// body but never declared anywhere else in the output.
    pub ghidra_data_symbols: Vec<String>,
    /// Ghidra's own `CONCATxy`/`SUBxy`/`ZEXTxy`/`SEXTxy` intrinsic names
    /// referenced somewhere in a recovered body -- exactly the set
    /// `render_ghidra_compat_header` needs to generate definitions for.
    pub ghidra_intrinsics: Vec<String>,
    /// Call-site names (`FUN_x`, `thunk_FUN_x`) M15's symbol resolution
    /// pass found no recovered definition for at all -- left as literal
    /// calls in the rewritten bodies, needing a permissive fallback
    /// declaration to at least parse.
    pub unresolved_calls: Vec<String>,
}
