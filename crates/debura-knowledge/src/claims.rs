use std::collections::HashSet;

use crate::{HypothesisStatus, KnowledgeGraph};

/// PROJECT.md M15: whether an ACCEPTED semantic_role hypothesis reflects
/// real application logic, or is compiler/library machinery Debura merely
/// *recognized*, must never collapse into one acceptance-rate number. A
/// real run's headline "8x more accepted knowledge" hid that 316 of 350
/// of those acceptances were libstdc++ internals (std::vector
/// reallocation, iterator helpers, `_Guard`) -- useful knowledge, but not
/// evidence Debura understands the game any better.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimClass {
    /// The subject's owning class (or its own name, for a free function)
    /// doesn't match C++'s own reserved-identifier shapes, so it's
    /// presumed to be code the binary's own author wrote.
    Application,
    /// A name starting with `_` followed by an uppercase letter, or
    /// containing `__`, is what the C++ standard itself reserves for the
    /// implementation -- compilers and standard library authors use
    /// exactly this convention, which makes it a reliable, principled
    /// signal that a name is library/runtime/compiler-generated rather
    /// than user-written, with no library-signature database needed.
    LibraryOrCompiler,
}

/// Exposed directly (not just through `classify_subject`) for a caller
/// that already has a name in hand -- e.g. debura-recovery excluding a
/// class from the recovered C++ output by its own name, before there's
/// any single subject address to look up.
pub fn is_reserved_identifier(name: &str) -> bool {
    if name.contains("__") {
        return true;
    }
    let mut chars = name.chars();
    matches!((chars.next(), chars.next()), (Some('_'), Some(c)) if c.is_ascii_uppercase())
}

/// Classifies a subject by its class membership (`is_method_of`), its
/// own name, or -- the strongest signal, checked first -- whether it's
/// listed in the binary's own import table at all: an `imports`
/// observation means the symbol is external to the binary by
/// construction (whether a dynamically-imported libstdc++/SDL symbol or
/// a statically-linked one Ghidra still recognized), which no
/// name-shape heuristic is needed to establish. A real run showed why
/// this matters beyond the C++-reserved-identifier convention alone:
/// SDL's own C API (`SDL_Init`, `TTF_OpenFont`) is plain PascalCase, not
/// underscore-prefixed, so it never matched `is_reserved_identifier` at
/// all -- diluting a library-dominated function's callee ratio with
/// calls that were just as clearly not application code, only shaped
/// differently.
///
/// Deliberately does NOT default to `Application` when nothing matches
/// (PROJECT.md M17): on a genuinely stripped binary, a real audit found
/// this cheap check has *no signal at all* for most subjects -- their
/// only observation is `has_name = FUN_<addr>`, which isn't
/// reserved-shaped, isn't an import, and has no `is_method_of` -- so
/// `classify_subject` alone can't tell Application from "no idea yet".
/// Use `classify_provenance` for a real per-subject verdict; this
/// function only answers the narrower, cheaper question "does this
/// subject's own name/owner/import status look like library code",
/// leaving everything else to whoever calls it.
pub fn classify_subject(graph: &KnowledgeGraph, subject: &str) -> ClaimClass {
    let imported = graph.observations().any(|o| o.subject == subject && o.predicate == "imports");
    if imported {
        return ClaimClass::LibraryOrCompiler;
    }

    if let Some(owner) = method_owner(graph, subject) {
        if is_reserved_identifier(&owner) {
            return ClaimClass::LibraryOrCompiler;
        }
    }

    let name = graph
        .observations()
        .find(|o| o.subject == subject && o.predicate == "has_name")
        .map(|o| o.value.as_str());
    if let Some(name) = name {
        if is_reserved_identifier(name) {
            return ClaimClass::LibraryOrCompiler;
        }
    }

    ClaimClass::Application
}

/// The class a subject belongs to, whether as an ordinary method, a
/// constructor, or a destructor -- the same three predicates
/// debura-recovery's own `class_method_addresses` treats as equivalent
/// ownership signals (`extract.rs`), so a constructor doesn't fall
/// through this crate's own name-shape/provenance checks just because
/// `is_method_of` specifically isn't the predicate Ghidra extraction used
/// for it.
fn method_owner(graph: &KnowledgeGraph, subject: &str) -> Option<String> {
    graph
        .observations()
        .find(|o| {
            o.subject == subject
                && matches!(o.predicate.as_str(), "is_method_of" | "is_constructor_of" | "is_destructor_of")
        })
        .map(|o| o.value.clone())
}

/// PROJECT.md M17: a real audit against a genuinely stripped Snake binary
/// found 10 of 37 ACCEPTED semantic_role claims were libstdc++/CRT
/// internals (`std::vector::_M_erase_at_end`, `_S_max_size`,
/// `__relocate_a`, MinGW's own `_pei386_runtime_relocator`) that had
/// earned application-sounding names (`invokeFunctionConditionally`,
/// `retrievePointer`, `initializeSettings`) and made it all the way into
/// the recovered `.cpp` output -- because the *previous* two-state
/// `Provenance` (Application / CompilerLibraryGlue) fell back to
/// `Application` whenever `classify_subject`'s name-shape check had
/// nothing to go on, which on a stripped binary is most of the time (see
/// `classify_subject`'s own doc comment). That fallback is exactly the
/// bug: "no recognizable library name" is not evidence *for*
/// Application, it's an absence of evidence either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Positively identified as application code: either its own name
    /// isn't library-shaped and it's a method of a real (non-reserved)
    /// class, or its callees are themselves dominated by confirmed
    /// Application code.
    Application,
    /// Confirmed library/runtime/compiler-generated code -- by direct
    /// name/import shape, by being a thunk to something confirmed
    /// library, or by callee composition dominated by confirmed library
    /// code (thunk-resolved, propagated up to `MAX_PROPAGATION_DEPTH`
    /// hops). Finer distinctions (hand-written STL vs. compiler-emitted
    /// relocation glue vs. a bare trampoline) aren't attempted here --
    /// the gate this feeds only needs "not application", and manufacturing
    /// a confident split the evidence doesn't support would repeat the
    /// exact mistake `mechanical_shape_check` exists to catch elsewhere.
    LibraryOrRuntime,
    /// No signal either way. MUST NOT be treated as Application by
    /// anything gating semantic_role generation -- this is the state the
    /// old fallback used to silently erase.
    Unknown,
}

/// How many calls a function may make and still be considered small
/// enough to be a pure single-target thunk/trampoline, by its own
/// `size_bytes` fact -- generous enough to include parameter shuffling
/// around one delegated call, not so generous it starts matching real
/// multi-step application logic.
const THUNK_MAX_SIZE_BYTES: u64 = 32;

/// A function whose entire recorded behavior is exactly one distinct
/// callee and a small enough body -- pure delegation, so its own
/// provenance is really its target's. Structural, using facts
/// debura-ghidra already extracts (`calls`, `size_bytes`); no decompiled
/// text parsing needed. Deliberately approximate (PROJECT.md M15's
/// documented thunk-normalization TODO, finally acted on): a real
/// compiler-emitted thunk and a one-line application forwarding wrapper
/// look the same by this measure, but both cases really do want their
/// own provenance to be inherited from their single callee, so the
/// approximation is sound either way.
fn thunk_target(graph: &KnowledgeGraph, subject: &str) -> Option<String> {
    let callees: HashSet<&str> = graph
        .observations()
        .filter(|o| o.subject == subject && o.predicate == "calls")
        .map(|o| o.value.as_str())
        .collect();
    if callees.len() != 1 {
        return None;
    }
    let size: u64 = graph
        .observations()
        .find(|o| o.subject == subject && o.predicate == "size_bytes")
        .and_then(|o| o.value.parse().ok())?;
    if size > THUNK_MAX_SIZE_BYTES {
        return None;
    }
    callees.into_iter().next().map(str::to_string)
}

/// How many hops of thunk-resolution and callee-composition propagation
/// to follow before giving up and calling a subject Unknown rather than
/// walking the whole call graph. A real chain this was measured against:
/// MinGW's `_pei386_runtime_relocator` (depth 0) calls four unnamed local
/// helpers (depth 1), one of which calls straight into an imported
/// symbol (depth 2) -- 5 comfortably covers chains like that without
/// unbounded graph traversal on a large binary.
const MAX_PROPAGATION_DEPTH: u32 = 5;

/// Dominance threshold above which a subject's callee composition decides
/// its provenance -- deliberately high (not "calls any library function
/// at all"), so real application code that calls a couple of library
/// helpers along the way isn't misclassified.
const LIBRARY_GLUE_THRESHOLD: f64 = 0.8;

/// The provenance judgment PROJECT.md M17 asks for, computed structurally
/// rather than assumed from a naming default: `classify_subject`'s
/// name/import shape first (cheap, and the strongest signal when it
/// fires), then a real application class's own (non-reserved-shaped)
/// method, then thunk resolution (inherit the single delegated-to
/// target's provenance), then callee-composition dominance -- computed
/// with callees *recursively* classified the same way (not just
/// name-shape), so a classification can propagate several hops from a
/// confirmed anchor (an import, a known application class) toward
/// something with no direct signal of its own. Only when none of that
/// produces an answer does this return `Unknown` -- never `Application`
/// by default.
pub fn classify_provenance(graph: &KnowledgeGraph, subject: &str) -> Provenance {
    classify_provenance_bounded(graph, subject, &mut HashSet::new(), MAX_PROPAGATION_DEPTH)
}

fn classify_provenance_bounded(
    graph: &KnowledgeGraph,
    subject: &str,
    visited: &mut HashSet<String>,
    depth: u32,
) -> Provenance {
    // Cycle guard. A real single-inheritance/call chain doesn't usually
    // cycle, but a diamond in the call graph (two callees of the same
    // subject sharing a common sub-callee) will hit this too -- an
    // under-classification (falling to Unknown) rather than
    // over-classification, which is the safe direction to err in here.
    if !visited.insert(subject.to_string()) {
        return Provenance::Unknown;
    }

    if let Some(p) = classify_shallow(graph, subject, visited, depth) {
        return p;
    }

    if depth == 0 {
        return Provenance::Unknown;
    }

    let callees: Vec<String> = graph
        .observations()
        .filter(|o| o.subject == subject && o.predicate == "calls")
        .map(|o| o.value.clone())
        .collect();
    if callees.is_empty() {
        return Provenance::Unknown;
    }

    // Library dominance is unaffected by the direct/transitive distinction
    // below: it's still asking "is this subject's callee composition
    // overwhelmingly library-shaped", which is safe to answer with each
    // callee's own full (possibly dominance-derived) verdict.
    let resolved: Vec<Provenance> = callees
        .iter()
        .map(|c| classify_provenance_bounded(graph, c, visited, depth - 1))
        .collect();
    let library_count = resolved.iter().filter(|p| **p == Provenance::LibraryOrRuntime).count();
    if library_count as f64 / resolved.len() as f64 >= LIBRARY_GLUE_THRESHOLD {
        return Provenance::LibraryOrRuntime;
    }

    // PROJECT.md M18: a direct call to a confirmed Application function is
    // strong evidence (`setupGame` directly calling `Snake::Snake`); an
    // Application hit reached only *transitively*, through intermediate
    // nodes with no Application signal of their own, is not -- a real
    // recovery run found MinGW's CRT startup routine inheriting Application
    // this way purely because it eventually calls `main`, which calls real
    // game code several hops down. Checking each direct callee with
    // `classify_shallow` (not the `resolved` verdicts above, which can
    // themselves be dominance-derived, i.e. exactly as transitive as the
    // bug this closes) is what enforces "direct", not just "any depth".
    let has_direct_application_callee = callees
        .iter()
        .any(|c| classify_shallow(graph, c, visited, depth.saturating_sub(1)) == Some(Provenance::Application));
    if has_direct_application_callee {
        return Provenance::Application;
    }

    Provenance::Unknown
}

/// The provenance signals that don't depend on a subject's own callees'
/// *composition* -- name/import shape, class ownership (`method_owner`),
/// own-state field access plus a thunked import call, and thunk
/// resolution (a thunk IS its target, not evidence *about* it, so this
/// still recurses through the target's own full classification). `None`
/// when none of these fire, meaning only callee-composition dominance (in
/// `classify_provenance_bounded`) is left to try.
///
/// Split out specifically so a subject's *direct* callees can be checked
/// for Application evidence this way, without recursing into *their*
/// callees' own composition -- see `classify_provenance_bounded`'s own
/// comment on why conflating the two let a multi-hop Application hit
/// propagate all the way back up through code with no Application signal
/// of its own.
fn classify_shallow(
    graph: &KnowledgeGraph,
    subject: &str,
    visited: &mut HashSet<String>,
    depth: u32,
) -> Option<Provenance> {
    if classify_subject(graph, subject) == ClaimClass::LibraryOrCompiler {
        return Some(Provenance::LibraryOrRuntime);
    }

    if let Some(owner) = method_owner(graph, subject) {
        if !is_reserved_identifier(&owner) {
            return Some(Provenance::Application);
        }
    }

    // PROJECT.md M18: a real frontier run found this gap concretely --
    // `Screen`/`Snake` have no vtable, so M7's structural detection never
    // gives their methods an `is_method_of` anchor at all, and most of
    // their own callees really are SDL/CRT imports (dominance would call
    // them library-dominated). But a thin library-forwarding thunk
    // touches at most one field of its own receiver, if any; genuine
    // lifecycle/orchestration code -- `Screen::init` writing its
    // window/renderer/texture/font pointers into five distinct fields,
    // `Screen::close` reading four distinct fields to tear each down --
    // touches several. This has to run before the dominance check below,
    // not after: `Screen::init`'s own callees are almost entirely SDL/TTF
    // imports (real library calls), so dominance alone would misclassify
    // it as library, not just leave it Unknown.
    //
    // The own-state check alone isn't enough, though: a real run found it
    // firing on plain STL container internals too (`std::vector`'s
    // `push_back` growth path touches its own begin/end/capacity fields
    // the same structural way) -- accessing several of your own fields
    // isn't unique to application code. What *is* distinctive about
    // `Screen::init`/`close` is that they reach a real import through a
    // genuine thunk -- a tiny, single-callee forwarding stub (Ghidra's
    // own `SDL_RenderClear` wrapper is a real, observed case: 6 bytes,
    // one call, straight to the import) -- while the vector internals'
    // own callees are real, multi-statement STL functions with actual
    // branching logic, never thunk-shaped, however many hops they are
    // from an eventual `operator_new`/`malloc`. Requiring the callee to
    // thunk-resolve to an import specifically (not just "is somewhere in
    // a chain that eventually reaches one", which almost any code
    // technically is) is what keeps this from re-admitting exactly the
    // library-leakage case the M17 provenance gate was built to close.
    if let Some(decompilation) = crate::decompilation::latest_decompilation(graph, subject).map(|o| o.value.as_str()) {
        if let Some(param) = first_param_name(decompilation) {
            // Body only, not the full text: the parameter's own
            // declaration (`TYPE *param_1`) contains the same `*param_1`
            // substring `distinct_param_slots_accessed`'s bare-dereference
            // case matches, which would otherwise count every pointer-
            // typed subject's own signature as a spurious extra slot.
            if let Some(body_start) = decompilation.find('{') {
                let body = &decompilation[body_start..];
                if distinct_param_slots_accessed(body, &param) >= MIN_OWN_STATE_SLOTS
                    && calls_something_that_thunks_to_an_import(graph, subject)
                {
                    return Some(Provenance::Application);
                }
            }
        }
    }

    if depth == 0 {
        return None;
    }

    if let Some(target) = thunk_target(graph, subject) {
        return Some(classify_provenance_bounded(graph, &target, visited, depth - 1));
    }

    None
}

/// How many distinct fields of its own receiver a function must touch
/// before that counts as "owns persistent state" rather than
/// coincidentally touching the same one twice. 2 is deliberately low --
/// this only needs to separate a thin forwarding thunk (touches at most
/// one field, if any) from genuine lifecycle code, not measure how
/// elaborate the lifecycle code is.
const MIN_OWN_STATE_SLOTS: usize = 2;

/// The name of a decompiled function's own first parameter -- Ghidra's
/// own C-shaped signature always has one, `param_1` in every case this
/// was built against. A best-effort read of the header text before the
/// body's own `{`, not a real C parser (matches the same trade-off
/// `debura-recovery`'s own signature parsing already makes for the same
/// kind of text).
fn first_param_name(decompilation: &str) -> Option<String> {
    let header_end = decompilation.find('{')?;
    let header = &decompilation[..header_end];
    let open = header.find('(')?;
    let close = header.rfind(')')?;
    if close <= open {
        return None;
    }
    let first = header[open + 1..close].split(',').next()?.trim();
    if first.is_empty() || first == "void" {
        return None;
    }
    first
        .rsplit(|c: char| c == ' ' || c == '*')
        .find(|s| !s.is_empty())
        .map(str::to_string)
}

/// Distinct "slots" of `param_name` accessed anywhere in `body` --
/// `param_1[N]` (array-style, N is the slot), `*param_1` (bare
/// dereference, its own slot), or `(param_1 + N)`/`((cast)param_1 + N)`
/// (pointer-arithmetic-style, N is the slot). Counts distinct slots, not
/// accesses: a real lifecycle/orchestration method typically touches
/// several different fields of its own receiver; a thin library-
/// forwarding thunk typically touches at most one (often passing the
/// receiver through unexamined, or reading exactly one field to hand to
/// a single library call).
fn distinct_param_slots_accessed(body: &str, param_name: &str) -> usize {
    let mut slots: HashSet<String> = HashSet::new();

    let bracket_needle = format!("{param_name}[");
    let mut rest = body;
    while let Some(pos) = rest.find(bracket_needle.as_str()) {
        let after = &rest[pos + bracket_needle.len()..];
        if let Some(close) = after.find(']') {
            slots.insert(after[..close].trim().to_string());
        }
        rest = &after[..];
    }

    let plus_needle = format!("{param_name} + ");
    let mut rest = body;
    while let Some(pos) = rest.find(plus_needle.as_str()) {
        let after = &rest[pos + plus_needle.len()..];
        let end = after
            .find(|c: char| !(c.is_ascii_hexdigit() || c == 'x'))
            .unwrap_or(after.len());
        if end > 0 {
            slots.insert(format!("+{}", &after[..end]));
        }
        rest = after;
    }

    let star_needle = format!("*{param_name}");
    let mut rest = body;
    while let Some(pos) = rest.find(star_needle.as_str()) {
        let after = &rest[pos + star_needle.len()..];
        let continues_word = after.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        if !continues_word && !after.starts_with('[') {
            slots.insert("*".to_string());
        }
        rest = after;
    }

    slots.len()
}

/// How many thunk-hops to follow looking for a real import before giving
/// up. 3 comfortably covers a real observed case (`Screen::init` calling
/// one Ghidra-named wrapper -- itself a 1-hop thunk straight to the
/// import) without walking so far that it starts crediting a subject for
/// an import buried deep in an unrelated call chain.
const MAX_IMPORT_THUNK_DEPTH: u32 = 3;

/// Whether any of `subject`'s own direct callees resolves, through a
/// chain of pure thunks (see `thunk_target`), to a real imported symbol.
/// Deliberately narrower than "is this callee's own provenance
/// `LibraryOrRuntime`" (which `distinct_param_slots_accessed`'s own
/// caller can't use without re-opening the exact false positive it was
/// built to close): a real compiled `std::vector::push_back` growth path
/// also touches several of its own fields, but its callees are genuine,
/// multi-statement STL functions -- never thunk-shaped, however many
/// hops they are from an eventual allocator call. A real, directly-
/// imported API call, by contrast, is reached through a *thunk* -- a
/// tiny, single-callee forwarding stub, the exact shape Ghidra's own
/// `SDL_RenderClear` wrapper has (6 bytes, one call, straight to the
/// import).
fn calls_something_that_thunks_to_an_import(graph: &KnowledgeGraph, subject: &str) -> bool {
    graph
        .observations()
        .filter(|o| o.subject == subject && o.predicate == "calls")
        .any(|o| thunks_to_an_import(graph, &o.value, MAX_IMPORT_THUNK_DEPTH))
}

fn thunks_to_an_import(graph: &KnowledgeGraph, addr: &str, depth: u32) -> bool {
    if graph.observations().any(|o| o.subject == addr && o.predicate == "imports") {
        return true;
    }
    if depth == 0 {
        return false;
    }
    match thunk_target(graph, addr) {
        Some(target) => thunks_to_an_import(graph, &target, depth - 1),
        None => false,
    }
}

/// How much of `subject`'s own behavior, by call composition, is really
/// library/compiler internals rather than anything application-specific
/// -- dominance, not presence. Single-hop only (callees judged by
/// `classify_subject`'s cheap name-shape check, not recursively): kept as
/// its own function because it's a genuinely different, simpler question
/// than `classify_provenance` answers ("does this subject's *own direct*
/// callee list look library-shaped" vs. "what is this subject's actual
/// provenance, propagated through the whole reachable graph"). Returns
/// 0.0 (never glue on this signal alone) for a subject with no recorded
/// callees at all, rather than treating "nothing known" as "entirely
/// library".
pub fn library_callee_ratio(graph: &KnowledgeGraph, subject: &str) -> f64 {
    let callees: Vec<&str> = graph
        .observations()
        .filter(|o| o.subject == subject && o.predicate == "calls")
        .map(|o| o.value.as_str())
        .collect();
    if callees.is_empty() {
        return 0.0;
    }
    let library_count = callees
        .iter()
        .filter(|callee| classify_subject(graph, callee) == ClaimClass::LibraryOrCompiler)
        .count();
    library_count as f64 / callees.len() as f64
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClaimBreakdown {
    pub application_accepted: usize,
    pub library_or_runtime_accepted: usize,
    /// PROJECT.md M17: ACCEPTED semantic_role claims on a subject whose
    /// provenance is genuinely undetermined. Should read zero once the
    /// provenance gate (reevaluate_hypothesis) is in place -- a nonzero
    /// count here means something reached ACCEPTED without going through
    /// that gate, which is itself worth knowing.
    pub unknown_provenance_accepted: usize,
}

/// Counts ACCEPTED semantic_role hypotheses by provenance -- the split
/// PROJECT.md M15 asks for instead of one blended "accepted" number,
/// since only the application count says anything about how well Debura
/// understands the program it's actually reversing.
pub fn claim_breakdown(graph: &KnowledgeGraph) -> ClaimBreakdown {
    let mut breakdown = ClaimBreakdown::default();
    for h in graph.hypotheses() {
        if h.predicate != "semantic_role" || h.status != HypothesisStatus::Accepted {
            continue;
        }
        match classify_provenance(graph, &h.subject) {
            Provenance::Application => breakdown.application_accepted += 1,
            Provenance::LibraryOrRuntime => breakdown.library_or_runtime_accepted += 1,
            Provenance::Unknown => breakdown.unknown_provenance_accepted += 1,
        }
    }
    breakdown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_identifier_shapes_match_libstdcxx_conventions() {
        assert!(is_reserved_identifier("_Guard"));
        assert!(is_reserved_identifier("_Vector_impl"));
        assert!(is_reserved_identifier("__normal_iterator"));
        assert!(!is_reserved_identifier("Snake"));
        assert!(!is_reserved_identifier("Wall"));
        assert!(!is_reserved_identifier("main"));
        // A leading underscore alone isn't reserved -- only underscore
        // immediately followed by an uppercase letter is (or a `__`
        // anywhere); `_lowercase` doesn't match the C++ reservation rule.
        assert!(!is_reserved_identifier("_lowercase"));
    }

    /// A real run showed SDL's own C API (`SDL_Init`, `TTF_OpenFont`) is
    /// plain PascalCase, never matching `is_reserved_identifier` -- an
    /// `imports` observation is a stronger, name-shape-independent
    /// signal that catches it anyway.
    #[test]
    fn an_imported_symbol_is_library_regardless_of_name_shape() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "SDL_Init", 0.95, "ghidra:function", None);
        graph.add_observation("0x1", "imports", "SDL2.dll!SDL_Init", 1.0, "ghidra:imports", None);

        assert_eq!(classify_subject(&graph, "0x1"), ClaimClass::LibraryOrCompiler);
    }

    #[test]
    fn classifies_by_owner_class_first_then_own_name() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "is_method_of", "Wall", 0.95, "ghidra:function", None);
        graph.add_observation("0x2", "is_method_of", "_Vector_impl", 0.95, "ghidra:function", None);
        graph.add_observation("0x3", "has_name", "__copy_move_a", 0.95, "ghidra:function", None);
        graph.add_observation("0x4", "has_name", "main", 0.95, "ghidra:function", None);

        assert_eq!(classify_subject(&graph, "0x1"), ClaimClass::Application);
        assert_eq!(classify_subject(&graph, "0x2"), ClaimClass::LibraryOrCompiler);
        assert_eq!(classify_subject(&graph, "0x3"), ClaimClass::LibraryOrCompiler);
        assert_eq!(classify_subject(&graph, "0x4"), ClaimClass::Application);
    }

    /// The exact real-world case `library_callee_ratio` exists for: a
    /// function named and owned like application code, whose entire body
    /// is calls into std::string's own private implementation.
    #[test]
    fn library_dominated_callees_reclassify_an_application_looking_name() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "constructString", 0.95, "ghidra:function", None);
        for callee in ["_M_create", "_M_data", "_M_capacity", "_M_set_length"] {
            graph.add_observation("0x1", "calls", callee, 0.95, "ghidra:call_graph", None);
            graph.add_observation(callee, "has_name", callee, 0.95, "ghidra:function", None);
        }

        // Name/owner shape alone still sees this as application code.
        assert_eq!(classify_subject(&graph, "0x1"), ClaimClass::Application);
        // Callee composition (100% library) confirms it either way:
        // the simple single-hop ratio,
        assert_eq!(library_callee_ratio(&graph, "0x1"), 1.0);
        // and the full recursive provenance classifier.
        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::LibraryOrRuntime);
    }

    /// The dominance requirement: real application code calling *one*
    /// STL helper alongside genuinely application-facing calls must not
    /// be misclassified as glue.
    #[test]
    fn a_couple_of_library_calls_does_not_make_application_code_glue() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "buildScoreText", 0.95, "ghidra:function", None);
        graph.add_observation("0x1", "is_method_of", "Screen", 0.95, "ghidra:function", None);
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None); // drawText
        graph.add_observation("0x1", "calls", "0x3", 0.95, "ghidra:call_graph", None); // _M_append
        graph.add_observation("0x1", "calls", "0x4", 0.95, "ghidra:call_graph", None); // getScore
        graph.add_observation("0x1", "calls", "0x5", 0.95, "ghidra:call_graph", None); // formatValue
        graph.add_observation("0x2", "has_name", "drawText", 0.95, "ghidra:function", None);
        graph.add_observation("0x3", "has_name", "_M_append", 0.95, "ghidra:function", None);
        graph.add_observation("0x4", "has_name", "getScore", 0.95, "ghidra:function", None);
        graph.add_observation("0x5", "has_name", "formatValue", 0.95, "ghidra:function", None);

        assert_eq!(library_callee_ratio(&graph, "0x1"), 0.25);
        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::Application);
    }

    /// PROJECT.md M18: a real recovery run found MinGW CRT startup code
    /// (sitting directly on the call path from the real entrypoint)
    /// inheriting Application purely because it eventually calls `main`,
    /// which calls real game code several hops down -- while a genuine
    /// setup/orchestration function's *direct* call into an Application
    /// method is exactly the same kind of evidence, just one hop away
    /// instead of several. A flat "any reachable Application callee"
    /// rule can't distinguish these; this test reproduces both shapes at
    /// once, in the corpus form the M18 discussion asked for.
    #[test]
    fn a_direct_application_call_dominates_but_a_transitive_one_through_unknown_nodes_does_not() {
        let mut graph = KnowledgeGraph::new();

        // setupGame -> Snake::Snake: one hop, direct evidence.
        graph.add_observation("0xsetup", "has_name", "setupGame", 0.95, "ghidra:function", None);
        graph.add_observation("0xsetup", "calls", "0xctor", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0xctor", "has_name", "Snake", 0.95, "ghidra:function", None);
        graph.add_observation("0xctor", "is_constructor_of", "Snake", 0.95, "ghidra:function", None);

        // CRT startup -> runtime_helper -> ... -> main -> Snake::Snake:
        // the same real Application target, but several hops down through
        // nodes with no Application signal of their own.
        graph.add_observation("0xcrt", "has_name", "FUN_crt", 0.95, "ghidra:function", None);
        graph.add_observation("0xcrt", "calls", "0xhelper1", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0xhelper1", "has_name", "FUN_helper1", 0.95, "ghidra:function", None);
        graph.add_observation("0xhelper1", "calls", "0xhelper2", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0xhelper2", "has_name", "FUN_helper2", 0.95, "ghidra:function", None);
        graph.add_observation("0xhelper2", "calls", "0xmain", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0xmain", "has_name", "main", 0.95, "ghidra:function", None);
        graph.add_observation("0xmain", "calls", "0xctor", 0.95, "ghidra:call_graph", None);

        assert_eq!(classify_provenance(&graph, "0xsetup"), Provenance::Application);
        assert_eq!(classify_provenance(&graph, "0xcrt"), Provenance::Unknown);
    }

    #[test]
    fn claim_breakdown_only_counts_accepted_semantic_role() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "is_method_of", "Wall", 0.95, "ghidra:function", None);
        graph.add_observation("0x2", "is_method_of", "_Vector_impl", 0.95, "ghidra:function", None);

        let app_hyp = graph.propose_hypothesis("0x1", "semantic_role", "draw", 0.95, None);
        graph.mark_verified(app_hyp, chrono::Utc::now()).unwrap();
        graph.set_status(app_hyp, HypothesisStatus::Accepted).unwrap();

        let lib_hyp = graph.propose_hypothesis("0x2", "semantic_role", "reallocate", 0.95, None);
        graph.mark_verified(lib_hyp, chrono::Utc::now()).unwrap();
        graph.set_status(lib_hyp, HypothesisStatus::Accepted).unwrap();

        // Not ACCEPTED -- must not count toward either bucket.
        graph.propose_hypothesis("0x1", "semantic_role", "unrelated", 0.5, None);
        // Not semantic_role -- must not count toward either bucket.
        let behavior = graph.propose_hypothesis("0x1", "mechanical_behavior", "loops", 0.95, None);
        graph.mark_verified(behavior, chrono::Utc::now()).unwrap();
        graph.set_status(behavior, HypothesisStatus::Accepted).unwrap();

        let breakdown = claim_breakdown(&graph);
        assert_eq!(breakdown.application_accepted, 1);
        assert_eq!(breakdown.library_or_runtime_accepted, 1);
        assert_eq!(breakdown.unknown_provenance_accepted, 0);
    }

    /// The core bug the M17 audit found: a subject with genuinely no
    /// name-shape signal (only `has_name = FUN_<addr>`, no `is_method_of`,
    /// no callees at all -- a small leaf function) must come back
    /// `Unknown`, not silently `Application`.
    #[test]
    fn a_stripped_leaf_function_with_no_signal_is_unknown_not_application() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140005bd0", "has_name", "FUN_140005bd0", 0.95, "ghidra:function", None);
        graph.add_observation("0x140005bd0", "size_bytes", "29", 0.95, "ghidra:function", None);

        assert_eq!(classify_provenance(&graph, "0x140005bd0"), Provenance::Unknown);
    }

    /// Regression test for the exact real chain the M17 audit traced:
    /// MinGW's `_pei386_runtime_relocator` (stripped to `FUN_1400045a8`)
    /// calls four unnamed local helpers, one of which (`FUN_1400040ff`)
    /// calls straight into an imported symbol. None of these five
    /// subjects has a real name anywhere in the graph -- the only
    /// evidence available on a genuinely stripped binary -- yet the top
    /// of the chain must still resolve to LibraryOrRuntime via thunk/
    /// dominance propagation, not fall back to Application.
    #[test]
    fn a_stripped_runtime_relocator_chain_resolves_to_library_via_propagation() {
        let mut graph = KnowledgeGraph::new();
        for addr in ["0x1400045a8", "0x1400040ff", "0x14000421e", "0x140004e4b", "0x140005480"] {
            graph.add_observation(addr, "has_name", format!("FUN_{}", &addr[2..]), 0.95, "ghidra:function", None);
        }
        // The relocator calls four local helpers, none named, none a
        // pure thunk (each has more than one callee or is above the
        // thunk size bound) -- so this can only resolve through the
        // dominance path, not thunk resolution.
        graph.add_observation("0x1400045a8", "size_bytes", "164", 0.95, "ghidra:function", None);
        for callee in ["0x1400040ff", "0x14000421e", "0x140004e4b", "0x140005480"] {
            graph.add_observation("0x1400045a8", "calls", callee, 0.95, "ghidra:call_graph", None);
        }
        // Each helper is itself a real (non-thunk-sized) function that
        // happens to call straight into an imported CRT/runtime symbol --
        // the one piece of ground truth available even on a stripped
        // binary.
        for (helper, import_addr) in [
            ("0x1400040ff", "0x33"),
            ("0x14000421e", "0x34"),
            ("0x140004e4b", "0x35"),
            ("0x140005480", "0x36"),
        ] {
            graph.add_observation(helper, "size_bytes", "200", 0.95, "ghidra:function", None);
            graph.add_observation(helper, "calls", import_addr, 0.95, "ghidra:call_graph", None);
            graph.add_observation(import_addr, "imports", format!("KERNEL32.DLL!Thing{import_addr}"), 1.0, "ghidra:imports", None);
        }

        assert_eq!(
            classify_provenance(&graph, "0x1400045a8"),
            Provenance::LibraryOrRuntime
        );
    }

    /// PROJECT.md M18: the real case this signal was built for. Real body
    /// (Screen::init, address stripped to `FUN_1400019ae`): writes to 5
    /// distinct fields of its own receiver, but its callees are almost
    /// entirely SDL/TTF imports -- dominance alone would call it library.
    #[test]
    fn a_lifecycle_method_dominated_by_library_calls_is_still_application() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        graph.add_observation(
            "0x1",
            "decompiles_to",
            "undefined8 FUN_1(longlong *param_1)\n\n{\n  \
             iVar1 = SDL_Init(0x20);\n  \
             TTF_Init();\n  \
             lVar3 = TTF_OpenFont(\"Roboto-Regular.ttf\",0x14);\n  \
             param_1[5] = lVar3;\n  \
             lVar3 = SDL_CreateWindow(\"Snake Game\",0x1fff0000,0x1fff0000,800,600,4);\n  \
             *param_1 = lVar3;\n  \
             lVar3 = SDL_CreateRenderer(*param_1,0xffffffff,4);\n  \
             param_1[1] = lVar3;\n  \
             lVar3 = SDL_CreateTexture(param_1[1],0x16462004,0,800,600);\n  \
             param_1[2] = lVar3;\n  \
             pvVar4 = operator_new__(0x1d4c00);\n  \
             param_1[6] = (longlong)pvVar4;\n  \
             return 1;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        for callee in ["0x10", "0x11", "0x12", "0x13", "0x14"] {
            graph.add_observation("0x1", "calls", callee, 0.95, "ghidra:call_graph", None);
            graph.add_observation(callee, "imports", format!("SDL2.DLL!Thing{callee}"), 1.0, "ghidra:imports", None);
        }

        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::Application);
    }

    /// The real shape this signal actually has to handle: Ghidra's own
    /// `SDL_RenderClear`-style wrapper is a genuine 1-hop *thunk* (a
    /// tiny, single-callee forwarding stub), not a direct call to the
    /// import itself -- confirmed against the real recovered binary.
    #[test]
    fn own_state_plus_a_thunked_import_call_is_application() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        graph.add_observation(
            "0x1",
            "decompiles_to",
            "void FUN_1(longlong *param_1)\n\n{\n  param_1[0] = SDL_RenderClear();\n  param_1[1] = 2;\n  return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        graph.add_observation("0x1", "calls", "0xthunk", 0.95, "ghidra:call_graph", None);
        // The thunk itself: one callee, tiny body, straight to the import.
        graph.add_observation("0xthunk", "size_bytes", "6", 0.95, "ghidra:function", None);
        graph.add_observation("0xthunk", "calls", "0xreal_import", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0xreal_import", "imports", "SDL2.DLL!SDL_RenderClear", 1.0, "ghidra:imports", None);

        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::Application);
    }

    /// The real false positive this refinement was built to close: a
    /// compiled `std::vector::push_back` growth path (real, observed
    /// shape) also touches 2 distinct fields of its own receiver
    /// (begin/end iterators) -- but its callees are genuine, multi-
    /// statement STL functions, never thunk-shaped, so this must NOT
    /// resolve to Application just because *some* chain eventually
    /// reaches an allocator.
    #[test]
    fn own_state_access_alone_does_not_rescue_a_generic_container_internal() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        graph.add_observation(
            "0x1",
            "decompiles_to",
            "void FUN_1(void **param_1,undefined8 param_2)\n\n{\n  \
             if (param_1[1] == param_1[2]) {\n    FUN_2(param_1,param_2);\n  }\n  \
             else {\n    param_1[1] = (void *)((longlong)param_1[1] + 8);\n  }\n  \
             return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
        // Not thunk-shaped: real logic, more than one callee, well above
        // the thunk size bound -- and its own callees eventually reach an
        // allocator, several real hops away, which must not count.
        graph.add_observation("0x2", "size_bytes", "120", 0.95, "ghidra:function", None);
        graph.add_observation("0x2", "calls", "0x3", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "calls", "0x4", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x3", "size_bytes", "50", 0.95, "ghidra:function", None);
        graph.add_observation("0x3", "calls", "0x5", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x5", "imports", "MSVCRT.DLL!operator_new", 1.0, "ghidra:imports", None);

        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::Unknown);
    }

    /// A pointer-typed first parameter's own declaration (`int *param_1`)
    /// contains the same `*param_1` substring the bare-dereference case
    /// matches inside a real body -- an early version of this signal
    /// scanned the *whole* decompilation text, including the header, so
    /// every pointer-typed subject's own signature silently counted as
    /// one extra slot access it never actually made. With a single real
    /// body access plus that spurious header match, the own-state check
    /// would have crossed the 2-slot bar and returned Application; scoped
    /// to the body only, it correctly doesn't fire at all, leaving the
    /// subject's provenance to fall through to the ordinary dominance
    /// check below (a single callee that's 100% library -- correctly
    /// LibraryOrRuntime, and unrelated to what this test is actually
    /// checking).
    #[test]
    fn the_parameter_declarations_own_pointer_syntax_is_not_counted_as_a_body_access() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        graph.add_observation(
            "0x1",
            "decompiles_to",
            "void FUN_1(int *param_1)\n\n{\n  param_1[0] = 5;\n  return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        graph.add_observation("0x1", "calls", "0xthunk", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0xthunk", "size_bytes", "6", 0.95, "ghidra:function", None);
        graph.add_observation("0xthunk", "calls", "0xreal_import", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0xreal_import", "imports", "SDL2.DLL!Thing", 1.0, "ghidra:imports", None);

        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::LibraryOrRuntime);
    }

    /// The other real half of the same case (Screen::clear, stripped to
    /// `FUN_1400018ca`): touches exactly one field of its own receiver,
    /// passing it straight to a single library call -- below the "owns
    /// state" bar, so this signal correctly declines to fire, leaving the
    /// existing dominance check's own (unrelated, already-correct)
    /// verdict alone: a single call straight into an imported symbol is
    /// exactly what dominance already calls library.
    #[test]
    fn a_single_field_forwarding_call_does_not_meet_the_own_state_bar() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        graph.add_observation(
            "0x1",
            "decompiles_to",
            "void FUN_1(longlong param_1)\n\n{\n  memset(*(void **)(param_1 + 0x30),0,0x1d4c00);\n  return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "imports", "MSVCRT.DLL!memset", 1.0, "ghidra:imports", None);

        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::LibraryOrRuntime);
    }

    #[test]
    fn first_param_name_reads_the_decompiled_headers_own_first_parameter() {
        assert_eq!(
            first_param_name("void FUN_1(longlong *param_1, int param_2)\n\n{\n  return;\n}"),
            Some("param_1".to_string())
        );
        assert_eq!(first_param_name("void FUN_1(void)\n\n{\n  return;\n}"), None);
    }

    #[test]
    fn distinct_param_slots_accessed_counts_each_shape_once() {
        let body = "param_1[5] = x; *param_1 = y; *(int *)(param_1 + 0xc) = z; param_1[5] = w;";
        // slot 5 (bracket, seen twice -> once), slot "*" (bare deref),
        // slot +0xc (pointer arithmetic) -- 3 distinct, not 4.
        assert_eq!(distinct_param_slots_accessed(body, "param_1"), 3);
    }

    #[test]
    fn distinct_param_slots_accessed_ignores_a_bare_cast_pass_through() {
        // Passing the whole receiver to another call, no field access at
        // all -- must not be mistaken for a slot access.
        let body = "FUN_2((longlong)param_1);";
        assert_eq!(distinct_param_slots_accessed(body, "param_1"), 0);
    }

    /// A pure single-callee, small-bodied function is treated as a thunk
    /// and inherits its target's provenance directly, regardless of its
    /// own name shape.
    #[test]
    fn a_small_single_callee_function_inherits_its_targets_provenance() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        graph.add_observation("0x1", "size_bytes", "12", 0.95, "ghidra:function", None);
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "imports", "MSVCRT.DLL!malloc", 1.0, "ghidra:imports", None);

        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::LibraryOrRuntime);
    }

    /// A large function with a single callee is NOT treated as a thunk --
    /// it's doing real work of its own beyond delegation, so its target's
    /// classification shouldn't simply override it.
    #[test]
    fn a_large_single_callee_function_is_not_treated_as_a_thunk() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "is_method_of", "Wall", 0.95, "ghidra:function", None);
        graph.add_observation("0x1", "size_bytes", "500", 0.95, "ghidra:function", None);
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "imports", "MSVCRT.DLL!malloc", 1.0, "ghidra:imports", None);

        // is_method_of a real application class wins outright here --
        // this subject was never in doubt regardless of the thunk check.
        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::Application);
    }
}
