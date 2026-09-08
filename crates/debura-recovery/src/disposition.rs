use std::collections::BTreeSet;

use debura_knowledge::{classify_provenance, is_degenerate_decompilation, latest_decompilation, KnowledgeGraph, Provenance};

use crate::extract::extract;
use crate::frontier::{reachable_from, UnresolvedSymbol};

/// PROJECT.md M18: `Provenance` (debura-knowledge) answers "is this
/// application-owned code" -- a claim about semantic ownership that M17's
/// whole discipline exists to keep honest, never inflated just because
/// the linker wants an answer (this session's own dominance-rule
/// regressions came from exactly that conflation). `RecoveryDisposition`
/// answers a different question entirely: "does this executable need this
/// function reconstructed to link and run" -- and `Provenance::Unknown`
/// is a completely legitimate answer to the first question for something
/// that's `RequiredUnknown` under the second. Recovering a function under
/// `FUN_<addr>` never requires knowing what it means; it only requires
/// knowing the program needs it and its body can be reconstructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDisposition {
    /// Reachable from the real entrypoint, `Provenance::Application`, and
    /// has a real (non-degenerate) decompiled body -- M18's original
    /// recovery frontier, unchanged by this axis existing.
    RequiredApplication,
    /// Reachable, `Provenance::Unknown`, but has a real recoverable body
    /// -- genuinely needed to link, reconstructable, just not something
    /// M17 has (or ever will have) grounds to claim application ownership
    /// of. Recover it under its raw `FUN_<addr>` name; don't hold source
    /// completeness hostage to a semantic question M17 may never answer.
    RequiredUnknown,
    /// Reachable, `Provenance::LibraryOrRuntime`, but with a real
    /// (non-degenerate) decompiled body of its own -- statically-linked
    /// runtime/CRT support code (an SDL event-poll loop, a VirtualProtect
    /// table walk, an argv-duplication helper, `operator new[]`'s
    /// overflow-length check) that just isn't application-owned. A real
    /// linker frontier found 9 of 10 remaining library/runtime-provenance
    /// unresolved symbols were exactly this shape, not bare thunks --
    /// checked directly against each one's own decompiled text, not
    /// assumed. `LibraryOrRuntime` governs semantic ownership (never
    /// treat this as game logic, never give it a semantic name); it does
    /// not mean "never emit source" -- that's `has_recoverable_body`'s
    /// question, the same body-recovery machinery `RequiredUnknown`
    /// already uses, extended here to a provenance this project's own
    /// M17 gate correctly keeps from ever claiming Application meaning
    /// for. Recovered under its raw `FUN_<addr>` name unconditionally
    /// (no semantic_role can ever attach to non-Application provenance in
    /// the first place, so there's nothing to fall back from).
    RequiredRuntimeBody,
    /// Reachable, `Provenance::LibraryOrRuntime`, with no recoverable
    /// body of its own, and resolves (directly or through a thunk chain)
    /// to a real binary import -- needs a real external library mapping
    /// or thunk canonicalization, not AI-recovered application code (and
    /// nothing to recover a body from even if it were wanted).
    ExternalLibrary,
    /// Reachable, `Provenance::LibraryOrRuntime`, with no recoverable
    /// body and no import anywhere in its thunk chain -- needs a real
    /// runtime-support implementation or a compat shim, not recovery.
    CompilerRuntime,
    /// Not reachable from the real entrypoint at all -- dead code from
    /// this program's own perspective, or a path this specific build
    /// never exercises. Recovery necessity doesn't even apply.
    Unreachable,
    /// Reachable, but either `Provenance::Unknown` with no usable
    /// decompiled body to reconstruct from, or otherwise not yet
    /// decidable. Nothing to recover from yet -- revisit once more
    /// evidence exists, never guessed at.
    Deferred,
}

/// One unresolved function's full diagnosis -- PROJECT.md M18's own
/// requested report shape: enough for a human to look at the whole
/// recovery frontier at once and decide where to spend effort, not just a
/// bucket name.
#[derive(Debug, Clone)]
pub struct DispositionEntry {
    pub address: String,
    pub literal_name: String,
    pub provenance: Provenance,
    pub reachable: bool,
    pub body_size: Option<u64>,
    pub has_recoverable_body: bool,
    /// This address's own single callee, if it has exactly one -- purely
    /// descriptive (not the same gated, size-bounded notion
    /// `classify_provenance`'s own thunk resolution uses internally).
    pub sole_callee: Option<String>,
    pub direct_callers: Vec<String>,
    /// The subset of `direct_callers` that `extract()` actually emits
    /// into the recovered program -- i.e., already part of the recovered
    /// execution closure, not just structurally reachable.
    pub direct_recovered_callers: Vec<String>,
    pub direct_unrecovered_callers: Vec<String>,
    pub disposition: RecoveryDisposition,
}

/// Every address `extract()` actually emits (as a class method or a
/// standalone function) -- what "part of the recovered execution closure"
/// concretely means right now, kept in sync with `extract()`'s own
/// inclusion rules by calling it directly rather than re-deriving a
/// second copy of that logic here.
fn recovered_program_addresses(graph: &KnowledgeGraph) -> BTreeSet<String> {
    let program = extract(graph);
    let mut addresses: BTreeSet<String> = BTreeSet::new();
    for class in &program.classes {
        for m in &class.methods {
            addresses.insert(m.address.clone());
        }
    }
    for f in &program.functions {
        addresses.insert(f.address.clone());
    }
    addresses
}

/// Whether `address` resolves, directly or through a chain of pure
/// single-callee delegation, to a real binary import -- the signal that
/// separates `ExternalLibrary` (needs a real library mapping) from
/// `CompilerRuntime` (statically-linked, needs a runtime-support
/// implementation instead). Deliberately not gated by
/// `classify_provenance`'s own `THUNK_MAX_SIZE_BYTES` (a different,
/// size-bounded notion of "thunk" used for provenance inheritance) --
/// this only asks the narrower, purely structural question "is there an
/// import anywhere on this address's single-callee chain", not "should
/// this address inherit that thing's full provenance".
fn resolves_to_a_real_import(graph: &KnowledgeGraph, address: &str, depth: u32) -> bool {
    if graph.observations().any(|o| o.subject == address && o.predicate == "imports") {
        return true;
    }
    if depth == 0 {
        return false;
    }
    match sole_callee(graph, address) {
        Some(only) => resolves_to_a_real_import(graph, &only, depth - 1),
        None => false,
    }
}

const IMPORT_CHAIN_DEPTH: u32 = 5;

fn sole_callee(graph: &KnowledgeGraph, address: &str) -> Option<String> {
    let callees: BTreeSet<String> = graph
        .observations()
        .filter(|o| o.subject == address && o.predicate == "calls")
        .map(|o| o.value.clone())
        .collect();
    match callees.len() {
        1 => callees.into_iter().next(),
        _ => None,
    }
}

/// Classifies every unresolved *function* reference (data symbols are a
/// separate kind of gap -- see `UnresolvedSymbol::Data` -- and aren't
/// diagnosed here) by recovery necessity, independently of whether M17
/// has (or will ever have) grounds to call it Application.
pub fn classify_recovery_disposition(
    graph: &KnowledgeGraph,
    unresolved: &[UnresolvedSymbol],
    entry: &str,
) -> Vec<DispositionEntry> {
    let reachable = reachable_from(graph, entry);
    let recovered = recovered_program_addresses(graph);

    unresolved
        .iter()
        .filter_map(|u| match u {
            UnresolvedSymbol::Function { address, literal_name } => {
                Some(diagnose_one(graph, address, literal_name, &reachable, &recovered))
            }
            UnresolvedSymbol::Data { .. } => None,
        })
        .collect()
}

fn diagnose_one(
    graph: &KnowledgeGraph,
    address: &str,
    literal_name: &str,
    reachable: &BTreeSet<String>,
    recovered: &BTreeSet<String>,
) -> DispositionEntry {
    let is_reachable = reachable.contains(address);
    let provenance = classify_provenance(graph, address);
    let body_size = graph
        .observations()
        .find(|o| o.subject == address && o.predicate == "size_bytes")
        .and_then(|o| o.value.parse().ok());
    let has_recoverable_body = latest_decompilation(graph, address)
        .is_some_and(|d| !is_degenerate_decompilation(&d.value));

    let mut direct_callers: Vec<String> = graph
        .observations()
        .filter(|o| o.predicate == "calls" && o.value == address)
        .map(|o| o.subject.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    direct_callers.sort();
    let (direct_recovered_callers, direct_unrecovered_callers): (Vec<String>, Vec<String>) =
        direct_callers.iter().cloned().partition(|c| recovered.contains(c));

    let disposition = if !is_reachable {
        RecoveryDisposition::Unreachable
    } else {
        match provenance {
            Provenance::Application => RecoveryDisposition::RequiredApplication,
            Provenance::Unknown if has_recoverable_body => RecoveryDisposition::RequiredUnknown,
            Provenance::Unknown => RecoveryDisposition::Deferred,
            Provenance::LibraryOrRuntime if has_recoverable_body => RecoveryDisposition::RequiredRuntimeBody,
            Provenance::LibraryOrRuntime => {
                if resolves_to_a_real_import(graph, address, IMPORT_CHAIN_DEPTH) {
                    RecoveryDisposition::ExternalLibrary
                } else {
                    RecoveryDisposition::CompilerRuntime
                }
            }
        }
    };

    DispositionEntry {
        address: address.to_string(),
        literal_name: literal_name.to_string(),
        provenance,
        reachable: is_reachable,
        body_size,
        has_recoverable_body,
        sole_callee: sole_callee(graph, address),
        direct_callers,
        direct_recovered_callers,
        direct_unrecovered_callers,
        disposition,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unresolved(address: &str) -> Vec<UnresolvedSymbol> {
        vec![UnresolvedSymbol::Function {
            address: address.to_string(),
            literal_name: format!("FUN_{}", address.trim_start_matches("0x")),
        }]
    }

    #[test]
    fn application_provenance_with_a_real_body_is_required_application() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x1", "is_method_of", "Wall", 0.95, "ghidra:function", None);
        graph.add_observation("0x1", "decompiles_to", "void FUN_1(void)\n\n{\n  return;\n}", 0.95, "ghidra:decompiler", None);

        let entries = classify_recovery_disposition(&graph, &unresolved("0x1"), "0xentry");

        assert_eq!(entries[0].disposition, RecoveryDisposition::RequiredApplication);
        assert!(entries[0].has_recoverable_body);
    }

    /// PROJECT.md M18's own motivating example: a subject with no
    /// provenance signal at all, but a real body and a real reason to
    /// exist (the linker needs it) -- recoverable under FUN_<addr> without
    /// claiming to know what it means.
    #[test]
    fn unknown_provenance_with_a_real_body_is_required_unknown() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        graph.add_observation("0x1", "decompiles_to", "void FUN_1(longlong param_1)\n\n{\n  *(int *)(param_1 + 4) = 0;\n  return;\n}", 0.95, "ghidra:decompiler", None);

        let entries = classify_recovery_disposition(&graph, &unresolved("0x1"), "0xentry");

        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::Unknown);
        assert_eq!(entries[0].disposition, RecoveryDisposition::RequiredUnknown);
    }

    #[test]
    fn unknown_provenance_with_no_usable_body_is_deferred_not_required() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        graph.add_observation("0x1", "decompiles_to", "void FUN_1(void) { ... }", 0.95, "ghidra:decompiler", None);

        let entries = classify_recovery_disposition(&graph, &unresolved("0x1"), "0xentry");

        assert_eq!(entries[0].disposition, RecoveryDisposition::Deferred);
        assert!(!entries[0].has_recoverable_body);
    }

    /// PROJECT.md M18: a real linker frontier found 9 of 10 remaining
    /// library/runtime unresolved symbols were substantive, real
    /// decompiled bodies (an SDL event-poll loop, a VirtualProtect table
    /// walk, ...), not bare thunks -- `LibraryOrRuntime` provenance
    /// controls semantic ownership, not whether a body can be emitted.
    #[test]
    fn library_provenance_with_a_real_body_is_required_runtime_body_not_external_or_compiler() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "imports", "SDL2.DLL!SDL_PollEvent", 1.0, "ghidra:imports", None);
        graph.add_observation("0x1", "size_bytes", "190", 0.95, "ghidra:function", None);
        graph.add_observation(
            "0x1",
            "decompiles_to",
            "undefined4 FUN_1(void)\n\n{\n  int local_48 [5];\n  while (SDL_PollEvent(local_48) != 0) {}\n  return 0;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );

        let entries = classify_recovery_disposition(&graph, &unresolved("0x1"), "0xentry");

        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::LibraryOrRuntime);
        assert!(entries[0].has_recoverable_body);
        assert_eq!(entries[0].disposition, RecoveryDisposition::RequiredRuntimeBody);
    }

    #[test]
    fn library_provenance_resolving_to_a_real_import_is_external_library() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "imports", "SDL2.DLL!SDL_Init", 1.0, "ghidra:imports", None);
        graph.add_observation("0x1", "size_bytes", "6", 0.95, "ghidra:function", None);

        let entries = classify_recovery_disposition(&graph, &unresolved("0x1"), "0xentry");

        assert_eq!(entries[0].disposition, RecoveryDisposition::ExternalLibrary);
    }

    #[test]
    fn library_provenance_with_no_import_anywhere_is_compiler_runtime() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x1", "has_name", "__cxa_atexit", 0.95, "ghidra:function", None);

        let entries = classify_recovery_disposition(&graph, &unresolved("0x1"), "0xentry");

        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::LibraryOrRuntime);
        assert_eq!(entries[0].disposition, RecoveryDisposition::CompilerRuntime);
    }

    #[test]
    fn unreachable_address_is_unreachable_regardless_of_provenance() {
        let mut graph = KnowledgeGraph::new();
        // Never wired up to 0xentry at all.
        graph.add_observation("0x1", "is_method_of", "Wall", 0.95, "ghidra:function", None);

        let entries = classify_recovery_disposition(&graph, &unresolved("0x1"), "0xentry");

        assert_eq!(entries[0].disposition, RecoveryDisposition::Unreachable);
        assert!(!entries[0].reachable);
    }

    #[test]
    fn direct_callers_are_split_by_whether_extract_actually_recovers_them() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
        // A recovered caller: a real class method.
        graph.add_observation("0x2", "calls", "0x1", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "has_name", "FUN_2", 0.95, "ghidra:function", None);
        graph.add_observation("0x2", "is_method_of", "Wall", 0.95, "ghidra:function", None);
        graph.add_observation("0x2", "decompiles_to", "void FUN_2(longlong param_1)\n\n{\n  FUN_1();\n  return;\n}", 0.95, "ghidra:decompiler", None);
        // An unrecovered caller: has_vtable_at requires a real name for
        // Wall already; this one has no anchor at all, so extract()
        // never emits it.
        graph.add_observation("0x3", "calls", "0x1", 0.95, "ghidra:call_graph", None);

        let entries = classify_recovery_disposition(&graph, &unresolved("0x1"), "0xentry");

        // "0xentry" is also a direct caller here (the fixture's own
        // reachability wiring at the top) -- included like any other
        // caller, and correctly unrecovered (the entrypoint itself is
        // never something `extract()` emits).
        assert_eq!(
            entries[0].direct_callers,
            vec!["0x2".to_string(), "0x3".to_string(), "0xentry".to_string()]
        );
        assert_eq!(entries[0].direct_recovered_callers, vec!["0x2".to_string()]);
        assert_eq!(
            entries[0].direct_unrecovered_callers,
            vec!["0x3".to_string(), "0xentry".to_string()]
        );
    }
}
