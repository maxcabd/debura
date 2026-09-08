use std::collections::BTreeSet;

use debura_knowledge::{classify_provenance, KnowledgeGraph, Provenance};

/// PROJECT.md M18: turning a real linker failure into a deterministic
/// recovery frontier, instead of treating "does it link" as a single
/// pass/fail question. Every unresolved `FUN_<addr>` a real link produces
/// already names the exact binary address that needs a decision; this
/// module makes that decision structurally (reachability + provenance),
/// so recovery effort goes toward the transitive application-dependency
/// closure the program actually needs to run, not toward all ~280
/// functions Ghidra happened to find in the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnresolvedSymbol {
    /// A `FUN_<addr>`/`thunk_FUN_<addr>` call target -- something
    /// Debura's own M15 symbol resolution left unresolved, naming a real
    /// binary address.
    Function { address: String, literal_name: String },
    /// A `DAT_*`/`PTR_*`/`_refptr_*` data symbol -- a different kind of
    /// gap (unknown *value*, not a missing recovered function) that this
    /// module doesn't attempt to resolve; still recorded so a frontier
    /// report accounts for every unresolved reference, not just function
    /// ones.
    Data { literal_name: String },
}

/// Parses GNU ld's `undefined reference to `NAME'` lines out of real
/// linker stderr. Deduplicates by name (the same symbol is typically
/// reported once per referencing object file, or per subsequent
/// reference, or both). `NAME` may carry a trailing `(...)` -- the
/// literal argument list `symbols.rs`'s permissive fallback declarations
/// use for every genuinely unresolved call -- which is stripped so the
/// remaining name matches exactly what the rest of Debura's own naming
/// (`FUN_<addr>`, `DAT_<addr>`, ...) already uses elsewhere.
pub fn parse_undefined_symbols(linker_output: &str) -> Vec<UnresolvedSymbol> {
    const NEEDLE: &str = "undefined reference to `";
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for line in linker_output.lines() {
        let Some(start) = line.find(NEEDLE) else {
            continue;
        };
        let rest = &line[start + NEEDLE.len()..];
        let Some(end) = rest.find('\'') else {
            continue;
        };
        let raw = &rest[..end];
        let name = raw.strip_suffix("(...)").unwrap_or(raw);
        if !seen.insert(name.to_string()) {
            continue;
        }

        let addr_suffix = name.strip_prefix("FUN_").or_else(|| name.strip_prefix("thunk_FUN_"));
        match addr_suffix {
            Some(hex) if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) => {
                out.push(UnresolvedSymbol::Function {
                    address: format!("0x{}", hex.to_lowercase()),
                    literal_name: name.to_string(),
                });
            }
            _ => out.push(UnresolvedSymbol::Data { literal_name: name.to_string() }),
        }
    }

    out
}

/// Every address transitively reachable from `entry` by following `calls`
/// edges -- the program's real, exercised dependency graph, as opposed to
/// every function Ghidra happened to find in the binary. `entry` is
/// Ghidra's own `exports` fact named literally `"entry"` (the PE's real
/// `AddressOfEntryPoint`, captured by `ExtractFacts.py` regardless of
/// whether the binary exports anything else), not `main`/`WinMain`/
/// `SDL_main` -- those are just wherever CRT startup, itself reachable
/// this way, happens to call next.
pub fn reachable_from(graph: &KnowledgeGraph, entry: &str) -> BTreeSet<String> {
    let mut visited = BTreeSet::new();
    let mut frontier = vec![entry.to_string()];
    visited.insert(entry.to_string());

    while let Some(addr) = frontier.pop() {
        let callees: Vec<String> = graph
            .observations()
            .filter(|o| o.subject == addr && o.predicate == "calls")
            .map(|o| o.value.clone())
            .collect();
        for callee in callees {
            if visited.insert(callee.clone()) {
                frontier.push(callee);
            }
        }
    }

    visited
}

/// The decision an unresolved function address resolves to, once
/// reachability and provenance are both known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontierBucket {
    /// Reachable from the entrypoint and genuinely Application-provenance
    /// -- the real recovery frontier: recovering these (getting an
    /// ACCEPTED semantic_role so `extract()` includes them) is what
    /// actually moves the program toward linking.
    NeedsRecovery,
    /// Reachable, but confirmed library/runtime code -- recovering a
    /// *name* for these doesn't help; they need mapping to a real
    /// library/compat implementation instead, a different kind of work
    /// entirely.
    LibraryOrRuntime,
    /// Either not reachable from the entrypoint at all (dead code from
    /// this program's own perspective, or a path this binary's build
    /// never actually exercises), or reachable with no structural
    /// provenance signal yet (`Provenance::Unknown`) -- not confirmed
    /// Application, so not worth spending recovery effort on until it
    /// is. Both cases get the same verdict here for the same reason:
    /// neither is a *confirmed* application dependency yet.
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontierEntry {
    pub address: String,
    pub literal_name: String,
    pub reachable: bool,
    pub bucket: FrontierBucket,
}

/// Classifies every unresolved *function* reference (data symbols are a
/// separate kind of gap, see `UnresolvedSymbol::Data`, and aren't
/// classified here) into `FrontierBucket`s -- the concrete next-action
/// list PROJECT.md M18 asks for, instead of treating "58 unresolved
/// references" as one undifferentiated number.
pub fn classify_frontier(graph: &KnowledgeGraph, unresolved: &[UnresolvedSymbol], entry: &str) -> Vec<FrontierEntry> {
    let reachable = reachable_from(graph, entry);

    unresolved
        .iter()
        .filter_map(|u| match u {
            UnresolvedSymbol::Function { address, literal_name } => {
                let is_reachable = reachable.contains(address);
                let bucket = if !is_reachable {
                    FrontierBucket::Deferred
                } else {
                    match classify_provenance(graph, address) {
                        Provenance::Application => FrontierBucket::NeedsRecovery,
                        Provenance::LibraryOrRuntime => FrontierBucket::LibraryOrRuntime,
                        Provenance::Unknown => FrontierBucket::Deferred,
                    }
                };
                Some(FrontierEntry {
                    address: address.clone(),
                    literal_name: literal_name.clone(),
                    reachable: is_reachable,
                    bucket,
                })
            }
            UnresolvedSymbol::Data { .. } => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_function_and_data_symbols_and_dedupes() {
        let output = "\
ld.exe: a.o: undefined reference to `FUN_1400018ca(...)'
ld.exe: b.o: undefined reference to `FUN_1400018ca(...)'
ld.exe: a.o: undefined reference to `DAT_140009070'
ld.exe: a.o: undefined reference to `thunk_FUN_140002f10(...)'
";
        let symbols = parse_undefined_symbols(output);
        assert_eq!(
            symbols,
            vec![
                UnresolvedSymbol::Function {
                    address: "0x1400018ca".to_string(),
                    literal_name: "FUN_1400018ca".to_string(),
                },
                UnresolvedSymbol::Data { literal_name: "DAT_140009070".to_string() },
                UnresolvedSymbol::Function {
                    address: "0x140002f10".to_string(),
                    literal_name: "thunk_FUN_140002f10".to_string(),
                },
            ]
        );
    }

    #[test]
    fn a_refptr_symbol_is_classified_as_data_not_a_malformed_function() {
        let output = "undefined reference to `_refptr__ZN9SnakeGame6Screen7S_WIDTHE'\n";
        let symbols = parse_undefined_symbols(output);
        assert_eq!(symbols, vec![UnresolvedSymbol::Data { literal_name: "_refptr__ZN9SnakeGame6Screen7S_WIDTHE".to_string() }]);
    }

    #[test]
    fn reachability_follows_calls_transitively_from_the_entry_point() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xentry", "calls", "0xmain", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0xmain", "calls", "0xdraw", 0.95, "ghidra:call_graph", None);
        // Never reachable from entry -- a real function elsewhere in the
        // binary that this program's own call graph never exercises.
        graph.add_observation("0xdead", "calls", "0xother", 0.95, "ghidra:call_graph", None);

        let reachable = reachable_from(&graph, "0xentry");
        assert!(reachable.contains("0xentry"));
        assert!(reachable.contains("0xmain"));
        assert!(reachable.contains("0xdraw"));
        assert!(!reachable.contains("0xdead"));
        assert!(!reachable.contains("0xother"));
    }

    #[test]
    fn reachability_does_not_loop_forever_on_a_cycle() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xa", "calls", "0xb", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0xb", "calls", "0xa", 0.95, "ghidra:call_graph", None);

        let reachable = reachable_from(&graph, "0xa");
        assert_eq!(reachable.len(), 2);
    }

    #[test]
    fn an_application_function_reachable_from_entry_needs_recovery() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x1", "is_method_of", "Food", 0.95, "ghidra:function", None);

        let unresolved = vec![UnresolvedSymbol::Function {
            address: "0x1".to_string(),
            literal_name: "FUN_1".to_string(),
        }];
        let entries = classify_frontier(&graph, &unresolved, "0xentry");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].bucket, FrontierBucket::NeedsRecovery);
        assert!(entries[0].reachable);
    }

    #[test]
    fn a_library_function_reachable_from_entry_is_not_a_recovery_target() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x1", "imports", "SDL2.DLL!SDL_Init", 1.0, "ghidra:imports", None);

        let unresolved = vec![UnresolvedSymbol::Function {
            address: "0x1".to_string(),
            literal_name: "FUN_1".to_string(),
        }];
        let entries = classify_frontier(&graph, &unresolved, "0xentry");

        assert_eq!(entries[0].bucket, FrontierBucket::LibraryOrRuntime);
    }

    #[test]
    fn an_unreachable_function_is_deferred_regardless_of_provenance() {
        let mut graph = KnowledgeGraph::new();
        // Never wired up to 0xentry at all.
        graph.add_observation("0x1", "is_method_of", "Food", 0.95, "ghidra:function", None);

        let unresolved = vec![UnresolvedSymbol::Function {
            address: "0x1".to_string(),
            literal_name: "FUN_1".to_string(),
        }];
        let entries = classify_frontier(&graph, &unresolved, "0xentry");

        assert_eq!(entries[0].bucket, FrontierBucket::Deferred);
        assert!(!entries[0].reachable);
    }

    #[test]
    fn a_reachable_function_with_no_provenance_signal_is_deferred_not_recovered() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
        // No is_method_of, no imports, no callees -- genuinely unknown.

        let unresolved = vec![UnresolvedSymbol::Function {
            address: "0x1".to_string(),
            literal_name: "FUN_1".to_string(),
        }];
        let entries = classify_frontier(&graph, &unresolved, "0xentry");

        assert_eq!(entries[0].bucket, FrontierBucket::Deferred);
        assert!(entries[0].reachable);
    }

    #[test]
    fn data_symbols_are_excluded_from_classification() {
        let graph = KnowledgeGraph::new();
        let unresolved = vec![UnresolvedSymbol::Data { literal_name: "DAT_1".to_string() }];
        assert!(classify_frontier(&graph, &unresolved, "0xentry").is_empty());
    }
}
