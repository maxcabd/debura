//! Deterministic binary observation extraction (PROJECT.md S21).
//!
//! Bridges M1's raw Ghidra facts (`debura_ghidra::AnalysisResult`) into
//! M2's epistemic model (`debura_knowledge::Observation`). Nothing here
//! interprets meaning -- it only restates Ghidra's own findings as
//! subject/predicate/value facts the knowledge graph can index and, later,
//! reason over.
//!
//! Confidence is split by how the fact was obtained (PROJECT.md S5):
//! imports/exports are read directly from the file's own header tables, so
//! they get 1.0; everything else passes through Ghidra's analysis
//! heuristics (function boundaries, disassembly, decompilation, string
//! detection) and so is marked 0.95 -- deterministic and unaffected by any
//! model, but not literally infallible the way a header field is.
//!
//! Raw xrefs from the analysis artifact aren't turned into observations
//! yet: with no consumer for them, doing so now would just be speculative
//! volume.
//!
//! M7 adds vtables, inheritance, constructors/destructors and candidate
//! fields. Two independent paths feed this: Ghidra's own Itanium C++ ABI
//! symbols (`vtable for X`, `typeinfo for X`, demangled method names)
//! where they're present, and -- for a genuinely stripped binary, where
//! there are no such symbols to read -- `ExtractFacts.py`'s own
//! structural discovery, which finds the same vtable/RTTI data by
//! cross-referencing constructors' own `this->vptr` stores and reading
//! the Itanium ABI's typeinfo name strings directly, no symbol involved.
//! Confirmed against a real stripped build: recovers every real class
//! with its correct name, including one whose vtable's virtual-method
//! slots are themselves genuinely null. It's still narrower than the
//! symbol-based path -- it doesn't distinguish constructors from
//! destructors, or find inheritance edges or non-virtual methods -- so a
//! stripped binary's `owner_class`/`is_method_of` facts can be less
//! complete even when the class name itself came through correctly.
//!
//! `ingest` is idempotent per (subject, predicate, value): calling it
//! again with facts the graph already has adds nothing. This matters now
//! that `debura analyze` loads and merges into an existing graph instead
//! of replacing it (a genuinely changed fact, e.g. a name after an M8
//! rename, still lands as a new observation -- only exact repeats are
//! skipped).

use std::collections::HashSet;

use debura_ghidra::AnalysisResult;
use debura_knowledge::KnowledgeGraph;

const HEURISTIC_CONFIDENCE: f64 = 0.95;
const HEADER_CONFIDENCE: f64 = 1.0;
/// Field candidates are a regex over already-decompiled text (see
/// ExtractFacts.py), layered on top of decompilation's own 0.95 -- lower
/// to reflect that compounding, and because two accesses to the same
/// offset can disagree on type (signedness, in particular).
const FIELD_CANDIDATE_CONFIDENCE: f64 = 0.85;

type SeenKey = (String, String, String);

fn add_once(
    graph: &mut KnowledgeGraph,
    seen: &mut HashSet<SeenKey>,
    subject: impl Into<String>,
    predicate: impl Into<String>,
    value: impl Into<String>,
    confidence: f64,
    source: &str,
    artifact: Option<String>,
) {
    let subject = subject.into();
    let predicate = predicate.into();
    let value = value.into();

    if seen.insert((subject.clone(), predicate.clone(), value.clone())) {
        graph.add_observation(subject, predicate, value, confidence, source, artifact);
    }
}

/// Adds one Observation per deterministic fact in `analysis` to `graph`
/// that it doesn't already have. `artifact_path` is recorded alongside
/// decompilation observations so the full source (with surrounding
/// context) can still be found later.
pub fn ingest(graph: &mut KnowledgeGraph, analysis: &AnalysisResult, artifact_path: &str) {
    let mut seen: HashSet<SeenKey> = graph
        .observations()
        .map(|o| (o.subject.clone(), o.predicate.clone(), o.value.clone()))
        .collect();

    for f in &analysis.functions {
        add_once(graph, &mut seen, &f.address, "has_name", &f.name, HEURISTIC_CONFIDENCE, "ghidra:function", None);
        add_once(
            graph,
            &mut seen,
            &f.address,
            "has_signature",
            &f.signature,
            HEURISTIC_CONFIDENCE,
            "ghidra:function",
            None,
        );
        add_once(
            graph,
            &mut seen,
            &f.address,
            "calling_convention",
            &f.calling_convention,
            HEURISTIC_CONFIDENCE,
            "ghidra:function",
            None,
        );
        add_once(
            graph,
            &mut seen,
            &f.address,
            "size_bytes",
            f.size.to_string(),
            HEURISTIC_CONFIDENCE,
            "ghidra:function",
            None,
        );

        if !f.decompilation.is_empty() {
            add_once(
                graph,
                &mut seen,
                &f.address,
                "decompiles_to",
                &f.decompilation,
                HEURISTIC_CONFIDENCE,
                "ghidra:decompiler",
                Some(artifact_path.to_string()),
            );
        }

        for callee in &f.callees {
            add_once(
                graph,
                &mut seen,
                &f.address,
                "calls",
                callee,
                HEURISTIC_CONFIDENCE,
                "ghidra:call_graph",
                None,
            );
        }

        if let Some(owner) = &f.owner_class {
            add_once(
                graph,
                &mut seen,
                &f.address,
                "is_method_of",
                owner,
                HEURISTIC_CONFIDENCE,
                "ghidra:function",
                None,
            );
            if f.is_constructor {
                add_once(
                    graph,
                    &mut seen,
                    &f.address,
                    "is_constructor_of",
                    owner,
                    HEURISTIC_CONFIDENCE,
                    "ghidra:function",
                    None,
                );
            }
            if f.is_destructor {
                add_once(
                    graph,
                    &mut seen,
                    &f.address,
                    "is_destructor_of",
                    owner,
                    HEURISTIC_CONFIDENCE,
                    "ghidra:function",
                    None,
                );
            }
        }

        // A real run showed why this needs to be its own observation
        // rather than left implicit: without it, a structurally-discovered
        // constructor/destructor's decompilation (a base-class call plus a
        // pointer store) reads as generic, unremarkable code to a
        // reasoning model with no other signal -- it has no way to know
        // that pattern *is* the well-known ABI idiom, so it proposes a
        // vague semantic_role guess that an equally uninformed adversarial
        // challenge then rejects for being unsupported. Surfacing the
        // pattern explicitly (without claiming which of constructor/
        // destructor it is -- see `installs_vtable_of`'s own doc comment)
        // gives both sides of that exchange the context the symbol-based
        // path gets for free from `is_constructor_of`/`is_destructor_of`.
        if let Some(owner) = &f.installs_vtable_of {
            add_once(
                graph,
                &mut seen,
                &f.address,
                "vtable_install_pattern",
                format!(
                    "stores {owner}'s own vtable pointer into `this` early in this \
                     function's body -- the Itanium C++ ABI idiom every constructor and \
                     destructor performs (which of the two this is isn't determined)"
                ),
                HEURISTIC_CONFIDENCE,
                "ghidra:function",
                None,
            );
        }
    }

    for v in &analysis.vtables {
        add_once(
            graph,
            &mut seen,
            &v.class_name,
            "has_vtable_at",
            &v.address,
            HEADER_CONFIDENCE,
            "ghidra:vtable",
            None,
        );
    }

    for m in &analysis.virtual_methods {
        add_once(
            graph,
            &mut seen,
            &m.class_name,
            "has_virtual_method",
            format!("slot {}: {}", m.slot, m.function_address),
            HEURISTIC_CONFIDENCE,
            "ghidra:vtable",
            None,
        );
    }

    for i in &analysis.inheritance {
        add_once(
            graph,
            &mut seen,
            &i.derived,
            "inherits_from",
            &i.base,
            HEADER_CONFIDENCE,
            "ghidra:rtti",
            None,
        );
    }

    for f in &analysis.fields {
        add_once(
            graph,
            &mut seen,
            &f.class_name,
            "has_field_candidate",
            format!("{}:{}", f.offset, f.field_type),
            FIELD_CANDIDATE_CONFIDENCE,
            "ghidra:decompiler_heuristic",
            None,
        );
    }

    for s in &analysis.strings {
        add_once(
            graph,
            &mut seen,
            &s.address,
            "contains_string",
            &s.value,
            HEURISTIC_CONFIDENCE,
            "ghidra:strings",
            None,
        );
    }

    for i in &analysis.imports {
        add_once(
            graph,
            &mut seen,
            &i.address,
            "imports",
            format!("{}!{}", i.namespace, i.name),
            HEADER_CONFIDENCE,
            "ghidra:imports",
            None,
        );
    }

    for e in &analysis.exports {
        add_once(
            graph,
            &mut seen,
            &e.address,
            "exports",
            &e.name,
            HEADER_CONFIDENCE,
            "ghidra:exports",
            None,
        );
    }
}
