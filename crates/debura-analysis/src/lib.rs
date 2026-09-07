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
//! fields -- all read from Itanium C++ ABI symbols (`vtable for X`,
//! `typeinfo for X`, demangled method names) that Ghidra's own demangler
//! already produces. That's the caveat worth being explicit about: this
//! entire category depends on those mangled symbols still being present.
//! On a genuinely stripped release binary there are no such symbols to
//! read, and recovering the same facts would need structural heuristics
//! (vtable-shaped pointer arrays, RTTI-shaped data) instead of label
//! lookups -- a materially harder, unimplemented problem.

use debura_ghidra::AnalysisResult;
use debura_knowledge::KnowledgeGraph;

const HEURISTIC_CONFIDENCE: f64 = 0.95;
const HEADER_CONFIDENCE: f64 = 1.0;
/// Field candidates are a regex over already-decompiled text (see
/// ExtractFacts.py), layered on top of decompilation's own 0.95 -- lower
/// to reflect that compounding, and because two accesses to the same
/// offset can disagree on type (signedness, in particular).
const FIELD_CANDIDATE_CONFIDENCE: f64 = 0.85;

/// Adds one Observation per deterministic fact in `analysis` to `graph`.
/// `artifact_path` is recorded alongside decompilation observations so the
/// full source (with surrounding context) can still be found later.
pub fn ingest(graph: &mut KnowledgeGraph, analysis: &AnalysisResult, artifact_path: &str) {
    for f in &analysis.functions {
        graph.add_observation(
            &f.address,
            "has_name",
            &f.name,
            HEURISTIC_CONFIDENCE,
            "ghidra:function",
            None,
        );
        graph.add_observation(
            &f.address,
            "has_signature",
            &f.signature,
            HEURISTIC_CONFIDENCE,
            "ghidra:function",
            None,
        );
        graph.add_observation(
            &f.address,
            "calling_convention",
            &f.calling_convention,
            HEURISTIC_CONFIDENCE,
            "ghidra:function",
            None,
        );
        graph.add_observation(
            &f.address,
            "size_bytes",
            f.size.to_string(),
            HEURISTIC_CONFIDENCE,
            "ghidra:function",
            None,
        );

        if !f.decompilation.is_empty() {
            graph.add_observation(
                &f.address,
                "decompiles_to",
                &f.decompilation,
                HEURISTIC_CONFIDENCE,
                "ghidra:decompiler",
                Some(artifact_path.to_string()),
            );
        }

        for callee in &f.callees {
            graph.add_observation(
                &f.address,
                "calls",
                callee,
                HEURISTIC_CONFIDENCE,
                "ghidra:call_graph",
                None,
            );
        }

        if let Some(owner) = &f.owner_class {
            if f.is_constructor {
                graph.add_observation(
                    &f.address,
                    "is_constructor_of",
                    owner,
                    HEURISTIC_CONFIDENCE,
                    "ghidra:function",
                    None,
                );
            }
            if f.is_destructor {
                graph.add_observation(
                    &f.address,
                    "is_destructor_of",
                    owner,
                    HEURISTIC_CONFIDENCE,
                    "ghidra:function",
                    None,
                );
            }
        }
    }

    for v in &analysis.vtables {
        graph.add_observation(
            &v.class_name,
            "has_vtable_at",
            &v.address,
            HEADER_CONFIDENCE,
            "ghidra:vtable",
            None,
        );
    }

    for m in &analysis.virtual_methods {
        graph.add_observation(
            &m.class_name,
            "has_virtual_method",
            format!("slot {}: {}", m.slot, m.function_address),
            HEURISTIC_CONFIDENCE,
            "ghidra:vtable",
            None,
        );
    }

    for i in &analysis.inheritance {
        graph.add_observation(
            &i.derived,
            "inherits_from",
            &i.base,
            HEADER_CONFIDENCE,
            "ghidra:rtti",
            None,
        );
    }

    for f in &analysis.fields {
        graph.add_observation(
            &f.class_name,
            "has_field_candidate",
            format!("{}:{}", f.offset, f.field_type),
            FIELD_CANDIDATE_CONFIDENCE,
            "ghidra:decompiler_heuristic",
            None,
        );
    }

    for s in &analysis.strings {
        graph.add_observation(
            &s.address,
            "contains_string",
            &s.value,
            HEURISTIC_CONFIDENCE,
            "ghidra:strings",
            None,
        );
    }

    for i in &analysis.imports {
        graph.add_observation(
            &i.address,
            "imports",
            format!("{}!{}", i.namespace, i.name),
            HEADER_CONFIDENCE,
            "ghidra:imports",
            None,
        );
    }

    for e in &analysis.exports {
        graph.add_observation(
            &e.address,
            "exports",
            &e.name,
            HEADER_CONFIDENCE,
            "ghidra:exports",
            None,
        );
    }
}
