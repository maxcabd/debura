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
//! yet: with no consumer for them until targeted field-offset analysis
//! (M7), doing so now would just be speculative volume.

use debura_ghidra::AnalysisResult;
use debura_knowledge::KnowledgeGraph;

const HEURISTIC_CONFIDENCE: f64 = 0.95;
const HEADER_CONFIDENCE: f64 = 1.0;

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
