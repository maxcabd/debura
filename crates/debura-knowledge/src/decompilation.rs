use crate::graph::KnowledgeGraph;
use crate::observation::Observation;

/// The most recent *substantive* `decompiles_to` fact for `subject` --
/// preferring any non-degenerate decompilation over a later, degraded one
/// left by a repeat Ghidra pass, falling back to the latest of any kind
/// only if every recorded decompilation is degenerate.
///
/// PROJECT.md M18: found live, independently, in three different ad-hoc
/// lookups across two crates before being centralized here -- a naive
/// "highest id wins" in `classify_provenance`'s own-state signal (silently
/// stopped seeing a subject's real body the moment a later re-analysis
/// pass degraded it), and an even less predictable bare `.find()` in
/// `call_sequence_neighbors` (whatever order `KnowledgeGraph`'s internal
/// `HashMap` happens to iterate in -- not even id-ordered). A real project
/// database was checked and genuinely has dozens of subjects with more
/// than one `decompiles_to` observation, so this wasn't a theoretical
/// risk. Every recoverability or provenance decision that reads a
/// subject's decompiled body must go through this, not re-derive its own
/// selection.
pub fn latest_decompilation<'a>(graph: &'a KnowledgeGraph, subject: &str) -> Option<&'a Observation> {
    let mut candidates: Vec<&Observation> = graph
        .observations()
        .filter(|o| o.subject == subject && o.predicate == "decompiles_to")
        .collect();
    candidates.sort_by_key(|o| o.id.0);
    candidates
        .iter()
        .rev()
        .find(|o| !is_degenerate_decompilation(&o.value))
        .or_else(|| candidates.last())
        .copied()
}

/// A decompilation whose body is empty or just an elided `{...}`
/// placeholder -- Ghidra emits this on some re-analysis passes for a
/// subject it successfully decompiled fully on an earlier pass.
pub fn is_degenerate_decompilation(text: &str) -> bool {
    match text.find('{') {
        Some(idx) => matches!(text[idx..].trim(), "{...}" | "{ ... }"),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_the_most_recent_substantive_decompilation_over_a_later_degenerate_one() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation(
            "0x1",
            "decompiles_to",
            "void FUN_1(void)\n\n{\n  real_body();\n  return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        graph.add_observation("0x1", "decompiles_to", "void FUN_1(void) { ... }", 0.95, "ghidra:decompiler", None);

        let latest = latest_decompilation(&graph, "0x1").unwrap();
        assert!(latest.value.contains("real_body"));
    }

    #[test]
    fn falls_back_to_the_latest_of_any_kind_when_every_decompilation_is_degenerate() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "decompiles_to", "void FUN_1(void) { ... }", 0.95, "ghidra:decompiler", None);
        graph.add_observation("0x1", "decompiles_to", "void FUN_1(void) {...}", 0.95, "ghidra:decompiler", None);

        let latest = latest_decompilation(&graph, "0x1").unwrap();
        assert!(is_degenerate_decompilation(&latest.value));
    }

    #[test]
    fn returns_none_when_no_decompilation_exists_at_all() {
        let graph = KnowledgeGraph::new();
        assert!(latest_decompilation(&graph, "0x1").is_none());
    }
}
