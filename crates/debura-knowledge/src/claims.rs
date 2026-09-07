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

/// Classifies a subject by its class membership (`is_method_of`) or, for
/// a free function, its own name. Defaults to `Application` when neither
/// observation is present or neither matches a reserved shape -- an
/// unnamed structurally-discovered class (`Class_1400080e0`) counts as
/// Application too, since it's genuinely unverified rather than known to
/// be library code; ground-truth classification (a separate, manual
/// process) is still needed to judge its accuracy.
pub fn classify_subject(graph: &KnowledgeGraph, subject: &str) -> ClaimClass {
    let owner = graph
        .observations()
        .find(|o| o.subject == subject && o.predicate == "is_method_of")
        .map(|o| o.value.as_str());
    if let Some(owner) = owner {
        if is_reserved_identifier(owner) {
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

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClaimBreakdown {
    pub application_accepted: usize,
    pub library_or_compiler_accepted: usize,
}

/// Counts ACCEPTED semantic_role hypotheses by claim class -- the split
/// PROJECT.md M15 asks for instead of one blended "accepted" number,
/// since only the application count says anything about how well Debura
/// understands the program it's actually reversing.
pub fn claim_breakdown(graph: &KnowledgeGraph) -> ClaimBreakdown {
    let mut breakdown = ClaimBreakdown::default();
    for h in graph.hypotheses() {
        if h.predicate != "semantic_role" || h.status != HypothesisStatus::Accepted {
            continue;
        }
        match classify_subject(graph, &h.subject) {
            ClaimClass::Application => breakdown.application_accepted += 1,
            ClaimClass::LibraryOrCompiler => breakdown.library_or_compiler_accepted += 1,
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
        assert_eq!(breakdown.library_or_compiler_accepted, 1);
    }
}
