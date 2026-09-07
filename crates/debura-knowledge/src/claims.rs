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
/// differently. Defaults to `Application` when none of these observations
/// are present or none matches -- an unnamed structurally-discovered
/// class (`Class_1400080e0`) counts as Application too, since it's
/// genuinely unverified rather than known to be library code;
/// ground-truth classification (a separate, manual process) is still
/// needed to judge its accuracy.
pub fn classify_subject(graph: &KnowledgeGraph, subject: &str) -> ClaimClass {
    let imported = graph.observations().any(|o| o.subject == subject && o.predicate == "imports");
    if imported {
        return ClaimClass::LibraryOrCompiler;
    }

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

/// PROJECT.md M15: name/owner shape alone isn't enough. A real run's
/// `constructString` earned an ACCEPTED semantic_role and *looked* like
/// application code -- a readable, model-given name, no reserved-shaped
/// owner -- but its entire body was calls into `std::string`'s own
/// private implementation (`_M_create`, `_M_data`, `_M_capacity`,
/// `_M_set_length`): an inlined instantiation of the standard library's
/// own constructor logic that happened to get compiled as a separate
/// symbol, not anything the binary's author wrote. `ClaimClass` alone
/// can't see this -- it only ever looks at the subject's own name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Not library/compiler by name, and not dominated by calls into
    /// library/compiler internals either.
    Application,
    /// Either named like library/compiler code directly (subsumes every
    /// `ClaimClass::LibraryOrCompiler`), or -- the harder case --
    /// application-looking by name but almost entirely composed of
    /// calls into library internals with no other application-facing
    /// signal.
    CompilerLibraryGlue,
}

/// How much of `subject`'s own behavior, by call composition, is really
/// library/compiler internals rather than anything application-specific
/// -- dominance, not presence: real application code often calls one or
/// two STL helpers (`name += suffix`, `vector.push_back(x)`) without
/// being *defined by* them, so only a heavily library-dominated callee
/// list should count. Callees are judged by `classify_subject`'s own
/// cheap name-shape check -- library internals like
/// `std::string::_M_create` are already reserved-identifier-shaped, so
/// this needs no separate library-signature database. Returns 0.0 (never
/// glue on this signal alone) for a subject with no recorded callees at
/// all, rather than treating "nothing known" as "entirely library".
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

/// Dominance threshold for `library_callee_ratio` above which a subject
/// counts as compiler/library glue despite an application-looking name
/// -- deliberately high (not "calls any library function at all"), so
/// real application code that calls a couple of STL helpers along the
/// way isn't misclassified as glue.
const LIBRARY_GLUE_THRESHOLD: f64 = 0.8;

/// The provenance judgment PROJECT.md M15 asks for: `classify_subject`'s
/// name-shape check first (cheap, and already catches most library/
/// compiler code), then -- only for a subject whose own name looks like
/// application code -- the harder callee-composition check for a
/// function that's actually dominated by library internals despite
/// looking like application code by name alone.
pub fn classify_provenance(graph: &KnowledgeGraph, subject: &str) -> Provenance {
    if classify_subject(graph, subject) == ClaimClass::LibraryOrCompiler {
        return Provenance::CompilerLibraryGlue;
    }
    if library_callee_ratio(graph, subject) >= LIBRARY_GLUE_THRESHOLD {
        return Provenance::CompilerLibraryGlue;
    }
    Provenance::Application
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClaimBreakdown {
    pub application_accepted: usize,
    pub library_or_compiler_accepted: usize,
}

/// Counts ACCEPTED semantic_role hypotheses by provenance -- the split
/// PROJECT.md M15 asks for instead of one blended "accepted" number,
/// since only the application count says anything about how well Debura
/// understands the program it's actually reversing. Uses
/// `classify_provenance` (not just `classify_subject`) so a
/// library-dominated function that merely *looks* application-named
/// (PROJECT.md M15's `constructString` case) is counted correctly too.
pub fn claim_breakdown(graph: &KnowledgeGraph) -> ClaimBreakdown {
    let mut breakdown = ClaimBreakdown::default();
    for h in graph.hypotheses() {
        if h.predicate != "semantic_role" || h.status != HypothesisStatus::Accepted {
            continue;
        }
        match classify_provenance(graph, &h.subject) {
            Provenance::Application => breakdown.application_accepted += 1,
            Provenance::CompilerLibraryGlue => breakdown.library_or_compiler_accepted += 1,
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

    /// The exact real-world case this exists for: a function named and
    /// owned like application code, whose entire body is calls into
    /// std::string's own private implementation.
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
        // Callee composition (100% library) reclassifies it as glue.
        assert_eq!(library_callee_ratio(&graph, "0x1"), 1.0);
        assert_eq!(classify_provenance(&graph, "0x1"), Provenance::CompilerLibraryGlue);
    }

    /// The dominance requirement: real application code calling *one*
    /// STL helper alongside genuinely application-facing calls must not
    /// be misclassified as glue.
    #[test]
    fn a_couple_of_library_calls_does_not_make_application_code_glue() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "has_name", "buildScoreText", 0.95, "ghidra:function", None);
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
