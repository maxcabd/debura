use std::collections::BTreeSet;

use debura_knowledge::KnowledgeGraph;

use crate::frontier::reachable_from;

fn direct_callees(graph: &KnowledgeGraph, address: &str) -> BTreeSet<String> {
    graph.observations().filter(|o| o.subject == address && o.predicate == "calls").map(|o| o.value.clone()).collect()
}

/// The address CRT startup calls as its own single call into the
/// application's real `main()`/`SDL_main()` (PROJECT.md M18.3) --
/// found structurally, not by name or convention: among CRT startup's
/// own direct callees (siblings, not ancestors -- comparing every
/// reachable address's own subtree size directly, as a first version of
/// this did, always picks the *most upstream* one instead, since an
/// ancestor's own reachable set necessarily includes everything
/// downstream of it, main's whole subtree included), the one whose own
/// transitive call-graph closure is far larger than any other's.
/// Confirmed against the real Snake binary: `entry` -> `FUN_140001154`
/// (real, verified-by-reading `__tmainCRTStartup` decompiled text --
/// matches mingw-w64's own published crt1.c almost verbatim) calls
/// eleven siblings, one of which (`FUN_140003940`) has a reachable
/// closure of 268 addresses against a next-largest sibling of 30 -- an
/// unambiguous, order-of-magnitude gap, not a close call. `main` is
/// structurally unique this way: it's the one function whose call graph
/// eventually reaches almost the entire rest of a real program, while
/// every other CRT-startup helper (argv duplication, pseudo-relocation,
/// exception-filter setup, ...) stays narrowly self-contained by
/// comparison. Assumes `entry` has exactly one direct callee (true for
/// every real mingw-w64-built PE this was verified against -- the PE
/// entrypoint calls straight into `__tmainCRTStartup`/
/// `WinMainCRTStartup` and nothing else); returns `None` if that
/// assumption doesn't hold, or if that callee has no callees of its own
/// to compare at all.
/// How many times larger the winning sibling's own reachable set must be
/// than the runner-up's before this is trusted as a real "one dominant
/// sibling" signal, not a coincidence of a small/shallow call graph. A
/// real regression found the un-margined version misfiring on a trivial
/// `entry -> A -> B` shape (exactly what a minimal, unrelated test
/// fixture -- or a real, small binary with no real CRT-startup-shaped
/// fan-out at all -- looks like): with only one real "sibling" to
/// compare, that lone candidate always "wins" by definition, which isn't
/// evidence of anything. The real, verified case has a genuinely
/// enormous margin (268 vs. a next-largest of 30, ~9x) -- 3x is
/// deliberately far more permissive than that, while still requiring
/// real separation, not a trivial single-candidate default.
const DOMINANCE_MARGIN: usize = 3;
/// CRT startup's own sole callee must have at least this many real
/// siblings before "one clearly dominates" means anything -- a graph
/// with only one candidate can't demonstrate dominance over anything.
const MIN_SIBLINGS: usize = 2;

pub fn find_main_equivalent(graph: &KnowledgeGraph, entry: &str) -> Option<String> {
    let entry_callees = direct_callees(graph, entry);
    let [crt_startup] = entry_callees.iter().collect::<Vec<_>>()[..] else {
        return None;
    };
    let siblings = direct_callees(graph, crt_startup);
    if siblings.len() < MIN_SIBLINGS {
        return None;
    }
    let mut sizes: Vec<(String, usize)> =
        siblings.into_iter().map(|addr| (addr.clone(), reachable_from(graph, &addr).len())).collect();
    sizes.sort_by_key(|(_, size)| std::cmp::Reverse(*size));
    let (winner, winner_size) = &sizes[0];
    let (_, runner_up_size) = &sizes[1];
    if *winner_size >= runner_up_size.saturating_mul(DOMINANCE_MARGIN).max(1) {
        Some(winner.clone())
    } else {
        None
    }
}

/// Every address reachable from `entry` that is *not* part of the real
/// main-equivalent function's own subtree (PROJECT.md M18.3) -- i.e. the
/// binary's own copy of the compiler's runtime startup machinery itself
/// (`entry`, `__tmainCRTStartup`, argv duplication, pseudo-relocation,
/// exception-filter setup, ...), as opposed to the application's own
/// code (`main`'s own subtree). A real recovery run found these were
/// being recovered as ordinary application source right alongside real
/// game code -- both unnecessary (a normal `g++` build already links a
/// real, working CRT startup implementation automatically) and actively
/// harmful (the recovered duplicate is genuinely dead code -- the real
/// linked CRT startup is what the loader actually calls -- that
/// references CRT-internal storage locations, `.CRT`-section globals
/// among them, that were never meant to be redefined by application
/// code at all, producing exactly the cluster of otherwise-mysterious
/// unresolved data symbols a real link run hit). Debura should recover
/// program semantics, not recreate every artifact of the original
/// compiler's own startup implementation.
pub fn crt_startup_only_addresses(graph: &KnowledgeGraph, entry: &str) -> BTreeSet<String> {
    // No confidently-identified main-equivalent means no confident CRT
    // boundary either -- a real regression caught this exact gap:
    // defaulting to "everything reachable is CRT-only" when the
    // detection comes up empty is backwards (it doesn't just under-
    // exclude, it *over*-excludes everything, including genuine
    // application code) for any graph that doesn't have the specific
    // real, verified `entry -> CRT startup -> siblings incl. main`
    // shape this was built from -- exactly the kind of confidently-wrong
    // default this project's whole discipline exists to avoid. An empty
    // result here (nothing flagged `RuntimeArtifact`) is the safe
    // fallback, matching this project's own "Unknown is better than
    // confidently wrong" rule for every other classifier in this crate.
    let Some(main_addr) = find_main_equivalent(graph, entry) else {
        return BTreeSet::new();
    };
    let full = reachable_from(graph, entry);
    let main_subtree = reachable_from(graph, &main_addr);
    full.difference(&main_subtree).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_edge(graph: &mut KnowledgeGraph, from: &str, to: &str) {
        graph.add_observation(from, "calls", to, 0.95, "ghidra:call_graph", None);
    }

    /// The real, confirmed shape: `entry` calls CRT startup, which calls
    /// several small siblings plus one dominant one (`main`) whose own
    /// subtree dwarfs every sibling's.
    #[test]
    fn the_sibling_with_the_largest_subtree_is_found_as_main() {
        let mut graph = KnowledgeGraph::new();
        add_edge(&mut graph, "0xentry", "0xcrt_startup");
        add_edge(&mut graph, "0xcrt_startup", "0xargv_dup");
        add_edge(&mut graph, "0xcrt_startup", "0xpseudo_reloc");
        add_edge(&mut graph, "0xcrt_startup", "0xmain");
        // main's own large subtree -- real game code.
        add_edge(&mut graph, "0xmain", "0xgame_init");
        add_edge(&mut graph, "0xmain", "0xgame_loop");
        add_edge(&mut graph, "0xgame_loop", "0xrender");
        add_edge(&mut graph, "0xgame_loop", "0xupdate");
        add_edge(&mut graph, "0xupdate", "0xcollide");

        assert_eq!(find_main_equivalent(&graph, "0xentry").as_deref(), Some("0xmain"));
    }

    #[test]
    fn crt_only_addresses_excludes_mains_own_subtree() {
        let mut graph = KnowledgeGraph::new();
        add_edge(&mut graph, "0xentry", "0xcrt_startup");
        add_edge(&mut graph, "0xcrt_startup", "0xargv_dup");
        add_edge(&mut graph, "0xcrt_startup", "0xmain");
        add_edge(&mut graph, "0xmain", "0xgame_init");
        add_edge(&mut graph, "0xmain", "0xgame_loop");
        add_edge(&mut graph, "0xgame_loop", "0xrender");

        let crt_only = crt_startup_only_addresses(&graph, "0xentry");

        assert!(crt_only.contains("0xentry"));
        assert!(crt_only.contains("0xcrt_startup"));
        assert!(crt_only.contains("0xargv_dup"));
        assert!(!crt_only.contains("0xmain"));
        assert!(!crt_only.contains("0xgame_init"));
        assert!(!crt_only.contains("0xgame_loop"));
        assert!(!crt_only.contains("0xrender"));
    }

    /// A real regression: an earlier version defaulted to treating
    /// *everything* reachable as CRT-only when no main-equivalent could
    /// be confidently identified -- backwards, and disastrous for any
    /// graph shaped differently than the one real binary this was built
    /// from (confirmed: it mis-flagged ordinary test fixtures' own
    /// target addresses as `RuntimeArtifact`). No confident boundary
    /// found must mean no exclusion at all.
    #[test]
    fn no_main_equivalent_found_excludes_nothing() {
        let graph = KnowledgeGraph::new();
        assert_eq!(find_main_equivalent(&graph, "0xentry"), None);

        let crt_only = crt_startup_only_addresses(&graph, "0xentry");
        assert!(crt_only.is_empty(), "{crt_only:?}");
    }

    /// The same shape a real disposition-test fixture actually has: a
    /// shallow `entry -> target` graph with no real CRT-startup/main
    /// structure at all -- must not exclude the target.
    #[test]
    fn a_shallow_graph_with_no_crt_structure_excludes_nothing() {
        let mut graph = KnowledgeGraph::new();
        add_edge(&mut graph, "0xentry", "0x1");

        let crt_only = crt_startup_only_addresses(&graph, "0xentry");
        assert!(crt_only.is_empty(), "{crt_only:?}");
    }

    /// A real, direct regression: `entry -> 0x1 -> 0x2` is exactly the
    /// shape 6 real disposition tests use (a 2-hop chain with a single
    /// callee at each level) -- an earlier version of `find_main_equivalent`
    /// treated `0x1`'s own sole callee as "the dominant sibling" purely
    /// because it was the *only* candidate, misclassifying `0x1` itself
    /// as `RuntimeArtifact`. A lone candidate, with no real siblings to
    /// demonstrate dominance over, must never be trusted as "main".
    #[test]
    fn a_two_hop_chain_with_no_real_siblings_never_identifies_a_main_equivalent() {
        let mut graph = KnowledgeGraph::new();
        add_edge(&mut graph, "0xentry", "0x1");
        add_edge(&mut graph, "0x1", "0x2");

        assert_eq!(find_main_equivalent(&graph, "0xentry"), None);
        assert!(crt_startup_only_addresses(&graph, "0xentry").is_empty());
    }

    /// Even with real siblings present, a lead that isn't decisively
    /// larger (this project's own real case has a ~9x margin; a lead of
    /// less than `DOMINANCE_MARGIN` isn't trusted) must not be treated
    /// as a confirmed main-equivalent.
    #[test]
    fn siblings_with_no_decisive_margin_do_not_identify_a_main_equivalent() {
        let mut graph = KnowledgeGraph::new();
        add_edge(&mut graph, "0xentry", "0xcrt_startup");
        add_edge(&mut graph, "0xcrt_startup", "0xa");
        add_edge(&mut graph, "0xcrt_startup", "0xb");
        add_edge(&mut graph, "0xa", "0xa1");
        add_edge(&mut graph, "0xa", "0xa2");
        add_edge(&mut graph, "0xb", "0xb1");

        // 0xa's own subtree (3) isn't even twice 0xb's (2) -- nowhere
        // near the real, decisive margin this project's own actual case
        // has.
        assert_eq!(find_main_equivalent(&graph, "0xentry"), None);
    }
}
