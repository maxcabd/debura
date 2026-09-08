use std::collections::HashSet;

use debura_knowledge::{HypothesisStatus, KnowledgeGraph};

/// PROJECT.md M17: raw, structural evidence about a function's role that
/// needs no accepted neighbor name at all -- the "weak link" problem two
/// earlier versions of this mechanism hit head-on. Grounded against the
/// real Snake source: `Screen::update`'s own decompiled body already
/// contains `SDL_RenderClear`/`SDL_RenderCopy`/`SDL_RenderPresent`/
/// `SDL_UpdateTexture` by their real names -- Ghidra resolves import-table
/// calls to real names even in a fully stripped binary, so this needs no
/// propagation or acceptance step whatsoever, it's just never been
/// surfaced to the model as a distinct signal before. `Food::draw`, by
/// contrast, has no such signal reachable from its own body at all (its
/// only callee is an unnamed, no-further-callees pixel-setting helper) --
/// for it, the only available evidence is its neighbors' own raw mechanics
/// in the same caller's call sequence, which is why this module also
/// widened from "nearest labeled neighbor" (which depended on a neighbor
/// reaching ACCEPTED -- `Screen::clear`/`Screen::update` often never did)
/// to every neighbor's raw facts regardless of acceptance status.
///
/// Real chain this was measured against: `SDL_main` calls
/// `Screen::clear`, `Snake::draw`, `Food::draw`, `drawWalls`,
/// `Screen::update` in that literal order, with no polymorphic dispatch
/// site anywhere in the sequence -- `Food::draw`'s own callee tree is a
/// dead end, but `Screen::update`, two calls away, reaches four real SDL
/// render/texture names one hop into *its* callee tree. Combining "what
/// does this subject's own callee tree reach" with "what do this
/// subject's caller-sequence neighbors' callee trees reach" is meant to
/// let that signal travel the two hops needed to actually inform
/// `Food::draw`'s own semantic_role, without requiring `Screen::update` to
/// have ever earned an ACCEPTED name of its own.
const MAX_REACHABLE_DEPTH: u32 = 3;
const MAX_REACHABLE_HINTS: usize = 6;

/// Real (non-`FUN_`-placeholder) names reachable from `subject`'s own
/// `calls` edges, walking up to `MAX_REACHABLE_DEPTH` hops and stopping
/// early once `MAX_REACHABLE_HINTS` distinct names are found. A name here
/// is a plain structural fact (Ghidra's own import-table resolution, or a
/// prior investigation's `has_name` observation) -- it carries no
/// confidence/status of its own and needs none, unlike a hypothesis.
pub fn reachable_api_hints(graph: &KnowledgeGraph, subject: &str) -> Vec<String> {
    let mut hints = Vec::new();
    let mut seen = HashSet::new();
    seen.insert(subject.to_string());
    let mut frontier = vec![subject.to_string()];

    for _ in 0..MAX_REACHABLE_DEPTH {
        if hints.len() >= MAX_REACHABLE_HINTS {
            break;
        }
        let mut next_frontier = Vec::new();
        for addr in frontier {
            let callees: Vec<String> = graph
                .observations()
                .filter(|o| o.subject == addr && o.predicate == "calls")
                .map(|o| o.value.clone())
                .collect();
            for callee in callees {
                if !seen.insert(callee.clone()) {
                    continue;
                }
                if let Some(name) = graph
                    .observations()
                    .find(|o| o.subject == callee && o.predicate == "has_name")
                    .map(|o| o.value.clone())
                {
                    if !name.starts_with("FUN_") && !hints.contains(&name) {
                        hints.push(name);
                    }
                }
                next_frontier.push(callee);
            }
        }
        frontier = next_frontier;
        if hints.len() >= MAX_REACHABLE_HINTS {
            break;
        }
    }

    hints.truncate(MAX_REACHABLE_HINTS);
    hints
}

/// How many calls out, in either direction, to gather as caller-sequence
/// context. Measured against the real Snake source: `Food::draw` sits 2
/// calls from `Screen::update` (`Food::draw -> drawWalls -> update`) -- a
/// radius of 1 never reached it at all. 5 comfortably covers this
/// program's longest relevant clusters without walking so far it starts
/// pulling in calls with no real adjacency relationship to the subject.
const MAX_NEIGHBOR_DISTANCE: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencedCall {
    pub address: String,
    /// How many calls away from the subject this one is (1 = immediate
    /// neighbor). Included so the prompt can convey "two calls later" as
    /// weaker-but-real evidence rather than implying direct adjacency.
    pub distance: usize,
    /// An ACCEPTED semantic_role or mechanical_behavior, or a real (not
    /// Ghidra-placeholder) name -- the strongest available claim about
    /// this neighbor, when one has actually cleared verification.
    pub best_known_label: Option<String>,
    /// A `mechanical_behavior` value regardless of status -- real evidence
    /// about mechanism that hasn't (or never will) reach ACCEPTED, kept
    /// distinct from `best_known_label` so the prompt can tell a verified
    /// claim from a raw, unconfirmed one.
    pub raw_mechanical_behavior: Option<String>,
    /// Real names reachable from this neighbor's own callee tree (see
    /// `reachable_api_hints`) -- needs no acceptance status at all, and is
    /// often the richest signal available for a neighbor that never gets
    /// its own semantic_role accepted.
    pub reachable_api_hints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSequenceNeighbor {
    pub caller: String,
    /// Ordered nearest-to-farthest, up to `MAX_NEIGHBOR_DISTANCE` calls
    /// before `subject` in this caller's own call sequence.
    pub before: Vec<SequencedCall>,
    /// Ordered nearest-to-farthest, up to `MAX_NEIGHBOR_DISTANCE` calls
    /// after `subject`.
    pub after: Vec<SequencedCall>,
}

/// For each caller, every call within `MAX_NEIGHBOR_DISTANCE` of
/// `subject`'s own call site in that caller's `decompiles_to` body, each
/// carrying its own raw evidence bundle -- not just the nearest one that
/// happens to already have an accepted label (PROJECT.md M17: that
/// earlier version depended on a neighbor reaching ACCEPTED, which
/// `Screen::clear`/`Screen::update` often never did, so the signal never
/// arrived at all). Recomputed fresh from the graph on every call
/// (PROJECT.md S23) rather than persisted, since a neighbor's own
/// evidence changes as the run progresses and a stored snapshot would go
/// stale.
pub fn call_sequence_neighbors(graph: &KnowledgeGraph, subject: &str) -> Vec<CallSequenceNeighbor> {
    let callers: Vec<String> = graph
        .observations()
        .filter(|o| o.subject == subject && o.predicate == "called_by")
        .map(|o| o.value.clone())
        .collect();

    callers
        .into_iter()
        .filter_map(|caller| {
            let body = graph
                .observations()
                .find(|o| o.subject == caller && o.predicate == "decompiles_to")
                .map(|o| o.value.clone())?;
            let order = call_order_in_body(&body);
            let pos = order.iter().position(|c| c == subject)?;
            Some(CallSequenceNeighbor {
                before: members_in_direction(&order, graph, pos, -1),
                after: members_in_direction(&order, graph, pos, 1),
                caller,
            })
        })
        .collect()
}

/// Every call from `pos` in `step` direction (-1 or +1), up to
/// `MAX_NEIGHBOR_DISTANCE`, each with its own evidence bundle gathered
/// regardless of acceptance status.
fn members_in_direction(
    order: &[String],
    graph: &KnowledgeGraph,
    pos: usize,
    step: isize,
) -> Vec<SequencedCall> {
    let mut members = Vec::new();
    for distance in 1..=MAX_NEIGHBOR_DISTANCE {
        let idx = pos as isize + step * distance as isize;
        if idx < 0 || idx as usize >= order.len() {
            break;
        }
        let address = order[idx as usize].clone();
        members.push(SequencedCall {
            best_known_label: best_known_label(graph, &address),
            raw_mechanical_behavior: raw_mechanical_behavior(graph, &address),
            reachable_api_hints: reachable_api_hints(graph, &address),
            distance,
            address,
        });
    }
    members
}

/// An ACCEPTED semantic_role beats an ACCEPTED mechanical_behavior beats a
/// real (non-`FUN_`-placeholder) name -- the most specific, most-trusted
/// fact wins, and a Ghidra placeholder name conveys nothing beyond the
/// address the caller already has.
fn best_known_label(graph: &KnowledgeGraph, address: &str) -> Option<String> {
    graph
        .hypotheses()
        .find(|h| {
            h.subject == address && h.predicate == "semantic_role" && h.status == HypothesisStatus::Accepted
        })
        .or_else(|| {
            graph.hypotheses().find(|h| {
                h.subject == address
                    && h.predicate == "mechanical_behavior"
                    && h.status == HypothesisStatus::Accepted
            })
        })
        .map(|h| format!("{}: {}", h.predicate, h.value))
        .or_else(|| {
            graph
                .observations()
                .find(|o| o.subject == address && o.predicate == "has_name")
                .map(|o| o.value.clone())
                .filter(|name| !name.starts_with("FUN_"))
        })
}

/// `mechanical_behavior`'s value regardless of status -- a raw, possibly
/// still-unverified (or already-rejected-as-a-role-but-still-mechanically-
/// true) fact about what the code does, kept separate from
/// `best_known_label` so the prompt never confuses "verified" with
/// "merely proposed".
fn raw_mechanical_behavior(graph: &KnowledgeGraph, address: &str) -> Option<String> {
    graph
        .hypotheses()
        .find(|h| h.subject == address && h.predicate == "mechanical_behavior")
        .map(|h| h.value.clone())
}

/// The addresses `FUN_<hex>` is called, in the textual order they appear
/// in a decompiled body -- Ghidra's own raw call syntax before any
/// renaming, so this only ever runs against a subject's pristine
/// `decompiles_to` fact, never recovered/renamed output.
fn call_order_in_body(body: &str) -> Vec<String> {
    let mut calls = Vec::new();
    let mut i = 0;
    while let Some(rel) = body[i..].find("FUN_") {
        let start = i + rel + 4;
        let mut end = start;
        while end < body.len() && body.as_bytes()[end].is_ascii_hexdigit() {
            end += 1;
        }
        if end > start {
            calls.push(format!("0x{}", body[start..end].to_lowercase()));
            i = end;
        } else {
            i = start;
        }
    }
    calls
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_caller_with_sequence(graph: &mut KnowledgeGraph) {
        graph.add_observation(
            "0xcaller",
            "decompiles_to",
            "FUN_1400a(x); FUN_1400b(y); FUN_1400c(z);",
            1.0,
            "ghidra:function",
            None,
        );
        graph.add_observation("0x1400a", "called_by", "0xcaller", 1.0, "ghidra:function", None);
        graph.add_observation("0x1400b", "called_by", "0xcaller", 1.0, "ghidra:function", None);
        graph.add_observation("0x1400c", "called_by", "0xcaller", 1.0, "ghidra:function", None);
    }

    #[test]
    fn a_call_in_the_middle_of_a_sequence_gets_both_neighbors() {
        let mut graph = KnowledgeGraph::new();
        seed_caller_with_sequence(&mut graph);

        let neighbors = call_sequence_neighbors(&graph, "0x1400b");
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].caller, "0xcaller");
        assert_eq!(neighbors[0].before[0].address, "0x1400a");
        assert_eq!(neighbors[0].after[0].address, "0x1400c");
    }

    #[test]
    fn the_first_call_in_a_sequence_has_no_before() {
        let mut graph = KnowledgeGraph::new();
        seed_caller_with_sequence(&mut graph);

        let neighbors = call_sequence_neighbors(&graph, "0x1400a");
        assert!(neighbors[0].before.is_empty());
        assert_eq!(neighbors[0].after[0].address, "0x1400b");
    }

    #[test]
    fn the_last_call_in_a_sequence_has_no_after() {
        let mut graph = KnowledgeGraph::new();
        seed_caller_with_sequence(&mut graph);

        let neighbors = call_sequence_neighbors(&graph, "0x1400c");
        assert!(neighbors[0].after.is_empty());
        assert_eq!(neighbors[0].before[0].address, "0x1400b");
    }

    #[test]
    fn a_subject_with_no_recorded_caller_gets_no_neighbors() {
        let graph = KnowledgeGraph::new();
        assert!(call_sequence_neighbors(&graph, "0xdeadbeef").is_empty());
    }

    #[test]
    fn a_caller_with_no_decompiled_body_recorded_is_skipped() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1400a", "called_by", "0xcaller", 1.0, "ghidra:function", None);
        assert!(call_sequence_neighbors(&graph, "0x1400a").is_empty());
    }

    #[test]
    fn a_neighbor_with_an_accepted_semantic_role_carries_its_label() {
        let mut graph = KnowledgeGraph::new();
        seed_caller_with_sequence(&mut graph);
        let id = graph.propose_hypothesis("0x1400a", "semantic_role", "clearsScreen", 0.9, None);
        graph.mark_verified(id, chrono::Utc::now()).unwrap();
        graph.set_status(id, HypothesisStatus::Accepted).unwrap();

        let neighbors = call_sequence_neighbors(&graph, "0x1400b");
        assert_eq!(
            neighbors[0].before[0].best_known_label.as_deref(),
            Some("semantic_role: clearsScreen")
        );
    }

    #[test]
    fn a_raw_ghidra_placeholder_name_is_not_treated_as_a_label() {
        let mut graph = KnowledgeGraph::new();
        seed_caller_with_sequence(&mut graph);
        graph.add_observation("0x1400a", "has_name", "FUN_1400a", 1.0, "ghidra:function", None);

        let neighbors = call_sequence_neighbors(&graph, "0x1400b");
        assert!(neighbors[0].before[0].best_known_label.is_none());
    }

    /// The exact shape that motivated widening the search: real Snake
    /// source has `Food::draw` sitting 2 calls from a labeled
    /// `Screen::update`, with an unlabeled sibling call in between.
    #[test]
    fn a_labeled_call_two_steps_away_is_included_alongside_the_unlabeled_immediate_neighbor() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation(
            "0xcaller",
            "decompiles_to",
            "FUN_1400a(); FUN_1400b(); FUN_1400c(); FUN_1400d(); FUN_1400e();",
            1.0,
            "ghidra:function",
            None,
        );
        for addr in ["a", "b", "c", "d", "e"] {
            graph.add_observation(
                format!("0x1400{addr}"),
                "called_by",
                "0xcaller",
                1.0,
                "ghidra:function",
                None,
            );
        }
        let id = graph.propose_hypothesis("0x1400e", "semantic_role", "renderFrame", 0.9, None);
        graph.mark_verified(id, chrono::Utc::now()).unwrap();
        graph.set_status(id, HypothesisStatus::Accepted).unwrap();

        let neighbors = call_sequence_neighbors(&graph, "0x1400c");
        let after = &neighbors[0].after;
        assert_eq!(after.len(), 2, "both intervening calls after the subject must be present");
        assert_eq!(after[0].address, "0x1400d");
        assert!(after[0].best_known_label.is_none());
        assert_eq!(after[1].address, "0x1400e");
        assert_eq!(after[1].distance, 2);
        assert_eq!(after[1].best_known_label.as_deref(), Some("semantic_role: renderFrame"));
    }

    #[test]
    fn the_search_does_not_walk_past_the_configured_bound() {
        let mut graph = KnowledgeGraph::new();
        let body: String = (0..=(MAX_NEIGHBOR_DISTANCE + 2))
            .map(|i| format!("FUN_1400c{i}();"))
            .collect();
        graph.add_observation("0xcaller", "decompiles_to", body, 1.0, "ghidra:function", None);
        for i in 0..=(MAX_NEIGHBOR_DISTANCE + 2) {
            graph.add_observation(
                format!("0x1400c{i}"),
                "called_by",
                "0xcaller",
                1.0,
                "ghidra:function",
                None,
            );
        }

        let neighbors = call_sequence_neighbors(&graph, "0x1400c0");
        assert_eq!(neighbors[0].after.len(), MAX_NEIGHBOR_DISTANCE);
        assert_eq!(neighbors[0].after.last().unwrap().distance, MAX_NEIGHBOR_DISTANCE);
    }

    /// Real case this exists for: `mechanical_behavior` never reached
    /// ACCEPTED (or never will), but it's still a real fact worth showing.
    #[test]
    fn raw_mechanical_behavior_is_surfaced_regardless_of_status() {
        let mut graph = KnowledgeGraph::new();
        seed_caller_with_sequence(&mut graph);
        graph.propose_hypothesis("0x1400a", "mechanical_behavior", "memsetsBuffer", 0.6, None);

        let neighbors = call_sequence_neighbors(&graph, "0x1400b");
        assert_eq!(
            neighbors[0].before[0].raw_mechanical_behavior.as_deref(),
            Some("memsetsBuffer")
        );
        // Not accepted, so it must not show up as a trusted label either.
        assert!(neighbors[0].before[0].best_known_label.is_none());
    }

    /// The real case that motivated `reachable_api_hints` in the first
    /// place: a neighbor whose own body calls straight into a real,
    /// already-resolved API name, with no accepted hypothesis anywhere in
    /// the chain.
    #[test]
    fn reachable_api_hints_finds_a_real_name_two_hops_into_the_callee_tree() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "calls", "0x3", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x3", "has_name", "SDL_RenderClear", 0.95, "ghidra:function", None);

        assert_eq!(reachable_api_hints(&graph, "0x1"), vec!["SDL_RenderClear".to_string()]);
    }

    #[test]
    fn reachable_api_hints_does_not_walk_past_the_depth_bound() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "calls", "0x3", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x3", "calls", "0x4", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x4", "calls", "0x5", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x5", "has_name", "SDL_RenderClear", 0.95, "ghidra:function", None);

        assert!(reachable_api_hints(&graph, "0x1").is_empty());
    }

    #[test]
    fn reachable_api_hints_ignores_raw_ghidra_placeholder_names() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
        graph.add_observation("0x2", "has_name", "FUN_2", 0.95, "ghidra:function", None);

        assert!(reachable_api_hints(&graph, "0x1").is_empty());
    }

    #[test]
    fn reachable_api_hints_caps_at_the_configured_max() {
        let mut graph = KnowledgeGraph::new();
        for i in 0..(MAX_REACHABLE_HINTS + 3) {
            let callee = format!("0x{i}");
            graph.add_observation("0x1", "calls", &callee, 0.95, "ghidra:call_graph", None);
            graph.add_observation(&callee, "has_name", format!("RealName{i}"), 0.95, "ghidra:function", None);
        }

        assert_eq!(reachable_api_hints(&graph, "0x1").len(), MAX_REACHABLE_HINTS);
    }
}
