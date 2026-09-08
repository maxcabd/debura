use debura_knowledge::{HypothesisStatus, KnowledgeGraph};

/// PROJECT.md M17: adjacency in a shared caller's own call sequence.
///
/// Grounded against the real Snake source: `SDL_main` calls
/// `Snake::draw`/`Food::draw`/`drawWalls` directly by concrete name --
/// there is no polymorphic dispatch site for `draw` anywhere in this
/// program, so a mechanism that only reads vtable-slot dispatch context
/// has nothing to learn from here. But the calls are bracketed by
/// `Screen::clear()`/`Screen::update()` every frame, and that bracketing
/// is exactly the evidence a human reading the same decompilation would
/// use to place these calls in the render step rather than describing
/// only their own internal mechanism (`iterates14x14Grid`,
/// `populateCells`). It also reaches non-virtual siblings --
/// `Snake::move`/`Snake::collidesWith` are called from the very same
/// function, near the tick/collision-reset logic -- that a vtable-slot
/// mechanism can never touch, since Snake has no vtable at all.
/// How many calls out, in either direction, to search for a labeled one
/// before giving up and falling back to the bare immediate neighbor.
/// Measured against the real Snake source: `Food::draw` sits 2 calls from
/// `Screen::update` (`Food::draw -> drawWalls -> update`) -- a radius of 1
/// (the original version of this mechanism) never reached it at all, and a
/// real run confirmed that empirically: zero of the three draw-family
/// methods, and zero of the four Snake benchmark methods, ever had `draw`
/// or `render` even proposed. 5 comfortably covers this program's longest
/// relevant clusters without walking so far it starts pulling in calls
/// with no real adjacency relationship to the subject.
const MAX_NEIGHBOR_DISTANCE: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencedCall {
    pub address: String,
    /// How many calls away from the subject this one is (1 = immediate
    /// neighbor). Included so the prompt can convey "two calls later" as
    /// weaker-but-real evidence rather than implying direct adjacency.
    pub distance: usize,
    /// This neighbor's own best currently-known label, if any -- an
    /// ACCEPTED semantic_role or mechanical_behavior, or a real (not
    /// Ghidra-placeholder) name. `None` here (with `distance` still set to
    /// the immediate neighbor) means the search walked out to
    /// `MAX_NEIGHBOR_DISTANCE` and found nothing labeled in this
    /// direction, not that there's no neighbor there at all.
    pub best_known_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSequenceNeighbor {
    pub caller: String,
    pub before: Option<SequencedCall>,
    pub after: Option<SequencedCall>,
}

/// For each caller, the *nearest labeled* call in each direction from
/// `subject`'s own call site in that caller's `decompiles_to` body --
/// walking outward up to `MAX_NEIGHBOR_DISTANCE` calls rather than
/// stopping at the immediate neighbor, since the caller function's own
/// bracketing calls (its own "clear"/"update"-style calls that actually
/// carry a label) are often a few calls further out than the subject's
/// literal neighbors, which are frequently other same-role siblings with
/// nothing known about them yet either. Falls back to the bare immediate
/// neighbor when nothing within the bound is labeled, so callers still see
/// the raw structure even with zero semantic signal available yet.
/// Recomputed fresh from the graph on every call (PROJECT.md S23) rather
/// than persisted, since a neighbor's own best-known label changes as the
/// run progresses and a stored snapshot would go stale.
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
                before: nearest_labeled_in_direction(&order, graph, pos, -1),
                after: nearest_labeled_in_direction(&order, graph, pos, 1),
                caller,
            })
        })
        .collect()
}

/// Walks from `pos` in `step` direction (-1 or +1), up to
/// `MAX_NEIGHBOR_DISTANCE` calls, returning the first labeled one found. If
/// none are labeled, returns the immediate (distance-1) neighbor anyway
/// (still `None`-labeled) so structure is never lost entirely, or `None`
/// only when there's no call at all in that direction.
fn nearest_labeled_in_direction(
    order: &[String],
    graph: &KnowledgeGraph,
    pos: usize,
    step: isize,
) -> Option<SequencedCall> {
    let mut fallback = None;
    for distance in 1..=MAX_NEIGHBOR_DISTANCE {
        let idx = pos as isize + step * distance as isize;
        if idx < 0 || idx as usize >= order.len() {
            break;
        }
        let address = order[idx as usize].clone();
        let best_known_label = best_known_label(graph, &address);
        let found = best_known_label.is_some();
        let call = SequencedCall {
            address,
            distance,
            best_known_label,
        };
        if fallback.is_none() {
            fallback = Some(call.clone());
        }
        if found {
            return Some(call);
        }
    }
    fallback
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
        assert_eq!(neighbors[0].before.as_ref().unwrap().address, "0x1400a");
        assert_eq!(neighbors[0].after.as_ref().unwrap().address, "0x1400c");
    }

    #[test]
    fn the_first_call_in_a_sequence_has_no_before() {
        let mut graph = KnowledgeGraph::new();
        seed_caller_with_sequence(&mut graph);

        let neighbors = call_sequence_neighbors(&graph, "0x1400a");
        assert!(neighbors[0].before.is_none());
        assert_eq!(neighbors[0].after.as_ref().unwrap().address, "0x1400b");
    }

    #[test]
    fn the_last_call_in_a_sequence_has_no_after() {
        let mut graph = KnowledgeGraph::new();
        seed_caller_with_sequence(&mut graph);

        let neighbors = call_sequence_neighbors(&graph, "0x1400c");
        assert!(neighbors[0].after.is_none());
        assert_eq!(neighbors[0].before.as_ref().unwrap().address, "0x1400b");
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
            neighbors[0].before.as_ref().unwrap().best_known_label.as_deref(),
            Some("semantic_role: clearsScreen")
        );
    }

    #[test]
    fn a_raw_ghidra_placeholder_name_is_not_treated_as_a_label() {
        let mut graph = KnowledgeGraph::new();
        seed_caller_with_sequence(&mut graph);
        graph.add_observation("0x1400a", "has_name", "FUN_1400a", 1.0, "ghidra:function", None);

        let neighbors = call_sequence_neighbors(&graph, "0x1400b");
        assert!(neighbors[0].before.as_ref().unwrap().best_known_label.is_none());
    }

    /// The exact shape that motivated widening the search: real Snake
    /// source has `Food::draw` sitting 2 calls from a labeled
    /// `Screen::update`, with an unlabeled sibling call in between --
    /// `clear(); draw(); food_draw(); walls(); update();`, subject is
    /// `food_draw`.
    #[test]
    fn a_labeled_call_two_steps_away_is_found_when_the_immediate_neighbor_is_unlabeled() {
        // Mirrors the real Snake shape: clear(); Snake::draw(); Food::draw();
        // drawWalls(); update() -- subject is Food::draw (0x1400c), and the
        // labeled call (update, 0x1400e) is 2 calls away, past the
        // unlabeled drawWalls (0x1400d) sitting immediately after it.
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
        let after = neighbors[0].after.as_ref().unwrap();
        assert_eq!(after.address, "0x1400e");
        assert_eq!(after.distance, 2);
        assert_eq!(after.best_known_label.as_deref(), Some("semantic_role: renderFrame"));

        // The unlabeled immediate neighbor (drawWalls) is correctly
        // skipped over, not returned instead.
        assert_ne!(after.address, "0x1400d");
    }

    #[test]
    fn nothing_labeled_within_the_bound_falls_back_to_the_immediate_neighbor() {
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
        // Label the call far past the search bound -- it must not be found.
        let far = format!("0x1400c{}", MAX_NEIGHBOR_DISTANCE + 2);
        let id = graph.propose_hypothesis(far.as_str(), "semantic_role", "farAway", 0.9, None);
        graph.mark_verified(id, chrono::Utc::now()).unwrap();
        graph.set_status(id, HypothesisStatus::Accepted).unwrap();

        let neighbors = call_sequence_neighbors(&graph, "0x1400c0");
        let after = neighbors[0].after.as_ref().unwrap();
        assert_eq!(after.distance, 1);
        assert_eq!(after.address, "0x1400c1");
        assert!(after.best_known_label.is_none());
    }
}
