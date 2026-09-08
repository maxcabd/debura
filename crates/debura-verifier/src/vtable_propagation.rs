use std::collections::{BTreeSet, HashSet};

use debura_knowledge::{HypothesisId, HypothesisStatus, KnowledgeGraph};

/// PROJECT.md M17: when a `semantic_role` hypothesis for a virtual
/// method slot reaches ACCEPTED, propagate it as evidence to every
/// *sibling* class's own method at the same vtable slot -- classes
/// sharing a common ancestor share the same slot-to-method-purpose
/// mapping by Itanium ABI construction (slot N means the same logical
/// method across every class in a hierarchy, just with a different
/// override), so an accepted role for one is strong, structural
/// evidence for the others. This is meant to let something like
/// Wall::draw's accepted role help name Food::draw and Section::draw
/// too, instead of three independent, context-blind investigations each
/// starting from nothing.
///
/// Emits an *observation*, never a hypothesis: the normal
/// AnalyzeFunction/ChallengeHypothesis pipeline still has to propose and
/// adversarially verify the sibling's own role -- this only makes sure
/// the evidence that should inform that guess is actually present in
/// its context the next time it's built, the same way any other
/// structural fact is (PROJECT.md S23: task context is read fresh from
/// the graph, so this reaches a subject whether it hasn't been
/// investigated yet, is due for a bounded retry, or only gets picked up
/// on a later run against the same project).
///
/// Called from `reevaluate_hypothesis` -- the single choke point for
/// every path that can newly promote a hypothesis to ACCEPTED -- rather
/// than from each of its several callers individually.
pub fn propagate_vtable_slot_role(graph: &mut KnowledgeGraph, hypothesis_id: HypothesisId) {
    let Some(hyp) = graph.hypothesis(hypothesis_id) else {
        return;
    };
    if hyp.predicate != "semantic_role" || hyp.status != HypothesisStatus::Accepted {
        return;
    }
    let subject = hyp.subject.clone();
    let role = hyp.value.clone();

    let Some(owner) = is_method_of(graph, &subject) else {
        return;
    };
    let Some(slot) = virtual_method_slot(graph, &owner, &subject) else {
        return;
    };
    let root = hierarchy_root(graph, &owner);

    for (sibling_class, sibling_addr) in sibling_slot_methods(graph, &root, slot) {
        if sibling_addr == subject || has_accepted_semantic_role(graph, &sibling_addr) {
            continue;
        }
        let text = format!(
            "sibling class {sibling_class} shares vtable slot {slot} with {owner} via \
             common ancestor {root}; {owner}'s own method at this slot was ACCEPTED as \
             semantic_role '{role}' -- the same or an analogous role is a strong structural \
             prior for this method too, not just another independent guess"
        );
        graph.add_observation(
            sibling_addr,
            "sibling_vtable_role",
            text,
            0.9,
            "debura:vtable_propagation",
            None,
        );
    }
}

fn is_method_of(graph: &KnowledgeGraph, subject: &str) -> Option<String> {
    graph
        .observations()
        .find(|o| o.subject == subject && o.predicate == "is_method_of")
        .map(|o| o.value.clone())
}

/// Parses `has_virtual_method`'s own `"slot {N}: {address}"` value shape
/// (see debura-analysis's ingest) to find which slot number `address`
/// occupies in `class`'s vtable.
fn virtual_method_slot(graph: &KnowledgeGraph, class: &str, address: &str) -> Option<usize> {
    graph
        .observations()
        .filter(|o| o.subject == class && o.predicate == "has_virtual_method")
        .find_map(|o| {
            let (slot_str, slot_addr) = o.value.split_once(": ")?;
            if slot_addr != address {
                return None;
            }
            slot_str.strip_prefix("slot ")?.parse::<usize>().ok()
        })
}

/// Walks `inherits_from` edges to the ultimate ancestor -- the shared
/// root that makes two classes' vtable slots comparable at all. A class
/// with no recorded base is its own root. Cycle-guarded even though a
/// real single-inheritance chain can't actually cycle, the same
/// defensive posture the rest of this crate already takes around graph
/// traversal.
fn hierarchy_root(graph: &KnowledgeGraph, class: &str) -> String {
    let mut current = class.to_string();
    let mut seen = HashSet::new();
    while seen.insert(current.clone()) {
        let Some(base) = graph
            .observations()
            .find(|o| o.subject == current && o.predicate == "inherits_from")
            .map(|o| o.value.clone())
        else {
            break;
        };
        current = base;
    }
    current
}

/// Every `(class, address)` pair, across the whole graph, where `class`
/// shares `root` as its hierarchy root and has a virtual method at
/// exactly `slot`.
fn sibling_slot_methods(graph: &KnowledgeGraph, root: &str, slot: usize) -> Vec<(String, String)> {
    let classes: BTreeSet<String> = graph
        .observations()
        .filter(|o| o.predicate == "has_virtual_method")
        .map(|o| o.subject.clone())
        .collect();

    let mut result = Vec::new();
    for class in classes {
        if hierarchy_root(graph, &class) != root {
            continue;
        }
        for o in graph.observations().filter(|o| o.subject == class && o.predicate == "has_virtual_method") {
            let Some((slot_str, addr)) = o.value.split_once(": ") else {
                continue;
            };
            if slot_str.strip_prefix("slot ").and_then(|s| s.parse::<usize>().ok()) == Some(slot) {
                result.push((class.clone(), addr.to_string()));
            }
        }
    }
    result
}

fn has_accepted_semantic_role(graph: &KnowledgeGraph, address: &str) -> bool {
    graph
        .hypotheses()
        .any(|h| h.subject == address && h.predicate == "semantic_role" && h.status == HypothesisStatus::Accepted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_hierarchy(graph: &mut KnowledgeGraph) {
        // Drawable <- Collideable <- {Wall, Food, Section}, each with
        // its own draw() at slot 0 -- the real Snake shape.
        graph.add_observation("Collideable", "inherits_from", "Drawable", 0.95, "ghidra:function", None);
        graph.add_observation("Wall", "inherits_from", "Collideable", 0.95, "ghidra:function", None);
        graph.add_observation("Food", "inherits_from", "Collideable", 0.95, "ghidra:function", None);
        graph.add_observation("Section", "inherits_from", "Collideable", 0.95, "ghidra:function", None);

        graph.add_observation("Wall", "has_virtual_method", "slot 0: 0xa1", 1.0, "ghidra:vtable", None);
        graph.add_observation("Food", "has_virtual_method", "slot 0: 0xb1", 1.0, "ghidra:vtable", None);
        graph.add_observation("Section", "has_virtual_method", "slot 0: 0xc1", 1.0, "ghidra:vtable", None);

        graph.add_observation("0xa1", "is_method_of", "Wall", 0.95, "ghidra:function", None);
        graph.add_observation("0xb1", "is_method_of", "Food", 0.95, "ghidra:function", None);
        graph.add_observation("0xc1", "is_method_of", "Section", 0.95, "ghidra:function", None);
    }

    fn accept(graph: &mut KnowledgeGraph, subject: &str, value: &str) -> HypothesisId {
        let id = graph.propose_hypothesis(subject, "semantic_role", value, 0.95, None);
        graph.mark_verified(id, chrono::Utc::now()).unwrap();
        graph.set_status(id, HypothesisStatus::Accepted).unwrap();
        id
    }

    #[test]
    fn accepting_one_siblings_role_propagates_evidence_to_the_others() {
        let mut graph = KnowledgeGraph::new();
        seed_hierarchy(&mut graph);
        let wall_hyp = accept(&mut graph, "0xa1", "draw");

        propagate_vtable_slot_role(&mut graph, wall_hyp);

        let food_evidence: Vec<_> = graph
            .observations()
            .filter(|o| o.subject == "0xb1" && o.predicate == "sibling_vtable_role")
            .collect();
        assert_eq!(food_evidence.len(), 1);
        assert!(food_evidence[0].value.contains("Wall"));
        assert!(food_evidence[0].value.contains("draw"));

        let section_evidence: Vec<_> = graph
            .observations()
            .filter(|o| o.subject == "0xc1" && o.predicate == "sibling_vtable_role")
            .collect();
        assert_eq!(section_evidence.len(), 1);

        // Wall's own subject must not get evidence pointed at itself.
        assert!(graph.observations().all(|o| !(o.subject == "0xa1" && o.predicate == "sibling_vtable_role")));
    }

    #[test]
    fn a_sibling_that_already_has_an_accepted_role_is_left_alone() {
        let mut graph = KnowledgeGraph::new();
        seed_hierarchy(&mut graph);
        accept(&mut graph, "0xb1", "renderSprite"); // Food already settled
        let wall_hyp = accept(&mut graph, "0xa1", "draw");

        propagate_vtable_slot_role(&mut graph, wall_hyp);

        assert!(graph
            .observations()
            .all(|o| !(o.subject == "0xb1" && o.predicate == "sibling_vtable_role")));
    }

    #[test]
    fn unrelated_hierarchies_never_share_slot_evidence() {
        let mut graph = KnowledgeGraph::new();
        seed_hierarchy(&mut graph);
        // A second, unrelated single-method hierarchy also using slot 0.
        graph.add_observation("Widget", "has_virtual_method", "slot 0: 0xd1", 1.0, "ghidra:vtable", None);
        graph.add_observation("0xd1", "is_method_of", "Widget", 0.95, "ghidra:function", None);

        let wall_hyp = accept(&mut graph, "0xa1", "draw");
        propagate_vtable_slot_role(&mut graph, wall_hyp);

        assert!(graph
            .observations()
            .all(|o| !(o.subject == "0xd1" && o.predicate == "sibling_vtable_role")));
    }

    #[test]
    fn a_merely_proposed_hypothesis_never_propagates() {
        let mut graph = KnowledgeGraph::new();
        seed_hierarchy(&mut graph);

        let proposed = graph.propose_hypothesis("0xa1", "semantic_role", "draw", 0.5, None);
        propagate_vtable_slot_role(&mut graph, proposed);
        assert!(graph.observations().all(|o| o.predicate != "sibling_vtable_role"));
    }

    #[test]
    fn a_mechanical_behavior_hypothesis_never_propagates_even_if_accepted() {
        let mut graph = KnowledgeGraph::new();
        seed_hierarchy(&mut graph);

        let id = graph.propose_hypothesis("0xa1", "mechanical_behavior", "iteratesGrid", 0.95, None);
        graph.mark_verified(id, chrono::Utc::now()).unwrap();
        graph.set_status(id, HypothesisStatus::Accepted).unwrap();

        propagate_vtable_slot_role(&mut graph, id);
        assert!(graph.observations().all(|o| o.predicate != "sibling_vtable_role"));
    }
}
