use std::collections::HashSet;

use debura_knowledge::{HypothesisId, KnowledgeGraph};

/// PROJECT.md M17: a `semantic_role` whose own words are all already
/// present in the same subject's own `mechanical_behavior` value is
/// restating what the function's body literally does under a different
/// name, not naming why it exists -- exactly the failure CHALLENGE_SYSTEM's
/// side-effect question already asks about, except that check depends on
/// the model noticing it fresh on every review. Made deterministic here
/// because it didn't hold up in practice: a real run accepted
/// `semantic_role` "iteratesGrid" for three sibling classes, each already
/// carrying a `mechanical_behavior` of "iterates14x14Grid" /
/// "nestedIterates14x14Grid" -- every word in the semantic claim was
/// already in the mechanical one, and ChallengeHypothesis let it through
/// three times regardless, including once purely on sibling-vtable
/// agreement (see `vtable_propagation`).
///
/// Returns the colliding `mechanical_behavior` value for use in a
/// contradiction message, or `None` if nothing here looks
/// mechanically-shaped (including: `id` isn't a `semantic_role` at all, or
/// this subject has no recorded `mechanical_behavior` to compare against).
/// This only flags the hypothesis -- see `reevaluate_hypothesis`, which
/// routes a flagged one through the normal CONTESTED ->
/// ResolveContradiction path rather than blocking it outright, the same
/// "AI proposes, adversarial verification confirms" discipline
/// `vtable_propagation` follows for its own evidence.
pub fn mechanically_shaped_reason(graph: &KnowledgeGraph, id: HypothesisId) -> Option<String> {
    let hyp = graph.hypothesis(id)?;
    if hyp.predicate != "semantic_role" {
        return None;
    }
    let semantic_tokens = tokenize(&hyp.value);
    if semantic_tokens.is_empty() {
        return None;
    }

    graph
        .hypotheses()
        .filter(|h| h.subject == hyp.subject && h.predicate == "mechanical_behavior")
        .find_map(|h| {
            let mechanical_tokens = tokenize(&h.value);
            if semantic_tokens.is_subset(&mechanical_tokens) {
                Some(format!(
                    "semantic_role '{}' contributes no word that isn't already in this \
                     subject's own mechanical_behavior '{}' -- it reads as a restatement of \
                     mechanism, not a distinct claim about the function's role in the \
                     application",
                    hyp.value, h.value
                ))
            } else {
                None
            }
        })
}

/// Splits camelCase/PascalCase and digit runs into lowercase words, and
/// drops anything length <= 2 or purely numeric -- short connector words
/// and Ghidra's own embedded magnitude noise (`14x14`) shouldn't count as
/// meaningful overlap in either direction.
fn tokenize(value: &str) -> HashSet<String> {
    let chars: Vec<char> = value.chars().collect();
    let mut tokens = Vec::new();
    let mut current = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        if i > 0 {
            let prev = chars[i - 1];
            let boundary = (prev.is_lowercase() && c.is_uppercase())
                || (prev.is_alphabetic() && c.is_numeric())
                || (prev.is_numeric() && c.is_alphabetic());
            if boundary && !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        }
        current.push(c.to_ascii_lowercase());
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
        .into_iter()
        .filter(|t| t.len() > 2 && !t.chars().all(|c| c.is_ascii_digit()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn propose_and_verify(
        graph: &mut KnowledgeGraph,
        subject: &str,
        predicate: &str,
        value: &str,
        confidence: f64,
    ) -> HypothesisId {
        let id = graph.propose_hypothesis(subject, predicate, value, confidence, None);
        graph.mark_verified(id, chrono::Utc::now()).unwrap();
        id
    }

    #[test]
    fn a_semantic_role_that_only_restates_mechanical_behavior_is_flagged() {
        let mut graph = KnowledgeGraph::new();
        propose_and_verify(
            &mut graph,
            "0xa1",
            "mechanical_behavior",
            "iterates14x14Grid",
            0.9,
        );
        let semantic = propose_and_verify(&mut graph, "0xa1", "semantic_role", "iteratesGrid", 0.9);

        let reason = mechanically_shaped_reason(&graph, semantic);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("iterates14x14Grid"));
    }

    #[test]
    fn a_semantic_role_with_its_own_distinct_vocabulary_is_not_flagged() {
        let mut graph = KnowledgeGraph::new();
        propose_and_verify(
            &mut graph,
            "0xa1",
            "mechanical_behavior",
            "storesOwnVtablePointerAtOffset0",
            0.9,
        );
        let semantic =
            propose_and_verify(&mut graph, "0xa1", "semantic_role", "installFoodVtable", 0.9);

        assert!(mechanically_shaped_reason(&graph, semantic).is_none());
    }

    #[test]
    fn a_subject_with_no_mechanical_behavior_recorded_is_not_flagged() {
        let mut graph = KnowledgeGraph::new();
        let semantic = propose_and_verify(&mut graph, "0xa1", "semantic_role", "iteratesGrid", 0.9);

        assert!(mechanically_shaped_reason(&graph, semantic).is_none());
    }

    #[test]
    fn mechanical_behavior_hypotheses_are_never_flagged() {
        let mut graph = KnowledgeGraph::new();
        let mech = propose_and_verify(
            &mut graph,
            "0xa1",
            "mechanical_behavior",
            "iterates14x14Grid",
            0.9,
        );
        assert!(mechanically_shaped_reason(&graph, mech).is_none());
    }
}
