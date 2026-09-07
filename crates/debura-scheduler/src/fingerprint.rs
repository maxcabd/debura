use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use debura_agent::{commit_hypothesis, ProposedHypothesis};
use debura_knowledge::{HypothesisStatus, KnowledgeGraph};

use crate::seed::latest_value;
use crate::task::Task;

/// Replaces a Ghidra-synthesized address suffix (`DAT_140009070`,
/// `PTR_draw_140009a40`, `_refptr__ZN9SnakeGame6Screen7S_WIDTHE`'s
/// trailing hex, ...) with a placeholder, leaving everything else about
/// the token alone. Ghidra always spells these as the token's own name
/// plus an underscore plus 6+ hex digits, so that shape -- not a fixed
/// prefix list -- is what's matched; a real source identifier practically
/// never ends that way by coincidence.
fn normalize_token(token: &str) -> String {
    let hex_len = token.chars().rev().take_while(char::is_ascii_hexdigit).count();
    if hex_len < 6 {
        return token.to_string();
    }
    let cut = token.len() - hex_len;
    if token.as_bytes().get(cut.wrapping_sub(1)) == Some(&b'_') {
        format!("{}<ADDR>", &token[..cut])
    } else {
        token.to_string()
    }
}

/// Normalizes a decompiled body so two different addresses whose only
/// difference is which specific global/vtable/string they reference
/// fingerprint the same, while genuinely different logic (different
/// literals, different call targets) still doesn't. Deliberately
/// conservative: this is for "the exact same code, seen at two
/// addresses" (duplicate/COMDAT-folded functions), not "structurally
/// similar" -- two different classes' `draw()` methods that call
/// different things are not expected to normalize to the same text.
fn normalize_body(decompiled: &str) -> String {
    let mut out = String::with_capacity(decompiled.len());
    let mut token = String::new();
    for c in decompiled.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            token.push(c);
        } else {
            if !token.is_empty() {
                out.push_str(&normalize_token(&token));
                token.clear();
            }
            out.push(c);
        }
    }
    if !token.is_empty() {
        out.push_str(&normalize_token(&token));
    }
    out
}

/// A compact, deterministic (within one process/build -- `DefaultHasher`
/// is fixed-keyed, not randomized like `HashMap`'s `RandomState`) stand-in
/// for a subject's normalized body, cheap to compare and store. Not
/// cryptographic; collisions would only ever cause a missed cache hit
/// (falling back to a real investigation), never a wrong one being
/// accepted without its own verification pass.
pub fn fingerprint(decompiled: &str) -> String {
    let normalized = normalize_body(decompiled);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    normalized.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn fingerprint_for_subject(graph: &KnowledgeGraph, subject: &str) -> Option<String> {
    let decompiled = latest_value(graph, subject, "decompiles_to")?;
    if decompiled.trim().is_empty() {
        return None;
    }
    Some(fingerprint(decompiled))
}

/// Before a subject gets a fresh `AnalyzeFunction` call, check whether
/// another subject with the exact same (normalized) decompiled body
/// already has an ACCEPTED `semantic_role` -- if so, clone every accepted
/// hypothesis from that subject onto this one instead of spending a
/// model call on code we've already solved once. The clone still goes
/// through the normal `ChallengeHypothesis` follow-up (returned here so
/// the caller can enqueue it): it's a shortcut past re-investigating, not
/// past re-verifying.
///
/// `candidates` is the same subject list `seed_initial_tasks` is about to
/// seed from -- passed in rather than recomputed so this can run once,
/// before seeding, without scanning the graph twice for "already
/// analyzed."
pub(crate) fn apply_fingerprint_cache(graph: &mut KnowledgeGraph, candidates: &[String]) -> Vec<Task> {
    let mut solved_by_fingerprint: HashMap<String, String> = HashMap::new();
    for h in graph
        .hypotheses()
        .filter(|h| h.predicate == "semantic_role" && h.status == HypothesisStatus::Accepted)
    {
        if let Some(fp) = fingerprint_for_subject(graph, &h.subject) {
            solved_by_fingerprint.entry(fp).or_insert_with(|| h.subject.clone());
        }
    }

    let mut followups = Vec::new();
    for subject in candidates {
        let Some(fp) = fingerprint_for_subject(graph, subject) else {
            continue;
        };
        let Some(matched) = solved_by_fingerprint.get(&fp).filter(|m| *m != subject) else {
            continue;
        };
        let matched = matched.clone();

        let accepted: Vec<_> = graph
            .hypotheses()
            .filter(|h| h.subject == matched && h.status == HypothesisStatus::Accepted)
            .cloned()
            .collect();
        if accepted.is_empty() {
            continue;
        }

        graph.add_observation(
            subject.clone(),
            "fingerprint_cache_source",
            matched.clone(),
            1.0,
            "debura:fingerprint_cache",
            None,
        );
        for h in accepted {
            let proposed = ProposedHypothesis {
                predicate: h.predicate,
                value: h.value,
                confidence: h.confidence,
                depends_on: Vec::new(),
            };
            let new_id = commit_hypothesis(graph, subject, &proposed, None);
            followups.push(Task::ChallengeHypothesis { hypothesis: new_id });
        }
        tracing::info!(%subject, matched, "reused accepted hypotheses from a structurally identical subject");
    }

    followups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ghidra_address_suffixes_but_keeps_everything_else() {
        let a = "iVar1 = *(int *)(this + 8) - DAT_140009070; PTR_draw_140009a40->call();";
        let b = "iVar1 = *(int *)(this + 8) - DAT_1400091a0; PTR_draw_140009b71->call();";
        assert_eq!(fingerprint(a), fingerprint(b));
    }

    #[test]
    fn different_literals_or_call_targets_still_differ() {
        let a = "return *(int *)(this + 8) + 1;";
        let b = "return *(int *)(this + 8) + 2;";
        assert_ne!(fingerprint(a), fingerprint(b));

        let c = "Collideable::operator=((Collideable *)this,(Collideable *)param_1);";
        let d = "Drawable::operator=((Drawable *)this,(Drawable *)param_1);";
        assert_ne!(fingerprint(c), fingerprint(d));
    }

    #[test]
    fn short_numeric_tails_are_not_mistaken_for_addresses() {
        // "param_1" ends in a digit but not 6+ hex digits -- must not be
        // touched, or every function's own parameter names would collide.
        assert_eq!(normalize_token("param_1"), "param_1");
        assert_eq!(normalize_token("local_c"), "local_c");
    }
}
