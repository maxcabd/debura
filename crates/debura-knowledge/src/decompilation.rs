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

/// A decompilation whose body is empty, just an elided `{...}`
/// placeholder (Ghidra emits this on some re-analysis passes for a
/// subject it successfully decompiled fully on an earlier pass), or --
/// a real case a real recovery run found -- contains nothing but a
/// comment (`{\n // body omitted for brevity\n}`, a non-Ghidra shape:
/// no decompiler ever writes English prose, so this can only be a
/// model-generated placeholder that got stored as if it were a real
/// decompilation). The exact-`{...}` check alone let that second shape
/// silently outrank an earlier, real, complete decompilation for the
/// same address -- `latest_decompilation`'s whole "prefer substantive
/// over degenerate" contract only works if every real degenerate shape
/// is actually recognized as one.
pub fn is_degenerate_decompilation(text: &str) -> bool {
    let Some(idx) = text.find('{') else { return true };
    let remainder = text[idx..].trim();
    if matches!(remainder, "{...}" | "{ ... }") {
        return true;
    }
    match remainder.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        Some(body) => body_has_only_comments_or_whitespace(body) || has_uninitialized_pointer_dereference(body),
        None => true,
    }
}

/// A body that declares a local pointer, never assigns it a value anywhere,
/// and dereferences it anyway -- real, observed Ghidra output from a stale
/// re-analysis pass (`FUN_140006750`'s two real observations for the same
/// address: an earlier, complete body computes a real value through
/// `puVar1`; a later pass produced just `ulonglong *puVar1; return
/// *puVar1;`, syntactically valid C that can only ever read garbage off the
/// stack). Not caught by the comment-only check above -- this is real code,
/// just code no real computation ever produces. `latest_decompilation`'s
/// "prefer substantive" contract only holds if this shape is recognized as
/// degenerate too, so a later stale pass never silently outranks an
/// earlier, real body for the same address.
fn has_uninitialized_pointer_dereference(body: &str) -> bool {
    for (decl_line_no, line) in body.lines().enumerate() {
        let Some(name) = declared_pointer_local_name(line) else {
            continue;
        };
        let mut assigned = false;
        let mut dereferenced = false;
        for (line_no, other) in body.lines().enumerate() {
            if line_no == decl_line_no {
                continue;
            }
            if is_bare_assignment(other, name) {
                assigned = true;
            }
            if is_dereferenced(other, name) {
                dereferenced = true;
            }
        }
        if !assigned && dereferenced {
            return true;
        }
    }
    false
}

/// Ghidra keywords that can legitimately precede a `*expr` in a statement
/// without that statement being a pointer declaration -- excluded so
/// `return *puVar1;` is never mistaken for a declaration of a local named
/// `puVar1` with type `return`.
const NOT_A_TYPE: &[&str] = &["return", "if", "while", "for", "switch", "case", "break", "continue", "else", "do", "goto"];

/// Whether `line` is a simple, single-declarator pointer-local declaration
/// (`TYPE *name;`), and if so, the declared name. Deliberately narrow: no
/// `=` (an initialized declaration already has its value), no `(` (rules
/// out both function declarations and any statement with a call in it), no
/// `,` (rules out multi-declarator lines this pass doesn't need to
/// handle).
fn declared_pointer_local_name(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let inner = trimmed.strip_suffix(';')?;
    if inner.contains('=') || inner.contains('(') || inner.contains(',') {
        return None;
    }
    let star_pos = inner.rfind('*')?;
    let name = inner[star_pos + 1..].trim();
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    if name.chars().next()?.is_ascii_digit() {
        return None;
    }
    let type_part = inner[..star_pos].trim();
    if type_part.is_empty() || NOT_A_TYPE.contains(&type_part.rsplit(char::is_whitespace).next().unwrap_or(type_part)) {
        return None;
    }
    Some(name)
}

/// Whether `line` contains a bare `name = ...` (not `==`, and not `*name =
/// ...`, which assigns through the pointer rather than to it).
fn is_bare_assignment(line: &str, name: &str) -> bool {
    for (i, _) in line.match_indices(name) {
        if !is_identifier_boundary(line, i, name.len()) {
            continue;
        }
        if line[..i].trim_end().ends_with('*') {
            continue;
        }
        let after = line[i + name.len()..].trim_start();
        if after.starts_with('=') && !after.starts_with("==") {
            return true;
        }
    }
    false
}

/// Whether `line` dereferences `name` (`*name` or `name->`).
fn is_dereferenced(line: &str, name: &str) -> bool {
    for (i, _) in line.match_indices(name) {
        if !is_identifier_boundary(line, i, name.len()) {
            continue;
        }
        if line[..i].trim_end().ends_with('*') {
            return true;
        }
        if line[i + name.len()..].starts_with("->") {
            return true;
        }
    }
    false
}

/// Whether the occurrence of a `len`-byte identifier starting at byte
/// offset `start` in `line` is a whole identifier, not a substring of a
/// longer one (`puVar1` inside `puVar10`).
fn is_identifier_boundary(line: &str, start: usize, len: usize) -> bool {
    let before_ok = line[..start].chars().next_back().is_none_or(|c| !c.is_alphanumeric() && c != '_');
    let end = start + len;
    let after_ok = line[end..].chars().next().is_none_or(|c| !c.is_alphanumeric() && c != '_');
    before_ok && after_ok
}

/// Whether `body` (the text strictly between a decompilation's own outer
/// `{`/`}`) contains any real code at all -- `false` the moment a
/// non-whitespace character outside a `//`/`/* */` comment is found. A
/// genuinely empty function body still has at least one real statement
/// in Ghidra's own output (`return;`, at minimum); only a
/// model-generated or otherwise fabricated placeholder ever has nothing
/// but a comment.
fn body_has_only_comments_or_whitespace(body: &str) -> bool {
    let mut chars = body.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if body[i..].starts_with("//") {
            for (_, c2) in chars.by_ref() {
                if c2 == '\n' {
                    break;
                }
            }
            continue;
        }
        if body[i..].starts_with("/*") {
            let Some(end) = body[i + 2..].find("*/") else {
                // Unterminated block comment -- nothing real can follow
                // it within this body.
                return true;
            };
            let skip_to = i + 2 + end + 2;
            while let Some(&(j, _)) = chars.peek() {
                if j >= skip_to {
                    break;
                }
                chars.next();
            }
            continue;
        }
        return false;
    }
    true
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

    /// The real, confirmed case a real recovery run found: a later
    /// observation whose body is nothing but an English-prose comment
    /// (`// body omitted for brevity`) -- no Ghidra decompiler pass ever
    /// writes that shape, only a model-generated placeholder does.
    /// Silently outranking the earlier, real, complete decompilation for
    /// the same address (`FUN_140006870`, a real `std::vector` growth
    /// helper) corrupted a vector's own "end" pointer at runtime: its
    /// caller expected the real body's real writes, got an empty
    /// function instead.
    #[test]
    fn a_comment_only_placeholder_is_recognized_as_degenerate() {
        assert!(is_degenerate_decompilation(
            "void FUN_140006870(void **param_1,undefined8 param_2)\n\n{\n // body omitted for brevity\n}"
        ));
    }

    #[test]
    fn prefers_an_earlier_real_decompilation_over_a_later_comment_only_placeholder() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation(
            "0x140006870",
            "decompiles_to",
            "void FUN_140006870(void **param_1,undefined8 param_2)\n\n{\n  param_1[1] = param_2;\n  return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        graph.add_observation(
            "0x140006870",
            "decompiles_to",
            "void FUN_140006870(void **param_1,undefined8 param_2)\n\n{\n // body omitted for brevity\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );

        let latest = latest_decompilation(&graph, "0x140006870").unwrap();
        assert!(latest.value.contains("param_1[1] = param_2;"), "{}", latest.value);
    }

    /// A real, trivial body (just `return;`, real Ghidra output for a
    /// genuinely empty function) must never be mistaken for a
    /// placeholder -- it has real code, just not much of it.
    #[test]
    fn a_trivial_but_real_body_is_not_degenerate() {
        assert!(!is_degenerate_decompilation("void FUN_1(void)\n\n{\n  return;\n}"));
    }

    /// A real body that happens to contain a comment (Ghidra's own
    /// `/* WARNING: ... */` decompiler notes, a real, previously-seen
    /// shape) alongside real code must not be mistaken for a
    /// comment-only placeholder either.
    #[test]
    fn a_real_body_with_a_leading_comment_is_not_degenerate() {
        assert!(!is_degenerate_decompilation(
            "void FUN_1(void)\n\n{\n  /* WARNING: unknown */\n  real_call();\n  return;\n}"
        ));
    }

    /// The real, confirmed case: `FUN_140006750`'s later observation, a
    /// stale re-analysis pass that declared `puVar1` and dereferenced it
    /// without ever assigning it a value.
    #[test]
    fn a_body_that_dereferences_an_unassigned_pointer_local_is_degenerate() {
        assert!(is_degenerate_decompilation(
            "ulonglong FUN_140006750(undefined8 param_1)\n{\n ulonglong *puVar1;\n return *puVar1;\n}"
        ));
    }

    /// The same address's earlier, real observation -- `puVar1` is declared,
    /// assigned from a real call, and only then dereferenced -- must not be
    /// mistaken for the degenerate shape above.
    #[test]
    fn a_body_that_assigns_a_pointer_local_before_dereferencing_it_is_not_degenerate() {
        assert!(!is_degenerate_decompilation(
            "ulonglong FUN_140006750(undefined8 param_1)\n\n{\n  ulonglong *puVar1;\n  ulonglong local_30;\n  \n  local_30 = param_1;\n  puVar1 = FUN_140007800(&local_30);\n  return *puVar1;\n}"
        ));
    }

    /// `return *ptr;` must never be mistaken for a declaration of a local
    /// named `ptr` with type `return` -- `NOT_A_TYPE` exists specifically
    /// to keep control-flow keywords from being parsed as pointer types.
    #[test]
    fn a_bare_return_of_a_dereference_is_not_mistaken_for_a_declaration() {
        assert!(!is_degenerate_decompilation(
            "int FUN_1(int *ptr)\n\n{\n  return *ptr;\n}"
        ));
    }

    /// `latest_decompilation` itself must prefer the earlier, real body
    /// over this specific degenerate shape, end to end -- the real
    /// regression `FUN_140006750` exhibited before this fix.
    #[test]
    fn latest_decompilation_prefers_the_real_body_over_a_stale_uninitialized_read() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation(
            "0x140006750",
            "decompiles_to",
            "ulonglong FUN_140006750(undefined8 param_1)\n\n{\n  ulonglong *puVar1;\n  ulonglong local_30;\n  \n  local_30 = param_1;\n  puVar1 = FUN_140007800(&local_30);\n  return *puVar1;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        graph.add_observation(
            "0x140006750",
            "decompiles_to",
            "ulonglong FUN_140006750(undefined8 param_1)\n{\n ulonglong *puVar1;\n return *puVar1;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );

        let latest = latest_decompilation(&graph, "0x140006750").unwrap();
        assert!(latest.value.contains("FUN_140007800"), "{}", latest.value);
    }
}
