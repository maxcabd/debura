/// PROJECT.md M18.3/M19: a real Ghidra decompiler bug found by hand while
/// getting the Snake binary to actually run -- a self-collision-check
/// loop in the real recovered `Screen::update` render loop passed a
/// declared-but-never-initialized local (`local_a8`) to the exact same
/// vector-accessor pair (`size()`/`operator[]`-shaped helpers) every
/// *other* real caller in the program reaches through a fixed field
/// offset from its own object parameter (`this + 0x10`, Snake's own
/// `m_sections` vector). Ghidra's decompiler failed to recognize this as
/// a second access to that already-reachable field and invented a
/// separate, uninitialized stack slot instead. Confirmed by real tracing
/// to corrupt the stack in a way that only manifested much later, as a
/// null-pointer call deep inside `SDL_RenderPresent` -- silently emitting
/// this as valid C++ is a real correctness bug in the *generated*
/// program, not just an inconvenience.
///
/// This module generalizes that fix into a real, structural pass instead
/// of leaving it as a one-off hand patch: it finds locals that provably
/// can never hold a value (see `is_ever_assigned`'s own doc comment) and,
/// where the rest of the program provides strong enough evidence for
/// exactly one safe replacement, rewrites the local away entirely.
/// "Strong enough evidence" is deliberately narrow -- see
/// `find_alias_replacement`'s own doc comment -- a local this module
/// can't confidently resolve is left exactly as Ghidra decompiled it
/// (matching this crate's own "unknown is better than confidently wrong"
/// principle throughout); a future pass could still surface it as a
/// flagged review item, but this one never guesses.
///
/// **Scope, and the real dependency this pass had on `stack_object.rs`**:
/// a replacement base is either a parameter *already declared as a
/// byte-granular pointer*, or `&LOCAL` where `LOCAL` is confirmed (by
/// text, never guessed) to be a real `unsigned char LOCAL[N]` array --
/// exactly what `stack_object.rs` produces once it's reconstructed a
/// fragmented object. This module first shipped *without* the `&LOCAL`
/// case: on that same night's real Snake output, `initializeRandomState`
/// hadn't been split into a smaller function taking Snake by pointer,
/// so the real Snake object was reached as `&local_b8`, and `local_b8`
/// itself was still Ghidra's own stale, too-narrow scalar declaration --
/// accepting `&local_b8` as a base then would have meant trusting an
/// *unconfirmed* element type, silently risking a pointer-arithmetic bug
/// at the wrong scale, exactly the class of mistake this module exists
/// to prevent. Once `stack_object.rs` landed and started correctly
/// widening `local_b8` into a real byte array first, this pass was
/// extended to accept `&LOCAL` too -- but only ever when
/// `caller_local_is_byte_array` can point at the literal, already-
/// rewritten declaration confirming it, never by inferring it from the
/// call site alone. Confirmed end-to-end against a real, fresh
/// regeneration of Snake: with both passes wired in (`stack_object.rs`
/// running first), `local_a8` -- the exact case that motivated this
/// whole module -- now resolves automatically.
use std::collections::HashMap;

use crate::forwarding_thunk::{matching_close, parse_int_literal, parse_param_names, split_top_level_comma};
use crate::model::RecoveredFunction;

/// Every call expression `NAME(ARGS)` found anywhere in `text`, however
/// deeply nested inside control-flow constructs (`for`/`while`/`switch`,
/// none of which this crate's existing `split_top_level_statements`
/// understands) or other expressions -- this module only ever needs
/// "what gets called with what," never real statement structure, so it
/// scans the raw text directly instead of requiring a full parse. Also
/// matches `if`/`for`/`while`/`switch` themselves as spurious "calls"
/// (an identifier immediately followed by `(`) -- harmless, since every
/// real lookup in this module searches for a specific, real callee name
/// that keyword text never equals.
pub(crate) fn find_calls(text: &str) -> Vec<(&str, &str)> {
    let mut calls = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b':') {
                i += 1;
            }
            let name = &text[start..i];
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if bytes.get(j) == Some(&b'(') {
                if let Some(close) = matching_close(text, j, b'(', b')') {
                    calls.push((name, &text[j + 1..close]));
                    i = j + 1;
                    continue;
                }
            }
            continue;
        }
        i += 1;
    }
    calls
}

/// Repeatedly strips a leading C-style cast (`(TYPE)`/`(TYPE *)`) and any
/// fully-redundant surrounding parens until neither remains. A leading
/// `(...)` is a cast exactly when more text follows its own matching
/// close paren (`(longlong *)(param_1 + 0x10)`); when the closing paren
/// is the last character, the parens are always safe to drop --  either
/// a cast with nothing after it (which could never be a complete
/// argument expression anyway) or genuinely redundant grouping around a
/// real expression (`((longlong)snake)` -> `(longlong)snake` -> `snake`).
pub(crate) fn strip_casts_and_parens(expr: &str) -> &str {
    let mut expr = expr.trim();
    while expr.starts_with('(') {
        let Some(close) = matching_close(expr, 0, b'(', b')') else { break };
        if close == expr.len() - 1 {
            expr = expr[1..close].trim();
        } else {
            expr = expr[close + 1..].trim();
        }
    }
    expr
}

/// `expr`, stripped of casts/redundant parens, if what remains is
/// exactly `IDENT + LITERAL` or `IDENT - LITERAL` (a field-offset access
/// off a single named object) -- `None` for anything more complex than
/// that one shape, on purpose: this module only ever trusts a field
/// access it can attribute unambiguously to one identifier and one
/// constant.
fn match_ident_plus_offset(expr: &str) -> Option<(&str, i64)> {
    let expr = strip_casts_and_parens(expr);
    let (ident, lit, sign): (&str, &str, i64) = if let Some((a, b)) = expr.split_once('+') {
        (a, b, 1)
    } else if let Some((a, b)) = expr.split_once('-') {
        (a, b, -1)
    } else {
        return None;
    };
    let ident = ident.trim();
    let mut chars = ident.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let offset = parse_int_literal(lit.trim())? as i64 * sign;
    Some((ident, offset))
}

/// Whether adding a byte offset to a parameter of this declared type
/// gives the intended byte address rather than one scaled by
/// `sizeof` -- true for a raw integer type (no `*` at all, e.g.
/// `longlong`/`undefined8`, the common "address held as an integer"
/// shape this codebase's own recovered bodies already use everywhere for
/// this exact kind of field access) or an explicit single-byte pointer
/// (`char *`/`unsigned char *`/`void *`); false for any other pointer
/// type, where real C++ arithmetic would scale by that type's own size
/// instead of walking raw bytes. `None` if `name` isn't declared among
/// `params` at all.
fn param_is_byte_granular(params: &str, name: &str) -> Option<bool> {
    for p in params.split(',') {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let ident = p.rsplit(|c: char| c == ' ' || c == '*').find(|s| !s.is_empty())?;
        if ident != name {
            continue;
        }
        let type_text = p[..p.len() - ident.len()].trim();
        if !type_text.contains('*') {
            return Some(true);
        }
        let base = type_text.trim_end_matches('*').trim();
        return Some(matches!(base, "char" | "unsigned char" | "void" | "const char" | "const unsigned char" | "const void"));
    }
    None
}

/// Splits a function body (the text strictly between its own `{`/`}`)
/// into its leading locals-declaration block and everything after --
/// every real decompiled function body this crate has seen declares
/// every local up front, one per line, followed by exactly one blank
/// separator line before the first real statement. That separator line
/// is blank only after trimming -- Ghidra's own real output often still
/// indents it (e.g. two spaces, matching its neighbors), so a literal
/// `"\n\n"` search never matches real bodies; this scans line by line
/// instead. `None` if that exact shape isn't found (a function with no
/// locals at all, or one whose shape this module doesn't recognize)
/// rather than guessing at a different split point.
pub(crate) fn split_locals_block(body: &str) -> Option<(&str, &str)> {
    let mut offset = 0usize;
    for line in body.split_inclusive('\n') {
        if line.trim().is_empty() && offset > 0 {
            return Some((&body[..offset], &body[offset..]));
        }
        offset += line.len();
    }
    None
}

/// The declared name of each local a locals-declaration block declares,
/// in order -- the trailing identifier on each line, before a trailing
/// `;` or an array-bound `[`.
pub(crate) fn declared_local_names(locals_block: &str) -> Vec<&str> {
    locals_block
        .lines()
        .filter_map(|line| {
            let line = line.trim().trim_end_matches(';').trim();
            if line.is_empty() {
                return None;
            }
            let before_bracket = line.split('[').next().unwrap_or(line).trim();
            before_bracket.rsplit(|c: char| c == ' ' || c == '*').find(|s| !s.is_empty())
        })
        .collect()
}

/// Whether `name` is ever given a defined value anywhere in `body` --
/// checked as a whole-identifier match (so `local_a8` never matches
/// inside `local_a80`) and deliberately broad about what counts as
/// "given a value": a plain assignment (but not `==`/`<=`/`>=`/`!=`), a
/// compound assignment, an increment/decrement, or its address being
/// taken (passed to some real constructor-shaped call). This only exists
/// to rule OUT locals that really are used normally, so it must never
/// under-count a real assignment -- a false "never assigned" here would
/// mean silently discarding a real value.
pub(crate) fn is_ever_assigned(name: &str, body: &str) -> bool {
    for (i, _) in body.match_indices(name) {
        let before_ok = body[..i].chars().next_back().is_none_or(|c| !c.is_alphanumeric() && c != '_');
        let after = &body[i + name.len()..];
        let after_ok = after.chars().next().is_none_or(|c| !c.is_alphanumeric() && c != '_');
        if !before_ok || !after_ok {
            continue;
        }
        if body[..i].trim_end().ends_with('&') {
            return true;
        }
        let after_trimmed = after.trim_start();
        if let Some(rest) = after_trimmed.strip_prefix('=') {
            if !rest.starts_with('=') {
                return true;
            }
        }
        for op in ["+=", "-=", "*=", "/=", "++", "--"] {
            if after_trimmed.starts_with(op) {
                return true;
            }
        }
        // An indexed write (`name[EXPR] = ...`) is also a real
        // assignment -- checked separately since the immediate next
        // character is `[`, not `=`.
        if after_trimmed.starts_with('[') {
            if let Some(close) = matching_close(after_trimmed, 0, b'[', b']') {
                let post_index = after_trimmed[close + 1..].trim_start();
                if let Some(rest) = post_index.strip_prefix('=') {
                    if !rest.starts_with('=') {
                        return true;
                    }
                }
                for op in ["+=", "-=", "*=", "/="] {
                    if post_index.starts_with(op) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Every callee `name` is passed to as a bare, unadorned argument
/// (after stripping casts/redundant parens) anywhere in `body` -- never
/// `&name` (that would mean something really does initialize it) and
/// never `name` buried inside a larger expression (`name + 1`, say --
/// not the shape this module knows how to reason about).
fn callees_receiving_bare_identifier<'a>(body: &'a str, name: &str) -> Vec<&'a str> {
    let mut callees = Vec::new();
    for (callee, args_text) in find_calls(body) {
        for arg in split_top_level_comma(args_text) {
            if strip_casts_and_parens(arg) == name {
                callees.push(callee);
            }
        }
    }
    callees
}

/// For every function in `functions`: every call site within its own
/// body shaped `CALLEE(PARAM + OFFSET, ...)` (checked only in the first
/// argument position, matching this codebase's own heavy "argument 0 is
/// the object" convention) where `PARAM` is one of that *same*
/// function's own declared parameters, and that parameter's type makes
/// `+ OFFSET` a real byte address rather than a `sizeof`-scaled one --
/// recorded as "this function is a known, safe passthrough to CALLEE at
/// a fixed field offset from its own object parameter." Keyed by the
/// callee's raw `FUN_<addr>` name: this pass runs before call sites are
/// rewritten against the whole-program symbol table, so every call site
/// is still spelled that way.
fn build_offset_passthrough_facts(functions: &[RecoveredFunction]) -> HashMap<String, Vec<(String, i64)>> {
    let mut facts: HashMap<String, Vec<(String, i64)>> = HashMap::new();
    for f in functions {
        let brace_open = match f.decompilation.find('{') {
            Some(i) => i,
            None => continue,
        };
        let Some(params) = parse_param_names(&f.decompilation[..brace_open + 1]) else { continue };
        for (callee, args_text) in find_calls(&f.decompilation) {
            let Some(first_arg) = split_top_level_comma(args_text).into_iter().next() else { continue };
            let Some((ident, offset)) = match_ident_plus_offset(first_arg) else { continue };
            if !params.iter().any(|p| p == ident) {
                continue;
            }
            if param_is_byte_granular(&f.params, ident) != Some(true) {
                continue;
            }
            // Recorded under *both* names: a project whose earlier
            // `debura apply` run already renamed `f` in Ghidra itself
            // has every one of `f`'s own call sites (system-wide, since
            // Ghidra's own decompiler always uses a symbol's *current*
            // name) showing the pretty name, not `f.raw_name` -- and
            // `find_alias_replacement` below has no way to know which
            // form a given caller's own text uses. Confirmed against a
            // real, fresh regeneration of Snake, where this was a real,
            // silent gap (not merely a hypothetical one).
            facts.entry(callee.to_string()).or_default().push((f.raw_name.clone(), offset));
            if f.display_name != f.raw_name {
                facts.entry(callee.to_string()).or_default().push((f.display_name.clone(), offset));
            }
        }
    }
    facts
}

/// The single, unambiguous replacement for a phantom local passed to
/// `callees` within `caller` -- or `None` if the evidence doesn't
/// converge on exactly one answer. For each callee the local is passed
/// to, this looks up which *other* functions are known (via
/// `passthrough`) to reach that same callee through a fixed offset off
/// their own object parameter, then checks whether `caller`'s own body
/// calls any of those functions with a bare, byte-granular parameter of
/// its own as the first argument -- if so, that parameter plus that
/// offset is the real object the phantom local should have aliased.
/// Deliberately requires every callee/evidence path that produces an
/// answer at all to agree on the exact same `(identifier, offset)` pair
/// before accepting it: a real fix is never guessed from a single, weak
/// signal when the local is used in more than one place.
/// Whether `caller_decompilation`'s own locals-declaration block
/// declares `name` as a real `unsigned char name[N]` array -- exactly
/// the shape `stack_object.rs`'s own reconstruction produces for a
/// correctly-widened stack object. Confirming this makes a call-site
/// argument `&name` exactly as safe a base as a byte-granular parameter
/// already was: `&name`'s own C++ type (pointer-to-array) differs from
/// the array's own decayed pointer type, but the numeric address is
/// identical either way, and this module's own replacement always uses
/// the bare name (relying on that same decay), never the `&` itself.
fn caller_local_is_byte_array(caller_decompilation: &str, name: &str) -> bool {
    caller_decompilation.contains(&format!("unsigned char {}[", name))
}

fn find_alias_replacement(
    caller: &RecoveredFunction,
    callees: &[&str],
    passthrough: &HashMap<String, Vec<(String, i64)>>,
) -> Option<(String, i64)> {
    let mut candidates: Vec<(String, i64)> = Vec::new();
    for callee in callees {
        let Some(known_passthroughs) = passthrough.get(*callee) else { continue };
        for (via_fn, offset) in known_passthroughs {
            for (name, args_text) in find_calls(&caller.decompilation) {
                if name != via_fn {
                    continue;
                }
                let Some(first_arg) = split_top_level_comma(args_text).into_iter().next() else { continue };
                let raw_ident = strip_casts_and_parens(first_arg);
                // `&LOCAL`, where `LOCAL` is confirmed (not guessed) to
                // be a real byte array `stack_object.rs` already
                // reconstructed -- use the bare name (array decay), not
                // the `&` itself, as the base for arithmetic. Anything
                // else starting with `&` (a scalar's address, or a name
                // this module can't confirm is byte-granular) is
                // rejected, matching this module's existing "never
                // guess" discipline -- see this function's own former
                // "known scope limit" doc note, now narrowed to exactly
                // this one additional, confirmed-safe case.
                let ident = match raw_ident.strip_prefix('&') {
                    Some(bare) if caller_local_is_byte_array(&caller.decompilation, bare) => bare,
                    Some(_) => continue,
                    None => raw_ident,
                };
                if ident.is_empty() || !ident.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
                    continue;
                }
                if !ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    continue;
                }
                if raw_ident == ident && param_is_byte_granular(&caller.params, ident) != Some(true) {
                    continue;
                }
                let candidate = (ident.to_string(), *offset);
                if !candidates.contains(&candidate) {
                    candidates.push(candidate);
                }
            }
        }
    }
    match candidates.len() {
        1 => candidates.into_iter().next(),
        _ => None,
    }
}

/// Replaces every whole-identifier occurrence of `name` in `text` with
/// `replacement`, parenthesized -- a plain substring replace would also
/// hit `name` as a prefix of some longer identifier, which whole-word
/// matching (the same check `is_ever_assigned` uses) rules out.
pub(crate) fn replace_whole_identifier(text: &str, name: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(name) {
        let before_ok = rest[..pos].chars().next_back().is_none_or(|c| !c.is_alphanumeric() && c != '_');
        let after = &rest[pos + name.len()..];
        let after_ok = after.chars().next().is_none_or(|c| !c.is_alphanumeric() && c != '_');
        out.push_str(&rest[..pos]);
        if before_ok && after_ok {
            out.push_str(replacement);
        } else {
            out.push_str(name);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Removes `name`'s own declaration line from `locals_block` (the exact
/// line `declared_local_names` attributed it to), trimming the blank
/// line left behind if removing it empties the block entirely.
pub(crate) fn remove_declaration(locals_block: &str, name: &str) -> String {
    let kept: String = locals_block
        .lines()
        .filter(|line| {
            let trimmed = line.trim().trim_end_matches(';').trim();
            let before_bracket = trimmed.split('[').next().unwrap_or(trimmed).trim();
            before_bracket.rsplit(|c: char| c == ' ' || c == '*').find(|s| !s.is_empty()) != Some(name)
        })
        .collect::<Vec<_>>()
        .join("\n");
    // `locals_block` (per `split_locals_block`'s own construction)
    // always ends with a trailing newline, right before the real blank
    // separator line that starts `stmts_block`; `.lines().join("\n")`
    // drops it. Losing it here silently merges the last remaining
    // declaration onto the same line as that separator once this gets
    // concatenated back with `stmts_block` -- destroying the only blank
    // line `split_locals_block` looks for on any *later* pass over this
    // same body (a real, confirmed regression: `stack_object.rs`
    // widening `local_b8` and merging its own siblings left
    // `initializeRandomState`'s own locals block with no blank
    // separator left at all, so `phantom_local.rs`'s own later pass
    // over the very same function silently found nothing to do).
    if kept.is_empty() {
        kept
    } else {
        kept + "\n"
    }
}

/// Finds every phantom local (declared, never given a value -- see
/// `is_ever_assigned`) in every function's decompiled body and, wherever
/// the rest of the program provides unambiguous evidence for exactly one
/// safe replacement (see `find_alias_replacement`), rewrites it away:
/// drops the declaration and replaces every use with the real object
/// expression it should have aliased. A phantom local this module can't
/// confidently resolve is left exactly as Ghidra decompiled it.
pub fn generalize_phantom_local_aliases(functions: &mut [RecoveredFunction]) {
    let passthrough = build_offset_passthrough_facts(functions);

    for i in 0..functions.len() {
        let decompilation = functions[i].decompilation.clone();
        let Some(brace_open) = decompilation.find('{') else { continue };
        let Some(brace_close) = matching_close(&decompilation, brace_open, b'{', b'}') else { continue };
        let body = &decompilation[brace_open + 1..brace_close];
        let Some((locals_block, stmts_block)) = split_locals_block(body) else { continue };

        let mut new_locals_block = locals_block.to_string();
        let mut new_stmts_block = stmts_block.to_string();
        let mut changed = false;

        for name in declared_local_names(locals_block) {
            if is_ever_assigned(name, stmts_block) {
                continue;
            }
            let callees = callees_receiving_bare_identifier(stmts_block, name);
            if callees.is_empty() {
                continue;
            }
            let Some((replacement_ident, offset)) = find_alias_replacement(&functions[i], &callees, &passthrough)
            else {
                continue;
            };
            let replacement = if offset >= 0 {
                format!("({} + 0x{:x})", replacement_ident, offset)
            } else {
                format!("({} - 0x{:x})", replacement_ident, -offset)
            };
            new_locals_block = remove_declaration(&new_locals_block, name);
            new_stmts_block = replace_whole_identifier(&new_stmts_block, name, &replacement);
            changed = true;
        }

        if changed {
            functions[i].decompilation = format!(
                "{}{}{}{}",
                &decompilation[..brace_open + 1],
                new_locals_block,
                new_stmts_block,
                &decompilation[brace_close..]
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{NameSource, RecoveredFunction};

    fn function(address: &str, params: &str, decompilation: &str) -> RecoveredFunction {
        let raw_name = format!("FUN_{}", &address[2..]);
        RecoveredFunction {
            address: address.to_string(),
            raw_name: raw_name.clone(),
            display_name: raw_name,
            name_source: NameSource::Raw,
            return_type: "undefined".to_string(),
            params: params.to_string(),
            decompilation: decompilation.to_string(),
        }
    }

    #[test]
    fn strips_casts_and_redundant_parens() {
        assert_eq!(strip_casts_and_parens("(longlong *)(param_1 + 0x10)"), "param_1 + 0x10");
        assert_eq!(strip_casts_and_parens("((longlong)snake)"), "snake");
        assert_eq!(strip_casts_and_parens("(longlong)((longlong)snake)"), "snake");
    }

    #[test]
    fn matches_identifier_plus_hex_offset() {
        assert_eq!(match_ident_plus_offset("(longlong *)(param_1 + 0x10)"), Some(("param_1", 0x10)));
        assert_eq!(match_ident_plus_offset("param_1 - 0x8"), Some(("param_1", -8)));
        assert_eq!(match_ident_plus_offset("param_1"), None);
        assert_eq!(match_ident_plus_offset("param_1 + param_2"), None);
    }

    #[test]
    fn byte_granular_types_are_recognized() {
        assert_eq!(param_is_byte_granular("longlong param_1", "param_1"), Some(true));
        assert_eq!(param_is_byte_granular("unsigned char *snake", "snake"), Some(true));
        assert_eq!(param_is_byte_granular("void *screen", "screen"), Some(true));
        assert_eq!(param_is_byte_granular("Section *param_1", "param_1"), Some(false));
        assert_eq!(param_is_byte_granular("longlong param_1", "other"), None);
    }

    #[test]
    fn a_local_never_assigned_is_detected() {
        let body = "  longlong *plVar6;\n  \n  plVar6 = FUN_1(local_a8);\n  return;\n";
        assert!(is_ever_assigned("plVar6", body), "sanity: plVar6 IS assigned");
        assert!(!is_ever_assigned("local_a8", body));
    }

    #[test]
    fn a_local_assigned_a_value_is_not_a_phantom() {
        let body = "  local_a8 = FUN_1();\n  FUN_2(local_a8);\n  return;\n";
        assert!(is_ever_assigned("local_a8", body));
    }

    #[test]
    fn a_local_whose_address_is_taken_is_not_a_phantom() {
        let body = "  FUN_ctor(&local_a8);\n  FUN_2(local_a8);\n  return;\n";
        assert!(is_ever_assigned("local_a8", body));
    }

    #[test]
    fn a_comparison_is_not_mistaken_for_an_assignment() {
        let body = "  if (local_a8 == 0) {\n  }\n  FUN_2(local_a8);\n  return;\n";
        assert!(!is_ever_assigned("local_a8", body));
    }

    #[test]
    fn an_indexed_write_is_a_real_assignment() {
        let body = "  local_a8[0] = 5;\n  FUN_2(local_a8);\n  return;\n";
        assert!(is_ever_assigned("local_a8", body));
    }

    #[test]
    fn an_indexed_comparison_is_not_mistaken_for_an_assignment() {
        let body = "  if (local_a8[0] == 5) {\n  }\n  FUN_2(local_a8);\n  return;\n";
        assert!(!is_ever_assigned("local_a8", body));
    }

    /// The real, confirmed case: a self-collision-check loop
    /// (`runGameLoop`'s own recovered shape) passes a never-initialized
    /// `local_a8` to `FUN_140006050`/`FUN_140007250` -- the exact same
    /// pair `FUN_140002bf4` reaches through `param_1 + 0x10`, and
    /// `runGameLoop` itself calls `FUN_140002bf4` with its own `snake`
    /// parameter. Must resolve to `snake + 0x10`.
    #[test]
    fn the_real_snake_local_a8_case_resolves_correctly() {
        let mut functions = vec![
            function(
                "0x140006050",
                "longlong *param_1",
                "longlong FUN_140006050(longlong *param_1)\n\n{\n  \n  return param_1[1] - *param_1 >> 3;\n}",
            ),
            function(
                "0x140007250",
                "longlong *param_1, longlong param_2",
                "longlong FUN_140007250(longlong *param_1, longlong param_2)\n\n{\n  \n  return *param_1 + param_2 * 8;\n}",
            ),
            function(
                "0x140002bf4",
                "longlong param_1",
                "undefined FUN_140002bf4(longlong param_1)\n\n{\n  longlong lVar1;\n  \n  lVar1 = FUN_140006050((longlong *)(param_1 + 0x10));\n  return;\n}",
            ),
            function(
                "0x140003476",
                "void *screen, unsigned char *snake, void *food",
                "undefined8 runGameLoop(void *screen, unsigned char *snake, void *food)\n\n{\n  longlong local_a8 [4];\n  longlong *plVar6;\n  ulonglong uVar7;\n  ulonglong uVar8;\n  int local_24;\n  \n  FUN_140002bf4((longlong)((longlong)snake));\n  for (local_24 = 1; uVar8 = (ulonglong)local_24, uVar7 = FUN_140006050((longlong *)(local_a8)), uVar8 < uVar7; local_24 = local_24 + 1) {\n    plVar6 = (longlong *)FUN_140007250((longlong *)(local_a8),(longlong)((longlong)local_24));\n  }\n  return 0;\n}",
            ),
        ];

        generalize_phantom_local_aliases(&mut functions);

        let body = &functions[3].decompilation;
        assert!(!body.contains("local_a8"), "the phantom local must be fully removed: {body}");
        assert!(body.contains("FUN_140006050((longlong *)((snake + 0x10)))"), "{body}");
        assert!(body.contains("FUN_140007250((longlong *)((snake + 0x10)),(longlong)((longlong)local_24))"), "{body}");
    }

    /// A local that's genuinely, normally used (assigned a value at some
    /// point) must never be touched, even if it's also passed to one of
    /// the callees this module knows an offset fact for.
    #[test]
    fn a_normally_used_local_is_left_untouched() {
        let mut functions = vec![
            function(
                "0x140002bf4",
                "longlong param_1",
                "undefined FUN_140002bf4(longlong param_1)\n\n{\n  longlong lVar1;\n  \n  lVar1 = FUN_140006050((longlong *)(param_1 + 0x10));\n  return;\n}",
            ),
            function(
                "0x2",
                "unsigned char *snake",
                "undefined8 FUN_2(unsigned char *snake)\n\n{\n  longlong local_a8 [4];\n  \n  local_a8[0] = 5;\n  FUN_140002bf4((longlong)((longlong)snake));\n  FUN_140006050((longlong *)(local_a8));\n  return 0;\n}",
            ),
        ];

        generalize_phantom_local_aliases(&mut functions);

        assert!(functions[1].decompilation.contains("local_a8"), "a genuinely-assigned local must survive untouched");
    }

    /// No corroborating evidence anywhere in the program (the callee this
    /// local is passed to has no known passthrough fact at all) -- must
    /// leave the local exactly as decompiled, never guess.
    #[test]
    fn no_evidence_leaves_the_local_untouched() {
        let mut functions = vec![function(
            "0x1",
            "unsigned char *snake",
            "undefined8 FUN_1(unsigned char *snake)\n\n{\n  longlong local_a8 [4];\n  longlong *plVar6;\n  \n  plVar6 = (longlong *)FUN_999(local_a8);\n  return 0;\n}",
        )];

        generalize_phantom_local_aliases(&mut functions);

        assert!(functions[0].decompilation.contains("local_a8"), "no evidence must mean no rewrite");
    }

    /// A passthrough function whose own matched parameter isn't
    /// byte-granular (a real class pointer, where `+ offset` would be
    /// scaled by `sizeof` under real C++ rules) must never be trusted as
    /// evidence.
    #[test]
    fn a_non_byte_granular_passthrough_parameter_is_rejected() {
        let mut functions = vec![
            function(
                "0x140002bf4",
                "Section *param_1",
                "undefined FUN_140002bf4(Section *param_1)\n\n{\n  longlong lVar1;\n  \n  lVar1 = FUN_140006050((longlong *)(param_1 + 0x10));\n  return;\n}",
            ),
            function(
                "0x2",
                "unsigned char *snake",
                "undefined8 FUN_2(unsigned char *snake)\n\n{\n  longlong local_a8 [4];\n  longlong *plVar6;\n  \n  FUN_140002bf4((Section *)(snake));\n  plVar6 = (longlong *)FUN_140006050((longlong *)(local_a8));\n  return 0;\n}",
            ),
        ];

        generalize_phantom_local_aliases(&mut functions);

        assert!(functions[1].decompilation.contains("local_a8"), "a Section*-typed passthrough must not be trusted");
    }
}
