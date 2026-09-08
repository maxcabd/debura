use std::collections::BTreeSet;

use debura_knowledge::{is_degenerate_decompilation, latest_decompilation, KnowledgeGraph};

use crate::symtab::{ArgTransform, ArgumentMapping, SymbolKind, SymbolTable};

/// The one real MinGW/libstdc++ idiom this module recognizes (PROJECT.md
/// M18.3): a compiled function whose *entire* body is nothing but a
/// defensive throw-guard (or a nest of them) followed by exactly one
/// forwarding call into a real, already-declared runtime allocation
/// primitive (`operator_new`/`operator_delete`, see M18.2's
/// `ghidra_compat.hpp`) -- the compiler's own `std::allocator<T>`
/// adapter, specialized (and inlined into its own standalone address)
/// for one specific element size. A real, non-degenerate body M15's own
/// library-glue exclusion correctly keeps out of `recovered/` as its own
/// function (this module doesn't bypass that -- the two real cases this
/// was built from, `operator_delete(param_2,param_3 * 8)` and
/// `operator_new(param_2 << 3)`, are never independently recovered
/// either). But a real call *site* elsewhere still needs to resolve
/// through it -- this is what lets that call site rewrite directly to
/// the real target, with the exact same (bounded, deterministic)
/// argument transform its own body performs, instead of staying an
/// unresolvable `FUN_<addr>` reference at link time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardingThunk {
    pub canonical_target: String,
    pub argument_mapping: Vec<ArgumentMapping>,
    /// The thunk's own declared parameter count -- what a call *site*
    /// naming this address is expected to supply, not
    /// `argument_mapping.len()` (which counts only what the canonical
    /// target actually needs; a real case drops its own leading
    /// parameter entirely).
    pub own_param_count: usize,
}

// `ArgumentMapping`/`ArgTransform` themselves live in `symtab.rs` (see
// `SymbolKind::ForwardingThunk`'s own doc comment for why) -- imported
// above, not redefined here.

/// The only real targets this ever binds to -- PROJECT.md M18.2's
/// `ghidra_compat.hpp` already declares both, so a rewritten call site
/// always resolves regardless of whether this specific thunk's own
/// address was ever independently recovered. A fixed, explicit
/// allowlist, never inferred from the callee's own name shape alone.
const CANONICAL_TARGETS: &[&str] = &["operator_new", "operator_delete"];

/// Real, recognized libstdc++ helpers that only ever throw (never
/// return) -- a fixed, explicit allowlist, not "any call": broadening
/// this to "any call whose branch happens to never return" would need
/// real control-flow analysis this module deliberately doesn't attempt.
/// Both of these are the real ones a real run found guarding a real
/// forwarding thunk (`operator_new`'s own overflow checks).
const NONRETURNING_THROW_HELPERS: &[&str] = &["std::__throw_bad_alloc", "std::__throw_bad_array_new_length"];

#[derive(Debug, Clone)]
enum Stmt<'a> {
    Call { text: &'a str },
    IfBlock { inner: &'a str },
}

/// The matching close bracket for the open bracket at `text[open]`,
/// tracking nesting depth of that exact bracket pair only (never
/// confused by a differently-bracketed construct inside, e.g. a call's
/// own parens while scanning for a brace) -- the same approach
/// `symtab.rs`'s `matching_close_paren` already uses, generalized to
/// either bracket pair since this module needs both.
fn matching_close(text: &str, open: usize, open_ch: u8, close_ch: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        if b == open_ch {
            depth += 1;
        } else if b == close_ch {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// Splits `s` on its own top-level commas (parens/brackets balanced) --
/// no string-literal handling, unlike `symtab.rs`'s own `split_args`:
/// neither a declared parameter list nor this module's own narrow,
/// identifier/literal-only argument shapes ever contain one.
fn split_top_level_comma(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(s[start..i].trim());
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts
}

/// Splits `body` (the text strictly between a `{`/`}` pair, braces not
/// included) into top-level statements, in order. Only recognizes
/// exactly the two shapes this module needs: a semicolon-terminated call
/// statement (including a bare `return;`, which parses as a zero-arg
/// "call" named `return`), or an `if (...) { ... }` block with no
/// trailing `else`. Any other shape -- a bare assignment, a loop, an
/// `else` branch -- returns `None`, the same "bail rather than guess"
/// discipline as everywhere else in this crate's classification code.
fn split_top_level_statements(body: &str) -> Option<Vec<Stmt<'_>>> {
    let mut stmts = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0usize;
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let is_if = body[i..].starts_with("if")
            && body[i..].as_bytes().get(2).is_some_and(|c| !c.is_ascii_alphanumeric() && *c != b'_');
        if is_if {
            let paren_open = i + 2 + body[i + 2..].find('(')?;
            let paren_close = matching_close(body, paren_open, b'(', b')')?;
            let mut j = paren_close + 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if bytes.get(j) != Some(&b'{') {
                return None;
            }
            let brace_close = matching_close(body, j, b'{', b'}')?;
            stmts.push(Stmt::IfBlock { inner: &body[j + 1..brace_close] });
            i = brace_close + 1;
            let mut k = i;
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if body[k..].starts_with("else") {
                // Outside this module's narrow, confirmed shape --
                // never seen in a real forwarding thunk, and an
                // untaken `else` branch could hide anything.
                return None;
            }
            continue;
        }
        let start = i;
        let mut depth = 0i32;
        let mut end = None;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                b'{' | b'}' if depth == 0 => return None,
                b';' if depth == 0 => {
                    end = Some(i);
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        let end = end?;
        stmts.push(Stmt::Call { text: body[start..end].trim() });
        i = end + 1;
    }
    Some(stmts)
}

/// `NAME(ARGS)` -- the whole trimmed text, not just a prefix, so a
/// trailing expression this module doesn't understand (anything past a
/// call's own closing paren) is rejected rather than silently ignored.
/// `None` for a bare `return` (no parens at all): callers that need to
/// tell "a real call" from "the terminal `return`" check for that
/// exact text themselves, since a real call is never spelled that way.
fn call_name_and_args(text: &str) -> Option<(&str, &str)> {
    if text == "return" {
        return None;
    }
    let open = text.find('(')?;
    if !text.ends_with(')') {
        return None;
    }
    let name = text[..open].trim();
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == ':') {
        return None;
    }
    Some((name, &text[open + 1..text.len() - 1]))
}

/// Whether every statement inside a guard's own `if` body is either a
/// recognized non-returning throw call, or another such guard nested
/// inside it (a real case -- `operator_new`'s own overflow check --
/// nests one guard inside another). An empty body is never trusted:
/// nothing there proves it's actually a no-op with respect to
/// forwarding, so a real case would still need to be seen before this
/// accepts it.
fn is_pure_throw_guard(inner: &str) -> bool {
    let Some(stmts) = split_top_level_statements(inner) else { return false };
    !stmts.is_empty()
        && stmts.iter().all(|s| match s {
            Stmt::Call { text } => {
                call_name_and_args(text).is_some_and(|(name, _)| NONRETURNING_THROW_HELPERS.contains(&name))
            }
            Stmt::IfBlock { inner } => is_pure_throw_guard(inner),
        })
}

fn parse_param_names(signature: &str) -> Option<Vec<String>> {
    let open = signature.find('(')?;
    let close = matching_close(signature, open, b'(', b')')?;
    let params = signature[open + 1..close].trim();
    if params.is_empty() || params == "void" {
        return Some(Vec::new());
    }
    split_top_level_comma(params)
        .into_iter()
        .map(|part| {
            part.rsplit(|c: char| c == ' ' || c == '*').find(|s| !s.is_empty()).map(str::to_string)
        })
        .collect()
}

fn parse_int_literal(s: &str) -> Option<u64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse::<u64>().ok(),
    }
}

/// One canonical-target argument's real source: either one of the
/// thunk's own declared parameters, passed through unchanged, or that
/// same parameter scaled by a literal constant the thunk's own body
/// applies (`param_3 * 8`, `param_2 << 3` -- both real, confirmed
/// shapes; an element-size scaling factor a compiler bakes in when it
/// specializes an allocator adapter for one specific type). Nothing
/// else is accepted -- an argument this module can't attribute to
/// exactly one declared parameter, with at most one literal
/// multiply/shift applied, means this isn't the narrow idiom this
/// module exists to recognize.
fn parse_argument_mapping(arg: &str, param_names: &[String]) -> Option<ArgumentMapping> {
    let arg = arg.trim();
    if let Some(idx) = param_names.iter().position(|p| p == arg) {
        return Some(ArgumentMapping { source_param_index: idx, transform: None });
    }
    if let Some((ident, num)) = arg.split_once('*') {
        let idx = param_names.iter().position(|p| p == ident.trim())?;
        return Some(ArgumentMapping {
            source_param_index: idx,
            transform: Some(ArgTransform::Multiply(parse_int_literal(num.trim())?)),
        });
    }
    if let Some((ident, num)) = arg.split_once("<<") {
        let idx = param_names.iter().position(|p| p == ident.trim())?;
        return Some(ArgumentMapping {
            source_param_index: idx,
            transform: Some(ArgTransform::ShiftLeft(parse_int_literal(num.trim())?)),
        });
    }
    None
}

/// Attempts to recognize `decompilation` as a real forwarding thunk
/// (see this module's own top-level doc comment) -- `None` for anything
/// that doesn't match the narrow, confirmed shape exactly, never a
/// best-effort partial match.
pub fn detect_forwarding_runtime_thunk(decompilation: &str) -> Option<ForwardingThunk> {
    let brace_open = decompilation.find('{')?;
    let brace_close = matching_close(decompilation, brace_open, b'{', b'}')?;
    let body = &decompilation[brace_open + 1..brace_close];
    let signature = &decompilation[..brace_open];

    let param_names = parse_param_names(signature)?;
    let mut stmts = split_top_level_statements(body)?;

    if let Some(Stmt::Call { text }) = stmts.last() {
        if *text == "return" {
            stmts.pop();
        }
    }

    let mut idx = 0;
    while let Some(Stmt::IfBlock { inner }) = stmts.get(idx) {
        if !is_pure_throw_guard(inner) {
            break;
        }
        idx += 1;
    }
    let remaining = &stmts[idx..];
    let [Stmt::Call { text: call_text }] = remaining else { return None };

    let (name, args_text) = call_name_and_args(call_text)?;
    if !CANONICAL_TARGETS.contains(&name) {
        return None;
    }

    let args = if args_text.trim().is_empty() { Vec::new() } else { split_top_level_comma(args_text) };
    let argument_mapping =
        args.into_iter().map(|a| parse_argument_mapping(a, &param_names)).collect::<Option<Vec<_>>>()?;

    Some(ForwardingThunk { canonical_target: name.to_string(), argument_mapping, own_param_count: param_names.len() })
}

/// Scans every subject in the graph with a real, non-degenerate
/// `decompiles_to` fact for the forwarding-thunk shape, and adds a
/// `SymbolKind::ForwardingThunk` entry for each match -- independent of
/// provenance or recovery-worthiness (a real forwarding thunk is never
/// itself recovered, see this module's own doc comment, so it would
/// otherwise have no entry in `table` at all for a real call site
/// elsewhere to resolve against). Never overwrites an address `table`
/// already has an entry for: a real, already-recovered class
/// method/function always wins over this narrow fallback pattern.
pub fn add_forwarding_thunks(graph: &KnowledgeGraph, table: &mut SymbolTable) {
    let subjects: BTreeSet<String> =
        graph.observations().filter(|o| o.predicate == "decompiles_to").map(|o| o.subject.clone()).collect();
    for subject in subjects {
        if table.contains_key(&subject) {
            continue;
        }
        let Some(decompilation) = latest_decompilation(graph, &subject) else { continue };
        if is_degenerate_decompilation(&decompilation.value) {
            continue;
        }
        let Some(thunk) = detect_forwarding_runtime_thunk(&decompilation.value) else { continue };
        table.insert(
            subject,
            crate::symtab::RecoveredSymbol {
                kind: SymbolKind::ForwardingThunk,
                owner: String::new(),
                display_name: thunk.canonical_target.clone(),
                expected_args: thunk.own_param_count,
                param_types: Vec::new(),
                canonical_target: thunk.canonical_target,
                argument_mapping: thunk.argument_mapping,
                return_type: String::new(),
                raw_params: String::new(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real, confirmed case: `FUN_1400065c0` -- a sized-delete
    /// forwarding thunk. `param_1` (the receiver of whatever inlined
    /// `allocator<T>::deallocate` this was) is dropped entirely; `param_3`
    /// is scaled by 8 (`sizeof` the specialized element type).
    #[test]
    fn a_sized_delete_thunk_is_recognized() {
        let decompilation = "void FUN_1400065c0(undefined8 param_1,void *param_2,longlong param_3)\n\n{\n  operator_delete(param_2,param_3 * 8);\n  return;\n}";
        let thunk = detect_forwarding_runtime_thunk(decompilation).expect("must be recognized");
        assert_eq!(thunk.canonical_target, "operator_delete");
        assert_eq!(thunk.own_param_count, 3);
        assert_eq!(
            thunk.argument_mapping,
            vec![
                ArgumentMapping { source_param_index: 1, transform: None },
                ArgumentMapping { source_param_index: 2, transform: Some(ArgTransform::Multiply(8)) },
            ]
        );
    }

    /// The real, confirmed case: `FUN_1400066c0` -- a sized-new
    /// forwarding thunk with two nested overflow-check guards ahead of
    /// the real call, both of which only ever throw.
    #[test]
    fn a_sized_new_thunk_with_nested_throw_guards_is_recognized() {
        let decompilation = "void FUN_1400066c0(undefined8 param_1,ulonglong param_2)\n\n{\n  if (0xfffffffffffffff < param_2) {\n    if (0x1fffffffffffffff < param_2) {\n      std::__throw_bad_array_new_length();\n    }\n    std::__throw_bad_alloc();\n  }\n  operator_new(param_2 << 3);\n  return;\n}";
        let thunk = detect_forwarding_runtime_thunk(decompilation).expect("must be recognized");
        assert_eq!(thunk.canonical_target, "operator_new");
        assert_eq!(thunk.own_param_count, 2);
        assert_eq!(
            thunk.argument_mapping,
            vec![ArgumentMapping { source_param_index: 1, transform: Some(ArgTransform::ShiftLeft(3)) }]
        );
    }

    /// A guard whose body does something other than throw (a real early
    /// return with its own value, say) must never be treated as inert --
    /// this module has no control-flow model, only a fixed allowlist of
    /// calls known to never return.
    #[test]
    fn a_guard_that_does_not_only_throw_is_rejected() {
        let decompilation = "undefined8 FUN_1(longlong param_1,ulonglong param_2)\n\n{\n  if (param_2 == 0) {\n    return 0;\n  }\n  operator_new(param_2 << 3);\n  return 1;\n}";
        assert!(detect_forwarding_runtime_thunk(decompilation).is_none());
    }

    /// An ordinary, real function body -- not a forwarding thunk at all --
    /// must never match.
    #[test]
    fn an_ordinary_function_is_not_a_forwarding_thunk() {
        let decompilation = "void FUN_1(longlong param_1)\n\n{\n  *(int *)(param_1 + 4) = 0;\n  return;\n}";
        assert!(detect_forwarding_runtime_thunk(decompilation).is_none());
    }

    /// A call to something outside the fixed canonical-target allowlist
    /// (even a real, plausible-looking one) must never match -- this
    /// module only ever binds to `operator_new`/`operator_delete`.
    #[test]
    fn a_forwarding_call_to_an_unlisted_target_is_rejected() {
        let decompilation = "void FUN_1(void *param_1)\n\n{\n  free(param_1);\n  return;\n}";
        assert!(detect_forwarding_runtime_thunk(decompilation).is_none());
    }

    /// An argument that isn't a bare declared parameter or a
    /// parameter scaled by a literal constant (a second parameter added
    /// together, say) must reject the whole thunk rather than guess at
    /// a mapping.
    #[test]
    fn an_argument_shape_this_module_does_not_understand_is_rejected() {
        let decompilation = "void FUN_1(void *param_1,longlong param_2,longlong param_3)\n\n{\n  operator_delete(param_1,param_2 + param_3);\n  return;\n}";
        assert!(detect_forwarding_runtime_thunk(decompilation).is_none());
    }
}
