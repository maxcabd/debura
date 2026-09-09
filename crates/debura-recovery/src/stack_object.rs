/// PROJECT.md M18.3/M19: the deeper, still-manual stack-object-extent
/// bug this session's `phantom_local.rs` documents needing as its own
/// prerequisite -- Ghidra sometimes models one real C++ object as
/// several separately-declared, undersized locals, because different
/// call sites access it at different offsets without the decompiler
/// recognizing the shared extent. Three real, independently-found
/// instances tonight all had this exact shape:
///
/// - Snake's own state object (`local_b8`): declared a bare 4-byte
///   scalar, but really ~40 bytes -- several scalar fields, then a
///   `std::vector` header at offset 0x10 -- with two of its OWN fields
///   (`m_lives`, `m_hasUpdated`) separately declared as `local_b4`/
///   `local_ac`, aliasing `local_b8+4`/`local_b8+0xc`.
/// - `FUN_140001bf2`'s own SDL event buffer (`local_48`): declared
///   `int [5]` (20 bytes), with a *separate* local (`local_34`) for the
///   keycode field at byte offset 0x14 -- but the call site casts it to
///   `SDL_Event *` and hands it to `SDL_PollEvent`, which writes a full
///   56-byte `SDL_Event` into it every call. This was the actual root
///   cause of a crash that survived an entire night of differential-
///   execution debugging (see this file's own M19 section in
///   PROJECT.md): a real stack buffer overflow on every single frame,
///   corrupting adjacent memory in a way that only became visible much
///   later, as a null-pointer fault deep inside `SDL_RenderPresent`.
///
/// This module generalizes the reconstruction: given a local `L` whose
/// address is passed to some other, already-recovered function `H`,
/// collect every offset+width field access `H`'s own body makes into
/// the parameter `&L` was passed as, merge in any *sibling* locals in
/// `L`'s own function that are themselves fragments of the same object
/// (see `find_sibling_locals`'s own doc comment for the exact evidence
/// required), and -- only when every discovered fact is unambiguous --
/// widen `L` into a single, real, byte-addressable object covering the
/// full extent, replacing every fragment with a direct offset access
/// into it. A function this module can't confidently resolve is left
/// exactly as Ghidra decompiled it, the same "never guess" discipline
/// `phantom_local.rs` and every other pass in this crate already follow.
use std::collections::HashMap;

use crate::forwarding_thunk::{matching_close, parse_int_literal, parse_param_names, split_top_level_comma};
use crate::model::RecoveredFunction;
use crate::phantom_local::{
    declared_local_names, find_calls, is_ever_assigned, remove_declaration, replace_whole_identifier,
    split_locals_block, strip_casts_and_parens,
};

/// One real field this module has evidence for: a byte offset and the
/// width (in bytes) something reads or writes there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FieldFact {
    offset: i64,
    width: u32,
}

/// The width (in bytes) of the value a dereference through this cast's
/// own inner type text actually reads/writes -- `cast_inner` is
/// everything between a cast's own parens (e.g. `"int"`, `"void **"`,
/// `"undefined"`), always ending in at least one `*` (the dereference
/// this expression's own leading `*` consumes) since only
/// `find_offset_dereferences` ever calls this, and it already checked
/// that. A pointer *field* (the cast has more than one `*`, e.g.
/// `*(void **)...` reading a stored `void*`) is always 8 bytes,
/// regardless of what it points to. A scalar field's width comes from a
/// small, fixed allowlist of the type names this crate's own recovered
/// bodies actually use -- `None` for anything else, so an unrecognized
/// type can never be silently mis-sized.
fn width_from_cast_inner(cast_inner: &str) -> Option<u32> {
    let field_type = cast_inner.trim().strip_suffix('*')?.trim();
    if field_type.contains('*') {
        return Some(8);
    }
    match field_type {
        "undefined" | "char" | "unsigned char" | "bool" | "byte" => Some(1),
        "undefined2" | "short" | "unsigned short" | "wchar_t" => Some(2),
        "undefined4" | "int" | "uint" | "float" => Some(4),
        "undefined8" | "longlong" | "ulonglong" | "double" => Some(8),
        _ => None,
    }
}

/// Every `*(TYPE *)(EXPR)` or `*(TYPE *)IDENT`-shaped dereference found
/// anywhere in `text`, as `(cast_inner, pointee_expr)` pairs -- the two
/// real shapes this crate's own recovered bodies use throughout for a
/// field access at a known offset (`*(int *)(param_1 + 8)`) or at
/// offset zero (`*(int *)param_1`). Deliberately text-scanned rather
/// than requiring a full statement parse, the same reasoning
/// `phantom_local.rs`'s own `find_calls` documents.
fn find_offset_dereferences(text: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'(') {
            if let Some(cast_close) = matching_close(text, i + 1, b'(', b')') {
                let cast_inner = text[i + 2..cast_close].trim();
                if cast_inner.ends_with('*') {
                    let mut j = cast_close + 1;
                    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if bytes.get(j) == Some(&b'(') {
                        if let Some(expr_close) = matching_close(text, j, b'(', b')') {
                            out.push((cast_inner, &text[j + 1..expr_close]));
                            i = expr_close + 1;
                            continue;
                        }
                    } else {
                        let start = j;
                        let mut k = j;
                        while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_') {
                            k += 1;
                        }
                        if k > start {
                            out.push((cast_inner, &text[start..k]));
                            i = k;
                            continue;
                        }
                    }
                }
            }
        }
        i += 1;
    }
    out
}

/// How a declared parameter's own type governs arithmetic done on it in
/// decompiled text -- Ghidra emits real C pointer-arithmetic rules for a
/// genuinely typed pointer parameter (`param + 3` on an `undefined4
/// *param` means 3 *elements*, 12 real bytes), but this codebase's own
/// heavy "self pointer passed as a plain integer" convention
/// (`longlong param_1`) means the same-shaped `param + 3` is already 3
/// real bytes -- there's no pointee type to scale by at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamKind {
    /// A plain integer type -- arithmetic on it is already byte-exact.
    PlainInteger,
    /// A real pointer to one of this module's known scalar types --
    /// arithmetic on it is scaled by this pointee width.
    TypedPointer { width: u32 },
}

/// `name`'s own `ParamKind` per its declaration in `params` -- `None` if
/// `name` isn't declared at all, or is a pointer to a type outside this
/// module's small, known-width allowlist (never guessed).
fn param_kind(params: &str, name: &str) -> Option<ParamKind> {
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
        return match type_text.strip_suffix('*') {
            None => Some(ParamKind::PlainInteger),
            Some(base) => {
                let width = width_of_declared_type(base.trim())?;
                Some(ParamKind::TypedPointer { width })
            }
        };
    }
    None
}

/// `expr` (after stripping casts/redundant parens) is exactly `IDENT`
/// (offset 0) or `IDENT + LITERAL`/`IDENT - LITERAL` (a field access,
/// with the raw literal scaled by `scale` -- see `ParamKind`'s own doc
/// comment for why arithmetic on a real typed pointer needs scaling
/// while a plain-integer "self pointer" doesn't) where `IDENT` is
/// `param`. `None` for anything else, or if the identifier isn't
/// `param` at all.
fn offset_if_matches_param(expr: &str, param: &str, scale: i64) -> Option<i64> {
    let expr = strip_casts_and_parens(expr);
    if expr == param {
        return Some(0);
    }
    let (ident, lit, sign): (&str, &str, i64) = if let Some((a, b)) = expr.split_once('+') {
        (a, b, 1)
    } else if let Some((a, b)) = expr.split_once('-') {
        (a, b, -1)
    } else {
        return None;
    };
    if ident.trim() != param {
        return None;
    }
    Some(parse_int_literal(lit.trim())? as i64 * sign * scale)
}

/// Every field fact `function`'s own body provides for its parameter
/// `param`, at recursion `depth` (bounded to guard against a pathological
/// call cycle -- a real, finite call graph never needs more than a
/// handful of hops): direct `*(TYPE *)(param [+/- OFFSET])` dereferences,
/// a bare `*param` dereference when `param` is already a typed pointer
/// (offset 0, width = its own pointee width), `param[N]`-shaped array
/// indexing, and -- the case that reaches Snake's own real vector header
/// two hops away -- every place `function` itself passes `param` (at
/// some offset) onward to *another* already-recovered function, whose
/// own field facts (for the corresponding parameter) are recursively
/// collected and shifted by that offset. `None` if any single access
/// can't be confidently attributed a width -- never a partial fact set
/// silently missing a real field.
fn field_facts_for_param(
    functions_by_name: &HashMap<&str, &RecoveredFunction>,
    function: &RecoveredFunction,
    param: &str,
    depth: u32,
) -> Option<Vec<FieldFact>> {
    if depth > 4 {
        return Some(Vec::new());
    }
    let kind = param_kind(&function.params, param)?;
    let scale = match kind {
        ParamKind::PlainInteger => 1,
        ParamKind::TypedPointer { width } => width as i64,
    };

    // Every step below skips just the one access/call site it can't
    // confidently read, rather than propagating failure out of this
    // whole function -- a single unrecognized cast type or an
    // unrelated, unresolvable callee somewhere in a real, messy real-
    // world body must never discard every *other* access this function
    // genuinely does provide good evidence for. Confirmed against a
    // real regression tonight: an earlier version of this function used
    // `?` throughout this loop, and Snake's own real
    // `initializeFoodParameters` (which also constructs `Section`
    // objects, calls vtable methods, etc. -- plenty for something to
    // trip on) silently lost every one of its real field facts because
    // of it.
    let mut facts = Vec::new();
    for (cast_inner, pointee_expr) in find_offset_dereferences(&function.decompilation) {
        let Some(offset) = offset_if_matches_param(pointee_expr, param, scale) else { continue };
        let Some(width) = width_from_cast_inner(cast_inner) else { continue };
        facts.push(FieldFact { offset, width });
    }

    if let ParamKind::TypedPointer { width } = kind {
        let bare = format!("*{}", param);
        let mut start = 0usize;
        while let Some(rel) = function.decompilation[start..].find(&bare) {
            let abs = start + rel;
            let prev_not_star_or_ident =
                function.decompilation[..abs].chars().next_back().is_none_or(|c| c != '*' && !c.is_alphanumeric() && c != '_');
            let after_pos = abs + bare.len();
            let after_ok =
                function.decompilation[after_pos..].chars().next().is_none_or(|c| !c.is_alphanumeric() && c != '_');
            if prev_not_star_or_ident && after_ok {
                facts.push(FieldFact { offset: 0, width });
            }
            start = after_pos;
        }

        let pattern = format!("{}[", param);
        let mut start = 0usize;
        while let Some(rel) = function.decompilation[start..].find(&pattern) {
            let abs = start + rel;
            let before_ok =
                function.decompilation[..abs].chars().next_back().is_none_or(|c| !c.is_alphanumeric() && c != '_');
            let bracket_pos = abs + pattern.len();
            if before_ok {
                if let Some(close_rel) = function.decompilation[bracket_pos..].find(']') {
                    let idx_text = function.decompilation[bracket_pos..bracket_pos + close_rel].trim();
                    if let Some(idx) = parse_int_literal(idx_text) {
                        facts.push(FieldFact { offset: idx as i64 * width as i64, width });
                    }
                }
            }
            start = bracket_pos;
        }
    }

    for (callee_name, args_text) in find_calls(&function.decompilation) {
        if callee_name == function.raw_name {
            continue;
        }
        let Some(callee) = functions_by_name.get(callee_name) else { continue };
        for (position, arg) in split_top_level_comma(args_text).into_iter().enumerate() {
            let Some(hop_offset) = offset_if_matches_param(arg, param, scale) else { continue };
            let Some(brace_open) = callee.decompilation.find('{') else { continue };
            let Some(callee_params) = parse_param_names(&callee.decompilation[..brace_open + 1]) else { continue };
            let Some(callee_param) = callee_params.get(position) else { continue };
            let Some(sub_facts) = field_facts_for_param(functions_by_name, callee, callee_param, depth + 1) else {
                continue;
            };
            for f in sub_facts {
                facts.push(FieldFact { offset: f.offset + hop_offset, width: f.width });
            }
        }
    }

    Some(facts)
}

/// A small, explicit allowlist of external (never Debura-recovered)
/// struct sizes this module trusts by name -- never inferred, always a
/// fixed, documented fact about a real, well-known ABI this project
/// links against. `SDL_Event` is the real, confirmed case tonight:
/// `FUN_140001bf2` declared its event buffer as `int [5]` (20 bytes)
/// because Ghidra only ever saw two of its fields directly read, but
/// the call site casts it to `SDL_Event *` and hands it to
/// `SDL_PollEvent` -- an external library function that will never
/// appear in `functions_by_name` at all, so `field_facts_for_param`'s
/// own cross-function mechanism can never reach this evidence. Extend
/// this table only for other real, confirmed cases -- never to "cover"
/// a type nothing has actually exercised.
const KNOWN_EXTERNAL_TYPE_SIZES: &[(&str, u32)] = &[("SDL_Event", 56)];

/// Every field fact `local`'s own address (or, once it's an array, its
/// own decayed name) provides by being cast to a known external type
/// and passed to *any* call in `stmts_block` -- resolved or not. A
/// single fact covering the whole known size, at offset 0.
fn external_cast_facts(stmts_block: &str, local: &str) -> Vec<FieldFact> {
    let mut facts = Vec::new();
    for (_, args_text) in find_calls(stmts_block) {
        for arg in split_top_level_comma(args_text) {
            let arg = arg.trim();
            if !arg.starts_with('(') {
                continue;
            }
            let Some(close) = matching_close(arg, 0, b'(', b')') else { continue };
            let cast_inner = arg[1..close].trim();
            let Some(type_name) = cast_inner.strip_suffix('*').map(str::trim) else { continue };
            let Some(&(_, width)) = KNOWN_EXTERNAL_TYPE_SIZES.iter().find(|(n, _)| *n == type_name) else {
                continue;
            };
            let rest = arg[close + 1..].trim();
            let target = rest.strip_prefix('&').unwrap_or(rest);
            if target == local {
                facts.push(FieldFact { offset: 0, width });
            }
        }
    }
    facts
}

/// A small, explicit allowlist of external (never Debura-recovered)
/// function *signatures* this module trusts by name and parameter
/// position -- `(function_name, param_index, param_width)`.
/// `SDL_PollEvent`'s own real declaration (`int SDL_PollEvent(SDL_Event
/// *event)`) is a fixed, well-known fact about the SDL2 headers this
/// project links against, not something inferred from any one call
/// site's own text: the real, confirmed case tonight is that Ghidra's
/// own raw decompilation sometimes omits the cast entirely when passing
/// an array whose element type happens to satisfy the callee's own
/// declared parameter type well enough for its type model (`local_48`,
/// already an `int [5]`, passed completely bare to `SDL_PollEvent`) --
/// so `external_cast_facts`'s own cast-text matching has nothing to see
/// at all. Extend this table only for other real, confirmed cases.
const KNOWN_EXTERNAL_CALL_PARAM_SIZES: &[(&str, usize, u32)] = &[("SDL_PollEvent", 0, 56)];

/// Every field fact `local` gets by being passed (bare, or address-of)
/// as the matching parameter position of a call to one of
/// `KNOWN_EXTERNAL_CALL_PARAM_SIZES`'s own named functions -- a single
/// fact covering that parameter's own known width, at offset 0.
fn external_call_facts(stmts_block: &str, local: &str) -> Vec<FieldFact> {
    let mut facts = Vec::new();
    for (callee, args_text) in find_calls(stmts_block) {
        let Some(&(_, position, width)) = KNOWN_EXTERNAL_CALL_PARAM_SIZES.iter().find(|(n, _, _)| *n == callee)
        else {
            continue;
        };
        let Some(arg) = split_top_level_comma(args_text).into_iter().nth(position) else { continue };
        let target = strip_casts_and_parens(arg);
        let bare_target = target.strip_prefix('&').unwrap_or(target);
        if bare_target == local {
            facts.push(FieldFact { offset: 0, width });
        }
    }
    facts
}

/// Every call site anywhere in `caller`'s body of the shape
/// `CALLEE(..., &LOCAL, ...)` -- `LOCAL`'s address passed bare (after
/// stripping casts) to some other, already-recovered function -- as
/// `(callee_raw_name, argument_position)` pairs. Argument position
/// matters: it's what tells us *which* of `callee`'s own declared
/// parameters received `&LOCAL`, and so which parameter's own field
/// facts apply.
fn address_taken_call_sites<'a>(caller_body: &'a str, local: &str) -> Vec<(&'a str, usize)> {
    let mut sites = Vec::new();
    let target = format!("&{}", local);
    for (callee, args_text) in find_calls(caller_body) {
        for (position, arg) in split_top_level_comma(args_text).into_iter().enumerate() {
            if strip_casts_and_parens(arg) == target {
                sites.push((callee, position));
            }
        }
    }
    sites
}

/// Every field fact available for `local` from every real call site
/// passing `&local` to some other, already-recovered function -- `None`
/// if no such evidence exists at all, or if any single piece of
/// evidence can't be confidently attributed a width (see
/// `field_facts_for_param`).
fn collect_field_facts(
    caller_body: &str,
    local: &str,
    functions_by_name: &HashMap<&str, &RecoveredFunction>,
) -> Option<Vec<FieldFact>> {
    let sites = address_taken_call_sites(caller_body, local);
    if sites.is_empty() {
        return None;
    }
    let mut facts = Vec::new();
    for (callee_name, position) in sites {
        let Some(callee) = functions_by_name.get(callee_name) else { continue };
        // A single site this module can't confidently read (an
        // unresolvable width somewhere in *this one* callee, say) must
        // never discard every other site's own, independently-good
        // evidence -- skip just this one, rather than propagating
        // failure out of the whole collection.
        let Some(brace_open) = callee.decompilation.find('{') else { continue };
        let Some(params) = parse_param_names(&callee.decompilation[..brace_open + 1]) else { continue };
        let Some(param_name) = params.get(position) else { continue };
        if let Some(sub_facts) = field_facts_for_param(functions_by_name, callee, param_name, 0) {
            facts.extend(sub_facts);
        }
    }
    Some(facts)
}

/// One local this module has decided is really a fragment of `base` at
/// a specific offset -- `name` and `declared_type` are Ghidra's own
/// text for it, used to render the exact same access width back once
/// it's rewritten as `*(declared_type *)(base + offset)`.
struct Sibling {
    name: String,
    declared_type: String,
    offset: i64,
}

/// The declared type text for a local in a locals-declaration block --
/// everything before the trailing identifier `declared_local_names`
/// itself extracts, mirroring that function's own line-parsing.
fn declared_type_of(locals_block: &str, name: &str) -> Option<String> {
    for line in locals_block.lines() {
        let trimmed = line.trim().trim_end_matches(';').trim();
        if trimmed.is_empty() {
            continue;
        }
        let before_bracket = trimmed.split('[').next().unwrap_or(trimmed).trim();
        let Some(ident) = before_bracket.rsplit(|c: char| c == ' ' || c == '*').find(|s| !s.is_empty()) else {
            continue;
        };
        if ident == name {
            return Some(before_bracket[..before_bracket.len() - ident.len()].trim().to_string());
        }
    }
    None
}

/// Whether `name` is currently declared as an array (`TYPE name [N]`)
/// rather than a plain scalar. An array-declared sibling candidate is
/// never merged as a scalar fragment (`find_sibling_locals` excludes
/// it): a real case tonight (`local_a8`, a phantom `longlong [4]`
/// vector-header stand-in) coincidentally satisfied this module's own
/// name-offset and field-evidence checks for a *scalar* 8-byte fragment
/// of `local_b8`, which would have rewritten every use as an incorrect
/// extra dereference (`*(longlong *)(local_b8 + 0x10)`) instead of the
/// plain address `phantom_local.rs`'s own, separate mechanism correctly
/// produces for this exact shape -- merging a whole array-typed local
/// as a scalar fragment is simply the wrong operation, not something
/// this module's rewrite format can express correctly.
fn is_declared_as_array(locals_block: &str, name: &str) -> bool {
    locals_block.lines().any(|line| {
        let trimmed = line.trim().trim_end_matches(';').trim();
        let Some(bracket_pos) = trimmed.find('[') else { return false };
        let before_bracket = trimmed[..bracket_pos].trim();
        before_bracket.rsplit(|c: char| c == ' ' || c == '*').find(|s| !s.is_empty()) == Some(name)
    })
}

/// The total byte size `name` already occupies per its *current*
/// declaration in `locals_block` -- a scalar's own width, or (for an
/// already-array-declared local, like `FUN_140001bf2`'s own
/// `int local_48 [5]`) its element count times that element's width.
/// `None` if `name` isn't declared, or its base type isn't one of this
/// module's own known scalar widths.
fn current_declared_size(locals_block: &str, name: &str) -> Option<i64> {
    for line in locals_block.lines() {
        let trimmed = line.trim().trim_end_matches(';').trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some(bracket_pos) = trimmed.find('[') else {
            let before_bracket = trimmed;
            let ident = before_bracket.rsplit(|c: char| c == ' ' || c == '*').find(|s| !s.is_empty())?;
            if ident != name {
                continue;
            }
            let base_type = before_bracket[..before_bracket.len() - ident.len()].trim();
            return width_of_declared_type(base_type).map(i64::from);
        };
        let before_bracket = trimmed[..bracket_pos].trim();
        let Some(ident) = before_bracket.rsplit(|c: char| c == ' ' || c == '*').find(|s| !s.is_empty()) else {
            continue;
        };
        if ident != name {
            continue;
        }
        let base_type = before_bracket[..before_bracket.len() - ident.len()].trim();
        let width = width_of_declared_type(base_type)?;
        let close = trimmed[bracket_pos..].find(']')?;
        let count_text = trimmed[bracket_pos + 1..bracket_pos + close].trim();
        let count = parse_int_literal(count_text)?;
        return Some(count as i64 * width as i64);
    }
    None
}

/// The byte width of a local's own declared scalar type -- the same
/// small, fixed allowlist `width_from_cast_inner` uses (a local
/// declared as anything else, an array or an unrecognized type, is
/// never treated as a sibling candidate).
fn width_of_declared_type(declared_type: &str) -> Option<u32> {
    match declared_type {
        "undefined" | "char" | "unsigned char" | "bool" | "byte" => Some(1),
        "undefined2" | "short" | "unsigned short" => Some(2),
        "undefined4" | "int" | "uint" | "float" => Some(4),
        "undefined8" | "longlong" | "ulonglong" | "double" => Some(8),
        _ => None,
    }
}

/// Ghidra's own hex suffix from a `local_XX`/`Stack_XX`-shaped name
/// (`local_b8` -> `0xb8`), if it has one. This directly encodes the
/// variable's own position in the real stack frame relative to whatever
/// fixed reference point Ghidra picked (its own decompiler convention,
/// not something Debura invented) -- a *smaller* suffix means a
/// *higher* address, closer to the saved return address, since Ghidra
/// names a stack slot after its own negative frame offset. That's
/// exactly why two such names' suffixes subtract to their real byte
/// distance apart in memory: confirmed against both real cases tonight
/// (`local_b8`/`local_b4` differ by `0xb8 - 0xb4 = 4`, matching
/// `m_lives`'s real offset; `local_48`/`local_34` differ by
/// `0x48 - 0x34 = 0x14`, matching the exact byte offset of a real
/// `SDL_Event`'s `key.keysym.sym` field). `None` for a name that
/// doesn't end in a hex suffix at all (a real semantic name already
/// applied, or some other naming shape entirely).
pub(crate) fn ghidra_stack_offset(name: &str) -> Option<i64> {
    let hex = name.rsplit('_').next()?;
    if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    i64::from_str_radix(hex, 16).ok()
}

/// Every *other* local declared in the same function as `base` that is
/// really a fragment of `base`, at the exact byte offset Ghidra's own
/// naming convention already encodes (`ghidra_stack_offset`) -- not
/// guessed from width-matching alone, which is genuinely ambiguous when
/// more than one same-width field exists (a real case tonight: Snake's
/// own offset 4 and offset 8 are both 4-byte fields, and only the name
/// itself, not the field evidence, tells `local_b4` apart from either).
/// Two pieces of evidence are still required before trusting the name:
/// the candidate is never given a value anywhere in the function
/// (`is_ever_assigned` says no -- the same "this local is read from
/// memory some other code path actually writes" signal
/// `phantom_local.rs` uses for a different shape of the same underlying
/// bug), and `all_facts` either independently confirms a real access of
/// the *same width* at that *same* name-derived offset somewhere in the
/// program, or the name-derived offset+width falls entirely within some
/// already-known total object envelope (`FieldFact { offset: 0, width }`
/// -- the real shape `external_cast_facts` provides: a `SDL_Event`'s
/// own confirmed 56-byte size already accounts for every field inside
/// it, even ones with no independent point-access evidence of their
/// own). Either way, a coincidentally hex-suffixed local with no real
/// grounding at all is never merged in.
fn find_sibling_locals(
    locals_block: &str,
    stmts_block: &str,
    base: &str,
    all_facts: &[FieldFact],
) -> Option<Vec<Sibling>> {
    let Some(base_offset) = ghidra_stack_offset(base) else { return Some(Vec::new()) };

    let mut siblings = Vec::new();
    for name in declared_local_names(locals_block) {
        if name == base || is_ever_assigned(name, stmts_block) || is_declared_as_array(locals_block, name) {
            continue;
        }
        let Some(name_offset) = ghidra_stack_offset(name) else { continue };
        if name_offset >= base_offset {
            continue;
        }
        let relative_offset = base_offset - name_offset;
        let Some(declared_type) = declared_type_of(locals_block, name) else { continue };
        let Some(width) = width_of_declared_type(&declared_type) else { continue };
        let point_confirmed = all_facts.iter().any(|f| f.offset == relative_offset && f.width == width);
        let within_known_envelope =
            all_facts.iter().any(|f| f.offset == 0 && f.width as i64 >= relative_offset + width as i64);
        if !point_confirmed && !within_known_envelope {
            continue;
        }
        siblings.push(Sibling { name: name.to_string(), declared_type, offset: relative_offset });
    }
    Some(siblings)
}

/// The minimum byte extent `base` must span to safely hold every
/// discovered field, widened defensively when the evidence itself
/// implies a well-known ABI shape this crate shouldn't have to
/// rediscover from scratch: two adjacent 8-byte fields at `O` and
/// `O + 8` are exactly a real `std::vector`'s own `begin`/`end` pointer
/// pair, and every real `std::vector` carries a third `capacity`
/// pointer immediately after them, at `O + 16` -- whether or not
/// anything in the recovered call graph happens to access it
/// independently. This is the one deliberately non-local inference this
/// module makes, and it's grounded in a fixed, well-documented ABI
/// layout (libstdc++'s own `vector::_Vector_impl`), not a guess about
/// this specific program.
fn minimum_extent(facts: &[FieldFact]) -> i64 {
    let mut extent = facts.iter().map(|f| f.offset + f.width as i64).max().unwrap_or(0);
    let offsets: std::collections::BTreeSet<i64> = facts.iter().filter(|f| f.width == 8).map(|f| f.offset).collect();
    for &o in &offsets {
        if offsets.contains(&(o + 8)) {
            extent = extent.max(o + 24);
        }
    }
    extent
}

/// Reconstructs every fragmented stack object this module can safely
/// resolve, function by function: finds a local whose address is passed
/// to some other, already-recovered function, collects every field fact
/// that function (and any sibling locals in the same scope) provides,
/// and -- only when the evidence is completely unambiguous, and the
/// local's own declared size doesn't already cover the full extent --
/// widens it into a real byte-addressable object, merging every
/// fragment into a direct offset access. Must run before
/// `phantom_local.rs`'s own pass: that pass needs a real, byte-granular
/// pointer or array in scope to alias against, which this pass is what
/// actually produces.
pub fn reconstruct_stack_objects(functions: &mut [RecoveredFunction]) {
    // Keyed by *both* raw and display name: a real project whose earlier
    // `debura apply` run already renamed some functions in Ghidra itself
    // has call sites that mix the two -- a function renamed at some
    // point has every one of its own call sites (system-wide, since
    // Ghidra's own decompiler always uses a symbol's *current* name)
    // showing the pretty name, while an unrenamed one still shows its
    // raw `FUN_<addr>`. Confirmed against a real, fresh regeneration of
    // Snake: `initializeFoodParameters`'s own call sites already read
    // that way, not `FUN_1400025b0(...)`.
    let mut functions_by_name: HashMap<&str, &RecoveredFunction> = HashMap::new();
    for f in functions.iter() {
        functions_by_name.insert(f.raw_name.as_str(), f);
        functions_by_name.insert(f.display_name.as_str(), f);
    }

    let mut rewrites: Vec<(usize, String)> = Vec::new();

    for (i, f) in functions.iter().enumerate() {
        let Some(brace_open) = f.decompilation.find('{') else { continue };
        let Some(brace_close) = matching_close(&f.decompilation, brace_open, b'{', b'}') else { continue };
        let body = &f.decompilation[brace_open + 1..brace_close];
        let Some((locals_block, stmts_block)) = split_locals_block(body) else { continue };

        let mut new_locals_block = locals_block.to_string();
        let mut new_stmts_block = stmts_block.to_string();
        let mut changed = false;

        for base in declared_local_names(locals_block) {
            let Some(base_type) = declared_type_of(&new_locals_block, base) else { continue };
            let Some(current_size) = current_declared_size(&new_locals_block, base) else { continue };
            let already_array = is_declared_as_array(&new_locals_block, base);
            let mut facts = collect_field_facts(stmts_block, base, &functions_by_name).unwrap_or_default();
            facts.extend(external_cast_facts(stmts_block, base));
            facts.extend(external_call_facts(stmts_block, base));
            if facts.is_empty() {
                continue;
            }
            facts.push(FieldFact { offset: 0, width: current_size.min(u32::MAX as i64) as u32 });

            let Some(siblings) = find_sibling_locals(&new_locals_block, stmts_block, base, &facts) else { continue };
            let mut all_facts = facts.clone();
            all_facts.extend(siblings.iter().map(|s| FieldFact { offset: s.offset, width: width_of_declared_type(&s.declared_type).unwrap() }));

            let extent = minimum_extent(&all_facts);
            if extent <= current_size {
                continue;
            }

            new_locals_block = replace_declaration_with_array(&new_locals_block, base, extent as u64);
            if !already_array {
                new_stmts_block = replace_bare_identifier_not_address_of(
                    &new_stmts_block,
                    base,
                    &format!("*({} *)({} + 0)", base_type, base),
                );
            }
            for s in &siblings {
                new_locals_block = remove_declaration(&new_locals_block, &s.name);
                let replacement = format!("*({} *)({} + 0x{:x})", s.declared_type, base, s.offset);
                new_stmts_block = replace_whole_identifier(&new_stmts_block, &s.name, &replacement);
            }
            changed = true;
        }

        if changed {
            let rewritten = format!(
                "{}{}{}{}",
                &f.decompilation[..brace_open + 1],
                new_locals_block,
                new_stmts_block,
                &f.decompilation[brace_close..]
            );
            rewrites.push((i, rewritten));
        }
    }

    for (i, rewritten) in rewrites {
        functions[i].decompilation = rewritten;
    }
}

/// `locals_block`, with `name`'s own scalar declaration replaced by a
/// real `unsigned char name[extent];` array -- every remaining use of
/// `name` elsewhere in the body still compiles unchanged: a bare
/// `&name` decays to the same numeric address either way (a plain
/// value, never re-typed by anything downstream that doesn't already
/// cast it -- confirmed against every real call site this session
/// found), and every *value* use is rewritten separately by this
/// module's own caller before this is invoked.
fn replace_declaration_with_array(locals_block: &str, name: &str, extent: u64) -> String {
    let rebuilt: String = locals_block
        .lines()
        .map(|line| {
            let trimmed = line.trim().trim_end_matches(';').trim();
            let before_bracket = trimmed.split('[').next().unwrap_or(trimmed).trim();
            let ident = before_bracket.rsplit(|c: char| c == ' ' || c == '*').find(|s| !s.is_empty());
            if ident == Some(name) {
                format!("  unsigned char {}[{}];", name, extent)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    // See `remove_declaration`'s own doc comment (phantom_local.rs): a
    // locals block must always keep its own trailing newline, or the
    // real blank separator line that starts the statements block gets
    // silently merged onto the same line once this is concatenated back
    // -- destroying the only blank line any *later* pass's own
    // `split_locals_block` looks for on this same body.
    if rebuilt.is_empty() {
        rebuilt
    } else {
        rebuilt + "\n"
    }
}

/// Replaces every whole-identifier occurrence of `name` in `text` with
/// `replacement`, *except* one immediately preceded by `&` -- `&name`
/// itself is left completely untouched (a bare `&name` already decays
/// to the same numeric address once `name` is a real array, and every
/// real call site this session found immediately casts it away anyway,
/// so rewriting it too would only produce redundant, harder-to-read
/// `&*(...)` text without changing behavior).
fn replace_bare_identifier_not_address_of(text: &str, name: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(name) {
        let before = rest[..pos].chars().next_back();
        let before_ok = before.is_none_or(|c| !c.is_alphanumeric() && c != '_');
        let after = &rest[pos + name.len()..];
        let after_ok = after.chars().next().is_none_or(|c| !c.is_alphanumeric() && c != '_');
        out.push_str(&rest[..pos]);
        if before_ok && after_ok && before != Some('&') {
            out.push_str(replacement);
        } else {
            out.push_str(name);
        }
        rest = after;
    }
    out.push_str(rest);
    out
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
    fn finds_offset_dereferences() {
        let derefs = find_offset_dereferences("*(int *)(param_1 + 8) = param_2; *(undefined *)param_1 = 0;");
        assert_eq!(derefs, vec![("int *", "param_1 + 8"), ("undefined *", "param_1")]);
    }

    #[test]
    fn width_from_cast_inner_handles_pointer_fields() {
        assert_eq!(width_from_cast_inner("int *"), Some(4));
        assert_eq!(width_from_cast_inner("undefined *"), Some(1));
        assert_eq!(width_from_cast_inner("void **"), Some(8));
        assert_eq!(width_from_cast_inner("longlong *"), Some(8));
        assert_eq!(width_from_cast_inner("Section *"), None);
    }

    #[test]
    fn minimum_extent_infers_a_full_vector_from_begin_and_end() {
        let facts = vec![FieldFact { offset: 0x10, width: 8 }, FieldFact { offset: 0x18, width: 8 }];
        assert_eq!(minimum_extent(&facts), 0x28);
    }

    #[test]
    fn minimum_extent_without_a_begin_end_pair_is_just_the_max() {
        let facts = vec![FieldFact { offset: 0, width: 4 }, FieldFact { offset: 4, width: 4 }];
        assert_eq!(minimum_extent(&facts), 8);
    }

    /// The real, confirmed Snake case: `local_b8` (declared a bare
    /// 4-byte scalar) is really Snake's own state object --
    /// `initializeFoodParameters` writes offsets 0/4/8/0xc through its
    /// own `param_1`, `FUN_140002784` writes offsets 8/0xc through its
    /// own `param_1`, and a vector-accessor pair is reached at
    /// `param_1 + 0x10` elsewhere. `local_b4`/`local_ac` are separately
    /// declared locals that are really `local_b8+4`/`local_b8+0xc`.
    /// Must widen `local_b8` to a real byte array covering the full
    /// vector, and rewrite every fragment into a direct offset access.
    #[test]
    fn the_real_snake_local_b8_case_resolves_correctly() {
        let mut functions = vec![
            function(
                "0x1400025b0",
                "undefined4 *param_1",
                "undefined FUN_1400025b0(undefined4 *param_1)\n\n{\n  \n  *param_1 = 1;\n  param_1[1] = 3;\n  param_1[2] = 3;\n  *(undefined *)(param_1 + 3) = 0;\n  return;\n}",
            ),
            function(
                "0x140002784",
                "longlong param_1, int param_2",
                "undefined FUN_140002784(longlong param_1, int param_2)\n\n{\n  \n  *(int *)(param_1 + 8) = param_2;\n  *(undefined *)(param_1 + 0xc) = 1;\n  return;\n}",
            ),
            function(
                "0x140006050",
                "longlong *param_1",
                "longlong FUN_140006050(longlong *param_1)\n\n{\n  \n  return param_1[1] - *param_1 >> 3;\n}",
            ),
            function(
                "0x1400026f2",
                "longlong param_1, undefined8 param_2",
                "undefined FUN_1400026f2(longlong param_1, undefined8 param_2)\n\n{\n  longlong lVar1;\n  \n  lVar1 = FUN_140006050((longlong *)(param_1 + 0x10));\n  return;\n}",
            ),
            function(
                "0x140003476",
                "void",
                "undefined8 initializeRandomState(void)\n\n{\n  undefined4 local_b8;\n  int local_b4;\n  char local_ac;\n  int local_1c;\n  \n  FUN_1400025b0((undefined4 *)(&local_b8));\n  local_1c = 0;\n  while (0 < local_b4) {\n    FUN_1400026f2((longlong)((longlong)&local_b8),(undefined8)(0));\n    if (local_ac != '\\x01') {\n      FUN_140002784((longlong)((longlong)&local_b8),(int)(0));\n    }\n    local_1c = local_1c + 1;\n  }\n  return 0;\n}",
            ),
        ];

        reconstruct_stack_objects(&mut functions);

        let body = &functions[4].decompilation;
        assert!(body.contains("unsigned char local_b8[40];"), "{body}");
        assert!(!body.contains("local_b4"), "{body}");
        assert!(!body.contains("local_ac"), "{body}");
        assert!(body.contains("*(int *)(local_b8 + 0x4)"), "{body}");
        assert!(body.contains("*(char *)(local_b8 + 0xc)"), "{body}");
    }

    /// No address-taken evidence at all -- must never touch the local.
    #[test]
    fn no_evidence_leaves_the_local_untouched() {
        let mut functions =
            vec![function("0x1", "void", "undefined8 FUN_1(void)\n\n{\n  int local_8;\n  \n  local_8 = 5;\n  return 0;\n}")];
        reconstruct_stack_objects(&mut functions);
        assert!(functions[0].decompilation.contains("int local_8;"));
    }

    /// A local already declared big enough for every discovered field
    /// must be left completely alone -- nothing to widen.
    #[test]
    fn an_already_sufficient_local_is_left_untouched() {
        let mut functions = vec![
            function(
                "0x140002784",
                "longlong param_1, int param_2",
                "undefined FUN_140002784(longlong param_1, int param_2)\n\n{\n  \n  *(int *)(param_1) = param_2;\n  return;\n}",
            ),
            function(
                "0x2",
                "void",
                "undefined8 FUN_2(void)\n\n{\n  longlong local_8;\n  \n  FUN_140002784((longlong)((longlong)&local_8),(int)(0));\n  return 0;\n}",
            ),
        ];
        reconstruct_stack_objects(&mut functions);
        assert!(functions[1].decompilation.contains("longlong local_8;"), "{}", functions[1].decompilation);
    }

    /// The real, confirmed root cause of tonight's crash: `local_48`
    /// (declared `int [5]`, 20 bytes) is passed completely *bare* --
    /// Ghidra's own raw decompilation doesn't even emit a cast here --
    /// to `SDL_PollEvent`. An external library call never appears in
    /// `functions_by_name`, and there's no cast text for
    /// `external_cast_facts` to read either, so this evidence can only
    /// come from `external_call_facts`'s own known-signature table.
    /// `local_34` is a separate local that's really `local_48 + 0x14`
    /// (Ghidra's own naming: `0x48 - 0x34 = 0x14`, exactly a real
    /// `SDL_Event`'s `key.keysym.sym` field). Must widen `local_48` to
    /// the real 56-byte `SDL_Event` size and merge `local_34` in,
    /// *without* rewriting `local_48`'s own (already-correct,
    /// array-decay) uses.
    #[test]
    fn the_real_sdl_event_local_48_case_resolves_correctly() {
        let mut functions = vec![function(
            "0x140001bf2",
            "void",
            "undefined4 FUN_140001bf2(void)\n\n{\n  int iVar1;\n  int local_48 [5];\n  int local_34;\n  undefined4 local_c;\n  \n  local_c = 0xffffffff;\n  while (iVar1 = SDL_PollEvent(local_48), iVar1 != 0) {\n    if (local_48[0] == 0x100) {\n      local_c = 0;\n    }\n    else if (local_34 == 0x40000052) {\n      local_c = 1;\n    }\n  }\n  return local_c;\n}",
        )];

        reconstruct_stack_objects(&mut functions);

        let body = &functions[0].decompilation;
        assert!(body.contains("unsigned char local_48[56];"), "{body}");
        assert!(!body.contains("local_34"), "{body}");
        assert!(body.contains("SDL_PollEvent(local_48)"), "base's own array-decay use must survive unchanged: {body}");
        assert!(body.contains("*(int *)(local_48 + 0x14)"), "{body}");
    }
}
