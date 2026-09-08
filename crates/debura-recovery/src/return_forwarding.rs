/// PROJECT.md M18.3: a real, repeated pattern found while getting the
/// Snake binary to actually link and run -- Ghidra's own return-type
/// inference sometimes concludes a function returns nothing meaningful
/// (the bare `undefined` placeholder, its own least-committal marker --
/// see `data_symbols.rs`'s own established distinction between that and
/// a real, sized/void commitment) when the real compiled function's
/// only substantive work is a single call whose real return value it
/// passes straight through unchanged. Four real, independently-found
/// instances in one evening (`FUN_140006c90`, `FUN_140007570`,
/// `FUN_1400067b0`, `FUN_140007500`, chaining down to a real,
/// concretely-typed `void *` at the bottom) all had this exact shape --
/// silently truncating a real pointer to whatever leftover byte
/// happened to be in AL/RAX's low bits, corrupting every caller up the
/// chain at runtime. This is what replaces hand-patching each one found
/// this way: detected purely structurally (never guessed at what a
/// function "should" return), and only ever applied once the callee's
/// own return type is already concretely established -- a real value
/// propagated from real evidence, the same "trust the body over a stale
/// signature" principle this crate already applies to stale parameter
/// counts.
use crate::forwarding_thunk::matching_close;

/// Whether `decompilation`'s own body is *exactly* one call statement
/// followed by a bare `return;` (no value) -- `None` for anything else
/// (multiple statements, a call whose own result is actually used, a
/// guard branch, a non-`FUN_<addr>` callee, ...). Deliberately narrow:
/// every real case this was built from has this exact shape, and a
/// broader match risks rewriting a body this module has no real grounds
/// to understand.
pub fn detect_return_forwarding_wrapper(decompilation: &str) -> Option<String> {
    let brace_open = decompilation.find('{')?;
    let brace_close = matching_close(decompilation, brace_open, b'{', b'}')?;
    let body = decompilation[brace_open + 1..brace_close].trim();

    let semi = body.find(';')?;
    let call_stmt = body[..semi].trim();
    let rest = body[semi + 1..].trim();
    if rest != "return;" {
        return None;
    }

    let open = call_stmt.find('(')?;
    if !call_stmt.ends_with(')') {
        return None;
    }
    let name = call_stmt[..open].trim();
    if !name.starts_with("FUN_") || !name["FUN_".len()..].chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(name.to_string())
}

/// `decompilation`, rewritten so its one real statement forwards its own
/// return value (`CALL(...); return;` -> `return CALL(...);`) --
/// assumes `detect_return_forwarding_wrapper` already matched this exact
/// text.
fn rewrite_to_forward_return_value(decompilation: &str) -> String {
    let brace_open = decompilation.find('{').expect("caller already confirmed a body exists");
    let brace_close = matching_close(decompilation, brace_open, b'{', b'}').expect("caller already confirmed a matching close brace");
    let body = &decompilation[brace_open + 1..brace_close];
    let semi = body.find(';').expect("caller already confirmed a call statement");
    let call_stmt = body[..semi].trim();
    format!("{}{{\n  return {};\n}}", &decompilation[..brace_open], call_stmt)
}

/// The bare, uncommitted Ghidra placeholder -- see `data_symbols.rs`'s
/// own doc comments on why this specific string (never a real sized
/// type) is the one signal that a declared type isn't a real
/// commitment.
fn is_uncommitted_return_type(return_type: &str) -> bool {
    return_type == "undefined"
}

/// The address a `FUN_<hex>` raw name embeds directly in its own text --
/// simpler than `data_symbols.rs`'s own `address_from_symbol_name` (no
/// other prefix shapes to handle here, since `detect_return_forwarding_wrapper`
/// already only ever matches this one).
fn address_from_raw_name(raw_name: &str) -> Option<String> {
    Some(format!("0x{}", raw_name.strip_prefix("FUN_")?))
}

/// Finds every standalone function whose own body is a pure return-
/// forwarding wrapper (see this module's own top-level doc comment) and,
/// wherever the callee's own return type is already concretely known,
/// corrects the wrapper's declared return type and rewrites its body to
/// really forward the value -- in place, as a fixed-point loop so a real
/// chain of several such wrappers (as tonight's real case had) resolves
/// however deep it goes, not just one hop. A wrapper whose callee is
/// itself still uncommitted (address unknown, or also still `undefined`
/// and never resolved) is left exactly as recovered -- "Unknown is
/// better than confidently wrong" applies here the same as everywhere
/// else in this crate.
pub fn propagate_forwarded_return_types(functions: &mut [crate::model::RecoveredFunction]) {
    use std::collections::HashMap;

    let address_to_index: HashMap<String, usize> =
        functions.iter().enumerate().map(|(i, f)| (f.address.clone(), i)).collect();

    let candidates: Vec<(usize, String)> = functions
        .iter()
        .enumerate()
        .filter(|(_, f)| is_uncommitted_return_type(&f.return_type))
        .filter_map(|(i, f)| detect_return_forwarding_wrapper(&f.decompilation).map(|callee| (i, callee)))
        .collect();

    loop {
        let mut progressed = false;
        for (i, callee_raw_name) in &candidates {
            if !is_uncommitted_return_type(&functions[*i].return_type) {
                continue;
            }
            let Some(callee_addr) = address_from_raw_name(callee_raw_name) else { continue };
            let Some(&callee_idx) = address_to_index.get(&callee_addr) else { continue };
            let callee_return_type = functions[callee_idx].return_type.clone();
            if is_uncommitted_return_type(&callee_return_type) {
                continue;
            }
            functions[*i].return_type = callee_return_type;
            functions[*i].decompilation = rewrite_to_forward_return_value(&functions[*i].decompilation);
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{NameSource, RecoveredFunction};

    #[test]
    fn a_pure_forwarding_body_is_recognized() {
        let decompilation = "undefined FUN_140006c90(undefined8 param_1,undefined8 param_2,undefined8 param_3)\n\n{\n  FUN_140007570((undefined8)(param_1),(undefined8)(param_2),(undefined8)(param_3));\n  return;\n}";
        assert_eq!(detect_return_forwarding_wrapper(decompilation).as_deref(), Some("FUN_140007570"));
    }

    /// A real body that actually *uses* the call's own result must never
    /// match -- there's nothing being silently discarded here.
    #[test]
    fn a_body_that_uses_the_calls_result_is_not_a_forwarding_wrapper() {
        let decompilation = "undefined8 FUN_1(undefined8 param_1)\n\n{\n  undefined8 uVar1;\n  uVar1 = FUN_2(param_1);\n  return uVar1;\n}";
        assert!(detect_return_forwarding_wrapper(decompilation).is_none());
    }

    #[test]
    fn a_body_with_more_than_one_statement_is_not_a_forwarding_wrapper() {
        let decompilation = "undefined FUN_1(undefined8 param_1)\n\n{\n  FUN_2(param_1);\n  FUN_3(param_1);\n  return;\n}";
        assert!(detect_return_forwarding_wrapper(decompilation).is_none());
    }

    /// A call to a real, recognized-by-name CRT function (not a
    /// `FUN_<addr>` placeholder) is never rewritten this way -- this
    /// module only resolves chains through *other recovered functions*
    /// it can look up an address for.
    #[test]
    fn a_call_to_a_named_function_is_not_a_forwarding_wrapper() {
        let decompilation = "undefined FUN_1(undefined8 param_1)\n\n{\n  _initterm(param_1);\n  return;\n}";
        assert!(detect_return_forwarding_wrapper(decompilation).is_none());
    }

    fn function(address: &str, return_type: &str, decompilation: &str) -> RecoveredFunction {
        let raw_name = format!("FUN_{}", &address[2..]);
        RecoveredFunction {
            address: address.to_string(),
            raw_name: raw_name.clone(),
            display_name: raw_name,
            name_source: NameSource::Raw,
            return_type: return_type.to_string(),
            params: String::new(),
            decompilation: decompilation.to_string(),
        }
    }

    /// The real, confirmed case: a two-hop chain (matching
    /// `FUN_140006c90` -> `FUN_140007570` -> a real, concretely-typed
    /// pointer-returning function) must resolve fully, not just one hop.
    #[test]
    fn a_two_hop_chain_resolves_to_the_real_concrete_type() {
        let mut functions = vec![
            function(
                "0x1",
                "undefined",
                "undefined FUN_1(undefined8 param_1)\n\n{\n  FUN_2(param_1);\n  return;\n}",
            ),
            function(
                "0x2",
                "undefined",
                "undefined FUN_2(undefined8 param_1)\n\n{\n  FUN_3(param_1);\n  return;\n}",
            ),
            function("0x3", "void *", "void * FUN_3(undefined8 param_1)\n\n{\n  return (void *)param_1;\n}"),
        ];

        propagate_forwarded_return_types(&mut functions);

        assert_eq!(functions[0].return_type, "void *");
        assert!(functions[0].decompilation.contains("return FUN_2(param_1);"), "{}", functions[0].decompilation);
        assert_eq!(functions[1].return_type, "void *");
        assert!(functions[1].decompilation.contains("return FUN_3(param_1);"), "{}", functions[1].decompilation);
    }

    /// A wrapper whose callee is never resolved to a concrete type (an
    /// address Debura has no record of at all) must be left completely
    /// untouched -- never guessed at.
    #[test]
    fn an_unresolvable_callee_leaves_the_wrapper_untouched() {
        let mut functions = vec![function(
            "0x1",
            "undefined",
            "undefined FUN_1(undefined8 param_1)\n\n{\n  FUN_deadbeef(param_1);\n  return;\n}",
        )];

        propagate_forwarded_return_types(&mut functions);

        assert_eq!(functions[0].return_type, "undefined");
        assert!(functions[0].decompilation.contains("FUN_deadbeef(param_1);\n  return;"), "{}", functions[0].decompilation);
    }
}
