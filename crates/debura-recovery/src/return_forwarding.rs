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
use crate::forwarding_thunk::{call_name_and_args, matching_close, split_top_level_statements, Stmt};

/// Whether `decompilation`'s own body ends with a plain call statement
/// immediately followed by a bare `return;` (no value) -- `None` for
/// anything else (the call's own result assigned to a variable, a
/// non-`FUN_<addr>` callee, an `if` block as the final statement, a body
/// `split_top_level_statements` can't parse at all, ...). Deliberately
/// narrow: every real case this was built from has this exact shape
/// (any amount of real work *before* the final call is fine -- only the
/// last two statements matter), and a broader match risks rewriting a
/// body this module has no real grounds to understand. Unlike
/// `forwarding_thunk.rs`'s own detector, earlier statements are never
/// required to be guard-shaped -- this only cares that the call's own
/// result is genuinely discarded, not why.
pub fn detect_return_forwarding_wrapper(decompilation: &str) -> Option<String> {
    let brace_open = decompilation.find('{')?;
    let brace_close = matching_close(decompilation, brace_open, b'{', b'}')?;
    let body = &decompilation[brace_open + 1..brace_close];
    let stmts = split_top_level_statements(body)?;

    let [.., Stmt::Call { text: call_stmt }, Stmt::Call { text: "return" }] = stmts.as_slice() else {
        return None;
    };
    let (name, _args) = call_name_and_args(call_stmt)?;
    if !name.starts_with("FUN_") || !name["FUN_".len()..].chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(name.to_string())
}

/// `decompilation`, rewritten so its final statement forwards its own
/// return value (`...; CALL(...); return;` -> `...; return CALL(...);`)
/// -- assumes `detect_return_forwarding_wrapper` already matched this
/// exact text (so the body's own last statement is exactly `return;`,
/// preceded by exactly one real call statement).
fn rewrite_to_forward_return_value(decompilation: &str) -> String {
    let brace_open = decompilation.find('{').expect("caller already confirmed a body exists");
    let brace_close =
        matching_close(decompilation, brace_open, b'{', b'}').expect("caller already confirmed a matching close brace");
    let body = &decompilation[brace_open + 1..brace_close];
    // The call statement's own text is exactly what
    // `detect_return_forwarding_wrapper` matched as the second-to-last
    // top-level statement -- found the same way here (rather than
    // threading it through as a parameter) so this function stays a
    // pure function of the same text its caller already validated.
    let stmts = split_top_level_statements(body).expect("caller already confirmed this parses");
    let Some(Stmt::Call { text: call_stmt }) = stmts.iter().rev().nth(1) else {
        panic!("caller already confirmed the second-to-last statement is a plain call");
    };
    let before_call = body.rfind(call_stmt).expect("the call statement's own text must appear verbatim in body");
    format!("{}{{{}return {};\n}}", &decompilation[..brace_open], &body[..before_call], call_stmt)
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

    /// PROJECT.md M18.3: the real, confirmed case `FUN_140007570` needed
    /// -- real work (several local declarations and calls) before the
    /// final forwarding call is exactly what a real wrapper does; only
    /// the *last two* statements (a plain call, then a bare `return;`)
    /// need to match. Only the earlier, narrower version of this
    /// detector required the whole body to be a single statement.
    #[test]
    fn real_work_before_the_final_forwarding_call_still_matches() {
        let decompilation = "undefined FUN_1(undefined8 param_1)\n\n{\n  void *pvVar1;\n  pvVar1 = FUN_2(param_1);\n  FUN_3(pvVar1);\n  return;\n}";
        assert_eq!(detect_return_forwarding_wrapper(decompilation).as_deref(), Some("FUN_3"));
    }

    /// The second-to-last statement's own call result being assigned to
    /// a variable (even if that variable then goes unused) is not the
    /// same as the *final* call's result being genuinely discarded --
    /// only the call immediately before the bare `return;` matters.
    #[test]
    fn an_assignment_immediately_before_the_final_return_is_not_a_forwarding_wrapper() {
        let decompilation = "undefined FUN_1(undefined8 param_1)\n\n{\n  void *pvVar1;\n  pvVar1 = FUN_2(param_1);\n  return;\n}";
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

    /// PROJECT.md M18.3: the real, confirmed shape `FUN_140007570` had --
    /// real local declarations and calls before the final, discarded
    /// call -- must resolve exactly like the trivial single-statement
    /// case, with every earlier statement preserved verbatim.
    #[test]
    fn preceding_real_statements_survive_the_rewrite_unchanged() {
        let mut functions = vec![
            function(
                "0x1",
                "undefined",
                "undefined FUN_1(undefined8 param_1,undefined8 param_2,undefined8 param_3)\n\n{\n  void *pvVar1;\n  longlong lVar2;\n  \n  pvVar1 = (void *)FUN_480((undefined8)(param_3));\n  lVar2 = FUN_480((undefined8)(param_2));\n  FUN_2((void *)(pvVar1),(longlong)(lVar2));\n  return;\n}",
            ),
            function("0x2", "void *", "void * FUN_2(void *param_1, longlong param_2)\n\n{\n  return param_1;\n}"),
        ];

        propagate_forwarded_return_types(&mut functions);

        assert_eq!(functions[0].return_type, "void *");
        let body = &functions[0].decompilation;
        assert!(body.contains("pvVar1 = (void *)FUN_480((undefined8)(param_3));"), "{body}");
        assert!(body.contains("lVar2 = FUN_480((undefined8)(param_2));"), "{body}");
        assert!(body.contains("return FUN_2((void *)(pvVar1),(longlong)(lVar2));"), "{body}");
        assert!(!body.contains("  return;\n}"), "the bare trailing return must be replaced, not just followed: {body}");
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
