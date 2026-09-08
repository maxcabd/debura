use std::collections::{BTreeSet, HashMap};

use crate::model::{RecoveredClass, RecoveredFunction};

/// What a recovered address actually is, for call-site rendering
/// purposes (PROJECT.md M9+: "cross-unit symbol recovery"). A real
/// compile attempt showed why this needs to exist as its own pass rather
/// than a per-file compatibility shim: rendering every call site as a
/// literal `FUN_<addr>(args)` -- valid only for a genuine free function
/// -- produced 262 "not declared" errors, because most of those
/// addresses are actually constructors, destructors, or instance methods
/// that Ghidra's own C-shaped pseudocode calls as if they were ordinary
/// functions (`FUN_ctor(this, x, y)` for what a real compile needs as
/// `new (this) Class(x, y)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolKind {
    FreeFunction,
    Method,
    Constructor,
    Destructor,
    /// PROJECT.md M18.3: a real, compiled forwarding thunk (see
    /// `forwarding_thunk.rs`) -- never independently recovered as its
    /// own function, but a real call site elsewhere still needs to
    /// resolve through it. `RecoveredSymbol::canonical_target` and
    /// `argument_mapping` carry what a `FreeFunction`/`Method`/etc.
    /// entry doesn't need at all.
    ForwardingThunk,
}

/// One canonical-target argument's real source for a `ForwardingThunk`
/// entry -- see `forwarding_thunk.rs`'s own doc comment for the full
/// reasoning; defined here (not there) since `RecoveredSymbol` needs it
/// and `forwarding_thunk.rs` already depends on this module for
/// `SymbolTable`/`SymbolKind`, so the reverse dependency would cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentMapping {
    pub source_param_index: usize,
    pub transform: Option<ArgTransform>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgTransform {
    Multiply(u64),
    ShiftLeft(u64),
}

#[derive(Debug, Clone)]
pub struct RecoveredSymbol {
    pub kind: SymbolKind,
    /// Class name, for Method/Constructor/Destructor; unused for
    /// FreeFunction.
    pub owner: String,
    /// The name to call: a plain function name for FreeFunction, a
    /// bare method name for Method (dispatched through `->`), or the
    /// class name itself for Constructor/Destructor (C++ doesn't let a
    /// constructor/destructor be named any other way).
    pub display_name: String,
    /// How many arguments a call site naming this address should have,
    /// counting the this/ptr argument Ghidra's own C-shaped call always
    /// includes for Method/Constructor (0 for FreeFunction, which has no
    /// such argument; always 1 for Destructor, which the language
    /// guarantees takes no parameters of its own).
    pub expected_args: usize,
    /// Each declared parameter's own type (FreeFunction only; empty for
    /// Method/Constructor/Destructor, whose receiver is already cast
    /// separately and whose remaining parameters haven't shown this
    /// problem in practice). PROJECT.md M18: a real compile found two
    /// *different* Ghidra-inferred types for what's really the same
    /// pointer value at two different observation points -- a local
    /// declared `void **local_30;` at its own call site, passed straight
    /// into a callee whose own recovered signature says `undefined8
    /// *param_1`. C++ doesn't implicitly convert between unrelated
    /// pointer types, so the call site needs its own explicit cast to
    /// the callee's declared type, the same principle this module
    /// already applies to a method call's own receiver.
    pub param_types: Vec<String>,
    /// `ForwardingThunk` only -- the real runtime symbol a call site
    /// naming this address actually rewrites to (`display_name` is set
    /// to the same value, for anything that only ever reads that field
    /// generically). Empty for every other kind.
    pub canonical_target: String,
    /// `ForwardingThunk` only -- see `forwarding_thunk.rs`. Empty for
    /// every other kind.
    pub argument_mapping: Vec<ArgumentMapping>,
    /// The declared return type, exactly as recovered -- `Method` and
    /// `FreeFunction` only (PROJECT.md M18.3: needed to synthesize a
    /// vtable-slot trampoline's own signature, see
    /// `data_symbols::VtableSlotTarget::Method`). Empty for every other
    /// kind.
    pub return_type: String,
    /// The declared parameter list, exactly as recovered -- real types
    /// *and* names (`"longlong param_2"`, not just `param_types`' bare
    /// types), and never including the receiver. `Method`/`FreeFunction`
    /// only, empty for every other kind, same reasoning as
    /// `return_type`.
    pub raw_params: String,
}

/// Counts a recovered signature's own parameters -- `""`/`"void"` mean
/// zero, matching how `parse_signature` already renders a no-argument
/// C++ parameter list. A plain top-level comma count is enough here:
/// unlike a call site's arguments (which can nest other calls needing
/// balanced-paren-aware splitting), a *parameter list*'s own types don't
/// contain call syntax.
fn count_params(params: &str) -> usize {
    let trimmed = params.trim();
    if trimmed.is_empty() || trimmed == "void" {
        0
    } else {
        trimmed.split(',').count()
    }
}

/// One declared parameter's own type -- everything before its trailing
/// identifier, the same split `extract.rs`'s `strip_receiver_param`
/// already uses for the same shape of text (`TYPE *name`, `TYPE name`).
/// Empty when nothing looks like a real trailing name at all (defensive;
/// not expected against real Ghidra-shaped signatures).
fn param_type(param: &str) -> String {
    let trimmed = param.trim();
    match trimmed.rsplit(|c: char| c == ' ' || c == '*').find(|s| !s.is_empty()) {
        Some(name) if name.len() < trimmed.len() => trimmed[..trimmed.len() - name.len()].trim_end().to_string(),
        _ => String::new(),
    }
}

/// Every declared parameter's own type, in order -- `""`/`"void"` mean
/// none, matching `count_params`'s own convention.
fn param_types(params: &str) -> Vec<String> {
    let trimmed = params.trim();
    if trimmed.is_empty() || trimmed == "void" {
        Vec::new()
    } else {
        trimmed.split(',').map(param_type).collect()
    }
}

pub type SymbolTable = HashMap<String, RecoveredSymbol>;

/// Builds the whole-program symbol table from what `extract()` already
/// found -- no new facts needed, this only classifies what's already
/// there. Every class's own methods (including ctor/dtor, which
/// `RecoveredMethod` already distinguishes) plus every standalone
/// recovered function become one entry each, keyed by address so a call
/// site naming that address can be resolved regardless of which file
/// the caller or the callee ends up rendered into.
pub fn build_symbol_table(classes: &[RecoveredClass], functions: &[RecoveredFunction]) -> SymbolTable {
    let mut table = SymbolTable::new();
    for class in classes {
        for m in &class.methods {
            let kind = if m.is_constructor {
                SymbolKind::Constructor
            } else if m.is_destructor {
                SymbolKind::Destructor
            } else {
                SymbolKind::Method
            };
            let display_name = if m.is_constructor || m.is_destructor {
                class.name.clone()
            } else {
                m.display_name.clone()
            };
            // Destructors take no parameters of their own by language
            // rule, regardless of what `m.params` says (Ghidra's own
            // signature parsing doesn't specially distinguish them) --
            // only the this/ptr argument is ever expected.
            let expected_args = if m.is_destructor { 1 } else { count_params(&m.params) + 1 };
            table.insert(
                m.address.clone(),
                RecoveredSymbol {
                    kind,
                    owner: class.name.clone(),
                    display_name,
                    expected_args,
                    param_types: Vec::new(),
                    canonical_target: String::new(),
                    argument_mapping: Vec::new(),
                    return_type: m.return_type.clone(),
                    raw_params: m.params.clone(),
                },
            );
        }
    }
    for f in functions {
        table.insert(
            f.address.clone(),
            RecoveredSymbol {
                kind: SymbolKind::FreeFunction,
                owner: String::new(),
                display_name: f.display_name.clone(),
                expected_args: count_params(&f.params),
                param_types: param_types(&f.params),
                canonical_target: String::new(),
                argument_mapping: Vec::new(),
                return_type: f.return_type.clone(),
                raw_params: f.params.clone(),
            },
        );
    }
    table
}

/// One `FUN_<hex>`/`thunk_FUN_<hex>` call site: the byte range of its
/// name, the byte offset of the `(` that follows, the address it names,
/// and its exact literal spelling (needed separately from the address --
/// `FUN_x` and `thunk_FUN_x` for the same address need their own
/// fallback declaration each, if a call using that exact spelling ends
/// up left unresolved).
struct CallStart {
    name_start: usize,
    open_paren: usize,
    address: String,
    literal_name: String,
}

/// Matches a Ghidra raw call-target name at a call site: `FUN_<hex>`,
/// or the same address wrapped in `thunk_FUN_<hex>` (an indirect-jump
/// thunk Ghidra sometimes names separately from the real function it
/// jumps to, but which still names the same address in its own suffix).
fn find_call_starts(text: &str) -> Vec<CallStart> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if text[i..].starts_with("FUN_") || text[i..].starts_with("thunk_FUN_") {
            let start = i;
            let hex_start = if text[i..].starts_with("thunk_FUN_") { i + 6 } else { i };
            let mut j = hex_start + 4; // past "FUN_"
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            // Only a real call site, not e.g. a comment mentioning the
            // address or a function *declaration* line -- both this
            // module's own use sites always look for `(` immediately
            // (whitespace-tolerant) after the name.
            let mut k = j;
            while k < bytes.len() && bytes[k] == b' ' {
                k += 1;
            }
            if k < bytes.len() && bytes[k] == b'(' && j > hex_start + 4 {
                out.push(CallStart {
                    name_start: start,
                    open_paren: k,
                    address: format!("0x{}", &text[hex_start + 4..j]),
                    literal_name: text[start..j].to_string(),
                });
                i = k;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Splits a call's argument text on its top-level commas -- the same
/// balanced-paren tracking `extract_base_constructor_call` already needs
/// for the leading base-constructor-call case, generalized to any call
/// site and to more than one comma. Does track string-literal state (a
/// real case had a format-string argument -- `"...out of range,
/// targeting %p, yielding the value %p.\n"` -- whose own *literal text*
/// contained two commas; without this, those got treated as real
/// top-level argument separators, inflating a genuine 4-argument call
/// site to a counted 6, failing the arity check against the callee's
/// real declared signature, and leaving the call unresolved -- with a
/// competing, conflicting *variadic* fallback declaration generated for
/// it alongside the real, fixed-arity one, which is what a real link
/// actually failed on). Only double-quoted string literals, with `\"` as
/// the one escape this needs to recognize (Ghidra's own decompiled
/// output has been observed using it; nothing else does): not a full C
/// string-literal grammar, just enough to stop a comma inside one from
/// looking like an argument separator.
fn split_args(args: &str) -> Vec<&str> {
    if args.trim().is_empty() {
        return Vec::new();
    }
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut in_string = false;
    let mut chars = args.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if in_string {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(args[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(args[start..].trim());
    parts
}

/// Finds the matching close paren for the `(` at `open`, the same
/// depth-counting approach used throughout this crate for exactly this
/// (see `extract_base_constructor_call`).
fn matching_close_paren(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Rewrites every `FUN_<addr>(...)`/`thunk_FUN_<addr>(...)` call site in
/// `text` using `table`: a free function becomes a call by its real
/// name; a method becomes `((Owner *)(this_expr))->method(rest...)`; a
/// constructor becomes placement-new (`new ((void *)(ptr_expr))
/// Owner(rest...)`), and a destructor becomes an explicit destructor
/// call (`((Owner *)(ptr_expr))->~Owner()`) -- both real, standard C++
/// for re-invoking a constructor/destructor on already-allocated memory,
/// which is exactly what Ghidra's own C-shaped pseudocode is describing.
/// An address with no entry in `table` is left as a literal `FUN_addr`
/// call (its name, not its call syntax, is untouched either way) and
/// recorded into `unresolved` so the caller can still declare a
/// permissive fallback prototype for it -- a real, if generic, thing to
/// call beats a compile error.
pub fn rewrite_call_sites(text: &str, table: &SymbolTable, unresolved: &mut BTreeSet<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    loop {
        let calls = find_call_starts(&text[cursor..]);
        let Some(call) = calls.into_iter().next() else {
            out.push_str(&text[cursor..]);
            break;
        };
        let start = cursor + call.name_start;
        let open = cursor + call.open_paren;
        let addr = &call.address;
        let Some(close) = matching_close_paren(text, open) else {
            // No balanced close found (shouldn't happen in real
            // decompiled output) -- stop rewriting the rest of this
            // body rather than risk corrupting it.
            out.push_str(&text[cursor..]);
            break;
        };
        out.push_str(&text[cursor..start]);

        // Recurse into each argument *before* using it: a call's own
        // arguments can themselves contain further `FUN_*` calls (e.g.
        // `FUN_5(p,FUN_6(1),2)`), and this outer match's `close` already
        // spans past all of them -- without rewriting each argument
        // independently here, a nested call inside a resolved outer call
        // would never get its own turn.
        let args: Vec<String> = split_args(&text[open + 1..close])
            .into_iter()
            .map(|a| rewrite_call_sites(a, table, unresolved))
            .collect();
        // PROJECT.md M15: don't blindly forward Ghidra's raw argument
        // count into a constructor/method call whose recovered
        // declaration expects a different number -- an arity mismatch
        // means the call site doesn't actually match this symbol as
        // cleanly as its address alone suggested (an overload at a
        // different address, a variadic-shaped call, or a genuinely
        // wrong resolution), and rendering it anyway produces invalid
        // C++ (or silently wrong C++, which is worse). Falling back to
        // "unresolved" here is the conservative choice: a permissive
        // fallback prototype that at least compiles beats confidently
        // wrong or invalid call syntax.
        match table.get(addr).filter(|sym| args.len() == sym.expected_args) {
            Some(sym) => match sym.kind {
                SymbolKind::FreeFunction => {
                    out.push_str(&sym.display_name);
                    out.push('(');
                    // Cast each argument to the callee's own declared
                    // parameter type -- see `RecoveredSymbol::param_types`.
                    // A redundant cast to an argument's own already-
                    // correct type is inert; the only reason this always
                    // runs is that Ghidra assigning two different types to
                    // "the same" pointer at two different observation
                    // points can't be told apart from an already-matching
                    // one by comparing type text alone (formatting varies).
                    let casted: Vec<String> = args
                        .iter()
                        .enumerate()
                        .map(|(i, a)| match sym.param_types.get(i) {
                            Some(ty) if !ty.is_empty() => format!("({ty})({a})"),
                            _ => a.clone(),
                        })
                        .collect();
                    out.push_str(&casted.join(","));
                    out.push(')');
                }
                SymbolKind::Method => {
                    let this_expr = args.first().cloned().unwrap_or_else(|| "nullptr".to_string());
                    let rest = if args.len() > 1 { args[1..].join(",") } else { String::new() };
                    out.push_str(&format!(
                        "(({} *)({}))->{}({})",
                        sym.owner, this_expr, sym.display_name, rest
                    ));
                }
                SymbolKind::Constructor => {
                    let ptr_expr = args.first().cloned().unwrap_or_else(|| "nullptr".to_string());
                    let rest = if args.len() > 1 { args[1..].join(",") } else { String::new() };
                    out.push_str(&format!("new ((void *)({})) {}({})", ptr_expr, sym.owner, rest));
                }
                SymbolKind::Destructor => {
                    let ptr_expr = args.first().cloned().unwrap_or_else(|| "nullptr".to_string());
                    out.push_str(&format!("(({} *)({}))->~{}()", sym.owner, ptr_expr, sym.owner));
                }
                // PROJECT.md M18.3: a real, compiled forwarding thunk
                // (see `forwarding_thunk.rs`) -- rewritten directly to
                // the real target it forwards to, applying the exact
                // same (bounded, deterministic) argument transform its
                // own body performs, so the call site never needs the
                // thunk's own address to exist as a real function at
                // all.
                SymbolKind::ForwardingThunk => {
                    let mapped: Vec<String> = sym
                        .argument_mapping
                        .iter()
                        .map(|m| {
                            let base = args.get(m.source_param_index).cloned().unwrap_or_default();
                            match m.transform {
                                Some(ArgTransform::Multiply(n)) => format!("({base}) * {n}"),
                                Some(ArgTransform::ShiftLeft(n)) => format!("({base}) << {n}"),
                                None => base,
                            }
                        })
                        .collect();
                    out.push_str(&sym.canonical_target);
                    out.push('(');
                    out.push_str(&mapped.join(","));
                    out.push(')');
                }
            },
            None => {
                unresolved.insert(call.literal_name.clone());
                out.push_str(&call.literal_name);
                out.push('(');
                out.push_str(&args.join(","));
                out.push(')');
            }
        }

        cursor = close + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{NameSource, RecoveredField, RecoveredMethod};

    fn method(
        address: &str,
        display_name: &str,
        params: &str,
        is_constructor: bool,
        is_destructor: bool,
    ) -> RecoveredMethod {
        RecoveredMethod {
            address: address.to_string(),
            raw_name: format!("FUN_{}", &address[2..]),
            display_name: display_name.to_string(),
            name_source: NameSource::Raw,
            return_type: "void".to_string(),
            params: params.to_string(),
            is_constructor,
            is_destructor,
            receiver_alias: None,
            decompilation: String::new(),
        }
    }

    fn class_with(name: &str, methods: Vec<RecoveredMethod>) -> RecoveredClass {
        RecoveredClass {
            name: name.to_string(),
            base: None,
            vtable_address: String::new(),
            fields: Vec::<RecoveredField>::new(),
            methods,
            references: Vec::new(),
        }
    }

    #[test]
    fn constructor_call_becomes_placement_new() {
        let classes = vec![class_with("Section", vec![method("0x1", "Section", "int,int", true, false)])];
        let table = build_symbol_table(&classes, &[]);
        let mut unresolved = BTreeSet::new();

        let rewritten = rewrite_call_sites("FUN_1(this,1,2);", &table, &mut unresolved);
        assert_eq!(rewritten, "new ((void *)(this)) Section(1,2);");
        assert!(unresolved.is_empty());
    }

    #[test]
    fn destructor_call_becomes_explicit_destructor_call() {
        let classes = vec![class_with("Snake", vec![method("0x2", "Snake", "", false, true)])];
        let table = build_symbol_table(&classes, &[]);
        let mut unresolved = BTreeSet::new();

        let rewritten = rewrite_call_sites("FUN_2(param_1);", &table, &mut unresolved);
        assert_eq!(rewritten, "((Snake *)(param_1))->~Snake();");
    }

    #[test]
    fn method_call_dispatches_through_cast_this_pointer() {
        let classes = vec![class_with("Snake", vec![method("0x3", "move", "int,int", false, false)])];
        let table = build_symbol_table(&classes, &[]);
        let mut unresolved = BTreeSet::new();

        let rewritten = rewrite_call_sites("FUN_3(param_1,dx,dy);", &table, &mut unresolved);
        assert_eq!(rewritten, "((Snake *)(param_1))->move(dx,dy);");
    }

    #[test]
    fn free_function_call_is_renamed_in_place() {
        let functions = vec![RecoveredFunction {
            address: "0x4".to_string(),
            raw_name: "FUN_4".to_string(),
            display_name: "calculateOffset".to_string(),
            name_source: NameSource::Raw,
            return_type: "int".to_string(),
            params: "int,int".to_string(),
            decompilation: String::new(),
        }];
        let table = build_symbol_table(&[], &functions);
        let mut unresolved = BTreeSet::new();

        let rewritten = rewrite_call_sites("x = FUN_4(a,b);", &table, &mut unresolved);
        assert_eq!(rewritten, "x = calculateOffset(a,b);");
    }

    /// PROJECT.md M18: a real compile found two different Ghidra-inferred
    /// types for the same pointer value at two different observation
    /// points -- a caller's own local declared `void **local_30;`, passed
    /// to a callee whose own recovered signature says `undefined8
    /// *param_1`. C++ doesn't implicitly convert between unrelated
    /// pointer types; an explicit cast to the callee's own declared type
    /// is what a real compile confirmed fixes it.
    #[test]
    fn a_free_function_calls_own_arguments_are_cast_to_the_callees_declared_parameter_types() {
        let functions = vec![RecoveredFunction {
            address: "0x4".to_string(),
            raw_name: "FUN_4".to_string(),
            display_name: "FUN_4".to_string(),
            name_source: NameSource::Raw,
            return_type: "undefined".to_string(),
            params: "undefined8 *param_1".to_string(),
            decompilation: String::new(),
        }];
        let table = build_symbol_table(&[], &functions);
        let mut unresolved = BTreeSet::new();

        let rewritten = rewrite_call_sites("FUN_4(local_30);", &table, &mut unresolved);

        assert_eq!(rewritten, "FUN_4((undefined8 *)(local_30));");
    }

    #[test]
    fn arity_mismatch_falls_back_to_unresolved_instead_of_wrong_call() {
        // Recovered signature says Section's constructor takes 2 ints,
        // but this call site only supplies 1 -- don't render a
        // confidently wrong `Section(1)`.
        let classes = vec![class_with("Section", vec![method("0x1", "Section", "int,int", true, false)])];
        let table = build_symbol_table(&classes, &[]);
        let mut unresolved = BTreeSet::new();

        let rewritten = rewrite_call_sites("FUN_1(this,1);", &table, &mut unresolved);
        assert_eq!(rewritten, "FUN_1(this,1);");
        assert!(unresolved.contains("FUN_1"));
    }

    #[test]
    fn unknown_address_is_left_alone_and_recorded_as_unresolved() {
        let table = SymbolTable::new();
        let mut unresolved = BTreeSet::new();

        let rewritten = rewrite_call_sites("FUN_deadbeef(a);", &table, &mut unresolved);
        assert_eq!(rewritten, "FUN_deadbeef(a);");
        assert!(unresolved.contains("FUN_deadbeef"));
    }

    #[test]
    fn nested_calls_and_multiple_call_sites_all_resolve() {
        let classes = vec![class_with("Wall", vec![method("0x5", "draw", "int,int", false, false)])];
        let table = build_symbol_table(&classes, &[]);
        let mut unresolved = BTreeSet::new();

        let rewritten =
            rewrite_call_sites("FUN_5(p,FUN_6(1),2); FUN_5(p,3,4);", &table, &mut unresolved);
        assert_eq!(rewritten, "((Wall *)(p))->draw(FUN_6(1),2); ((Wall *)(p))->draw(3,4);");
        assert!(unresolved.contains("FUN_6"));
    }

    /// PROJECT.md M18: a real link failed on exactly this -- a genuine
    /// 4-argument call site whose first argument is a format-string
    /// literal containing two commas in its own *text*
    /// (`"...out of range, targeting %p, yielding the value %p.\n"`).
    /// Splitting on every comma regardless of string-literal state
    /// inflated this to a counted 6 arguments, failed the arity check
    /// against the real 4-parameter declared signature, and left the
    /// call unresolved -- generating a conflicting variadic fallback
    /// declaration with no definition, which is what the linker actually
    /// reported as undefined.
    #[test]
    fn a_comma_inside_a_string_literal_argument_is_not_treated_as_an_argument_separator() {
        let functions = vec![RecoveredFunction {
            address: "0x7".to_string(),
            raw_name: "FUN_7".to_string(),
            display_name: "FUN_7".to_string(),
            name_source: NameSource::Raw,
            return_type: "undefined".to_string(),
            params: "undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4".to_string(),
            decompilation: String::new(),
        }];
        let table = build_symbol_table(&[], &functions);
        let mut unresolved = BTreeSet::new();

        let rewritten = rewrite_call_sites(
            r#"FUN_7("%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p.\n",a,b,c);"#,
            &table,
            &mut unresolved,
        );

        assert!(unresolved.is_empty(), "{unresolved:?}");
        assert!(rewritten.starts_with("FUN_7(("), "{rewritten}");
    }
}
