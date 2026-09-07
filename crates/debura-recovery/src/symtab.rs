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
            table.insert(
                m.address.clone(),
                RecoveredSymbol { kind, owner: class.name.clone(), display_name },
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
/// site and to more than one comma. Doesn't need to understand string
/// literals: Ghidra's own decompiled call arguments are never string
/// literals containing a raw comma followed by more call syntax in a way
/// that's been seen to matter here, and stopping at unbalanced quotes
/// would be a bigger, separate parser than this pass needs.
fn split_args(args: &str) -> Vec<&str> {
    if args.trim().is_empty() {
        return Vec::new();
    }
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in args.char_indices() {
        match c {
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
        match table.get(addr) {
            Some(sym) => match sym.kind {
                SymbolKind::FreeFunction => {
                    out.push_str(&sym.display_name);
                    out.push('(');
                    out.push_str(&args.join(","));
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

    fn method(address: &str, display_name: &str, is_constructor: bool, is_destructor: bool) -> RecoveredMethod {
        RecoveredMethod {
            address: address.to_string(),
            raw_name: format!("FUN_{}", &address[2..]),
            display_name: display_name.to_string(),
            name_source: NameSource::Raw,
            return_type: "void".to_string(),
            params: String::new(),
            is_constructor,
            is_destructor,
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
        let classes = vec![class_with("Section", vec![method("0x1", "Section", true, false)])];
        let table = build_symbol_table(&classes, &[]);
        let mut unresolved = BTreeSet::new();

        let rewritten = rewrite_call_sites("FUN_1(this,1,2);", &table, &mut unresolved);
        assert_eq!(rewritten, "new ((void *)(this)) Section(1,2);");
        assert!(unresolved.is_empty());
    }

    #[test]
    fn destructor_call_becomes_explicit_destructor_call() {
        let classes = vec![class_with("Snake", vec![method("0x2", "Snake", false, true)])];
        let table = build_symbol_table(&classes, &[]);
        let mut unresolved = BTreeSet::new();

        let rewritten = rewrite_call_sites("FUN_2(param_1);", &table, &mut unresolved);
        assert_eq!(rewritten, "((Snake *)(param_1))->~Snake();");
    }

    #[test]
    fn method_call_dispatches_through_cast_this_pointer() {
        let classes = vec![class_with("Snake", vec![method("0x3", "move", false, false)])];
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
            params: String::new(),
            decompilation: String::new(),
        }];
        let table = build_symbol_table(&[], &functions);
        let mut unresolved = BTreeSet::new();

        let rewritten = rewrite_call_sites("x = FUN_4(a,b);", &table, &mut unresolved);
        assert_eq!(rewritten, "x = calculateOffset(a,b);");
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
        let classes = vec![class_with("Wall", vec![method("0x5", "draw", false, false)])];
        let table = build_symbol_table(&classes, &[]);
        let mut unresolved = BTreeSet::new();

        let rewritten =
            rewrite_call_sites("FUN_5(p,FUN_6(1),2); FUN_5(p,3,4);", &table, &mut unresolved);
        assert_eq!(rewritten, "((Wall *)(p))->draw(FUN_6(1),2); ((Wall *)(p))->draw(3,4);");
        assert!(unresolved.contains("FUN_6"));
    }
}
