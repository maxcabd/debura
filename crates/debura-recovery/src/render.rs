use crate::compat::GHIDRA_COMPAT_HEADER_NAME;
use crate::model::{NameSource, RecoveredClass, RecoveredFunction, RecoveredMethod};
use crate::symbols::GHIDRA_SYMBOLS_HEADER_NAME;

/// Ghidra's vtable-pointer-slot idiom assigns the *address* of a
/// synthesized data symbol to a pointer-to-pointer lvalue
/// (`*(undefined ***)this = &PTR_draw_140009a40;`), but the symbol
/// itself is only ever declared as a generic placeholder byte (its real
/// type isn't known -- see `symbols.rs`'s `render_ghidra_symbols_header`),
/// so `&SYMBOL` doesn't have the exact pointer type the assignment
/// needs. Inserting the cast the assignment's own left-hand side already
/// implies makes it compile regardless of what type the symbol is
/// actually declared as -- verified by compiling this exact
/// substitution. Real, observed shape from the Snake fixture; other
/// pointer-depth variants of the same idiom aren't handled yet.
fn patch_known_idioms(text: &str) -> String {
    let prefix = "*(undefined ***)this = ";
    let needle = format!("{prefix}&");
    let text = text.replace(&needle, &format!("{prefix}(undefined **)&"));

    // Ghidra decompiles `std::cout << x` (real signature: `ostream&
    // operator<<(ostream&, ...)`) as `std::operator<<(&cout, x)` --
    // references are raw pointers at the ABI level, which the real,
    // reference-taking overloads don't match at all. C++ also forbids
    // declaring a pointer-taking `operator<<` overload to catch this (a
    // non-member operator<< needs at least one class/enum/reference
    // parameter, which `(ostream *, T *)` never has); `compat.rs`'s
    // `debura_stream_output`/`debura_stream_endl` are ordinary functions
    // instead, which carry no such restriction, so the call sites are
    // renamed to them here rather than declaring an operator that could
    // never legally exist.
    let text = text.replace("std::operator<<(", "debura_stream_output(");
    let text = text.replace("std::endl<char,std::char_traits<char>>(", "debura_stream_endl(");
    // The *other* half of the chained-manipulator idiom
    // (`std::cout << msg << std::endl;`): the outer `operator<<` --
    // the overload that accepts a manipulator function pointer, which
    // really is a *member* of basic_ostream in the real ABI, unlike the
    // free-function overloads for ordinary values -- decompiles as a
    // qualified call to this exact class-scoped name, not
    // `std::operator<<`. `compat.rs`'s `debura_stream_manip` takes over
    // from here (and declares the function-pointer typedef this call's
    // own argument cast needs).
    // No trailing `(` in the needle: Ghidra sometimes wraps a long call
    // expression across lines, with the open paren on its own line --
    // a real case had exactly this, which an earlier version of this
    // replace (requiring an immediately-following `(`) silently missed.
    // Whitespace/a newline between a function name and its `(` is valid
    // C++ regardless, so dropping it from the needle is enough.
    let text = text.replace(
        "std::basic_ostream<char,std::char_traits<char>>::operator<<",
        "debura_stream_manip",
    );
    // Ghidra's decompiler occasionally names a local variable holding an
    // intermediate value literally `this` -- unrelated to the enclosing
    // function's own implicit `this`, but a hard conflict regardless,
    // since `this` is a reserved keyword. A real case had a
    // `basic_ostream *this;` local holding a chained `operator<<`
    // call's return value. Detected narrowly, only when an actual
    // declaration line names it, so a body that legitimately uses the
    // real, implicit `this` (never re-declared as a local) is untouched.
    let text = rename_this_local_variable(&text);

    // Ghidra always writes these STL types out with their real,
    // explicit (and in this codebase, always `char`-based) template
    // arguments -- valid against the *real* std:: templates, but not
    // against `ghidra_compat.hpp`'s own bare-name aliases (declared as
    // plain, non-template `using` aliases specifically so a bare
    // `basic_ostream *pbVar1;` -- Ghidra's *other* common shape for the
    // same type, with no template arguments at all -- also resolves). A
    // real compile hit "is not a template" for exactly this: a local
    // variable declared `basic_stringstream<char,...> local_1a8 [16];`.
    // Dropping the redundant explicit arguments (they name the exact
    // instantiation the bare alias already is) satisfies both shapes --
    // but only for the *bare* occurrence: a `std::`/`std::__cxx11::`-
    // qualified one names the real template directly, which does need
    // its arguments, and a first version of this that stripped them
    // unconditionally broke exactly that (`std::basic_ostream::
    // operator<<` with no arguments at all, "used without template
    // arguments").
    let text = strip_redundant_template_args(
        &text,
        "basic_stringstream<char,std::char_traits<char>,std::allocator<char>>",
        "basic_stringstream",
    );
    let text = strip_redundant_template_args(
        &text,
        "basic_string<char,std::char_traits<char>,std::allocator<char>>",
        "basic_string",
    );
    strip_redundant_template_args(&text, "basic_ostream<char,std::char_traits<char>>", "basic_ostream")
}

/// Renames a local variable literally declared `this` (e.g.
/// `basic_ostream *this;`) to `debura_local_this`, throughout the body --
/// but only when such a declaration line actually exists. A genuine,
/// implicit `this` is never re-declared this way, so its absence is a
/// reliable signal this body doesn't have the bug at all.
fn rename_this_local_variable(text: &str) -> String {
    let has_this_declaration = text.lines().any(|line| {
        let trimmed = line.trim();
        // A real declaration is bare (`TYPE *this;`, no `=`) and never a
        // `return`/assignment statement that merely *uses* a genuine,
        // implicit `this` and happens to also end the same way (`return
        // this;`, `pbVar1 = this;`).
        !trimmed.starts_with("return")
            && !trimmed.contains('=')
            && (trimmed.ends_with("*this;") || trimmed.ends_with(" this;"))
    });
    if !has_this_declaration {
        return text.to_string();
    }
    replace_whole_word(text, "this", "debura_local_this")
}

/// Replaces every whole-word occurrence of `word` with `replacement` --
/// unlike a plain substring replace, doesn't also match `word` as part of
/// a longer identifier.
fn replace_whole_word(text: &str, word: &str, replacement: &str) -> String {
    fn is_word_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(rel) = text[i..].find(word) {
        let start = i + rel;
        let end = start + word.len();
        let before_ok = start == 0 || !is_word_byte(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_word_byte(bytes[end]);
        out.push_str(&text[i..start]);
        out.push_str(if before_ok && after_ok { replacement } else { word });
        i = end;
    }
    out.push_str(&text[i..]);
    out
}

/// Replaces `templated` with `bare` everywhere it appears *without* a
/// `::`-qualification immediately before it (a bare occurrence, meant
/// for `ghidra_compat.hpp`'s own non-template alias) -- leaving any
/// `std::`/`std::__cxx11::`-qualified occurrence (naming the real
/// template directly, which still needs its arguments) untouched.
fn strip_redundant_template_args(text: &str, templated: &str, bare: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(templated) {
        let (before, after) = (&rest[..pos], &rest[pos + templated.len()..]);
        out.push_str(before);
        out.push_str(if before.ends_with("::") { templated } else { bare });
        rest = after;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod idiom_tests {
    use super::*;

    #[test]
    fn bare_occurrence_loses_its_redundant_template_args() {
        let text = "basic_ostream<char,std::char_traits<char>> *pbVar1;";
        assert_eq!(patch_known_idioms(text), "basic_ostream *pbVar1;");
    }

    /// A real compile hit this as a regression: the first version of
    /// this fix stripped template arguments unconditionally, breaking a
    /// fully `std::`-qualified reference to the real template (which
    /// still needs them) into `std::basic_ostream::flush` -- "used
    /// without template arguments". `operator<<` specifically is no
    /// longer a case this could even happen to (see the manipulator test
    /// below), so this uses a different qualified member reference to
    /// keep covering the general rule.
    #[test]
    fn std_qualified_occurrence_keeps_its_template_args() {
        let text = "std::basic_ostream<char,std::char_traits<char>>::flush(x);";
        assert_eq!(
            patch_known_idioms(text),
            "std::basic_ostream<char,std::char_traits<char>>::flush(x);"
        );
    }

    /// The chained-manipulator idiom (`std::cout << msg << std::endl;`):
    /// the outer `operator<<` decompiles as a qualified call to
    /// basic_ostream's own `operator<<`, not `std::operator<<` -- a real
    /// compile found this call form entirely unhandled ("not declared in
    /// this scope" for the argument's own function-pointer cast target).
    #[test]
    fn qualified_ostream_operator_shift_becomes_debura_stream_manip() {
        let text = "std::basic_ostream<char,std::char_traits<char>>::operator<<(x, y);";
        assert_eq!(patch_known_idioms(text), "debura_stream_manip(x, y);");
    }

    /// A real compile hit this: Ghidra wrapped a long call expression
    /// across lines, with the qualified name on one line and its `(` on
    /// the next -- an earlier version of this replace required an
    /// immediately-following `(` and silently missed it.
    #[test]
    fn qualified_ostream_operator_shift_is_replaced_even_when_line_wrapped() {
        let text = "std::basic_ostream<char,std::char_traits<char>>::operator<<\n          (x, y);";
        assert_eq!(patch_known_idioms(text), "debura_stream_manip\n          (x, y);");
    }

    /// The exact real case: a local variable Ghidra's decompiler named
    /// literally `this`, holding a chained `operator<<` call's return
    /// value -- a hard conflict with the reserved keyword regardless of
    /// what it means, caught by a real compile ("expected unqualified-id
    /// before 'this'").
    #[test]
    fn a_this_named_local_variable_is_renamed() {
        let text = "basic_ostream *this;\nthis = f(x);\ng(this);\n";
        assert_eq!(
            patch_known_idioms(text),
            "basic_ostream *debura_local_this;\ndebura_local_this = f(x);\ng(debura_local_this);\n"
        );
    }

    /// The real, implicit `this` parameter -- never re-declared as a
    /// local variable -- must be left completely untouched, including
    /// when a `return this;` statement (not a declaration) happens to
    /// end the same way a declaration line would.
    #[test]
    fn a_genuine_implicit_this_is_not_renamed() {
        let text = "undefined *Drawable::operator=(Drawable *this,Drawable *param_1)\n\n{\n  return this;\n}";
        assert_eq!(patch_known_idioms(text), text);
    }

    /// Same false-positive risk, the assignment-statement shape: `pbVar1
    /// = this;` also ends with `" this;"` without being a declaration.
    #[test]
    fn an_assignment_from_a_genuine_this_is_not_mistaken_for_a_declaration() {
        let text = "basic_ostream *pbVar1;\npbVar1 = this;\n";
        assert_eq!(patch_known_idioms(text), text);
    }
}

fn name_comment(source: &NameSource) -> String {
    match source {
        NameSource::Accepted { hypothesis, confidence } => {
            format!("{hypothesis}, ACCEPTED, confidence {confidence:.2}")
        }
        NameSource::Raw => "no accepted hypothesis -- Ghidra's raw name, unverified".to_string(),
    }
}

/// A constructor or destructor's name is fixed by the language to the
/// class's own name (`ClassName`/`~ClassName`) -- never `m.display_name`,
/// even when a `semantic_role` hypothesis renamed it to something else
/// (e.g. "initializeFood"). Rendering the renamed value there produces a
/// declaration C++ doesn't recognize as a constructor at all (GCC parses
/// it as an ordinary method with an implicit `int` return type instead),
/// which is exactly what a real compile of this output hit.
fn method_declaration(m: &RecoveredMethod, class_name: &str) -> String {
    if m.is_constructor {
        format!("{class_name}({});", m.params)
    } else if m.is_destructor {
        format!("~{class_name}();")
    } else {
        format!("{} {}({});", m.return_type, m.display_name, m.params)
    }
}

/// A real run had methods (e.g. a destructor-variant thunk) whose
/// `decompiles_to` observation was only ever a bare signature -- Ghidra
/// never produced a real body for that address. Rendering that text
/// as-is left a floating signature line with no braces, which doesn't
/// parse as anything.
fn extract_body(decompilation: &str) -> String {
    match decompilation.find('{') {
        Some(idx) => decompilation[idx..].trim_end().to_string(),
        None => "{\n  // Ghidra provided no decompiled body for this address.\n}".to_string(),
    }
}

pub fn render_header(class: &RecoveredClass) -> String {
    let mut out = String::new();
    out.push_str("// Recovered by Debura.\n");
    out.push_str("// Structural facts (vtable presence, inheritance, field offsets) are\n");
    out.push_str("// deterministic Ghidra observations, trusted without a verification pass\n");
    out.push_str("// (PROJECT.md S21). Member names are ACCEPTED hypotheses where noted;\n");
    out.push_str("// otherwise they are Ghidra's own unverified names, not Debura's judgment.\n");
    if class.vtable_address.is_empty() {
        out.push_str("// no vtable observed -- not a polymorphic class\n");
    } else {
        out.push_str(&format!("// vtable observed at {}\n", class.vtable_address));
    }
    out.push_str(&format!("\n#pragma once\n\n#include \"{GHIDRA_COMPAT_HEADER_NAME}\"\n\n"));
    // Forward-declared, not #include'd: every real reference from this
    // codebase is by pointer (Ghidra passes objects by pointer/this
    // throughout its decompiled output), which a forward declaration is
    // enough for -- and a real run showed two classes referencing each
    // other (Section <-> Screen <-> Snake) turns a full #include here
    // into a circular one, where whichever header starts the cycle
    // sees the other as still-incomplete. render_source() includes the
    // full header instead, where the class's members are actually used.
    for reference in &class.references {
        out.push_str(&format!("class {reference};\n"));
    }
    if !class.references.is_empty() {
        out.push('\n');
    }

    match &class.base {
        Some(base) => {
            out.push_str(&format!("#include \"{base}.hpp\"\n\n"));
            out.push_str(&format!("class {} : public {} {{\n", class.name, base));
        }
        None => out.push_str(&format!("class {} {{\n", class.name)),
    }

    if !class.methods.is_empty() {
        out.push_str("public:\n");
        for m in &class.methods {
            out.push_str(&format!("    // {}\n", name_comment(&m.name_source)));
            out.push_str(&format!("    {}\n\n", method_declaration(m, &class.name)));
        }
    }

    if !class.fields.is_empty() {
        out.push_str("private:\n");
        for f in &class.fields {
            let chosen = f.candidate_types.first().map(String::as_str).unwrap_or("undefined");
            out.push_str(&format!("    // offset {}: {}", f.offset, chosen));
            if f.candidate_types.len() > 1 {
                out.push_str(&format!(
                    " (other candidates seen: {})",
                    f.candidate_types[1..].join(", ")
                ));
            }
            out.push('\n');
            out.push_str(&format!("    {} field_{};\n", chosen, f.offset));
        }
    }

    out.push_str("};\n");
    out
}

/// A real run had every derived-class constructor's decompiled body
/// open by calling its base's constructor directly on `this`
/// (`Collideable::Collideable((Collideable *)this,0,0);`) -- valid
/// Ghidra pseudocode (the base subobject really is initialized there in
/// the compiled code), but not legal C++: you can't call a constructor
/// like an ordinary function on an object that already exists, and a
/// real C++ constructor already default-constructs its base *before*
/// the body even runs, so the call would be redundant even if it
/// somehow compiled. Finds exactly that call statement -- anywhere in
/// the body, not just as the very first statement: a real run had
/// constructors that hoist local variable declarations (Ghidra's usual
/// C89-style convention) before the base-constructor call, which the
/// first version of this only matching a leading statement missed
/// entirely -- and splits it into (initializer-list args, body with
/// that one statement spliced out, everything else left in place). Only
/// a call shaped exactly like Ghidra's own idiom counts; anything else
/// returns `None` and the body is left untouched, narrower than a real
/// C parser but matching what Ghidra actually produces for this.
fn extract_base_constructor_call(body: &str, base: &str) -> Option<(String, String)> {
    let needle = format!("{base}::{base}(");
    let start = body.find(&needle)?;
    let call_args = &body[start + needle.len()..];

    let mut depth = 1i32;
    let close = call_args.char_indices().find_map(|(i, c)| match c {
        '(' => {
            depth += 1;
            None
        }
        ')' => {
            depth -= 1;
            (depth == 0).then_some(i)
        }
        _ => None,
    })?;

    let after_semicolon = call_args[close + 1..].strip_prefix(';')?;
    let args = call_args[..close]
        .strip_prefix(&format!("({base} *)this"))?
        .trim_start_matches(',')
        .trim()
        .to_string();

    let mut remaining_body = body[..start].to_string();
    remaining_body.push_str(after_semicolon);
    Some((args, remaining_body))
}

pub fn render_source(class: &RecoveredClass) -> String {
    let mut out = String::new();
    out.push_str("// Recovered by Debura. Method bodies are Ghidra's decompiled output\n");
    out.push_str("// with the recovered name substituted in -- this is annotated decompiler\n");
    out.push_str("// output, not hand-lifted C++. Field accesses still show raw pointer\n");
    out.push_str("// arithmetic (`this + N`) rather than named members: Debura hasn't applied\n");
    out.push_str("// recovered field types back into Ghidra yet (that's a natural extension of\n");
    out.push_str("// M8's Ghidra feedback loop, not yet implemented for fields/structs).\n");
    out.push_str(&format!("#include \"{GHIDRA_SYMBOLS_HEADER_NAME}\"\n"));
    out.push_str(&format!("#include \"{}.hpp\"\n", class.name));
    // The header only forward-declares these (see render_header) -- the
    // full definition is needed here since method bodies actually call
    // into them.
    for reference in &class.references {
        out.push_str(&format!("#include \"{reference}.hpp\"\n"));
    }
    out.push('\n');

    for m in &class.methods {
        // Same rule as method_declaration(): a constructor/destructor's
        // name and the absence of a return type are fixed by the
        // language, not by any semantic_role rename.
        let (return_prefix, name) = if m.is_constructor {
            (String::new(), class.name.clone())
        } else if m.is_destructor {
            (String::new(), format!("~{}", class.name))
        } else {
            (format!("{} ", m.return_type), m.display_name.clone())
        };
        let decompilation = patch_known_idioms(&m.decompilation);
        let base_init = m.is_constructor.then(|| {
            class.base.as_ref().and_then(|base| extract_base_constructor_call(&decompilation, base))
        }).flatten();

        let (initializer_list, body) = match base_init {
            Some((args, patched)) => (
                format!(" : {}({args})", class.base.as_ref().unwrap()),
                extract_body(&patched),
            ),
            None => (String::new(), extract_body(&decompilation)),
        };

        out.push_str(&format!("// {}\n", name_comment(&m.name_source)));
        out.push_str(&format!(
            "{return_prefix}{}::{name}({}){initializer_list}\n{body}\n\n",
            class.name,
            m.params,
        ));
    }

    out
}

pub fn render_functions_source(functions: &[RecoveredFunction], references: &[String]) -> String {
    let mut out = String::new();
    out.push_str("// Recovered by Debura: standalone functions with an ACCEPTED semantic\n");
    out.push_str("// name (PROJECT.md M5). Bodies are Ghidra's decompiled output, unmodified\n");
    out.push_str("// beyond substituting the recovered name for Ghidra's raw one.\n");
    out.push_str(&format!("#include \"{GHIDRA_COMPAT_HEADER_NAME}\"\n"));
    out.push_str(&format!("#include \"{GHIDRA_SYMBOLS_HEADER_NAME}\"\n"));
    // A real run had a standalone function's M15-resolved body construct
    // a real class (`new (ptr) Wall(...)`) with nothing including
    // `Wall.hpp` anywhere in this file.
    for reference in references {
        out.push_str(&format!("#include \"{reference}.hpp\"\n"));
    }
    out.push('\n');

    for f in functions {
        out.push_str(&format!("// {}\n", name_comment(&f.name_source)));
        out.push_str(&format!(
            "// Ghidra's raw name: {}\n{} {}({})\n{}\n\n",
            f.raw_name,
            f.return_type,
            f.display_name,
            f.params,
            extract_body(&patch_known_idioms(&f.decompilation))
        ));
    }

    out
}
