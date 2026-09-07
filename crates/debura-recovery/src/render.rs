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
    text.replace(&needle, &format!("{prefix}(undefined **)&"))
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
