use crate::compat::GHIDRA_COMPAT_HEADER_NAME;
use crate::model::{NameSource, RecoveredClass, RecoveredFunction, RecoveredMethod};

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

fn extract_body(decompilation: &str) -> &str {
    match decompilation.find('{') {
        Some(idx) => decompilation[idx..].trim_end(),
        None => decompilation.trim_end(),
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
    out.push_str(&format!("\n#pragma once\n\n#include \"{GHIDRA_COMPAT_HEADER_NAME}\"\n"));
    for reference in &class.references {
        out.push_str(&format!("#include \"{reference}.hpp\"\n"));
    }
    out.push('\n');

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

pub fn render_source(class: &RecoveredClass) -> String {
    let mut out = String::new();
    out.push_str("// Recovered by Debura. Method bodies are Ghidra's decompiled output\n");
    out.push_str("// with the recovered name substituted in -- this is annotated decompiler\n");
    out.push_str("// output, not hand-lifted C++. Field accesses still show raw pointer\n");
    out.push_str("// arithmetic (`this + N`) rather than named members: Debura hasn't applied\n");
    out.push_str("// recovered field types back into Ghidra yet (that's a natural extension of\n");
    out.push_str("// M8's Ghidra feedback loop, not yet implemented for fields/structs).\n");
    out.push_str(&format!("#include \"{}.hpp\"\n\n", class.name));

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
        out.push_str(&format!("// {}\n", name_comment(&m.name_source)));
        out.push_str(&format!(
            "{return_prefix}{}::{name}({})\n{}\n\n",
            class.name,
            m.params,
            extract_body(&m.decompilation)
        ));
    }

    out
}

pub fn render_functions_source(functions: &[RecoveredFunction]) -> String {
    let mut out = String::new();
    out.push_str("// Recovered by Debura: standalone functions with an ACCEPTED semantic\n");
    out.push_str("// name (PROJECT.md M5). Bodies are Ghidra's decompiled output, unmodified\n");
    out.push_str("// beyond substituting the recovered name for Ghidra's raw one.\n");
    out.push_str(&format!("#include \"{GHIDRA_COMPAT_HEADER_NAME}\"\n\n"));

    for f in functions {
        out.push_str(&format!("// {}\n", name_comment(&f.name_source)));
        out.push_str(&format!(
            "// Ghidra's raw name: {}\n{} {}({})\n{}\n\n",
            f.raw_name,
            f.return_type,
            f.display_name,
            f.params,
            extract_body(&f.decompilation)
        ));
    }

    out
}
