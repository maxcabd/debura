use std::fs;
use std::path::Path;

use anyhow::Result;

use crate::compat::{render_ghidra_compat_header, GHIDRA_COMPAT_HEADER_NAME};
use crate::model::RecoveredProgram;
use crate::render::{render_functions_source, render_header, render_source};
use crate::symbols::{render_function_declarations, render_ghidra_symbols_header, GHIDRA_SYMBOLS_HEADER_NAME};

#[derive(Debug, Default)]
pub struct RecoverySummary {
    pub classes_written: usize,
    pub functions_written: usize,
}

/// Writes `program` into `<project_root>/recovered/{include,src}` (the
/// layout PROJECT.md S18 already reserves per-project). Subsystem-grouped
/// subfolders (`engine/`, `gameplay/`, ...) aren't used yet -- that needs
/// IdentifySubsystem, which doesn't exist yet either (PROJECT.md S28).
pub fn write_to_disk(project_root: &Path, program: &RecoveredProgram) -> Result<RecoverySummary> {
    let include_dir = project_root.join("recovered").join("include");
    let src_dir = project_root.join("recovered").join("src");
    fs::create_dir_all(&include_dir)?;
    fs::create_dir_all(&src_dir)?;

    fs::write(
        include_dir.join(GHIDRA_COMPAT_HEADER_NAME),
        render_ghidra_compat_header(&program.ghidra_intrinsics),
    )?;
    let function_declarations: Vec<(String, String, String)> = program
        .functions
        .iter()
        .map(|f| (f.return_type.clone(), f.display_name.clone(), f.params.clone()))
        .collect();
    fs::write(
        include_dir.join(GHIDRA_SYMBOLS_HEADER_NAME),
        render_ghidra_symbols_header(
            &program.ghidra_data_symbols,
            &program.unresolved_calls,
            &render_function_declarations(&function_declarations),
        ),
    )?;

    for class in &program.classes {
        fs::write(
            include_dir.join(format!("{}.hpp", class.name)),
            render_header(class),
        )?;
        fs::write(
            src_dir.join(format!("{}.cpp", class.name)),
            render_source(class),
        )?;
    }

    if !program.functions.is_empty() {
        fs::write(
            src_dir.join("functions.cpp"),
            render_functions_source(&program.functions, &program.function_references),
        )?;
    }

    Ok(RecoverySummary {
        classes_written: program.classes.len(),
        functions_written: program.functions.len(),
    })
}
