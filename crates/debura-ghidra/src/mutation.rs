use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::headless::{analyze_headless_binary, GHIDRA_PROJECT_NAME};

const APPLY_SCRIPT: &str = include_str!("../../../ghidra/scripts/ApplyMutations.py");
const APPLY_SCRIPT_NAME: &str = "ApplyMutations.py";

#[derive(Debug, Clone, Serialize)]
pub struct RenameRequest {
    pub address: String,
    pub new_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RenameOutcome {
    pub address: String,
    pub applied: bool,
    pub previous_name: Option<String>,
    pub new_name: Option<String>,
    pub error: Option<String>,
}

/// Whether `s` is safe to use as a Ghidra symbol name. A hypothesis's
/// `value` is free text a model produced -- it might be a clean identifier
/// ("TakeDamage") or a whole sentence ("move() and update() functionality",
/// a real example this project has already seen). Never hand the latter to
/// Ghidra.
pub fn is_valid_symbol_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Applies function renames to an *already-analyzed* Ghidra project
/// (PROJECT.md S29, M8) -- `-process`, not `-import`: this never
/// reimports the binary or reruns full auto-analysis, it only mutates
/// symbols that already exist. Run `analyze()` first.
pub fn apply_renames(
    project_root: &Path,
    binary_name: &str,
    renames: &[RenameRequest],
) -> Result<Vec<RenameOutcome>> {
    if renames.is_empty() {
        return Ok(Vec::new());
    }

    let analyze_headless = analyze_headless_binary()?;

    let ghidra_dir = project_root.join("ghidra");
    let ghidra_project_dir = ghidra_dir.join("project");
    anyhow::ensure!(
        ghidra_project_dir.is_dir(),
        "no Ghidra project at {} -- run `debura analyze` first",
        ghidra_project_dir.display()
    );

    let scripts_dir = ghidra_dir.join("scripts");
    fs::create_dir_all(&scripts_dir)?;
    fs::write(scripts_dir.join(APPLY_SCRIPT_NAME), APPLY_SCRIPT)?;

    let artifacts_dir = project_root.join("artifacts");
    fs::create_dir_all(&artifacts_dir)?;
    let input_path = artifacts_dir.join("renames_input.json");
    let output_path = artifacts_dir.join("renames_output.json");
    fs::write(&input_path, serde_json::to_string(renames)?)?;
    if output_path.exists() {
        fs::remove_file(&output_path)?;
    }

    tracing::info!(count = renames.len(), "applying renames to Ghidra project");

    let status = Command::new(&analyze_headless)
        .arg(&ghidra_project_dir)
        .arg(GHIDRA_PROJECT_NAME)
        .arg("-process")
        .arg(binary_name)
        .arg("-noanalysis")
        .arg("-scriptPath")
        .arg(&scripts_dir)
        .arg("-postScript")
        .arg(APPLY_SCRIPT_NAME)
        .arg(&input_path)
        .arg(&output_path)
        .status()
        .context("failed to launch analyzeHeadless")?;

    if !status.success() {
        bail!("analyzeHeadless exited with status {status}");
    }

    anyhow::ensure!(
        output_path.is_file(),
        "ApplyMutations.py completed but produced no output at {}",
        output_path.display()
    );

    let json = fs::read_to_string(&output_path)?;
    let outcomes: Vec<RenameOutcome> =
        serde_json::from_str(&json).context("failed to parse ApplyMutations.py output")?;

    for outcome in &outcomes {
        if !outcome.applied {
            tracing::warn!(address = %outcome.address, error = ?outcome.error, "rename failed");
        }
    }

    Ok(outcomes)
}
