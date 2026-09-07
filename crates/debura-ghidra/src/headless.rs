use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::model::AnalysisResult;

const EXTRACT_SCRIPT: &str = include_str!("../../../ghidra/scripts/ExtractFacts.py");
const SCRIPT_NAME: &str = "ExtractFacts.py";
pub(crate) const GHIDRA_PROJECT_NAME: &str = "debura";

fn ghidra_install_dir() -> Result<PathBuf> {
    let dir = std::env::var("GHIDRA_INSTALL_DIR")
        .context("GHIDRA_INSTALL_DIR is not set; point it at a Ghidra installation")?;
    let dir = PathBuf::from(dir);
    anyhow::ensure!(
        dir.is_dir(),
        "GHIDRA_INSTALL_DIR does not exist: {}",
        dir.display()
    );
    Ok(dir)
}

pub(crate) fn analyze_headless_binary() -> Result<PathBuf> {
    let install = ghidra_install_dir()?;
    let candidate = if cfg!(windows) {
        install.join("support").join("analyzeHeadless.bat")
    } else {
        install.join("support").join("analyzeHeadless")
    };
    anyhow::ensure!(
        candidate.is_file(),
        "analyzeHeadless not found at {}",
        candidate.display()
    );
    Ok(candidate)
}

/// Runs headless Ghidra against `binary_path`, extracting deterministic
/// facts (functions, strings, imports, exports, xrefs, decompilation) into
/// `<project_root>/artifacts/analysis.json` (PROJECT.md S21, M1).
///
/// Each call reimports the binary into a fresh Ghidra project under
/// `<project_root>/ghidra/project`. Incremental reanalysis (reusing an
/// already-analyzed project) is a concern for later milestones once
/// Ghidra feedback (S29-30) needs to re-run analysis after mutations.
pub fn analyze(project_root: &Path, binary_path: &Path) -> Result<AnalysisResult> {
    let analyze_headless = analyze_headless_binary()?;

    let ghidra_dir = project_root.join("ghidra");
    let ghidra_project_dir = ghidra_dir.join("project");
    if ghidra_project_dir.is_dir() {
        fs::remove_dir_all(&ghidra_project_dir)?;
    }
    fs::create_dir_all(&ghidra_project_dir)?;

    let scripts_dir = ghidra_dir.join("scripts");
    fs::create_dir_all(&scripts_dir)?;
    fs::write(scripts_dir.join(SCRIPT_NAME), EXTRACT_SCRIPT)?;

    let artifacts_dir = project_root.join("artifacts");
    fs::create_dir_all(&artifacts_dir)?;
    let output_path = artifacts_dir.join("analysis.json");
    if output_path.exists() {
        fs::remove_file(&output_path)?;
    }

    tracing::info!(binary = %binary_path.display(), "starting headless Ghidra analysis");

    let status = Command::new(&analyze_headless)
        .arg(&ghidra_project_dir)
        .arg(GHIDRA_PROJECT_NAME)
        .arg("-import")
        .arg(binary_path)
        .arg("-scriptPath")
        .arg(&scripts_dir)
        .arg("-postScript")
        .arg(SCRIPT_NAME)
        .arg(&output_path)
        .status()
        .context("failed to launch analyzeHeadless")?;

    if !status.success() {
        bail!("analyzeHeadless exited with status {status}");
    }

    anyhow::ensure!(
        output_path.is_file(),
        "analyzeHeadless completed but produced no output at {}",
        output_path.display()
    );

    let json = fs::read_to_string(&output_path)?;
    let result: AnalysisResult =
        serde_json::from_str(&json).context("failed to parse Ghidra analysis output")?;

    tracing::info!(
        functions = result.functions.len(),
        strings = result.strings.len(),
        imports = result.imports.len(),
        exports = result.exports.len(),
        xrefs = result.xrefs.len(),
        "headless Ghidra analysis complete"
    );

    Ok(result)
}

/// Re-extracts facts from an *already-analyzed* Ghidra project without
/// reimporting or rerunning full auto-analysis (PROJECT.md S29: "then
/// reanalyze" after applying mutations, so improved decompilation becomes
/// new evidence). `analyze()` would wipe out any mutations already
/// applied; this preserves them. Run `analyze()` at least once first.
pub fn reextract(project_root: &Path, binary_name: &str) -> Result<AnalysisResult> {
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
    fs::write(scripts_dir.join(SCRIPT_NAME), EXTRACT_SCRIPT)?;

    let artifacts_dir = project_root.join("artifacts");
    fs::create_dir_all(&artifacts_dir)?;
    let output_path = artifacts_dir.join("analysis.json");
    if output_path.exists() {
        fs::remove_file(&output_path)?;
    }

    tracing::info!(binary = %binary_name, "re-extracting facts from existing Ghidra project");

    let status = Command::new(&analyze_headless)
        .arg(&ghidra_project_dir)
        .arg(GHIDRA_PROJECT_NAME)
        .arg("-process")
        .arg(binary_name)
        .arg("-noanalysis")
        .arg("-scriptPath")
        .arg(&scripts_dir)
        .arg("-postScript")
        .arg(SCRIPT_NAME)
        .arg(&output_path)
        .status()
        .context("failed to launch analyzeHeadless")?;

    if !status.success() {
        bail!("analyzeHeadless exited with status {status}");
    }

    anyhow::ensure!(
        output_path.is_file(),
        "analyzeHeadless completed but produced no output at {}",
        output_path.display()
    );

    let json = fs::read_to_string(&output_path)?;
    let result: AnalysisResult =
        serde_json::from_str(&json).context("failed to parse Ghidra analysis output")?;

    tracing::info!(functions = result.functions.len(), "re-extraction complete");

    Ok(result)
}
