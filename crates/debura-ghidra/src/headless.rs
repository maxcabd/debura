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

/// `debura new` already creates an empty `ghidra/project/` directory
/// (PROJECT.md S18's layout), so the directory existing is not evidence a
/// Ghidra project actually lives there -- only the project file Ghidra
/// itself creates on import is. A real bug (M10) checked directory
/// existence alone and tried `-process` against an empty directory on
/// every brand-new project.
fn is_already_imported(ghidra_project_dir: &Path) -> bool {
    ghidra_project_dir
        .join(format!("{GHIDRA_PROJECT_NAME}.gpr"))
        .is_file()
}

/// Runs headless Ghidra against `binary_path`, extracting deterministic
/// facts (functions, strings, imports, exports, xrefs, decompilation) into
/// `<project_root>/artifacts/analysis.json` (PROJECT.md S21, M1).
///
/// The first call imports the binary into a fresh Ghidra project and runs
/// full auto-analysis. A later call against the same project reuses it
/// (`-process`, not `-import`) and skips auto-analysis -- it only
/// re-extracts, so it never destroys mutations M8's `apply` already made.
/// Re-running `analyze` used to always wipe and reimport, silently
/// discarding any applied renames; this is what fixes that.
pub fn analyze(project_root: &Path, binary_path: &Path) -> Result<AnalysisResult> {
    let analyze_headless = analyze_headless_binary()?;

    let ghidra_dir = project_root.join("ghidra");
    let ghidra_project_dir = ghidra_dir.join("project");
    let already_imported = is_already_imported(&ghidra_project_dir);
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

    let mut cmd = Command::new(&analyze_headless);
    cmd.arg(&ghidra_project_dir).arg(GHIDRA_PROJECT_NAME);

    if already_imported {
        let binary_name = binary_path
            .file_name()
            .and_then(|n| n.to_str())
            .context("binary path has no file name")?;
        tracing::info!(
            binary = %binary_path.display(),
            "re-analyzing existing Ghidra project (preserving prior mutations)"
        );
        cmd.arg("-process").arg(binary_name).arg("-noanalysis");
    } else {
        tracing::info!(binary = %binary_path.display(), "starting headless Ghidra analysis");
        cmd.arg("-import").arg(binary_path);
    }

    let status = cmd
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_project_directory_is_not_mistaken_for_an_imported_project() {
        let dir = tempfile::tempdir().unwrap();
        let ghidra_project_dir = dir.path().join("ghidra").join("project");
        // `debura new` creates exactly this: an empty directory, nothing else.
        fs::create_dir_all(&ghidra_project_dir).unwrap();

        assert!(!is_already_imported(&ghidra_project_dir));
    }

    #[test]
    fn a_real_gpr_file_is_recognized_as_already_imported() {
        let dir = tempfile::tempdir().unwrap();
        let ghidra_project_dir = dir.path().join("ghidra").join("project");
        fs::create_dir_all(&ghidra_project_dir).unwrap();
        fs::write(ghidra_project_dir.join(format!("{GHIDRA_PROJECT_NAME}.gpr")), "").unwrap();

        assert!(is_already_imported(&ghidra_project_dir));
    }
}
