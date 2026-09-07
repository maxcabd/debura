use std::path::PathBuf;

/// Resolves where Debura stores all project data.
///
/// Defaults to `~/.debura`, overridable with `DEBURA_HOME` so tests and
/// scripted runs don't touch a real home directory.
pub fn debura_home() -> PathBuf {
    if let Ok(home) = std::env::var("DEBURA_HOME") {
        return PathBuf::from(home);
    }

    dirs::home_dir()
        .expect("could not determine home directory")
        .join(".debura")
}

pub fn projects_dir() -> PathBuf {
    debura_home().join("projects")
}
