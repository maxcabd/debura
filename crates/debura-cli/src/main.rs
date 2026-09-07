use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use debura_core::project::{Project, ProjectState};

#[derive(Parser)]
#[command(
    name = "debura",
    version,
    about = "Autonomous program recovery from compiled binaries"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new Debura project from a binary
    New {
        /// Path to the binary to analyze
        binary: PathBuf,
    },
    /// Run headless Ghidra and extract deterministic facts
    Analyze {
        /// Project id, as printed by `debura new`
        project: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "debura=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::New { binary } => {
            let project = Project::create(&binary)?;

            println!("Created project {}\n", project.id);
            println!("Binary:\n{}\n", project.binary_name);
            println!("Architecture:\n{}\n", project.architecture);
            println!("Project:\n{}", project.root.display());
        }
        Command::Analyze { project } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");

            let state: ProjectState = serde_json::from_str(
                &std::fs::read_to_string(root.join("state.json"))
                    .context("reading project state.json")?,
            )?;

            let binary_path = root.join("binary").join(&state.binary_name);

            println!("Analyzing {}...\n", state.binary_name);
            let result = debura_ghidra::analyze(&root, &binary_path)?;

            println!("Functions: {}", result.functions.len());
            println!("Strings:   {}", result.strings.len());
            println!("Imports:   {}", result.imports.len());
            println!("Exports:   {}", result.exports.len());
            println!("Xrefs:     {}", result.xrefs.len());
        }
    }

    Ok(())
}
