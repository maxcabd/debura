use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use debura_core::project::Project;

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
    }

    Ok(())
}
