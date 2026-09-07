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
    /// Run headless Ghidra, extract deterministic facts, and persist them
    /// as observations
    Analyze {
        /// Project id, as printed by `debura new`
        project: String,
    },
    /// Report the persisted knowledge graph's current state
    Status {
        /// Project id, as printed by `debura new`
        project: String,
    },
    /// Run a bounded AnalyzeFunction investigation against one subject
    /// (currently always via the deterministic mock provider -- no real
    /// model is wired in yet)
    Investigate {
        /// Project id, as printed by `debura new`
        project: String,
        /// Subject address to investigate, e.g. 0x1400016e4
        subject: String,
    },
    /// Adversarially challenge one hypothesis (always via the mock
    /// provider for now)
    Challenge {
        /// Project id, as printed by `debura new`
        project: String,
        /// Hypothesis id, e.g. H1 (as printed by `debura investigate`)
        hypothesis: String,
    },
    /// Resolve a CONTESTED hypothesis (always via the mock provider for now)
    Resolve {
        /// Project id, as printed by `debura new`
        project: String,
        /// Hypothesis id, e.g. H1
        hypothesis: String,
    },
    /// Run the autonomous loop (always via the mock provider for now)
    Run {
        /// Project id, as printed by `debura new`
        project: String,
        /// Stop after this many tasks
        #[arg(long)]
        max_iterations: Option<u64>,
        /// Stop after this many seconds
        #[arg(long)]
        time_budget: Option<u64>,
        /// Stop after this many tokens spent (not yet enforced -- no
        /// provider reports usage yet)
        #[arg(long)]
        token_budget: Option<u64>,
        /// Stop after this much spent, in dollars (not yet enforced -- no
        /// provider reports usage yet)
        #[arg(long)]
        cost_budget: Option<f64>,
    },
}

fn parse_hypothesis_id(s: &str) -> anyhow::Result<debura_knowledge::HypothesisId> {
    let digits = s.strip_prefix(['H', 'h']).unwrap_or(s);
    Ok(debura_knowledge::HypothesisId(digits.parse()?))
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

            let mut graph = debura_knowledge::KnowledgeGraph::new();
            debura_analysis::ingest(&mut graph, &result, "artifacts/analysis.json");

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            debura_storage::knowledge::save(&conn, &graph)?;

            println!(
                "\nPersisted {} observations to project.sqlite",
                graph.observations().count()
            );
        }
        Command::Status { project } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let graph = debura_storage::knowledge::load(&conn)?;

            println!("Project: {project}\n");
            println!("Observations: {}", graph.observations().count());
            println!("Evidence:     {}", graph.all_evidence().count());
            println!("Hypotheses:   {}", graph.hypotheses().count());

            use debura_knowledge::HypothesisStatus::*;
            for status in [
                Proposed,
                Investigating,
                Supported,
                Accepted,
                Contested,
                Stale,
                Rejected,
            ] {
                let count = graph.hypotheses().filter(|h| h.status == status).count();
                if count > 0 {
                    println!("  {status:?}: {count}");
                }
            }
        }
        Command::Investigate { project, subject } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let mut graph = debura_storage::knowledge::load(&conn)?;

            let investigation_id =
                debura_agent::analyze_function(&mut graph, &debura_agent::mock::EchoProvider, &subject)?;

            debura_storage::knowledge::save(&conn, &graph)?;

            let investigation = graph.investigation(investigation_id).unwrap();
            println!("Investigation {investigation_id}\n");
            println!("New hypotheses:  {}", investigation.hypotheses_created.len());
            println!("Modified:        {}", investigation.hypotheses_modified.len());
            println!("New evidence:    {}", investigation.evidence_created.len());
            for id in &investigation.hypotheses_created {
                let h = graph.hypothesis(*id).unwrap();
                println!("\n  {id}: {} {} = {} (confidence {:.2}, {:?})", h.subject, h.predicate, h.value, h.confidence, h.status);
            }
            for task in &investigation.followup_tasks {
                println!("\nFollow-up: {task}");
            }
        }
        Command::Challenge { project, hypothesis } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");
            let id = parse_hypothesis_id(&hypothesis)?;

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let mut graph = debura_storage::knowledge::load(&conn)?;

            debura_verifier::challenge_hypothesis(
                &mut graph,
                &debura_agent::mock::EchoProvider,
                id,
                &debura_verifier::VerificationPolicy::default(),
            )?;

            debura_storage::knowledge::save(&conn, &graph)?;

            let h = graph.hypothesis(id).context("hypothesis vanished during challenge")?;
            println!(
                "{id}: {} {} = {} (confidence {:.2}, {:?})",
                h.subject, h.predicate, h.value, h.confidence, h.status
            );
        }
        Command::Resolve { project, hypothesis } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");
            let id = parse_hypothesis_id(&hypothesis)?;

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let mut graph = debura_storage::knowledge::load(&conn)?;

            debura_verifier::resolve_contradiction(
                &mut graph,
                &debura_agent::mock::EchoProvider,
                id,
                &debura_verifier::VerificationPolicy::default(),
            )?;

            debura_storage::knowledge::save(&conn, &graph)?;

            let h = graph.hypothesis(id).context("hypothesis vanished during resolution")?;
            println!(
                "{id}: {} {} = {} (confidence {:.2}, {:?})",
                h.subject, h.predicate, h.value, h.confidence, h.status
            );
        }
        Command::Run {
            project,
            max_iterations,
            time_budget,
            token_budget,
            cost_budget,
        } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let mut graph = debura_storage::knowledge::load(&conn)?;

            let budget = debura_scheduler::RunBudget {
                max_iterations,
                time_budget: time_budget.map(std::time::Duration::from_secs),
                token_budget,
                cost_budget,
            };

            println!("Project: {project}\n");

            let summary = debura_scheduler::run(
                &mut graph,
                &debura_agent::mock::EchoProvider,
                &debura_verifier::VerificationPolicy::default(),
                &budget,
                |iteration, task, graph| {
                    println!("[{iteration}] {task:?}");
                    if let Err(error) = debura_storage::knowledge::save(&conn, graph) {
                        tracing::warn!(%error, "failed to checkpoint after iteration");
                    }
                },
            );

            println!("\nIterations: {}", summary.iterations);
            println!("Stopped:    {:?}", summary.stopped_because);
            println!("Hypotheses: {}", graph.hypotheses().count());
        }
    }

    Ok(())
}
