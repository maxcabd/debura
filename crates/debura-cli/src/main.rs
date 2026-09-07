use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use debura_agent::AgentProvider;
use debura_core::project::{Project, ProjectState};

#[derive(Parser)]
#[command(
    name = "debura",
    version,
    about = "Autonomous program recovery from compiled binaries"
)]
struct Cli {
    /// Reasoning backend for any command that calls an AgentProvider
    #[arg(long, value_enum, global = true, default_value_t = ProviderChoice::Mock)]
    provider: ProviderChoice,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProviderChoice {
    /// Deterministic, no network calls, no cost -- see debura_agent::mock
    Mock,
    /// Real reasoning via OpenAI. Costs money per call; needs
    /// OPENAI_API_KEY (.env or a real env var).
    Openai,
}

fn make_provider(choice: ProviderChoice) -> Result<Box<dyn AgentProvider>> {
    Ok(match choice {
        ProviderChoice::Mock => Box::new(debura_agent::mock::EchoProvider),
        ProviderChoice::Openai => Box::new(debura_agent::openai::OpenAiProvider::from_env()?),
    })
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
    Investigate {
        /// Project id, as printed by `debura new`
        project: String,
        /// Subject address to investigate, e.g. 0x1400016e4
        subject: String,
    },
    /// Adversarially challenge one hypothesis
    Challenge {
        /// Project id, as printed by `debura new`
        project: String,
        /// Hypothesis id, e.g. H1 (as printed by `debura investigate`)
        hypothesis: String,
    },
    /// Resolve a CONTESTED hypothesis
    Resolve {
        /// Project id, as printed by `debura new`
        project: String,
        /// Hypothesis id, e.g. H1
        hypothesis: String,
    },
    /// Apply high-confidence findings to Ghidra (renames only, for now),
    /// reverting any previously-applied rename whose source hypothesis has
    /// since been rejected, then re-extracting so improved decompilation
    /// becomes new evidence
    Apply {
        /// Project id, as printed by `debura new`
        project: String,
    },
    /// Run the autonomous loop
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
    // Loads .env if present (walking up from the current directory), so a
    // provider API key can live in a gitignored file instead of needing
    // `export` in every shell. Silently does nothing if there is no file --
    // that's the normal case wherever the key is already a real env var.
    dotenvy::dotenv().ok();

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
            let provider = make_provider(cli.provider)?;

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let mut graph = debura_storage::knowledge::load(&conn)?;

            let investigation_id =
                debura_agent::analyze_function(&mut graph, provider.as_ref(), &subject)?;

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
            let provider = make_provider(cli.provider)?;

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let mut graph = debura_storage::knowledge::load(&conn)?;

            debura_verifier::challenge_hypothesis(
                &mut graph,
                provider.as_ref(),
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
            let provider = make_provider(cli.provider)?;

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let mut graph = debura_storage::knowledge::load(&conn)?;

            debura_verifier::resolve_contradiction(
                &mut graph,
                provider.as_ref(),
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
        Command::Apply { project } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");

            let state: ProjectState = serde_json::from_str(
                &std::fs::read_to_string(root.join("state.json"))
                    .context("reading project state.json")?,
            )?;

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let mut graph = debura_storage::knowledge::load(&conn)?;

            // Revert any previously-applied rename whose source hypothesis
            // is now REJECTED -- a mutation must not permanently poison the
            // decompiler state once the belief it rested on has been
            // rejected (PROJECT.md S30).
            let unreverted = debura_storage::mutations::list_unreverted(&conn)?;
            let to_revert: Vec<_> = unreverted
                .iter()
                .filter(|m| {
                    graph.hypothesis(m.hypothesis_id).map(|h| h.status)
                        == Some(debura_knowledge::HypothesisStatus::Rejected)
                })
                .collect();

            let mut changed_any = false;

            if !to_revert.is_empty() {
                let requests: Vec<debura_ghidra::RenameRequest> = to_revert
                    .iter()
                    .map(|m| debura_ghidra::RenameRequest {
                        address: m.target_address.clone(),
                        new_name: m.previous_value.clone(),
                    })
                    .collect();
                let outcomes = debura_ghidra::apply_renames(&root, &state.binary_name, &requests)?;
                for (mutation, outcome) in to_revert.iter().zip(outcomes.iter()) {
                    if outcome.applied {
                        debura_storage::mutations::mark_reverted(&conn, mutation.id, chrono::Utc::now())?;
                        println!(
                            "Reverted mutation {} ({} -> {})",
                            mutation.id, mutation.new_value, mutation.previous_value
                        );
                        changed_any = true;
                    } else {
                        tracing::warn!(mutation = mutation.id, error = ?outcome.error, "revert failed");
                    }
                }
            }

            // Apply high-confidence findings: ACCEPTED semantic_role
            // hypotheses on a real function address, not already mutated.
            let already_mutated: std::collections::HashSet<_> = debura_storage::mutations::list_unreverted(&conn)?
                .into_iter()
                .map(|m| m.hypothesis_id)
                .collect();

            let candidates: Vec<_> = graph
                .hypotheses()
                .filter(|h| {
                    h.status == debura_knowledge::HypothesisStatus::Accepted
                        && h.predicate == "semantic_role"
                        && h.subject.starts_with("0x")
                        && !already_mutated.contains(&h.id)
                })
                .cloned()
                .collect();

            for h in &candidates {
                if !debura_ghidra::is_valid_symbol_name(&h.value) {
                    println!("Skipping {}: {:?} is not a valid symbol name", h.id, h.value);
                    continue;
                }

                let outcomes = debura_ghidra::apply_renames(
                    &root,
                    &state.binary_name,
                    &[debura_ghidra::RenameRequest {
                        address: h.subject.clone(),
                        new_name: h.value.clone(),
                    }],
                )?;

                let Some(outcome) = outcomes.into_iter().next() else {
                    continue;
                };

                if outcome.applied {
                    let previous = outcome.previous_name.unwrap_or_default();
                    debura_storage::mutations::record(
                        &conn,
                        h.id,
                        debura_storage::mutations::MutationKind::RenameFunction,
                        &h.subject,
                        &previous,
                        &h.value,
                    )?;
                    println!("Applied {}: {} -> {}", h.id, previous, h.value);
                    changed_any = true;
                } else {
                    println!("Failed to apply {}: {:?}", h.id, outcome.error);
                }
            }

            if changed_any {
                let result = debura_ghidra::reextract(&root, &state.binary_name)?;
                debura_analysis::ingest(&mut graph, &result, "artifacts/analysis.json");
            }

            debura_storage::knowledge::save(&conn, &graph)?;

            if candidates.is_empty() && to_revert.is_empty() {
                println!("Nothing to apply or revert.");
            }
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
            let provider = make_provider(cli.provider)?;

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
                provider.as_ref(),
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
