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

fn make_provider(choice: ProviderChoice) -> Result<Box<dyn AgentProvider + Sync>> {
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
    /// Break down persisted investigations by task type (PROJECT.md
    /// M15): how many were run, how many produced a new hypothesis or
    /// evidence versus nothing at all, and the resulting productive
    /// investigation rate -- the metric to watch once a run is fast
    /// enough that wall-clock time stops being the bottleneck question.
    Stats {
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
    /// Generate recovered C++ from the accepted program model into
    /// <project>/recovered/{include,src}
    Recover {
        /// Project id, as printed by `debura new`
        project: String,
        /// Path to a file containing a real linker's stderr output (or
        /// `-` for stdin). When given, any `RecoveryDisposition::RequiredRuntimeBody`
        /// address `disposition` would report against this exact linker
        /// log -- reachable, `Provenance::LibraryOrRuntime`, but with a
        /// real, non-degenerate decompiled body a real link genuinely
        /// failed to resolve -- is recovered under its raw `FUN_<addr>`
        /// name too (PROJECT.md M18: never a project-wide sweep for this
        /// provenance -- only these exact, linker-verified addresses;
        /// see `debura_recovery::extract_with_required_runtime_bodies`'s
        /// own doc comment for why). Omit to recover exactly what
        /// `Provenance::Application`/`RequiredUnknown` already cover,
        /// unchanged.
        #[arg(long)]
        linker_log: Option<PathBuf>,
    },
    /// Classify a real linker's undefined-symbol output into the
    /// concrete recovery frontier (PROJECT.md M18): which unresolved
    /// addresses are real application dependencies still worth
    /// recovering, which are library/runtime code that need a different
    /// fix, and which aren't even reachable from this program's own
    /// entrypoint yet. Debura doesn't invoke the compiler/linker itself
    /// (build flags and library paths are project-specific) -- run your
    /// own build, capture its stderr, and point this at that file.
    Frontier {
        /// Project id, as printed by `debura new`
        project: String,
        /// Path to a file containing the linker's stderr output (or
        /// `-` to read stdin)
        linker_log: PathBuf,
    },
    /// Re-examine REJECTED semantic_role hypotheses whose rejection
    /// premise has since changed (PROJECT.md M18): the provenance gate's
    /// REJECTED verdict is a hard structural exclusion, correctly terminal
    /// against the generic dependency cascade -- but `classify_provenance`
    /// itself can gain a new signal, making an old rejection's premise
    /// ("this subject's provenance isn't Application") no longer true.
    /// Moves any such hypothesis to STALE (never straight back to
    /// ACCEPTED) so the normal investigate/challenge pipeline decides it
    /// fresh; does not itself call any AgentProvider.
    Reconsider {
        /// Project id, as printed by `debura new`
        project: String,
    },
    /// Print `classify_provenance`'s verdict for one address -- a debug
    /// aid for checking a specific provenance decision (and why it holds)
    /// against a real project's own graph, without a full `frontier` run.
    Classify {
        /// Project id, as printed by `debura new`
        project: String,
        /// Subject address to classify, e.g. 0x1400016e4
        address: String,
    },
    /// Diagnose every unresolved function by recovery necessity
    /// (PROJECT.md M18's `RecoveryDisposition`), independent of whether
    /// `classify_provenance` has (or ever will have) grounds to call it
    /// Application: RequiredApplication, RequiredUnknown (reachable, real
    /// body, but no semantic ownership claim), ExternalLibrary,
    /// CompilerRuntime, Unreachable, or Deferred. A diagnostic report --
    /// unlike `frontier`, generates nothing and changes no recovered
    /// output.
    Disposition {
        /// Project id, as printed by `debura new`
        project: String,
        /// Path to a file containing the linker's stderr output (or
        /// `-` to read stdin)
        linker_log: PathBuf,
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
        /// Stop once this fraction of seeded subjects (0.0-1.0) has
        /// reached a settled state (accepted, or given up on after
        /// max retries), even if tasks remain queued
        #[arg(long)]
        coverage_target: Option<f64>,
        /// How many tasks to run concurrently. Different subjects'/
        /// hypotheses' context never overlaps (PROJECT.md S23), so this is
        /// safe -- most of the wall-clock time with a real provider is
        /// network waiting, not computing, so this can exceed core count.
        #[arg(long, default_value_t = 16)]
        concurrency: usize,
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

            // Load whatever knowledge already exists (hypotheses, evidence,
            // investigations from prior runs) rather than starting from an
            // empty graph -- a repeat `analyze` used to silently discard
            // all of it. `ingest` is idempotent, so this only ever adds
            // genuinely new or changed facts.
            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let mut graph = debura_storage::knowledge::load(&conn)?;
            let hypotheses_before = graph.hypotheses().count();

            debura_analysis::ingest(&mut graph, &result, "artifacts/analysis.json");
            debura_storage::knowledge::save(&conn, &graph)?;

            println!(
                "\nPersisted {} observations ({} preserved hypotheses) to project.sqlite",
                graph.observations().count(),
                hypotheses_before
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
        Command::Stats { project } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let graph = debura_storage::knowledge::load(&conn)?;

            let report = debura_scheduler::investigation_report(&graph);

            println!("Project: {project}\n");
            println!(
                "{:<22} {:>8} {:>10} {:>10} {:>9} {:>9} {:>7}",
                "Task", "executed", "hyp.new", "hyp.mod", "evidence", "accepted", "no-op"
            );
            for stats in &report.by_task {
                println!(
                    "{:<22} {:>8} {:>10} {:>10} {:>9} {:>9} {:>7}",
                    stats.task,
                    stats.executed,
                    stats.hypotheses_created,
                    stats.hypotheses_modified,
                    stats.evidence_created,
                    stats.accepted_from_created,
                    stats.no_op,
                );
            }
            println!();
            println!("Fingerprint cache hits (no model call at all): {}", report.fingerprint_cache_hits);
            println!(
                "Productive investigations: {}/{} ({:.1}%)",
                report.productive_investigations,
                report.total_investigations,
                100.0 * report.productive_rate()
            );

            // PROJECT.md M15: a blended "accepted" count can't tell a
            // library-recognition win from real semantic recovery -- a
            // real run's headline "8x more accepted knowledge" hid that
            // most of it was libstdc++ internals, not game logic.
            let claims = debura_scheduler::claim_breakdown(&graph);
            println!();
            println!("Accepted semantic_role claims, by class:");
            println!("  Application:         {}", claims.application_accepted);
            println!("  Library/runtime:     {}", claims.library_or_runtime_accepted);
            println!("  Unknown provenance:  {}", claims.unknown_provenance_accepted);
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
        Command::Recover { project, linker_log } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let graph = debura_storage::knowledge::load(&conn)?;

            let (program, runtime_bodies_recovered) = match linker_log {
                None => (debura_recovery::extract(&graph), 0usize),
                Some(linker_log) => {
                    let entry = graph
                        .observations()
                        .find(|o| o.predicate == "exports" && o.value == "entry")
                        .map(|o| o.subject.clone())
                        .context("no 'entry' export found -- was this project analyzed?")?;
                    let log_text = if linker_log.as_os_str() == "-" {
                        std::io::read_to_string(std::io::stdin()).context("reading linker log from stdin")?
                    } else {
                        std::fs::read_to_string(&linker_log)
                            .with_context(|| format!("reading linker log at {}", linker_log.display()))?
                    };
                    let unresolved = debura_recovery::parse_undefined_symbols(&log_text);
                    let disposition = debura_recovery::classify_recovery_disposition(&graph, &unresolved, &entry);
                    let required_runtime_bodies: std::collections::BTreeSet<String> = disposition
                        .iter()
                        .filter(|e| e.disposition == debura_recovery::RecoveryDisposition::RequiredRuntimeBody)
                        .map(|e| e.address.clone())
                        .collect();
                    let count = required_runtime_bodies.len();
                    (
                        debura_recovery::extract_with_required_runtime_bodies(&graph, &required_runtime_bodies),
                        count,
                    )
                }
            };
            let summary = debura_recovery::write_to_disk(&root, &program)?;

            println!("Classes recovered:   {}", summary.classes_written);
            println!("Functions recovered: {}", summary.functions_written);
            if runtime_bodies_recovered > 0 {
                println!("  (including {runtime_bodies_recovered} linker-verified RequiredRuntimeBody)");
            }
            println!("Written to: {}", root.join("recovered").display());
        }
        Command::Frontier { project, linker_log } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let graph = debura_storage::knowledge::load(&conn)?;

            let entry = graph
                .observations()
                .find(|o| o.predicate == "exports" && o.value == "entry")
                .map(|o| o.subject.clone())
                .context("no 'entry' export found -- was this project analyzed?")?;

            let log_text = if linker_log.as_os_str() == "-" {
                std::io::read_to_string(std::io::stdin()).context("reading linker log from stdin")?
            } else {
                std::fs::read_to_string(&linker_log)
                    .with_context(|| format!("reading linker log at {}", linker_log.display()))?
            };

            let unresolved = debura_recovery::parse_undefined_symbols(&log_text);
            let data_count = unresolved.iter().filter(|u| matches!(u, debura_recovery::UnresolvedSymbol::Data { .. })).count();
            let entries = debura_recovery::classify_frontier(&graph, &unresolved, &entry);

            let mut needs_recovery: Vec<_> = entries
                .iter()
                .filter(|e| e.bucket == debura_recovery::FrontierBucket::NeedsRecovery)
                .collect();
            needs_recovery.sort_by(|a, b| a.address.cmp(&b.address));
            let mut library: Vec<_> = entries
                .iter()
                .filter(|e| e.bucket == debura_recovery::FrontierBucket::LibraryOrRuntime)
                .collect();
            library.sort_by(|a, b| a.address.cmp(&b.address));
            let mut deferred: Vec<_> = entries
                .iter()
                .filter(|e| e.bucket == debura_recovery::FrontierBucket::Deferred)
                .collect();
            deferred.sort_by(|a, b| a.address.cmp(&b.address));

            println!("Entry point: {entry}");
            println!("Unresolved references in linker log: {} function, {data_count} data\n", entries.len());

            println!("Needs recovery ({}) -- reachable, Application provenance:", needs_recovery.len());
            for e in &needs_recovery {
                println!("  {} ({})", e.address, e.literal_name);
            }
            println!("\nLibrary/runtime ({}) -- reachable, not an application function:", library.len());
            for e in &library {
                println!("  {} ({})", e.address, e.literal_name);
            }
            let unreachable_count = deferred.iter().filter(|e| !e.reachable).count();
            println!(
                "\nDeferred ({}) -- {unreachable_count} unreachable from entry, {} reachable but no provenance signal yet:",
                deferred.len(),
                deferred.len() - unreachable_count
            );
            for e in &deferred {
                println!("  {} ({}){}", e.address, e.literal_name, if e.reachable { "" } else { " [unreachable]" });
            }
        }
        Command::Disposition { project, linker_log } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let graph = debura_storage::knowledge::load(&conn)?;

            let entry = graph
                .observations()
                .find(|o| o.predicate == "exports" && o.value == "entry")
                .map(|o| o.subject.clone())
                .context("no 'entry' export found -- was this project analyzed?")?;

            let log_text = if linker_log.as_os_str() == "-" {
                std::io::read_to_string(std::io::stdin()).context("reading linker log from stdin")?
            } else {
                std::fs::read_to_string(&linker_log)
                    .with_context(|| format!("reading linker log at {}", linker_log.display()))?
            };

            let unresolved = debura_recovery::parse_undefined_symbols(&log_text);
            let mut entries = debura_recovery::classify_recovery_disposition(&graph, &unresolved, &entry);
            entries.sort_by(|a, b| a.address.cmp(&b.address));

            println!("Entry point: {entry}");
            println!("Unresolved functions: {}\n", entries.len());

            for e in &entries {
                let tag = match e.disposition {
                    debura_recovery::RecoveryDisposition::RequiredApplication => "RequiredApplication",
                    debura_recovery::RecoveryDisposition::RequiredUnknown => "RequiredUnknown",
                    debura_recovery::RecoveryDisposition::RequiredRuntimeBody => "RequiredRuntimeBody",
                    debura_recovery::RecoveryDisposition::ExternalLibrary => "ExternalLibrary",
                    debura_recovery::RecoveryDisposition::CompilerRuntime => "CompilerRuntime",
                    debura_recovery::RecoveryDisposition::Unreachable => "Unreachable",
                    debura_recovery::RecoveryDisposition::Deferred => "Deferred",
                };
                println!(
                    "{} ({}) [{tag}] provenance={:?} reachable={} body_size={} recoverable_body={} sole_callee={} callers={}/{} recovered",
                    e.address,
                    e.literal_name,
                    e.provenance,
                    e.reachable,
                    e.body_size.map(|s| s.to_string()).unwrap_or_else(|| "?".to_string()),
                    e.has_recoverable_body,
                    e.sole_callee.as_deref().unwrap_or("-"),
                    e.direct_recovered_callers.len(),
                    e.direct_callers.len(),
                );
            }

            let count = |want: debura_recovery::RecoveryDisposition| {
                entries.iter().filter(|e| e.disposition == want).count()
            };
            println!("\nSummary ({} total unresolved functions):", entries.len());
            println!("  RequiredApplication: {}", count(debura_recovery::RecoveryDisposition::RequiredApplication));
            println!("  RequiredUnknown:     {}", count(debura_recovery::RecoveryDisposition::RequiredUnknown));
            println!("  RequiredRuntimeBody: {}", count(debura_recovery::RecoveryDisposition::RequiredRuntimeBody));
            println!("  ExternalLibrary:     {}", count(debura_recovery::RecoveryDisposition::ExternalLibrary));
            println!("  CompilerRuntime:     {}", count(debura_recovery::RecoveryDisposition::CompilerRuntime));
            println!("  Unreachable:         {}", count(debura_recovery::RecoveryDisposition::Unreachable));
            println!("  Deferred:            {}", count(debura_recovery::RecoveryDisposition::Deferred));
        }
        Command::Reconsider { project } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let mut graph = debura_storage::knowledge::load(&conn)?;

            let reconsidered = debura_verifier::reconsider_stale_provenance_rejections(&mut graph);

            debura_storage::knowledge::save(&conn, &graph)?;

            println!("Reconsidered: {}", reconsidered.len());
            for id in &reconsidered {
                let h = graph.hypothesis(*id).context("hypothesis vanished during reconsideration")?;
                println!("  {id}: {} {} = {} (now {:?})", h.subject, h.predicate, h.value, h.status);
            }
        }
        Command::Classify { project, address } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let graph = debura_storage::knowledge::load(&conn)?;

            let provenance = debura_knowledge::classify_provenance(&graph, &address);
            println!("{address}: {provenance:?}");
        }
        Command::Run {
            project,
            max_iterations,
            time_budget,
            token_budget,
            cost_budget,
            coverage_target,
            concurrency,
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
                coverage_target,
            };

            println!("Project: {project} (concurrency {concurrency})\n");

            // A full checkpoint is a full-graph rewrite (M3); at the scale
            // a real binary's function count reaches, doing that on every
            // single committed result -- now arriving in bursts thanks to
            // concurrency -- would trade the network bottleneck we just
            // removed for an I/O one. Every 10th result plus a final
            // checkpoint keeps the cost down without leaving much
            // uncheckpointed work if the process is interrupted.
            const CHECKPOINT_EVERY: u64 = 10;
            let summary = debura_scheduler::run_with_concurrency(
                &mut graph,
                provider.as_ref(),
                &debura_verifier::VerificationPolicy::default(),
                &budget,
                concurrency,
                |iteration, task, graph| {
                    println!("[{iteration}] {task:?}");
                    if iteration % CHECKPOINT_EVERY == 0 {
                        if let Err(error) = debura_storage::knowledge::save(&conn, graph) {
                            tracing::warn!(%error, "failed to checkpoint after iteration");
                        }
                    }
                },
            );

            if let Err(error) = debura_storage::knowledge::save(&conn, &graph) {
                tracing::warn!(%error, "failed to checkpoint after run completed");
            }

            println!("\nIterations: {}", summary.iterations);
            println!("Elapsed:    {:.1}s", summary.elapsed.as_secs_f64());
            if summary.iterations > 0 {
                println!(
                    "Rate:       {:.2}s/iteration",
                    summary.elapsed.as_secs_f64() / summary.iterations as f64
                );
            }
            println!("Stopped:    {:?}", summary.stopped_because);
            if summary.total_subjects > 0 {
                println!(
                    "Coverage:   {}/{} ({:.1}%)",
                    summary.resolved_subjects,
                    summary.total_subjects,
                    100.0 * summary.resolved_subjects as f64 / summary.total_subjects as f64
                );
            }
            println!("Hypotheses: {}", graph.hypotheses().count());
            for status in [
                debura_knowledge::HypothesisStatus::Accepted,
                debura_knowledge::HypothesisStatus::Supported,
                debura_knowledge::HypothesisStatus::Contested,
                debura_knowledge::HypothesisStatus::Proposed,
                debura_knowledge::HypothesisStatus::Stale,
                debura_knowledge::HypothesisStatus::Rejected,
            ] {
                let count = graph.hypotheses().filter(|h| h.status == status).count();
                if count > 0 {
                    println!("  {status:?}: {count}");
                }
            }
        }
    }

    Ok(())
}
