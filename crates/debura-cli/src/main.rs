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

#[derive(Clone, Copy, ValueEnum)]
enum NamesChoice {
    Mechanical,
    Semantic,
    Mixed,
}

/// Every distinct `DAT_*`/`PTR_*`-shaped identifier mentioned in `text`
/// (PROJECT.md, "Deterministic string-literal extraction") -- a plain
/// byte scan, not a parse, since Ghidra's own naming convention is
/// exactly this fixed prefix followed by ordinary identifier characters.
fn extract_data_symbol_references(text: &str) -> std::collections::BTreeSet<String> {
    let mut found = std::collections::BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let is_boundary = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
        if is_boundary && (text[i..].starts_with("DAT_") || text[i..].starts_with("PTR_")) {
            let start = i;
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            found.insert(text[start..j].to_string());
            i = j;
        } else {
            i += 1;
        }
    }
    found
}

impl From<NamesChoice> for debura_recovery::NamesMode {
    fn from(choice: NamesChoice) -> Self {
        match choice {
            NamesChoice::Mechanical => debura_recovery::NamesMode::Mechanical,
            NamesChoice::Semantic => debura_recovery::NamesMode::Semantic,
            NamesChoice::Mixed => debura_recovery::NamesMode::Mixed,
        }
    }
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
        /// How accepted field names (PROJECT.md, "Field-level semantic
        /// naming") render: `mechanical` never looks at the graph, every
        /// field stays exactly as `stack_object.rs` rendered it;
        /// `semantic`/`mixed` (the default) use an accepted name
        /// wherever one exists, falling back to the mechanical form
        /// otherwise -- never inventing a name that hasn't cleared the
        /// same evidence/challenge bar every other accepted hypothesis
        /// clears.
        #[arg(long, value_enum, default_value_t = NamesChoice::Mixed)]
        names: NamesChoice,
    },
    /// Proposes and verifies semantic names for stack-object fields
    /// `debura recover` already discovered evidence for (PROJECT.md,
    /// "Field-level semantic naming") -- run only after a recovery is
    /// confirmed to build+link+run; static evidence only (the field's
    /// defining function decompilation, its call graph, and sibling
    /// fields already discovered on the same object). Skips any field
    /// that already has an ACCEPTED name. A later `--dynamic` tier
    /// (runtime value-transition evidence) is not implemented yet.
    Semantic {
        /// Project id, as printed by `debura new`
        project: String,
        /// Use only static evidence -- the only mode implemented so far.
        /// Required explicitly so a future `--dynamic` addition is an
        /// opt-in choice, not a silent default change.
        #[arg(long = "static")]
        static_pass: bool,
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
        Command::Recover { project, linker_log, names } => {
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");
            let names_mode: debura_recovery::NamesMode = names.into();

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let graph = debura_storage::knowledge::load(&conn)?;

            let (program, runtime_bodies_recovered) = match linker_log {
                None => (
                    debura_recovery::extract_with_options(&graph, &std::collections::BTreeSet::new(), None, names_mode),
                    0usize,
                ),
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
                    // PROJECT.md M18.3: `SDL_main`-shaped unresolved
                    // references never match `parse_undefined_symbols`'s
                    // own `FUN_<addr>` pattern (it's a real, plain-named
                    // external symbol, not one of Debura's own
                    // placeholder names), so it always parses as
                    // `UnresolvedSymbol::Data` regardless of really
                    // naming a function -- checked directly against the
                    // raw literal name here rather than only against
                    // `disposition`'s own function-only view.
                    let literal_names: Vec<&str> = unresolved
                        .iter()
                        .map(|u| match u {
                            debura_recovery::UnresolvedSymbol::Function { literal_name, .. } => literal_name.as_str(),
                            debura_recovery::UnresolvedSymbol::Data { literal_name } => literal_name.as_str(),
                        })
                        .collect();
                    let entry_wrapper_symbol = literal_names.contains(&"SDL_main").then_some("SDL_main");
                    (
                        debura_recovery::extract_with_options(
                            &graph,
                            &required_runtime_bodies,
                            entry_wrapper_symbol,
                            names_mode,
                        ),
                        count,
                    )
                }
            };
            let entry_wrapper = program.entry_wrapper.clone();
            let summary = debura_recovery::write_to_disk(&root, &program)?;

            println!("Classes recovered:   {}", summary.classes_written);
            println!("Functions recovered: {}", summary.functions_written);
            if runtime_bodies_recovered > 0 {
                println!("  (including {runtime_bodies_recovered} linker-verified RequiredRuntimeBody)");
            }
            if let Some((symbol, target)) = &entry_wrapper {
                println!("  (exposing {target} as {symbol})");
            }
            println!("Written to: {}", root.join("recovered").display());
        }
        Command::Semantic { project, static_pass } => {
            anyhow::ensure!(static_pass, "pass --static -- it's the only mode implemented so far");
            let root = debura_core::config::projects_dir().join(&project);
            anyhow::ensure!(root.is_dir(), "no such project: {project}");
            let provider = make_provider(cli.provider)?;
            let policy = debura_verifier::VerificationPolicy::default();

            let conn = debura_storage::init_project_db(&root.join("project.sqlite"))?;
            let mut graph = debura_storage::knowledge::load(&conn)?;

            let program = debura_recovery::extract(&graph);
            let functions_by_raw_name: std::collections::HashMap<&str, &debura_recovery::RecoveredFunction> =
                program.functions.iter().map(|f| (f.raw_name.as_str(), f)).collect();
            let symbol_table = debura_recovery::build_symbol_table(&program.classes, &program.functions);

            let mut skipped_existing = 0u32;
            let mut skipped_no_function = 0u32;
            let mut roles_proposed = 0u32;
            let mut roles_accepted = 0u32;
            let mut skipped_no_role = 0u32;
            let mut names_proposed = 0u32;
            let mut names_accepted = 0u32;

            for field in &program.discovered_fields {
                let already_named = graph.hypotheses().any(|h| {
                    h.subject == field.subject
                        && h.predicate == "field_semantic_name"
                        && h.status == debura_knowledge::HypothesisStatus::Accepted
                });
                if already_named {
                    skipped_existing += 1;
                    continue;
                }
                let Some(function) = functions_by_raw_name.get(field.function_raw_name.as_str()) else {
                    skipped_no_function += 1;
                    continue;
                };

                let sibling_fields: Vec<String> = program
                    .discovered_fields
                    .iter()
                    .filter(|other| {
                        other.function_raw_name == field.function_raw_name
                            && other.base == field.base
                            && other.offset != field.offset
                    })
                    .map(|other| format!("offset 0x{:x}, width {}, type {}", other.offset, other.width, other.declared_type))
                    .collect();

                let value_consumer_list = debura_recovery::find_field_value_consumers(&program.functions, field);
                let value_consumers: Vec<String> = value_consumer_list
                    .iter()
                    .map(|c| {
                        format!(
                            "value passed to {} (parameter {}), whose own body is:\n{}",
                            c.callee_raw_name, c.parameter_position, c.callee_decompilation
                        )
                    })
                    .collect();

                let mut data_symbol_names = extract_data_symbol_references(&function.decompilation);
                for c in &value_consumer_list {
                    data_symbol_names.extend(extract_data_symbol_references(&c.callee_decompilation));
                }
                let data_symbol_names: Vec<String> = data_symbol_names.into_iter().collect();
                let string_resolutions = debura_recovery::classify_data_symbols(&graph, &data_symbol_names, &symbol_table);
                let relevant_data_references: Vec<String> = string_resolutions
                    .iter()
                    .filter_map(|r| match &r.kind {
                        debura_recovery::DataSymbolKind::StringLiteral(value) => {
                            Some(format!("{}: string {:?}", r.symbol_name, value))
                        }
                        _ => None,
                    })
                    .collect();
                let resolved_strings: std::collections::HashMap<String, String> = string_resolutions
                    .into_iter()
                    .filter_map(|r| match r.kind {
                        debura_recovery::DataSymbolKind::StringLiteral(value) => Some((r.symbol_name, value)),
                        _ => None,
                    })
                    .collect();

                // PROJECT.md, "Two-stage semantic reasoning": real,
                // deterministic sink facts -- never model-guessed -- that
                // the tracked value is displayed adjacent to a resolved
                // string literal. The single strongest evidence category
                // when non-empty.
                let mut display_associations = Vec::new();
                for consumer in &value_consumer_list {
                    display_associations.extend(debura_recovery::find_display_associations(consumer, &resolved_strings));
                }
                let display_association_lines: Vec<String> = display_associations
                    .iter()
                    .map(|a| {
                        format!(
                            "tracked value, as \"{}\", is displayed immediately adjacent to {} (\"{}\") in {}",
                            a.value_expr, a.label_symbol, a.label, a.sink_function
                        )
                    })
                    .collect();
                // The exact evidence strings a `decisive_sink` citation is
                // checked against -- the same evidence the task itself was
                // given, so a proposal can never cite something it wasn't
                // actually shown.
                let mut known_sinks = display_association_lines.clone();
                known_sinks.extend(value_consumer_list.iter().map(|c| c.callee_raw_name.clone()));

                // Stage 1: establish what the field *means* before ever
                // asking how to spell it. An ACCEPTED role from a
                // previous run is reused as-is; otherwise propose one now
                // and commit only a Debura-computed confidence (never the
                // model's own self-report) once `decisive_sink` verifies
                // against real evidence -- `None` means no proposal is
                // committed at all this run, not even at low confidence.
                let accepted_role = graph
                    .hypotheses()
                    .filter(|h| {
                        h.subject == field.subject
                            && h.predicate == "field_semantic_role"
                            && h.status == debura_knowledge::HypothesisStatus::Accepted
                    })
                    .max_by_key(|h| h.id.0)
                    .map(|h| (h.value.clone(), h.id));

                // (role concept, the role hypothesis's own id -- carried
                // through so the naming stage below can record a real
                // DependsOn edge onto it, not just reuse its text) so that
                // if this role is ever later invalidated, truth
                // maintenance cascades the dependent name to Stale
                // automatically instead of leaving it accepted on a
                // premise that no longer holds.
                let role = match accepted_role {
                    Some(role) => Some(role),
                    None => {
                        let role_task = debura_agent::ProposeFieldSemanticRoleTask::build(
                            &graph,
                            &field.subject,
                            &function.address,
                            &function.display_name,
                            &function.decompilation,
                            &field.base,
                            field.offset,
                            field.width,
                            &field.declared_type,
                            sibling_fields.clone(),
                            value_consumers.clone(),
                            relevant_data_references.clone(),
                            display_association_lines,
                            known_sinks.clone(),
                        );
                        let role_result = provider.propose_field_semantic_role(&role_task)?;
                        match debura_agent::debura_confidence_for_role(&role_result, &known_sinks) {
                            None => {
                                skipped_no_role += 1;
                                None
                            }
                            Some(confidence) => {
                                roles_proposed += 1;
                                let hypothesis = debura_agent::ProposedHypothesis {
                                    predicate: "field_semantic_role".to_string(),
                                    value: role_result.semantic_role.clone().unwrap_or_default(),
                                    confidence,
                                    depends_on: Vec::new(),
                                };
                                let role_id = debura_agent::commit_hypothesis(&mut graph, &field.subject, &hypothesis, None);
                                let id = role_id;
                                // PROJECT.md, "Predicate-aware challenge": a
                                // field's semantic *role* has no caller/API
                                // context to speak of -- it's not a
                                // function -- so it's challenged through its
                                // own predicate-specific task, never the
                                // generic function-shaped one.
                                let challenge_task = debura_agent::ChallengeFieldSemanticRoleTask::build(&role_task, &role_result);
                                let challenge_result = provider.challenge_field_semantic_role(&challenge_task)?;
                                let context_snapshot = format!(
                                    "{} display associations, {} known sinks",
                                    challenge_task.display_associations.len(),
                                    challenge_task.known_sinks.len()
                                );
                                debura_verifier::commit_challenge(&mut graph, id, &context_snapshot, challenge_result, &policy)?;
                                if graph.hypothesis(id).map(|h| h.status) == Some(debura_knowledge::HypothesisStatus::Contested) {
                                    debura_verifier::resolve_contradiction(&mut graph, provider.as_ref(), id, &policy)?;
                                }
                                let status = graph.hypothesis(id).map(|h| h.status);
                                println!("{} (role): {} = {:.2} ({:?})", field.subject, hypothesis.value, confidence, status);
                                if status == Some(debura_knowledge::HypothesisStatus::Accepted) {
                                    roles_accepted += 1;
                                    Some((hypothesis.value, role_id))
                                } else {
                                    None
                                }
                            }
                        }
                    }
                };
                let Some((role, role_id)) = role else {
                    // No accepted role yet this run -- naming would have
                    // nothing real to spell, so it doesn't run at all.
                    continue;
                };

                // Stage 2: spell the already-established role as a real
                // identifier -- this task no longer has to (and must not)
                // re-derive what the field means.
                let task = debura_agent::ProposeFieldNameTask::build(
                    &graph,
                    &field.subject,
                    &function.address,
                    &function.display_name,
                    &function.decompilation,
                    &field.base,
                    field.offset,
                    field.width,
                    &field.declared_type,
                    sibling_fields,
                    value_consumers,
                    relevant_data_references,
                    &role,
                );

                let result = provider.propose_field_name(&task)?;
                for hypothesis in &result.hypotheses {
                    if hypothesis.predicate != "field_semantic_name" {
                        continue;
                    }
                    names_proposed += 1;
                    // Depends on the accepted role hypothesis, not just its
                    // text -- so if that role is later invalidated, this
                    // name cascades to Stale through the graph's own
                    // dependency-based truth maintenance rather than being
                    // left ACCEPTED on a premise that no longer holds.
                    let mut hypothesis = hypothesis.clone();
                    hypothesis.depends_on = vec![role_id];
                    let id = debura_agent::commit_hypothesis(&mut graph, &field.subject, &hypothesis, None);
                    // PROJECT.md, "Predicate-aware challenge": a proposed
                    // name has an already-ACCEPTED role to be judged
                    // against, not caller/API context -- the same
                    // predicate-specific dispatch as the role stage above.
                    let challenge_task = debura_agent::ChallengeFieldSemanticNameTask::build(&task, &hypothesis.value);
                    let challenge_result = provider.challenge_field_semantic_name(&challenge_task)?;
                    let context_snapshot = format!(
                        "established role {:?}, {} sibling fields, {} value consumers",
                        challenge_task.established_role,
                        challenge_task.sibling_fields.len(),
                        challenge_task.value_consumers.len()
                    );
                    debura_verifier::commit_challenge(&mut graph, id, &context_snapshot, challenge_result, &policy)?;
                    if graph.hypothesis(id).map(|h| h.status) == Some(debura_knowledge::HypothesisStatus::Contested) {
                        debura_verifier::resolve_contradiction(&mut graph, provider.as_ref(), id, &policy)?;
                    }
                    if let Some(h) = graph.hypothesis(id) {
                        println!("{}: {} = {} ({:?})", field.subject, h.value, h.confidence, h.status);
                        if h.status == debura_knowledge::HypothesisStatus::Accepted {
                            names_accepted += 1;
                        }
                    }
                }
            }

            debura_storage::knowledge::save(&conn, &graph)?;

            println!("\nFields considered:      {}", program.discovered_fields.len());
            println!("Already named:          {skipped_existing}");
            println!("No recovered function:  {skipped_no_function}");
            println!("Roles proposed:         {roles_proposed}");
            println!("Roles accepted:         {roles_accepted}");
            println!("No role this run:       {skipped_no_role}");
            println!("Names proposed:         {names_proposed}");
            println!("Names accepted:         {names_accepted}");
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
                    debura_recovery::RecoveryDisposition::RuntimeArtifact => "RuntimeArtifact",
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
            println!("  RuntimeArtifact:     {}", count(debura_recovery::RecoveryDisposition::RuntimeArtifact));
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
