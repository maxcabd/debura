use debura_knowledge::HypothesisId;
use serde::{Deserialize, Serialize};

/// A new observation the agent claims to have derived -- only meaningful
/// for a provider with live Ghidra tool access (S23: "the model may inspect
/// more evidence using Ghidra tools"). No provider does that yet, so this
/// is normally empty; the field exists so that capability doesn't require
/// a breaking change later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedObservation {
    pub subject: String,
    pub predicate: String,
    pub value: String,
    pub confidence: f64,
    pub source: String,
}

/// A new interpretation of the task's subject. `depends_on` must reference
/// hypotheses that already exist in the graph -- the harness drops (and
/// logs) anything that doesn't resolve rather than committing a dangling
/// dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedHypothesis {
    pub predicate: String,
    pub value: String,
    pub confidence: f64,
    pub depends_on: Vec<HypothesisId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceUpdate {
    pub hypothesis: HypothesisId,
    pub confidence: f64,
}

/// A claim that existing evidence contradicts `hypothesis`. The harness
/// turns `reason` into a real Observation + Evidence pair (source
/// "agent:AnalyzeFunction") so the claim is provenance-tracked like
/// anything else (S7), rather than being an untraceable side effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedContradiction {
    pub hypothesis: HypothesisId,
    pub reason: String,
}

/// What an AgentProvider returns for one AnalyzeFunctionTask (PROJECT.md
/// S11, S23). Nothing here is committed to the knowledge graph until the
/// harness validates it (S11: "the harness validates this result before
/// committing anything").
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvestigationResult {
    pub observations: Vec<ProposedObservation>,
    pub hypotheses: Vec<ProposedHypothesis>,
    pub confidence_updates: Vec<ConfidenceUpdate>,
    pub contradictions: Vec<ProposedContradiction>,
    pub followup_tasks: Vec<String>,
}
