use std::collections::{HashMap, HashSet, VecDeque};

use chrono::Utc;

use crate::dependency::{Dependency, DependencyKind};
use crate::error::KnowledgeError;
use crate::evidence::Evidence;
use crate::hypothesis::{Hypothesis, HypothesisStatus};
use crate::ids::{EvidenceId, HypothesisId, InvestigationId, ObservationId};
use crate::investigation::Investigation;
use crate::observation::Observation;
use crate::program_model::ProgramModel;

type Result<T> = std::result::Result<T, KnowledgeError>;

/// Debura's epistemic model (PROJECT.md S3, S19): observations, evidence,
/// hypotheses and the dependencies between them, held as hot in-memory
/// state. SQLite persistence of this graph arrives at M3.
#[derive(Debug, Default)]
pub struct KnowledgeGraph {
    next_observation_id: u64,
    next_evidence_id: u64,
    next_hypothesis_id: u64,
    next_investigation_id: u64,

    observations: HashMap<ObservationId, Observation>,
    evidence: HashMap<EvidenceId, Evidence>,
    hypotheses: HashMap<HypothesisId, Hypothesis>,
    dependencies: Vec<Dependency>,
    /// target -> hypotheses that DEPEND_ON it, i.e. targets' dependents.
    dependents_of: HashMap<HypothesisId, Vec<HypothesisId>>,
    investigations: HashMap<InvestigationId, Investigation>,
}

impl KnowledgeGraph {
    pub fn new() -> Self {
        Self::default()
    }

    // --- Observation -----------------------------------------------------

    pub fn add_observation(
        &mut self,
        subject: impl Into<String>,
        predicate: impl Into<String>,
        value: impl Into<String>,
        confidence: f64,
        source: impl Into<String>,
        artifact: Option<String>,
    ) -> ObservationId {
        self.next_observation_id += 1;
        let id = ObservationId(self.next_observation_id);
        self.observations.insert(
            id,
            Observation {
                id,
                subject: subject.into(),
                predicate: predicate.into(),
                value: value.into(),
                confidence,
                source: source.into(),
                artifact,
                created_at: Utc::now(),
            },
        );
        id
    }

    pub fn observation(&self, id: ObservationId) -> Option<&Observation> {
        self.observations.get(&id)
    }

    // --- Evidence ----------------------------------------------------------

    pub fn add_evidence(
        &mut self,
        observation_id: ObservationId,
        relevance: impl Into<String>,
        source: impl Into<String>,
        location: Option<String>,
        artifact_reference: Option<String>,
    ) -> Result<EvidenceId> {
        if !self.observations.contains_key(&observation_id) {
            return Err(KnowledgeError::UnknownObservation(observation_id));
        }

        self.next_evidence_id += 1;
        let id = EvidenceId(self.next_evidence_id);
        self.evidence.insert(
            id,
            Evidence {
                id,
                observation_id,
                relevance: relevance.into(),
                source: source.into(),
                location,
                artifact_reference,
            },
        );
        Ok(id)
    }

    pub fn evidence(&self, id: EvidenceId) -> Option<&Evidence> {
        self.evidence.get(&id)
    }

    // --- Hypothesis --------------------------------------------------------

    pub fn propose_hypothesis(
        &mut self,
        subject: impl Into<String>,
        predicate: impl Into<String>,
        value: impl Into<String>,
        confidence: f64,
        created_by: Option<InvestigationId>,
    ) -> HypothesisId {
        self.next_hypothesis_id += 1;
        let id = HypothesisId(self.next_hypothesis_id);
        let now = Utc::now();
        self.hypotheses.insert(
            id,
            Hypothesis {
                id,
                subject: subject.into(),
                predicate: predicate.into(),
                value: value.into(),
                confidence,
                status: HypothesisStatus::Proposed,
                supporting_evidence: Vec::new(),
                contradicting_evidence: Vec::new(),
                dependencies: Vec::new(),
                created_by,
                created_at: now,
                updated_at: now,
                last_verified_at: None,
            },
        );
        id
    }

    pub fn hypothesis(&self, id: HypothesisId) -> Option<&Hypothesis> {
        self.hypotheses.get(&id)
    }

    fn hypothesis_mut(&mut self, id: HypothesisId) -> Result<&mut Hypothesis> {
        self.hypotheses
            .get_mut(&id)
            .ok_or(KnowledgeError::UnknownHypothesis(id))
    }

    pub fn attach_supporting_evidence(
        &mut self,
        hypothesis: HypothesisId,
        evidence: EvidenceId,
    ) -> Result<()> {
        if !self.evidence.contains_key(&evidence) {
            return Err(KnowledgeError::UnknownEvidence(evidence));
        }
        let h = self.hypothesis_mut(hypothesis)?;
        h.supporting_evidence.push(evidence);
        h.updated_at = Utc::now();
        Ok(())
    }

    /// Attaches contradicting evidence and, per PROJECT.md S4, moves the
    /// hypothesis to CONTESTED (unless it's already REJECTED, which is
    /// terminal). Dependents are cascaded to STALE since they were built on
    /// a claim that is no longer settled.
    pub fn attach_contradicting_evidence(
        &mut self,
        hypothesis: HypothesisId,
        evidence: EvidenceId,
    ) -> Result<Vec<HypothesisId>> {
        if !self.evidence.contains_key(&evidence) {
            return Err(KnowledgeError::UnknownEvidence(evidence));
        }

        let h = self.hypothesis_mut(hypothesis)?;
        h.contradicting_evidence.push(evidence);
        h.updated_at = Utc::now();
        if h.status != HypothesisStatus::Rejected {
            h.status = HypothesisStatus::Contested;
        }

        Ok(self.mark_stale_dependents(hypothesis))
    }

    /// Updates a hypothesis's confidence and cascades STALE to anything
    /// that DEPENDS_ON it (PROJECT.md S9-10).
    pub fn set_confidence(
        &mut self,
        hypothesis: HypothesisId,
        confidence: f64,
    ) -> Result<Vec<HypothesisId>> {
        let h = self.hypothesis_mut(hypothesis)?;
        h.confidence = confidence;
        h.updated_at = Utc::now();
        Ok(self.mark_stale_dependents(hypothesis))
    }

    /// Updates a hypothesis's status and cascades STALE to anything
    /// DEPENDS_ON it (PROJECT.md S9-10). REJECTED is never overwritten by
    /// cascading staleness elsewhere in the graph, but setting it directly
    /// here is always honored.
    pub fn set_status(
        &mut self,
        hypothesis: HypothesisId,
        status: HypothesisStatus,
    ) -> Result<Vec<HypothesisId>> {
        let h = self.hypothesis_mut(hypothesis)?;
        h.status = status;
        h.updated_at = Utc::now();
        Ok(self.mark_stale_dependents(hypothesis))
    }

    // --- Dependency ----------------------------------------------------------

    /// Records `source <kind> target` (e.g. `source DEPENDS_ON target`).
    pub fn add_dependency(
        &mut self,
        source: HypothesisId,
        target: HypothesisId,
        kind: DependencyKind,
    ) -> Result<()> {
        if !self.hypotheses.contains_key(&source) {
            return Err(KnowledgeError::UnknownHypothesis(source));
        }
        if !self.hypotheses.contains_key(&target) {
            return Err(KnowledgeError::UnknownHypothesis(target));
        }

        if kind == DependencyKind::DependsOn {
            self.dependents_of.entry(target).or_default().push(source);
            if let Some(h) = self.hypotheses.get_mut(&source) {
                h.dependencies.push(target);
            }
        }

        self.dependencies.push(Dependency {
            source,
            target,
            kind,
        });
        Ok(())
    }

    /// Incremental truth maintenance (PROJECT.md S10): transitively marks
    /// every hypothesis that DEPENDS_ON `changed` as STALE, so an early
    /// guess can never remain a silent, unexamined anchor for everything
    /// built on top of it. REJECTED hypotheses are left untouched -- that
    /// status is terminal, not a step Debura ever walks back from via
    /// cascade. Returns the set of hypotheses newly marked STALE, for a
    /// scheduler to later enqueue for verification (M6).
    pub fn mark_stale_dependents(&mut self, changed: HypothesisId) -> Vec<HypothesisId> {
        let mut newly_stale = Vec::new();
        // Seed with `changed` itself so a cycle in the dependency graph
        // can never loop back and flip the very hypothesis whose change
        // triggered this cascade.
        let mut visited: HashSet<HypothesisId> = HashSet::from([changed]);
        let mut queue: VecDeque<HypothesisId> = self
            .dependents_of
            .get(&changed)
            .cloned()
            .unwrap_or_default()
            .into();

        while let Some(id) = queue.pop_front() {
            if !visited.insert(id) {
                continue;
            }

            if let Some(h) = self.hypotheses.get_mut(&id) {
                if h.status != HypothesisStatus::Rejected && h.status != HypothesisStatus::Stale {
                    h.status = HypothesisStatus::Stale;
                    h.updated_at = Utc::now();
                    newly_stale.push(id);
                }
            }

            if let Some(next) = self.dependents_of.get(&id) {
                queue.extend(next.iter().copied());
            }
        }

        newly_stale
    }

    // --- Investigation -------------------------------------------------------

    pub fn record_investigation(&mut self, mut investigation: Investigation) -> InvestigationId {
        self.next_investigation_id += 1;
        let id = InvestigationId(self.next_investigation_id);
        investigation.id = id;
        self.investigations.insert(id, investigation);
        id
    }

    pub fn investigation(&self, id: InvestigationId) -> Option<&Investigation> {
        self.investigations.get(&id)
    }

    // --- Program model -------------------------------------------------------

    pub fn program_model(&self) -> ProgramModel<'_> {
        ProgramModel {
            accepted: self
                .hypotheses
                .values()
                .filter(|h| h.status == HypothesisStatus::Accepted)
                .collect(),
        }
    }

    // --- Iteration (for persistence / summaries) ----------------------------

    pub fn observations(&self) -> impl Iterator<Item = &Observation> {
        self.observations.values()
    }

    pub fn all_evidence(&self) -> impl Iterator<Item = &Evidence> {
        self.evidence.values()
    }

    pub fn hypotheses(&self) -> impl Iterator<Item = &Hypothesis> {
        self.hypotheses.values()
    }

    pub fn dependencies(&self) -> &[Dependency] {
        &self.dependencies
    }

    // --- Restoration (for loading persisted state) --------------------------
    //
    // These bypass id generation and status-transition rules: they trust the
    // caller (debura-storage, reading back exactly what was saved) rather
    // than simulating new reasoning events. `add_*`/`set_*` above are for
    // live operation; `insert_*` below are for reconstructing prior state.

    pub fn insert_observation(&mut self, observation: Observation) {
        self.next_observation_id = self.next_observation_id.max(observation.id.0);
        self.observations.insert(observation.id, observation);
    }

    pub fn insert_evidence(&mut self, evidence: Evidence) {
        self.next_evidence_id = self.next_evidence_id.max(evidence.id.0);
        self.evidence.insert(evidence.id, evidence);
    }

    pub fn insert_hypothesis(&mut self, hypothesis: Hypothesis) {
        self.next_hypothesis_id = self.next_hypothesis_id.max(hypothesis.id.0);
        self.hypotheses.insert(hypothesis.id, hypothesis);
    }

    /// Restores a dependency edge, rebuilding the `dependents_of` index and
    /// the owning hypothesis's `dependencies` list. Call only after all
    /// hypotheses have been inserted.
    pub fn insert_dependency(&mut self, dependency: Dependency) {
        if dependency.kind == DependencyKind::DependsOn {
            self.dependents_of
                .entry(dependency.target)
                .or_default()
                .push(dependency.source);
            if let Some(h) = self.hypotheses.get_mut(&dependency.source) {
                h.dependencies.push(dependency.target);
            }
        }
        self.dependencies.push(dependency);
    }
}
