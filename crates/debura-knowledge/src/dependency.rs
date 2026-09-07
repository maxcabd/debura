use serde::{Deserialize, Serialize};

use crate::ids::HypothesisId;

/// PROJECT.md S8. Only `DependsOn` edges drive stale-propagation
/// (KnowledgeGraph::mark_stale_dependents) -- the others are recorded for
/// provenance/querying but don't yet trigger invalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencyKind {
    DependsOn,
    Supports,
    Contradicts,
    Implies,
}

/// `source DEPENDS_ON target` (or Supports/Contradicts/Implies): if `target`
/// changes, `source` may need reconsideration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub source: HypothesisId,
    pub target: HypothesisId,
    pub kind: DependencyKind,
}
