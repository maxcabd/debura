use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::ObservationId;

/// Something directly derived from the binary or deterministic analysis
/// (PROJECT.md S3.1). Not a semantic interpretation -- observations should
/// generally sit at very high confidence because nothing here was guessed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub id: ObservationId,
    pub subject: String,
    pub predicate: String,
    pub value: String,
    pub confidence: f64,
    pub source: String,
    pub artifact: Option<String>,
    pub created_at: DateTime<Utc>,
}
