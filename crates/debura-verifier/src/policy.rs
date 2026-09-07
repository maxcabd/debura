/// Confidence thresholds gating status promotion (PROJECT.md M5: "No
/// semantic hypothesis should become ACCEPTED without passing configured
/// verification requirements").
///
/// The values below are a starting point, not a tuned result -- M9's
/// evaluation against ground-truth binaries is what should eventually
/// justify (or move) them.
#[derive(Debug, Clone, Copy)]
pub struct VerificationPolicy {
    /// Minimum confidence to reach ACCEPTED. Requires `last_verified_at` to
    /// be set as well -- confidence alone is never enough (S11).
    pub acceptance_threshold: f64,
    /// Minimum confidence to reach SUPPORTED.
    pub support_threshold: f64,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            acceptance_threshold: 0.85,
            support_threshold: 0.6,
        }
    }
}
