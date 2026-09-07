//! Adversarial verification: ChallengeHypothesis, ReevaluateHypothesis,
//! ResolveContradiction (PROJECT.md S11, S12, M5).
//!
//! `reevaluate_hypothesis` is the acceptance gate: it's the only code path
//! that promotes a hypothesis to ACCEPTED, and it refuses to unless the
//! hypothesis has both a high enough confidence *and* an actual
//! verification attempt on record (`last_verified_at`). Confidence alone
//! is never enough.

mod policy;
mod reevaluate;
mod verify;

pub use policy::VerificationPolicy;
pub use reevaluate::reevaluate_hypothesis;
pub use verify::{
    build_challenge_task, build_resolve_task, challenge, challenge_hypothesis, commit_challenge,
    commit_resolution, resolve, resolve_contradiction,
};
