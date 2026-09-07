use debura_knowledge::HypothesisId;

/// The task kinds Debura can actually execute right now (PROJECT.md S28
/// lists a larger initial set -- AnalyzeType, AnalyzeVtable,
/// IdentifySubsystem, and more -- but only these three have real handlers
/// as of M4/M5. Adding the rest here ahead of their own milestones would
/// just be stub variants nothing can dispatch to.)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Task {
    AnalyzeFunction { subject: String },
    ChallengeHypothesis { hypothesis: HypothesisId },
    ResolveContradiction { hypothesis: HypothesisId },
}
