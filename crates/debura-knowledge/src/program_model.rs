use crate::hypothesis::Hypothesis;

/// The active reconstruction (PROJECT.md S13): only ACCEPTED hypotheses are
/// visible here. Merely PROPOSED or SUPPORTED claims must not silently
/// influence generated source, Ghidra mutations, or subsystem summaries.
///
/// This is a thin, derived view for now -- grouping accepted knowledge into
/// classes/fields/methods (the tree shape shown in S13's example) is type
/// recovery's job (M7), not the knowledge engine's.
#[derive(Debug)]
pub struct ProgramModel<'a> {
    pub accepted: Vec<&'a Hypothesis>,
}

impl<'a> ProgramModel<'a> {
    pub fn about(&self, subject: &str) -> Vec<&'a Hypothesis> {
        self.accepted
            .iter()
            .copied()
            .filter(|h| h.subject == subject)
            .collect()
    }
}
