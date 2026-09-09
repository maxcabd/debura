use debura_knowledge::{Hypothesis, KnowledgeGraph};

use crate::call_context;

/// PROJECT.md, "Field-level semantic naming": the field-scoped analog of
/// `AnalyzeFunctionTask` -- proposes a real name for one field
/// `stack_object::reconstruct_stack_objects` (debura-recovery) already
/// confirmed real offset/width evidence for. Deliberately built from
/// plain values, not debura-recovery's own `RecoveredFunction`/
/// `DiscoveredField` types: debura-agent doesn't depend on
/// debura-recovery today (the dependency runs the other way --
/// debura-cli depends on both), so the CLI orchestration that calls this
/// is what translates between the two, keeping this crate's own
/// dependency graph unchanged.
#[derive(Debug, Clone)]
pub struct ProposeFieldNameTask {
    pub subject: String,
    pub function_display_name: String,
    pub function_decompilation: String,
    pub base: String,
    pub offset: i64,
    pub width: u32,
    pub declared_type: String,
    /// Other confirmed fields on the same object, as human-readable
    /// facts (e.g. `"offset 0xc, width 1, type char"`) -- real context a
    /// person reading the same code would use too ("this sits right next
    /// to a bool-shaped field, so it's probably part of the same small
    /// state struct").
    pub sibling_fields: Vec<String>,
    /// Real API names reachable from the *defining function*'s own call
    /// graph, reused as-is from `call_context::reachable_api_hints` --
    /// e.g. a function that calls `SDL_RenderCopy` is probably part of
    /// rendering, useful context even when naming one of its fields.
    pub reachable_api_hints: Vec<String>,
    /// Any hypothesis already proposed for this exact field subject (a
    /// retry after a REJECTED/CONTESTED name), mirroring
    /// `AnalyzeFunctionTask::rejection_reasons`'s own purpose.
    pub existing_hypotheses: Vec<Hypothesis>,
}

impl ProposeFieldNameTask {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        graph: &KnowledgeGraph,
        subject: &str,
        function_address: &str,
        function_display_name: &str,
        function_decompilation: &str,
        base: &str,
        offset: i64,
        width: u32,
        declared_type: &str,
        sibling_fields: Vec<String>,
    ) -> Self {
        Self {
            subject: subject.to_string(),
            function_display_name: function_display_name.to_string(),
            function_decompilation: function_decompilation.to_string(),
            base: base.to_string(),
            offset,
            width,
            declared_type: declared_type.to_string(),
            sibling_fields,
            reachable_api_hints: call_context::reachable_api_hints(graph, function_address),
            existing_hypotheses: graph.hypotheses().filter(|h| h.subject == subject).cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_scopes_existing_hypotheses_to_the_field_subject_only() {
        let mut graph = KnowledgeGraph::new();
        graph.propose_hypothesis("field:FUN_1:local_b8+0x4", "field_semantic_name", "m_lives", 0.9, None);
        graph.propose_hypothesis("0x1", "semantic_role", "unrelatedFunction", 0.9, None);

        let task = ProposeFieldNameTask::build(
            &graph,
            "field:FUN_1:local_b8+0x4",
            "0x1",
            "initializeFoodParameters",
            "undefined initializeFoodParameters(undefined4 *param_1) { ... }",
            "local_b8",
            4,
            4,
            "int",
            vec!["offset 0xc, width 1, type char".to_string()],
        );

        assert_eq!(task.existing_hypotheses.len(), 1);
        assert_eq!(task.existing_hypotheses[0].value, "m_lives");
    }
}
