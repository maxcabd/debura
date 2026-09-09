/// PROJECT.md, "Field-level semantic naming": renders an ACCEPTED
/// `field_semantic_name` hypothesis (a new, distinct predicate from
/// `semantic_role` -- functions and fields are named through the same
/// evidence/challenge/accept machinery, but never share a predicate,
/// so existing function-naming stats/`apply`/rendering stay untouched)
/// into the function body that references it. `stack_object.rs` already
/// rewrites a fragmented stack object into `*(TYPE *)(base + offset)`
/// dereferences; this pass, given an ACCEPTED name for one, introduces a
/// real named alias for it instead -- the exact transformation done by
/// hand today for Snake's own lives counter
/// (`int *const m_lives = (int *)(param_1 + 1);` then `*m_lives = 5;`).
/// Must run after `phantom_local.rs`: it needs the final, fully-resolved
/// offset text, not an intermediate phantom-local alias still pointing
/// at a not-yet-widened base.
use debura_knowledge::{Hypothesis, HypothesisStatus, KnowledgeGraph};

use crate::extract::is_valid_cpp_identifier;
use crate::forwarding_thunk::matching_close;
use crate::model::RecoveredFunction;
use crate::phantom_local::split_locals_block;
use crate::stack_object::{mechanical_dereference_text, offset_text, DiscoveredField};

/// How field names render, mirroring `debura recover`'s own `--names`
/// flag. `Mechanical` never looks at the graph at all -- every field
/// stays exactly as `stack_object.rs` rendered it. `Semantic`/`Mixed`
/// both use an ACCEPTED alias wherever one exists; they differ only in
/// v2, once a field can be *required* to have a real name -- for now
/// both fall back to the mechanical form when none is accepted yet,
/// since inventing a name that hasn't cleared the same evidence bar
/// every other accepted hypothesis clears is exactly what this whole
/// pipeline exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamesMode {
    Mechanical,
    Semantic,
    Mixed,
}

/// The single most-recently-ACCEPTED `field_semantic_name` hypothesis
/// for `subject`, if its value is a real, usable C++ identifier -- same
/// "most recent wins, never guess a malformed name" contract as
/// `extract.rs`'s own `accepted_name` for `semantic_role`.
fn accepted_field_name<'a>(graph: &'a KnowledgeGraph, subject: &str) -> Option<&'a Hypothesis> {
    graph
        .hypotheses()
        .filter(|h| {
            h.subject == subject
                && h.predicate == "field_semantic_name"
                && h.status == HypothesisStatus::Accepted
                && is_valid_cpp_identifier(&h.value)
        })
        .max_by_key(|h| h.id.0)
}

/// Renders every ACCEPTED field name this project's knowledge graph has
/// for `discovered_fields`, in `mode`. Skipped entirely (no graph lookup
/// at all) when `mode` is `Mechanical`.
pub fn apply_field_names(
    functions: &mut [RecoveredFunction],
    discovered_fields: &[DiscoveredField],
    graph: &KnowledgeGraph,
    mode: NamesMode,
) {
    if mode == NamesMode::Mechanical {
        return;
    }
    for field in discovered_fields {
        let Some(name) = accepted_field_name(graph, &field.subject).map(|h| h.value.clone()) else {
            continue;
        };
        let Some(func) = functions.iter_mut().find(|f| f.raw_name == field.function_raw_name) else {
            continue;
        };
        apply_one_field_name(func, field, &name);
    }
}

/// Introduces a named pointer alias for `field` inside `func`'s own
/// body, replacing every occurrence of the mechanical dereference with
/// `*name`. A no-op (never partially applied) if the mechanical text
/// isn't found, or the body can't be split into a locals/statements
/// block -- naming is a readability improvement, never a precondition
/// for the mechanical form staying correct.
fn apply_one_field_name(func: &mut RecoveredFunction, field: &DiscoveredField, name: &str) {
    let mechanical = mechanical_dereference_text(field);
    if !func.decompilation.contains(&mechanical) {
        return;
    }
    let Some(brace_open) = func.decompilation.find('{') else { return };
    let Some(brace_close) = matching_close(&func.decompilation, brace_open, b'{', b'}') else {
        return;
    };
    let body = &func.decompilation[brace_open + 1..brace_close];
    let Some((locals_block, stmts_block)) = split_locals_block(body) else { return };

    let declaration = format!(
        "  {} *const {} = ({} *)({} + {});\n",
        field.declared_type,
        name,
        field.declared_type,
        field.base,
        offset_text(field.offset)
    );
    let new_locals_block = format!("{locals_block}{declaration}");
    let new_stmts_block = stmts_block.replace(&mechanical, &format!("*{name}"));

    func.decompilation = format!(
        "{}{}{}{}",
        &func.decompilation[..brace_open + 1],
        new_locals_block,
        new_stmts_block,
        &func.decompilation[brace_close..]
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NameSource;
    use debura_knowledge::KnowledgeGraph;

    fn field(subject: &str, function_raw_name: &str, base: &str, offset: i64, width: u32, declared_type: &str) -> DiscoveredField {
        DiscoveredField {
            subject: subject.to_string(),
            function_raw_name: function_raw_name.to_string(),
            base: base.to_string(),
            offset,
            width,
            declared_type: declared_type.to_string(),
        }
    }

    fn function(raw_name: &str, decompilation: &str) -> RecoveredFunction {
        RecoveredFunction {
            address: "0x1400025b0".to_string(),
            raw_name: raw_name.to_string(),
            display_name: raw_name.to_string(),
            name_source: NameSource::Raw,
            return_type: "undefined".to_string(),
            params: "undefined4 *param_1".to_string(),
            decompilation: decompilation.to_string(),
        }
    }

    /// The real, confirmed case: `initializeFoodParameters`'s own lives
    /// field, hand-named today, now produced by this pass instead.
    #[test]
    fn an_accepted_field_name_introduces_a_real_alias() {
        let mut functions = vec![function(
            "FUN_1400025b0",
            "undefined initializeFoodParameters(undefined4 *param_1)\n\n{\n  uint local_2c;\n  \n  *param_1 = 1;\n  *(int *)(param_1 + 0x4) = 3;\n  return;\n}",
        )];
        let fields = vec![field("field:FUN_1400025b0:param_1+0x4", "FUN_1400025b0", "param_1", 4, 4, "int")];
        let mut graph = KnowledgeGraph::new();
        graph.propose_hypothesis("field:FUN_1400025b0:param_1+0x4", "field_semantic_name", "m_lives", 0.96, None);
        let id = graph.hypotheses().next().unwrap().id;
        graph.set_status(id, HypothesisStatus::Accepted).unwrap();

        apply_one_field_name(&mut functions[0], &fields[0], "m_lives");

        let body = &functions[0].decompilation;
        assert!(body.contains("int *const m_lives = (int *)(param_1 + 0x4);"), "{body}");
        assert!(body.contains("*m_lives = 3;"), "{body}");
        assert!(!body.contains("*(int *)(param_1 + 0x4)"), "{body}");
    }

    #[test]
    fn mechanical_mode_never_touches_the_graph_or_the_body() {
        let mut functions = vec![function(
            "FUN_1",
            "undefined FUN_1(undefined4 *param_1)\n\n{\n  \n  *(int *)(param_1 + 0x4) = 3;\n  return;\n}",
        )];
        let original = functions[0].decompilation.clone();
        let fields = vec![field("field:FUN_1:param_1+0x4", "FUN_1", "param_1", 4, 4, "int")];
        let mut graph = KnowledgeGraph::new();
        graph.propose_hypothesis("field:FUN_1:param_1+0x4", "field_semantic_name", "m_lives", 0.96, None);
        let id = graph.hypotheses().next().unwrap().id;
        graph.set_status(id, HypothesisStatus::Accepted).unwrap();

        apply_field_names(&mut functions, &fields, &graph, NamesMode::Mechanical);

        assert_eq!(functions[0].decompilation, original);
    }

    #[test]
    fn a_field_with_no_accepted_name_is_left_mechanical() {
        let mut functions = vec![function(
            "FUN_1",
            "undefined FUN_1(undefined4 *param_1)\n\n{\n  \n  *(int *)(param_1 + 0x4) = 3;\n  return;\n}",
        )];
        let original = functions[0].decompilation.clone();
        let fields = vec![field("field:FUN_1:param_1+0x4", "FUN_1", "param_1", 4, 4, "int")];
        let graph = KnowledgeGraph::new();

        apply_field_names(&mut functions, &fields, &graph, NamesMode::Mixed);

        assert_eq!(functions[0].decompilation, original);
    }
}
