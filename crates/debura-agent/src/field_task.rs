use debura_knowledge::{Hypothesis, KnowledgeGraph};
use serde::{Deserialize, Serialize};

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
    /// Other functions (not the defining one) this field's own *value*
    /// -- not merely its address -- flows into, as human-readable facts
    /// pairing each callee's name with its own decompiled body. A real,
    /// confirmed reason this exists: Snake's own lives counter is only
    /// ever *set* where it's declared, but the evidence that actually
    /// justifies its name -- displayed next to "Lives: " -- lives two
    /// calls away, in a function that has nothing else to do with where
    /// the field itself is stored. Without this, a real run proposed
    /// `m_counter`/`m_isActive` instead and correctly had them rejected
    /// for lacking exactly this kind of evidence.
    pub value_consumers: Vec<String>,
    /// Real, decoded content for `DAT_*`/`PTR_*` data symbols referenced
    /// anywhere in the defining function or a value consumer's own body,
    /// as human-readable facts (e.g. `"DAT_14000e0c0 (section .bss):
    /// string \"Lives: \""`). PROJECT.md, "Deterministic string-literal
    /// extraction": the confirmed reason this exists -- Snake's own
    /// `createText` concatenates the lives field's value together with
    /// exactly this symbol's real content, but until this existed the
    /// symbol rendered as a completely opaque name, and a real run
    /// proposed `m_drawableInstances` instead of `m_lives` for lack of
    /// it. Deliberately narrow to symbols that actually resolved to a
    /// real string (never every data reference regardless of relevance)
    /// -- strings are the highest-value piece of this evidence class.
    pub relevant_data_references: Vec<String>,
    /// PROJECT.md, "Two-stage semantic reasoning": the ALREADY-ACCEPTED
    /// `field_semantic_role` for this exact field (e.g. `"remaining_lives"`)
    /// -- this task's own real job narrows to spelling that established
    /// concept as a real, idiomatic C++ identifier, never re-deriving or
    /// second-guessing what the field actually means. That reasoning
    /// already happened, adversarially verified, in
    /// `ProposeFieldSemanticRoleTask` below.
    pub established_role: String,
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
        value_consumers: Vec<String>,
        relevant_data_references: Vec<String>,
        established_role: &str,
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
            value_consumers,
            relevant_data_references,
            established_role: established_role.to_string(),
            existing_hypotheses: graph.hypotheses().filter(|h| h.subject == subject).cloned().collect(),
        }
    }
}

/// PROJECT.md, "Two-stage semantic reasoning": proposes what a field
/// *means* -- a concept (`"remaining_lives"`), never an identifier --
/// forcing the model to trace the tracked value through the same
/// evidence `ProposeFieldNameTask` sees and cite a `decisive_sink`
/// Debura can independently verify, rather than free-associating a
/// plausible-sounding name in one shot. The real, confirmed reason this
/// exists: with every piece of evidence already correct and complete
/// (the full value-consumer chain, a resolved `"Lives: "` string
/// literal immediately adjacent to the tracked value), a single-stage
/// naming task still proposed `m_drawableCount` at 0.95 self-reported
/// confidence -- correct evidence, wrong abstraction, a confidence
/// number with no real relationship to evidence quality. Splitting
/// "what does this mean" from "what do we call it" and requiring a
/// verifiable citation is the fix; `debura_confidence_for_role` below is
/// the other half (never trusting the model's own confidence directly).
#[derive(Debug, Clone)]
pub struct ProposeFieldSemanticRoleTask {
    pub subject: String,
    pub function_display_name: String,
    pub function_decompilation: String,
    pub base: String,
    pub offset: i64,
    pub width: u32,
    pub declared_type: String,
    pub sibling_fields: Vec<String>,
    pub reachable_api_hints: Vec<String>,
    pub value_consumers: Vec<String>,
    pub relevant_data_references: Vec<String>,
    /// PROJECT.md, "Deterministic string-literal extraction" +
    /// "Two-stage semantic reasoning": `DisplayAssociation` facts
    /// (`display_association::find_display_associations`, debura-
    /// recovery), formatted as human-readable sink descriptions (e.g.
    /// `"tracked value, as \"param_4 + -1\", is displayed immediately
    /// after DAT_14000e0c0 (\"Lives: \") in FUN_14000205a"`) -- the
    /// single strongest evidence category when non-empty, framed as
    /// such in the system prompt.
    pub display_associations: Vec<String>,
    /// The exact set of citable sink identifiers `verify_decisive_sink`
    /// checks a proposal's own `decisive_sink` against -- built from
    /// `display_associations` and `value_consumers` above, the same
    /// evidence the task itself was given, so a proposal can never cite
    /// a sink that wasn't actually shown to it.
    pub known_sinks: Vec<String>,
    pub existing_hypotheses: Vec<Hypothesis>,
}

impl ProposeFieldSemanticRoleTask {
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
        value_consumers: Vec<String>,
        relevant_data_references: Vec<String>,
        display_associations: Vec<String>,
        known_sinks: Vec<String>,
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
            value_consumers,
            relevant_data_references,
            display_associations,
            known_sinks,
            existing_hypotheses: graph.hypotheses().filter(|h| h.subject == subject).cloned().collect(),
        }
    }
}

/// What an `AgentProvider` returns for one `ProposeFieldSemanticRoleTask`
/// -- structured to force tracing, not just conclude. `semantic_role`
/// and `decisive_sink` are both `None`-able: the honest outcome when the
/// evidence doesn't actually support a specific claim is proposing
/// nothing, the same "leave it unproposed rather than guess" discipline
/// every other predicate in this codebase already follows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SemanticRoleResult {
    pub tracked_value: String,
    pub propagation_chain: Vec<String>,
    pub decisive_sink: Option<String>,
    pub semantic_role: Option<String>,
    pub evidence: Vec<String>,
    pub competing_interpretations: Vec<String>,
    /// The model's own self-reported confidence -- kept on the wire type
    /// for transparency and debugging, but `debura_confidence_for_role`
    /// below is what actually gets committed; this number, alone, is
    /// never trusted (the real, confirmed reason: `m_drawableCount` self-
    /// reported 0.95 with no relationship to evidence quality at all).
    pub confidence: f64,
}

/// Whether `result`'s own `decisive_sink` actually corresponds to a real
/// piece of evidence this exact task was given -- `known_sinks` is the
/// same list the task itself carried, so a proposal can never cite
/// something that wasn't actually shown to it. First tries whole-string
/// substring match in either direction; a real run showed that's too
/// strict on its own (a model paraphrasing a display-association sentence
/// -- same fact, different words -- failed it outright), so this falls
/// back to requiring the citation to name one of the same load-bearing
/// identifiers (a real symbol/function name, e.g. `DAT_14000e0c0` or
/// `FUN_140001cb0`) that the known sink itself names. That still can't be
/// satisfied by an invented sink -- the identifier has to be one Debura
/// actually put in front of the model -- but no longer requires
/// reproducing the exact sentence around it.
pub fn verify_decisive_sink(result: &SemanticRoleResult, known_sinks: &[String]) -> bool {
    let Some(sink) = result.decisive_sink.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    if known_sinks.iter().any(|known| known.contains(sink) || sink.contains(known.as_str())) {
        return true;
    }
    let sink_tokens: std::collections::HashSet<&str> = significant_tokens(sink).collect();
    known_sinks
        .iter()
        .any(|known| significant_tokens(known).any(|token| sink_tokens.contains(token)))
}

/// Identifier-shaped tokens (containing a digit or underscore, so
/// `DAT_14000e0c0`/`FUN_140001cb0`/`param_4`/`local_b8` all qualify but
/// ordinary English words in the surrounding sentence never do) -- the
/// only tokens specific enough to actually anchor a citation to one real
/// piece of evidence rather than any generic phrasing.
fn significant_tokens(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|t| t.len() >= 4 && (t.contains('_') || t.chars().any(|c| c.is_ascii_digit())))
}

/// PROJECT.md, "Two-stage semantic reasoning": Debura's own confidence
/// for a proposed `field_semantic_role` -- never `result.confidence`
/// (the model's own self-report) directly. `None` means: propose
/// nothing at all, not even at low confidence -- the "reject before
/// naming" gate, hit whenever no role was proposed, or a role was
/// proposed with no `decisive_sink` that `verify_decisive_sink` can
/// confirm against real evidence (exactly the `m_drawableCount` failure
/// mode: a confident-sounding claim with nothing underneath it).
/// `Some(confidence)` is a small, fixed, deliberately simple two-tier
/// value -- a real, defensible starting point, not a tuned weighted
/// formula -- rewarding a real, verified sink citation and a
/// non-trivial propagation trace, never the model's own number.
pub fn debura_confidence_for_role(result: &SemanticRoleResult, known_sinks: &[String]) -> Option<f64> {
    let role = result.semantic_role.as_deref().map(str::trim).filter(|s| !s.is_empty())?;
    let _ = role;
    if !verify_decisive_sink(result, known_sinks) {
        return None;
    }
    let trace_bonus = if result.propagation_chain.len() >= 2 { 0.1 } else { 0.0 };
    Some((0.8_f64 + trace_bonus).min(0.95))
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
            Vec::new(),
            Vec::new(),
            "remaining_lives",
        );

        assert_eq!(task.existing_hypotheses.len(), 1);
        assert_eq!(task.existing_hypotheses[0].value, "m_lives");
    }

    fn known_sinks() -> Vec<String> {
        vec![
            "tracked value, as \"param_4 + -1\", is displayed immediately adjacent to DAT_14000e0c0 (\"Lives: \") in FUN_14000205a".to_string(),
            "FUN_140001cb0".to_string(),
            "FUN_14000213e".to_string(),
        ]
    }

    /// The real, confirmed regression case: a role citing the exact real
    /// display-association evidence must verify and get a real,
    /// deterministic confidence -- never the model's own self-report.
    #[test]
    fn a_role_citing_the_real_display_association_verifies_and_gets_a_real_confidence() {
        let result = SemanticRoleResult {
            tracked_value: "param_4".to_string(),
            propagation_chain: vec![
                "field +0x4".to_string(),
                "passed to FUN_140001cb0 parameter 2".to_string(),
                "passed to FUN_14000205a parameter 3".to_string(),
            ],
            decisive_sink: Some(
                "tracked value, as \"param_4 + -1\", is displayed immediately adjacent to DAT_14000e0c0 (\"Lives: \") in FUN_14000205a"
                    .to_string(),
            ),
            semantic_role: Some("remaining_lives".to_string()),
            evidence: vec!["displayed next to Lives: label".to_string()],
            competing_interpretations: vec!["drawable_count -- rejected, does not explain the Lives: label".to_string()],
            confidence: 0.42, // deliberately different from what Debura should compute -- must never be used directly
        };

        assert!(verify_decisive_sink(&result, &known_sinks()));
        let confidence = debura_confidence_for_role(&result, &known_sinks());
        assert!(confidence.is_some());
        assert!((confidence.unwrap() - 0.42).abs() > 0.01, "must not reuse the model's own self-reported confidence");
    }

    /// A real `debura semantic --provider openai` run against Snake hit
    /// this exact case: the model cited `"param_4 + -1 immediately
    /// adjacent to DAT_14000e0c0 (\"Lives: \")"` -- the same real fact as
    /// `known_sinks()`'s display-association line, just reworded --
    /// which the old whole-string-only match rejected outright, silently
    /// blocking the role from ever being proposed. The shared identifier
    /// (`DAT_14000e0c0`) must still ground it.
    #[test]
    fn a_paraphrased_citation_of_the_real_display_association_still_verifies() {
        let result = SemanticRoleResult {
            tracked_value: "param_4".to_string(),
            propagation_chain: vec!["field +0x4".to_string(), "used as param_4 + -1".to_string()],
            decisive_sink: Some("param_4 + -1 immediately adjacent to DAT_14000e0c0 (\"Lives: \")".to_string()),
            semantic_role: Some("remaining_lives".to_string()),
            evidence: Vec::new(),
            competing_interpretations: Vec::new(),
            confidence: 0.95,
        };

        assert!(verify_decisive_sink(&result, &known_sinks()));
        assert!(debura_confidence_for_role(&result, &known_sinks()).is_some());
    }

    /// The fallback must still require a real, shared identifier -- a
    /// citation that shares no load-bearing token with anything in
    /// `known_sinks` (the `drawable_count`-shaped failure mode, reworded
    /// to also dodge whole-string matching) must still be rejected.
    #[test]
    fn a_paraphrase_sharing_no_real_identifier_is_still_rejected() {
        let result = SemanticRoleResult {
            tracked_value: "param_4".to_string(),
            propagation_chain: vec!["field +0x4".to_string()],
            decisive_sink: Some("used to track how many drawable objects currently exist on screen".to_string()),
            semantic_role: Some("drawable_count".to_string()),
            evidence: Vec::new(),
            competing_interpretations: Vec::new(),
            confidence: 0.95,
        };

        assert!(!verify_decisive_sink(&result, &known_sinks()));
        assert_eq!(debura_confidence_for_role(&result, &known_sinks()), None);
    }

    /// The real, confirmed failure mode this whole mechanism exists to
    /// catch: a confident-sounding role (`drawable_count`, self-reported
    /// 0.95 -- exactly what a real run without this gate produced) that
    /// cites no real sink from the evidence it was actually given. Must
    /// never be committed, regardless of its own stated confidence.
    #[test]
    fn a_drawable_count_shaped_proposal_with_no_matching_sink_is_never_committed() {
        let result = SemanticRoleResult {
            tracked_value: "param_4".to_string(),
            propagation_chain: vec!["field +0x4".to_string()],
            decisive_sink: Some("the field is used to track how many drawable objects exist".to_string()),
            semantic_role: Some("drawable_count".to_string()),
            evidence: Vec::new(),
            competing_interpretations: Vec::new(),
            confidence: 0.95,
        };

        assert!(!verify_decisive_sink(&result, &known_sinks()));
        assert_eq!(debura_confidence_for_role(&result, &known_sinks()), None);
    }

    /// No `decisive_sink` cited at all (the honest "I did no real
    /// tracing" outcome, e.g. `EchoProvider`'s own response) must also
    /// never be committed, even when a role is proposed.
    #[test]
    fn a_role_with_no_decisive_sink_at_all_is_never_committed() {
        let result = SemanticRoleResult {
            tracked_value: "param_4".to_string(),
            propagation_chain: Vec::new(),
            decisive_sink: None,
            semantic_role: Some("field_0x4".to_string()),
            evidence: Vec::new(),
            competing_interpretations: Vec::new(),
            confidence: 0.3,
        };

        assert_eq!(debura_confidence_for_role(&result, &known_sinks()), None);
    }

    /// No `semantic_role` proposed at all (the honest "the evidence
    /// doesn't support a specific claim" outcome) must never be
    /// committed either, even if a sink happens to be cited.
    #[test]
    fn no_semantic_role_proposed_is_never_committed() {
        let result = SemanticRoleResult {
            tracked_value: "param_4".to_string(),
            propagation_chain: Vec::new(),
            decisive_sink: Some("FUN_14000205a".to_string()),
            semantic_role: None,
            evidence: Vec::new(),
            competing_interpretations: Vec::new(),
            confidence: 0.9,
        };

        assert_eq!(debura_confidence_for_role(&result, &known_sinks()), None);
    }
}
