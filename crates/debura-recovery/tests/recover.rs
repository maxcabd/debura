use chrono::Utc;
use debura_knowledge::{HypothesisStatus, KnowledgeGraph};
use debura_recovery::{
    extract, render_function_declarations, render_ghidra_compat_header, render_ghidra_symbols_header,
    render_header, render_source, NameSource, GHIDRA_COMPAT_HEADER_NAME,
};

/// PROJECT.md M17: `extract()` now excludes anything whose provenance
/// isn't Application (the fix for library/CRT internals leaking
/// application-sounding names into recovered output) -- so a standalone
/// function fixture with no other context needs a real Application
/// anchor to stay recovered, the same way it would in a real graph via a
/// call to (or ownership by) actual game code. Adds a `calls` edge to a
/// synthetic, minimally-described method of a real (non-reserved) class
/// rather than making `subject` itself `is_method_of` anything, since
/// that would route it into class-method recovery instead of the
/// standalone-function path these tests are actually exercising.
fn anchor_as_application(graph: &mut KnowledgeGraph, subject: &str, anchor: &str) {
    graph.add_observation(subject, "calls", anchor, 0.95, "ghidra:call_graph", None);
    graph.add_observation(anchor, "has_name", "anchorMethod", 0.95, "ghidra:function", None);
    graph.add_observation(anchor, "is_method_of", "Wall", 0.95, "ghidra:function", None);
}

/// Builds a graph shaped like real debura-analysis output for the
/// Entity/Player fixture (crates/debura-testbins/fixtures/entity_player.cpp),
/// plus one ACCEPTED semantic_role hypothesis -- the shape a real M4/M5 run
/// would leave behind.
fn entity_player_graph() -> KnowledgeGraph {
    let mut g = KnowledgeGraph::new();

    // Entity
    g.add_observation("Entity", "has_vtable_at", "0x980", 1.0, "ghidra:vtable", None);
    g.add_observation("Entity", "has_field_candidate", "0x8:float", 0.85, "ghidra:decompiler_heuristic", None);
    g.add_observation("0x1", "has_name", "describe", 0.95, "ghidra:function", None);
    g.add_observation("0x1", "has_signature", "void describe(Entity * this)", 0.95, "ghidra:function", None);
    g.add_observation(
        "0x1",
        "decompiles_to",
        "void __thiscall Entity::describe(Entity *this)\n\n{\n  printf(\"...\");\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    g.add_observation("0x1", "is_method_of", "Entity", 0.95, "ghidra:function", None);

    g.add_observation("0x2", "has_name", "~Entity", 0.95, "ghidra:function", None);
    g.add_observation("0x2", "has_signature", "undefined ~Entity(Entity * this)", 0.95, "ghidra:function", None);
    g.add_observation("0x2", "decompiles_to", "void __thiscall Entity::~Entity(Entity *this)\n\n{\n  return;\n}", 0.95, "ghidra:decompiler", None);
    g.add_observation("0x2", "is_destructor_of", "Entity", 0.95, "ghidra:function", None);

    // Player : Entity, with a deliberately conflicting field candidate
    // (the real int/uint disagreement M7 actually surfaced).
    g.add_observation("Player", "has_vtable_at", "0x9b0", 1.0, "ghidra:vtable", None);
    g.add_observation("Player", "inherits_from", "Entity", 1.0, "ghidra:rtti", None);
    g.add_observation("Player", "has_field_candidate", "0x8:float", 0.85, "ghidra:decompiler_heuristic", None);
    g.add_observation("Player", "has_field_candidate", "0xc:int", 0.85, "ghidra:decompiler_heuristic", None);
    g.add_observation("Player", "has_field_candidate", "0xc:uint", 0.85, "ghidra:decompiler_heuristic", None);

    g.add_observation("0x3", "has_name", "takeDamage", 0.95, "ghidra:function", None);
    g.add_observation("0x3", "has_signature", "undefined takeDamage(Player * this, float param_1)", 0.95, "ghidra:function", None);
    g.add_observation(
        "0x3",
        "decompiles_to",
        "void __thiscall Player::takeDamage(Player *this,float param_1)\n\n{\n  *(float *)(this + 8) = *(float *)(this + 8) - param_1;\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    g.add_observation("0x3", "is_method_of", "Player", 0.95, "ghidra:function", None);

    let h = g.propose_hypothesis("0x3", "semantic_role", "ApplyDamage", 0.95, None);
    g.mark_verified(h, Utc::now()).unwrap();
    g.set_status(h, HypothesisStatus::Accepted).unwrap();

    g
}

#[test]
fn extracts_class_hierarchy_fields_and_methods() {
    let graph = entity_player_graph();
    let program = extract(&graph);

    assert_eq!(program.classes.len(), 2);
    let player = program.classes.iter().find(|c| c.name == "Player").unwrap();
    let entity = program.classes.iter().find(|c| c.name == "Entity").unwrap();

    assert_eq!(player.base.as_deref(), Some("Entity"));
    assert_eq!(entity.base, None);

    assert_eq!(player.vtable_address, "0x9b0");

    // Inherited field visible via Player's own accesses, at the same offset.
    let field_8 = player.fields.iter().find(|f| f.offset == "0x8").unwrap();
    assert_eq!(field_8.candidate_types, vec!["float".to_string()]);

    // The real int/uint disagreement: both candidates preserved, not
    // silently collapsed to one.
    let field_c = player.fields.iter().find(|f| f.offset == "0xc").unwrap();
    assert_eq!(field_c.candidate_types.len(), 2);
    assert!(field_c.candidate_types.contains(&"int".to_string()));
    assert!(field_c.candidate_types.contains(&"uint".to_string()));

    assert_eq!(player.methods.len(), 1);
    let take_damage = &player.methods[0];
    assert_eq!(take_damage.raw_name, "takeDamage");
    assert_eq!(take_damage.display_name, "ApplyDamage");
    assert!(matches!(take_damage.name_source, NameSource::Accepted { .. }));
    assert_eq!(take_damage.params, "float param_1");

    assert_eq!(entity.methods.len(), 2);
    let describe = entity.methods.iter().find(|m| m.raw_name == "describe").unwrap();
    assert_eq!(describe.display_name, "describe");
    assert!(matches!(describe.name_source, NameSource::Raw));
    let dtor = entity.methods.iter().find(|m| m.is_destructor).unwrap();
    assert_eq!(dtor.raw_name, "~Entity");
}

#[test]
fn header_shows_provenance_and_conflicting_field_candidates() {
    let graph = entity_player_graph();
    let program = extract(&graph);
    let player = program.classes.iter().find(|c| c.name == "Player").unwrap();

    let header = render_header(player);

    assert!(header.contains("class Player : public Entity"));
    assert!(header.contains("ACCEPTED"));
    // "undefined" is Ghidra's own honest placeholder before real type
    // recovery -- the renderer passes it through rather than hiding it.
    assert!(header.contains("undefined ApplyDamage(float param_1);"));
    assert!(header.contains("other candidates seen"));
}

#[test]
fn source_substitutes_recovered_name_but_keeps_raw_pointer_body() {
    let graph = entity_player_graph();
    let program = extract(&graph);
    let player = program.classes.iter().find(|c| c.name == "Player").unwrap();

    let source = render_source(player);

    assert!(source.contains("Player::ApplyDamage(float param_1)"));
    // Honest about the limitation: field accesses are not yet named.
    assert!(source.contains("this + 8"));
}

/// Itanium ABI emits multiple destructor variants (D0, D1, ...) at
/// different addresses -- a real thing this project's own test binary
/// does. A class can only declare one destructor.
#[test]
fn multiple_destructor_variants_collapse_to_one_declaration() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("Entity", "has_vtable_at", "0x1", 1.0, "ghidra:vtable", None);

    for addr in ["0x10", "0x11", "0x12"] {
        graph.add_observation(addr, "has_name", "~Entity", 0.95, "ghidra:function", None);
        graph.add_observation(addr, "has_signature", "undefined ~Entity(Entity * this)", 0.95, "ghidra:function", None);
        // debura-analysis emits both of these for every ctor/dtor, not
        // just is_destructor_of -- a real duplicate-declaration bug only
        // showed up once this test matched that shape.
        graph.add_observation(addr, "is_method_of", "Entity", 0.95, "ghidra:function", None);
        graph.add_observation(addr, "is_destructor_of", "Entity", 0.95, "ghidra:function", None);
    }

    let program = extract(&graph);
    let entity = &program.classes[0];
    assert_eq!(entity.methods.len(), 1, "only one destructor should be declared");
    assert_eq!(entity.methods[0].address, "0x10", "lowest address chosen deterministically");
}

/// A real run had a model propose a `semantic_role` for a constructor's
/// own address (nothing stops it from doing so) that didn't match the
/// class name -- rendering that value as the constructor's name produced
/// a declaration C++ doesn't recognize as a constructor at all (GCC
/// parses `initializeFood();` inside `class Food` as an ordinary method
/// with an implicit `int` return type, not `Food::Food()`). A
/// constructor's name is fixed by the language; renames must not apply.
#[test]
fn a_renamed_constructor_still_renders_with_the_class_name() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("Food", "has_vtable_at", "0x9c0", 1.0, "ghidra:vtable", None);

    graph.add_observation("0x1", "has_name", "Food", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "void Food(Food * this)", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "void __thiscall Food::Food(Food *this)\n\n{\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    graph.add_observation("0x1", "is_constructor_of", "Food", 0.95, "ghidra:function", None);

    let h = graph.propose_hypothesis("0x1", "semantic_role", "initializeFood", 0.9, None);
    graph.mark_verified(h, Utc::now()).unwrap();
    graph.set_status(h, HypothesisStatus::Accepted).unwrap();

    let program = extract(&graph);
    let food = program.classes.iter().find(|c| c.name == "Food").unwrap();

    let header = render_header(food);
    let source = render_source(food);

    assert!(header.contains("Food(void);") || header.contains("Food();"), "header:\n{header}");
    assert!(!header.contains("initializeFood"), "header:\n{header}");
    assert!(source.contains("Food::Food("), "source:\n{source}");
    assert!(!source.contains("initializeFood"), "source:\n{source}");
}

/// PROJECT.md M17 (compile-viability pass): a real compile hit this
/// exactly -- `has_signature` claimed `(void)` for a method whose
/// `decompiles_to` body (and that body's own header line) plainly uses
/// two parameters, so the rendered signature declared zero params while
/// the body referenced `param_1`/`param_2` as if they existed --
/// undeclared identifiers, a hard compile error. `decompiles_to`'s own
/// header is always self-consistent with the body that follows it, so it
/// must win over a stale `has_signature`.
#[test]
fn a_stale_void_signature_does_not_override_the_decompiled_bodys_own_params() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("Section", "has_vtable_at", "0x9d0", 1.0, "ghidra:vtable", None);
    graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "undefined FUN_1(void)", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "void FUN_1(longlong param_1,longlong param_2)\n\n{\n  FUN_2(param_2,param_1);\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    graph.add_observation("0x1", "is_method_of", "Section", 0.95, "ghidra:function", None);
    let h = graph.propose_hypothesis("0x1", "semantic_role", "populateGrid", 0.9, None);
    graph.mark_verified(h, Utc::now()).unwrap();
    graph.set_status(h, HypothesisStatus::Accepted).unwrap();

    let program = extract(&graph);
    let section = program.classes.iter().find(|c| c.name == "Section").unwrap();
    let method = &section.methods[0];

    // The receiver (param_1) is always excluded from the declared
    // params -- a call site's own leading argument always supplies it --
    // and re-bound inside the body instead (PROJECT.md M18), so the
    // body's own `FUN_2(param_2,param_1)` still resolves correctly.
    assert_eq!(method.params, "longlong param_2");
    // The alias is spliced in at render time, not stored back onto
    // `decompilation` itself (PROJECT.md M18: it has to run after
    // `render.rs`'s own `this`-local rename, not before).
    let source = render_source(section);
    assert!(
        source.replace(' ', "").contains("longlongparam_1=(longlong)this;"),
        "source:\n{source}"
    );
    assert!(source.contains("FUN_2(param_2,param_1)"), "source:\n{source}");
}

/// PROJECT.md M18: the real end-to-end regression this was built for --
/// a real link had `Food`'s constructor calling `Collideable`'s own
/// constructor (a real structurally-discovered address, never recognized
/// by Ghidra's own type system as a method at all, so its receiver shows
/// up as an ordinary `param_1` used for real field writes, not as
/// `this`) NOT through the leading-base-constructor-call special case
/// (no `inherits_from` edge existed for this pair in the real graph),
/// but through `rewrite_call_sites`'s general path. An earlier version
/// of the params fix either left the receiver in the declaration
/// (breaking the call site's arity against `symtab.rs`'s always-add-1
/// convention) or dropped it outright (breaking the body, which uses it
/// directly). This is the exact shape that must both compile *and* link.
#[test]
fn a_structurally_discovered_constructor_call_resolves_through_the_general_path() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("Collideable", "has_vtable_at", "0x980", 1.0, "ghidra:vtable", None);
    graph.add_observation("Food", "has_vtable_at", "0x9c0", 1.0, "ghidra:vtable", None);
    // Deliberately no `inherits_from` -- models the real graph shape
    // where this call site was never caught by the leading-base-
    // constructor-call special case, only the general one.

    graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "undefined FUN_1(undefined8 *param_1, undefined4 param_2, undefined4 param_3)", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "void FUN_1(undefined8 *param_1,undefined4 param_2,undefined4 param_3)\n\n{\n  \
         *param_1 = &DAT_140009a60;\n  \
         *(undefined4 *)(param_1 + 1) = param_2;\n  \
         return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    graph.add_observation("0x1", "is_constructor_of", "Collideable", 0.95, "ghidra:function", None);

    graph.add_observation("0x2", "has_name", "Food", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "has_signature", "undefined FUN_2(undefined8 *param_1)", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x2",
        "decompiles_to",
        "void FUN_2(undefined8 *param_1)\n\n{\n  FUN_1(param_1,0,0);\n  *param_1 = &PTR_draw_140009a00;\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    graph.add_observation("0x2", "is_constructor_of", "Food", 0.95, "ghidra:function", None);

    let program = extract(&graph);
    let food = program.classes.iter().find(|c| c.name == "Food").unwrap();
    let source = render_source(food);

    assert!(
        source.contains("new ((void *)(param_1)) Collideable(0,0)"),
        "the base's constructor call must resolve through the general path: {source}"
    );
    assert!(!source.contains("FUN_1("), "no raw unresolved call should remain: {source}");

    let collideable = program.classes.iter().find(|c| c.name == "Collideable").unwrap();
    let ctor = &collideable.methods[0];
    assert_eq!(ctor.params, "undefined4 param_2, undefined4 param_3");
    // The alias is spliced in at render time (see the Section test above),
    // not stored back onto `decompilation` itself.
    let collideable_source = render_source(collideable);
    let body = collideable_source.replace(' ', "");
    assert!(
        body.contains("undefined8*param_1=(undefined8*)this;"),
        "the receiver must be re-bound to the real `this` inside the body: {}",
        collideable_source
    );
}

/// PROJECT.md M17 (compile-viability pass): a real case had Ghidra's own
/// `/* WARNING: ... (addr, addr) */` decompiler notes sitting before the
/// real signature line -- a naive search for the first `(` grabbed the
/// warning's own parenthesized address pair instead of the function's
/// real parameter list, corrupting both the params and the rendered
/// signature line.
#[test]
fn a_leading_ghidra_warning_comment_does_not_corrupt_the_parsed_params() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "undefined FUN_1(void)", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "/* WARNING: Removing unreachable block (ram, 0x0001400017b4) */\n\nvoid FUN_1(undefined8 *param_1)\n\n{\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    anchor_as_application(&mut graph, "0x1", "0xa1");
    let h = graph.propose_hypothesis("0x1", "semantic_role", "spawnFood", 0.9, None);
    graph.mark_verified(h, Utc::now()).unwrap();
    graph.set_status(h, HypothesisStatus::Accepted).unwrap();

    let program = extract(&graph);
    let function = program.functions.iter().find(|f| f.address == "0x1").unwrap();

    assert_eq!(function.params, "undefined8 *param_1");
}

/// PROJECT.md M17 (compile-viability pass): a real compile hit this --
/// a subject with two `decompiles_to` observations, an earlier one
/// carrying the real, full body and a later one (a second Ghidra pass)
/// carrying a degenerate `{...}` placeholder. Picking "highest id" blindly
/// rendered a body that was literally the three characters `...`, which
/// doesn't compile at all.
#[test]
fn a_later_degenerate_decompilation_does_not_override_an_earlier_real_one() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "void FUN_1(void **param_1)", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "void FUN_1(void **param_1)\n\n{\n  FUN_2(param_1);\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    // A later re-analysis pass emitted a degenerate placeholder instead.
    graph.add_observation("0x1", "decompiles_to", "void FUN_1(void **param_1) {...}", 0.95, "ghidra:decompiler", None);
    anchor_as_application(&mut graph, "0x1", "0xa1");
    let h = graph.propose_hypothesis("0x1", "semantic_role", "createWalls", 0.9, None);
    graph.mark_verified(h, Utc::now()).unwrap();
    graph.set_status(h, HypothesisStatus::Accepted).unwrap();

    let program = extract(&graph);
    let function = program.functions.iter().find(|f| f.address == "0x1").unwrap();

    assert!(function.decompilation.contains("FUN_2(param_1);"), "{}", function.decompilation);
}

#[test]
fn functions_without_an_accepted_hypothesis_are_not_recovered() {
    // No `decompiles_to` at all -- not a real, structurally-complete
    // function Debura has grounds to recover under any name, accepted or
    // otherwise (PROJECT.md M18's FUN_<addr> fallback still requires a
    // real body -- see `an_application_function_with_no_accepted_name_is_still_recovered_under_its_raw_name`
    // for the case that *does* now recover without one).
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x99", "has_name", "FUN_99", 0.95, "ghidra:function", None);
    graph.propose_hypothesis("0x99", "semantic_role", "Guessed", 0.5, None); // PROPOSED, not ACCEPTED

    let program = extract(&graph);
    assert!(program.functions.is_empty());
    assert!(program.classes.is_empty());
}

/// PROJECT.md M18: a real linker frontier found 3 of 9 Application-
/// provenance, structurally-complete functions never earned an accepted
/// `semantic_role` after real, repeated challenge attempts -- a genuine
/// semantic-recovery gap, not a reason to leave them out of `recovered/`
/// entirely and block the link on a pretty name nothing was ever going to
/// confidently assign. Naming decides what a function is *called*, not
/// *whether* it's recovered.
#[test]
fn an_application_function_with_no_accepted_name_is_still_recovered_under_its_raw_name() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x99", "has_name", "FUN_99", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x99",
        "decompiles_to",
        "void FUN_99(void)\n\n{\n  anchorMethod();\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    // Every semantic_role attempt genuinely failed -- REJECTED, not just
    // absent -- which is exactly the real case this closes.
    let h = graph.propose_hypothesis("0x99", "semantic_role", "doSomething", 0.5, None);
    let _ = graph.set_status(h, HypothesisStatus::Rejected);
    anchor_as_application(&mut graph, "0x99", "0x100");

    let program = extract(&graph);

    let f = program.functions.iter().find(|f| f.address == "0x99").expect("recovered under its raw name");
    assert_eq!(f.display_name, "FUN_99");
    assert!(matches!(f.name_source, NameSource::Raw));
}

/// PROJECT.md M18's `RecoveryDisposition` finding: a real 31-symbol
/// linker frontier resolved to 0 Application, 28 `RequiredUnknown`, 3
/// library/runtime -- every one of the 28 was reachable from the real
/// entrypoint with a genuine recoverable body, just with no provenance
/// signal M17 has grounds to call Application. Recovery necessity and
/// semantic ownership are different questions; this proves `extract()`
/// answers the first one independently of the second, for a subject
/// that's reachable from the graph's own `exports`/`"entry"` fact.
#[test]
fn a_reachable_unknown_provenance_function_with_a_real_body_is_recovered_as_required_unknown() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "exports", "entry", 0.95, "ghidra:exports", None);
    graph.add_observation("0x1", "calls", "0x99", 0.95, "ghidra:call_graph", None);
    graph.add_observation("0x99", "has_name", "FUN_99", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x99",
        "decompiles_to",
        "void FUN_99(longlong param_1)\n\n{\n  *(int *)(param_1 + 4) = 0;\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    // No is_method_of, no imports, no own-state+thunk signal, no accepted
    // (or even proposed) semantic_role at all -- genuinely Unknown, not
    // merely un-named.
    assert_eq!(debura_knowledge::classify_provenance(&graph, "0x99"), debura_knowledge::Provenance::Unknown);

    let program = extract(&graph);

    let f = program.functions.iter().find(|f| f.address == "0x99").expect("recovered despite Unknown provenance");
    assert_eq!(f.display_name, "FUN_99");
    assert!(matches!(f.name_source, NameSource::Raw));
}

/// The reachability requirement is real, not decorative: an Unknown-
/// provenance subject with a genuine body still isn't recovered if
/// nothing on record ever calls it from the real entrypoint.
#[test]
fn an_unreachable_unknown_provenance_function_is_not_recovered() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "exports", "entry", 0.95, "ghidra:exports", None);
    // "0x99" is never wired into 0x1's own call graph at all.
    graph.add_observation("0x99", "has_name", "FUN_99", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x99",
        "decompiles_to",
        "void FUN_99(longlong param_1)\n\n{\n  *(int *)(param_1 + 4) = 0;\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );

    let program = extract(&graph);

    assert!(program.functions.iter().all(|f| f.address != "0x99"));
}

/// Confirms the pre-existing behavior with no `exports`/`"entry"` fact at
/// all (every fixture in this file before this one) is unaffected: an
/// Unknown-provenance subject is never recovered when reachability can't
/// even be computed.
#[test]
fn unknown_provenance_is_never_recovered_when_the_graph_has_no_entry_fact() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x99", "has_name", "FUN_99", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x99",
        "decompiles_to",
        "void FUN_99(longlong param_1)\n\n{\n  *(int *)(param_1 + 4) = 0;\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );

    let program = extract(&graph);

    assert!(program.functions.iter().all(|f| f.address != "0x99"));
}

/// A real run had `_Guard`, `_Vector_impl`, and `__class_type_info` --
/// real classes Ghidra's own demangler recognized, but libstdc++
/// internals, not application code -- getting the exact same recovery
/// treatment as `Wall`/`Food`/`Snake`, rendered into their own .hpp/.cpp
/// files that then failed to compile (they call MinGW runtime internals
/// like HeapAlloc/EnterCriticalSection that a normal g++ build already
/// supplies). PROJECT.md M15's reserved-identifier convention keeps them
/// out of recovered output entirely.
#[test]
fn libstdcxx_internal_classes_are_not_recovered() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_vtable_at", "0x100", 1.0, "ghidra:vtable", None);
    graph.add_observation("0x2", "is_method_of", "_Vector_impl", 0.95, "ghidra:function", None);
    graph.add_observation("0x3", "is_constructor_of", "_Guard", 0.95, "ghidra:function", None);
    // A real application class, for contrast -- must still be recovered.
    graph.add_observation("0x4", "is_method_of", "Wall", 0.95, "ghidra:function", None);

    let program = extract(&graph);
    let class_names: Vec<&str> = program.classes.iter().map(|c| c.name.as_str()).collect();
    assert!(!class_names.contains(&"_Vector_impl"));
    assert!(!class_names.contains(&"_Guard"));
    assert!(class_names.contains(&"Wall"));
}

/// Same reasoning, for a standalone function: a real run recovered
/// `__p___argc`/`_cexit`-shaped CRT startup internals as if they were
/// missing application code.
#[test]
fn libstdcxx_and_crt_standalone_functions_are_not_recovered() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x99", "has_name", "__p___argc", 0.95, "ghidra:function", None);
    let h = graph.propose_hypothesis("0x99", "semantic_role", "getArgCount", 0.95, None);
    graph.mark_verified(h, Utc::now()).unwrap();
    graph.set_status(h, HypothesisStatus::Accepted).unwrap();

    let program = extract(&graph);
    assert!(program.functions.is_empty());
}

/// PROJECT.md M15: the harder case name-shape alone can't catch. A real
/// run's `constructString` earned an ACCEPTED semantic_role and looked
/// like application code by name -- but its entire body was calls into
/// std::string's own private implementation (`_M_create`, `_M_data`,
/// `_M_capacity`, `_M_set_length`), an inlined instantiation of the
/// standard library's own logic, not anything the binary's author
/// wrote. Recovering it produced qualified-id calls into libstdc++
/// internals with no object, none of which a real g++ build accepts.
#[test]
fn functions_dominated_by_library_callees_are_not_recovered_despite_an_application_looking_name() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "constructString", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "void constructString(void)", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "decompiles_to", "void constructString(void)\n\n{\n  return;\n}", 0.95, "ghidra:decompiler", None);
    for callee in ["0x2", "0x3", "0x4", "0x5"] {
        graph.add_observation("0x1", "calls", callee, 0.95, "ghidra:call_graph", None);
    }
    for (addr, name) in [
        ("0x2", "_M_create"),
        ("0x3", "_M_data"),
        ("0x4", "_M_capacity"),
        ("0x5", "_M_set_length"),
    ] {
        graph.add_observation(addr, "has_name", name, 0.95, "ghidra:function", None);
    }
    let h = graph.propose_hypothesis("0x1", "semantic_role", "constructString", 0.95, None);
    graph.mark_verified(h, Utc::now()).unwrap();
    graph.set_status(h, HypothesisStatus::Accepted).unwrap();

    let program = extract(&graph);
    assert!(program.functions.is_empty(), "{:?}", program.functions);
}

/// PROJECT.md M18's `RequiredRuntimeBody` disposition must not undo
/// this exact protection when the graph *does* have a real entry fact
/// (the previous test's fixture has none, so it can't actually exercise
/// the new sweep at all) -- a trivial, real (non-degenerate)
/// STL-glue-shaped body is exactly the kind of "has a body" case that
/// must stay excluded regardless of reachability.
#[test]
fn library_dominated_glue_is_still_excluded_even_when_reachable_from_a_real_entry() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0xentry", "exports", "entry", 0.95, "ghidra:exports", None);
    graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
    graph.add_observation("0x1", "has_name", "constructString", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "void constructString(void)", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "decompiles_to", "void constructString(void)\n\n{\n  return;\n}", 0.95, "ghidra:decompiler", None);
    for callee in ["0x2", "0x3", "0x4", "0x5"] {
        graph.add_observation("0x1", "calls", callee, 0.95, "ghidra:call_graph", None);
    }
    for (addr, name) in [
        ("0x2", "_M_create"),
        ("0x3", "_M_data"),
        ("0x4", "_M_capacity"),
        ("0x5", "_M_set_length"),
    ] {
        graph.add_observation(addr, "has_name", name, 0.95, "ghidra:function", None);
    }

    let program = extract(&graph);
    assert!(program.functions.is_empty(), "{:?}", program.functions);
}

/// The positive side of the same finding: `extract_with_required_runtime_bodies`
/// still recovers an explicitly-named `LibraryOrRuntime` address with a
/// real body -- the 9 real cases (an SDL event-poll loop, a
/// VirtualProtect table walk, ...) a real linker log's
/// `RecoveryDisposition::RequiredRuntimeBody` entries name explicitly.
#[test]
fn an_explicitly_required_runtime_body_is_recovered_under_its_raw_name() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0xentry", "exports", "entry", 0.95, "ghidra:exports", None);
    graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
    graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "undefined4 FUN_1(void)\n\n{\n  int local_48 [5];\n  while (SDL_PollEvent(local_48) != 0) {}\n  return 0;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);
    graph.add_observation("0x2", "imports", "SDL2.DLL!SDL_PollEvent", 1.0, "ghidra:imports", None);

    let mut required = std::collections::BTreeSet::new();
    required.insert("0x1".to_string());

    let program = debura_recovery::extract_with_required_runtime_bodies(&graph, &required, None);

    let f = program.functions.iter().find(|f| f.address == "0x1").expect("explicitly required runtime body recovered");
    assert_eq!(f.display_name, "FUN_1");
    assert!(matches!(f.name_source, NameSource::Raw));
}

/// A real run had two unrelated addresses independently earn the exact
/// same generic name (`invokeFunction`) from a conservative
/// mechanical-behavior-style guess -- both landing in `functions.cpp`'s
/// single shared scope, which C++ doesn't allow (a real "redefinition"
/// compile error). PROJECT.md M15's disambiguation should catch the
/// collision and rename both, appending each one's own address.
#[test]
fn colliding_function_names_are_disambiguated_by_address() {
    let mut graph = KnowledgeGraph::new();
    for (addr, raw, anchor) in [("0x10", "FUN_10", "0xa10"), ("0x20", "FUN_20", "0xa20")] {
        graph.add_observation(addr, "has_name", raw, 0.95, "ghidra:function", None);
        graph.add_observation(addr, "has_signature", format!("void {raw}(void)"), 0.95, "ghidra:function", None);
        graph.add_observation(addr, "decompiles_to", format!("void {raw}(void)\n\n{{\n  return;\n}}"), 0.95, "ghidra:decompiler", None);
        anchor_as_application(&mut graph, addr, anchor);
        let h = graph.propose_hypothesis(addr, "semantic_role", "invokeFunction", 0.95, None);
        graph.mark_verified(h, Utc::now()).unwrap();
        graph.set_status(h, HypothesisStatus::Accepted).unwrap();
    }

    let program = extract(&graph);
    let names: Vec<&str> = program.functions.iter().map(|f| f.display_name.as_str()).collect();
    assert_eq!(names, vec!["invokeFunction_10", "invokeFunction_20"]);
}

/// A real run hit this: a retry after a *sibling* hypothesis (a
/// different predicate from the same investigation) gets rejected
/// re-runs AnalyzeFunction on the whole subject, and a fresh
/// semantic_role proposal that re-confirms the same name is itself
/// ACCEPTED again rather than replacing the earlier one -- so one
/// subject ended up with three separate ACCEPTED semantic_role
/// hypotheses, and each was rendered as its own function definition with
/// the identical name. Not valid C++: only the latest should count.
#[test]
fn a_subject_with_several_accepted_semantic_role_hypotheses_recovers_once() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1bf2", "has_name", "processEvents", 0.95, "ghidra:function", None);
    anchor_as_application(&mut graph, "0x1bf2", "0xa1bf2");

    for _ in 0..3 {
        let h = graph.propose_hypothesis("0x1bf2", "semantic_role", "processEvents", 0.95, None);
        graph.mark_verified(h, Utc::now()).unwrap();
        graph.set_status(h, HypothesisStatus::Accepted).unwrap();
    }

    let program = extract(&graph);
    assert_eq!(program.functions.len(), 1, "one subject must recover to one function, not one per hypothesis");
}

/// The model is told to give semantic_role an identifier-style value,
/// but nothing enforces that -- a real run had an ACCEPTED hypothesis
/// whose value was a full sentence. Used as a C++ name that doesn't
/// compile, so it must fall back to Ghidra's raw name instead, the same
/// as having no accepted hypothesis at all.
#[test]
fn a_non_identifier_accepted_value_falls_back_to_the_raw_name() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "FUN_drawtext", 0.95, "ghidra:function", None);
    anchor_as_application(&mut graph, "0x1", "0xa1");
    let h = graph.propose_hypothesis(
        "0x1",
        "semantic_role",
        "draws text and other visual elements on a screen",
        0.9,
        None,
    );
    graph.mark_verified(h, Utc::now()).unwrap();
    graph.set_status(h, HypothesisStatus::Accepted).unwrap();

    let program = extract(&graph);
    let function = program.functions.iter().find(|f| f.address == "0x1").unwrap();
    assert_eq!(function.display_name, "FUN_drawtext");
    assert!(matches!(function.name_source, NameSource::Raw));
}

/// A real run had `Screen` and `Snake` -- real classes the binary
/// defines, with their own methods -- referenced by name in already-
/// recovered classes' method signatures (`Food::draw(Screen *)`), but
/// never declared anywhere in the output: `extract()` only recovered
/// classes with a detected vtable, and neither of those is polymorphic.
/// A class with real methods of its own must be recovered even without
/// one.
#[test]
fn a_class_with_methods_but_no_vtable_is_still_recovered() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "setPixel", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "void __thiscall Screen::setPixel(Screen *this,int x,int y)\n\n{\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    graph.add_observation("0x1", "is_method_of", "Screen", 0.95, "ghidra:function", None);

    let program = extract(&graph);
    let screen = program.classes.iter().find(|c| c.name == "Screen");
    assert!(screen.is_some(), "a class with real methods must be recovered even without a vtable");

    let screen = screen.unwrap();
    assert_eq!(screen.methods.len(), 1);
    assert!(screen.vtable_address.is_empty());

    let header = render_header(screen);
    assert!(header.contains("no vtable observed"), "header:\n{header}");
    assert!(!header.contains("vtable observed at"), "header:\n{header}");
    assert!(
        header.contains(&format!("#include \"{GHIDRA_COMPAT_HEADER_NAME}\"")),
        "every recovered header must pull in Ghidra's placeholder types: {header}"
    );
}

/// A real run also had `Food::draw(Screen *)` compile-fail even after
/// `Screen` itself was recovered: `Screen.hpp` existed on disk, but
/// nothing in `Food.hpp` pulled it in. A class must `#include` every
/// other recovered class its own methods/fields mention, not just its
/// base class.
#[test]
fn a_class_includes_every_other_recovered_class_it_references() {
    let mut graph = KnowledgeGraph::new();

    graph.add_observation("0x1", "has_name", "setPixel", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "is_method_of", "Screen", 0.95, "ghidra:function", None);

    graph.add_observation("Food", "has_vtable_at", "0x9c0", 1.0, "ghidra:vtable", None);
    graph.add_observation("0x2", "has_name", "draw", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "has_signature", "undefined draw(Food * this, Screen * param_1)", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "decompiles_to", "void __thiscall Food::draw(Food *this,Screen *param_1)\n\n{\n  return;\n}", 0.95, "ghidra:decompiler", None);
    graph.add_observation("0x2", "is_method_of", "Food", 0.95, "ghidra:function", None);

    let program = extract(&graph);
    let food = program.classes.iter().find(|c| c.name == "Food").unwrap();

    assert_eq!(food.references, vec!["Screen".to_string()]);

    // The header forward-declares it (a real run showed two classes
    // referencing each other -- Section <-> Screen <-> Snake -- turns a
    // full #include here into a circular one); render_source() carries
    // the real #include, where the class's members are actually used.
    let header = render_header(food);
    assert!(header.contains("class Screen;"), "header:\n{header}");
    assert!(!header.contains("#include \"Screen.hpp\""), "header:\n{header}");

    let source = render_source(food);
    assert!(source.contains("#include \"Screen.hpp\""), "source:\n{source}");
}

/// A real run had every derived-class constructor's decompiled body
/// open by C-calling its base constructor directly on `this`
/// (`Collideable::Collideable((Collideable *)this,0,0);`), which isn't
/// legal C++ and also breaks because the language already
/// default-constructs the base before the body runs. That leading call
/// must become a real member-initializer-list entry, and disappear from
/// the body.
#[test]
fn a_leading_base_constructor_call_becomes_a_real_initializer_list() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("Collideable", "has_vtable_at", "0x980", 1.0, "ghidra:vtable", None);
    graph.add_observation("Wall", "has_vtable_at", "0x9b0", 1.0, "ghidra:vtable", None);
    graph.add_observation("Wall", "inherits_from", "Collideable", 1.0, "ghidra:rtti", None);

    graph.add_observation("0x1", "has_name", "Wall", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "void Wall(Wall * this, int param_1, int param_2)", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "void __thiscall Wall::Wall(Wall *this,int param_1,int param_2)\n\n{\n  Collideable::Collideable((Collideable *)this,param_1,param_2);\n  *(undefined ***)this = &PTR_draw_140009a20;\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    graph.add_observation("0x1", "is_constructor_of", "Wall", 0.95, "ghidra:function", None);

    let program = extract(&graph);
    let wall = program.classes.iter().find(|c| c.name == "Wall").unwrap();

    let source = render_source(wall);
    assert!(
        source.contains("Wall::Wall(int param_1, int param_2) : Collideable(param_1,param_2)"),
        "source:\n{source}"
    );
    assert!(
        !source.contains("Collideable::Collideable((Collideable *)this"),
        "the raw base-constructor call must not remain in the body: {source}"
    );
}

/// A real run's `Food::Food()` had Ghidra hoist local variable
/// declarations (its usual C89-style convention) *before* the
/// base-constructor call, which the first version of this rewrite --
/// requiring the call to be the very first statement -- missed
/// entirely, leaving the illegal C-style call in the body and breaking
/// the compile with "no matching function for call to
/// 'Collideable::Collideable()'" (the implicit no-arg default the
/// compiler was left needing). The call must be found and spliced out
/// wherever it actually is.
#[test]
fn a_base_constructor_call_after_local_declarations_is_still_found() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("Collideable", "has_vtable_at", "0x980", 1.0, "ghidra:vtable", None);
    graph.add_observation("Food", "has_vtable_at", "0x9c0", 1.0, "ghidra:vtable", None);
    graph.add_observation("Food", "inherits_from", "Collideable", 1.0, "ghidra:rtti", None);

    graph.add_observation("0x1", "has_name", "Food", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "void Food(Food * this)", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "void __thiscall Food::Food(Food *this)\n\n{\n  double dVar1;\n  int iVar2;\n  \n  Collideable::Collideable((Collideable *)this,0,0);\n  iVar2 = rand();\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    graph.add_observation("0x1", "is_constructor_of", "Food", 0.95, "ghidra:function", None);

    let program = extract(&graph);
    let food = program.classes.iter().find(|c| c.name == "Food").unwrap();

    let source = render_source(food);
    assert!(source.contains("Food::Food() : Collideable(0,0)"), "source:\n{source}");
    assert!(source.contains("double dVar1;"), "local declarations before the call must survive: {source}");
    assert!(source.contains("iVar2 = rand();"), "statements after the call must survive: {source}");
    assert!(
        !source.contains("Collideable::Collideable((Collideable *)this"),
        "the raw base-constructor call must not remain in the body: {source}"
    );
}

/// A real compile hit `*_refptr_...` (dereferencing the symbol directly)
/// failing with "invalid type argument of unary '*'" against a plain
/// byte declaration -- `_refptr_*` specifically means a synthesized
/// pointer-to-a-relocated-global in Ghidra's own naming convention, so
/// unlike `DAT_*`/`PTR_*` it needs to be declared as a pointer.
#[test]
fn refptr_symbols_are_declared_as_pointers_not_plain_bytes() {
    let header = render_ghidra_symbols_header(
        &[
            "DAT_140009070".to_string(),
            "_refptr__ZN9SnakeGame6Screen7S_WIDTHE".to_string(),
        ],
        &[],
        "",
    );
    assert!(header.contains("extern unsigned char DAT_140009070;"), "header:\n{header}");
    assert!(
        header.contains("extern unsigned char *_refptr__ZN9SnakeGame6Screen7S_WIDTHE;"),
        "header:\n{header}"
    );
}

/// PROJECT.md M17 (compile-viability pass): a real compile hit this --
/// `*PTR_DAT_1400096a0` (dereferencing a `PTR_*`-prefixed symbol, Ghidra's
/// own naming convention for "this address holds a pointer") against a
/// plain `unsigned char` declaration fails with "invalid type argument of
/// unary '*'", the same failure `_refptr_*` was already fixed for.
#[test]
fn ptr_prefixed_symbols_are_declared_as_pointers_too() {
    let header = render_ghidra_symbols_header(&["PTR_DAT_1400096a0".to_string()], &[], "");
    assert!(
        header.contains("extern unsigned char *PTR_DAT_1400096a0;"),
        "header:\n{header}"
    );
}

/// A compact sanity check that the compat header actually declares what
/// this session's real compile attempt against the Snake fixture showed
/// was missing -- not exhaustive, just a guard against silently deleting
/// the entries that were verified to matter.
#[test]
fn ghidra_compat_header_declares_the_types_a_real_compile_needed() {
    let header = render_ghidra_compat_header(&["CONCAT44".to_string()]);
    for needed in [
        "undefined", "undefined4", "undefined8", "uint", "ulonglong", "code", "CONCAT44",
        "__thiscall", "operator_new", "operator_delete", "<windows.h>", "<iostream>", "<cstring>",
    ] {
        assert!(
            header.contains(needed),
            "compat header is missing {needed:?}, which a real g++ run against recovered Snake output required"
        );
    }
}

/// `DAT_140009070`, `PTR_draw_140009a40`, `_refptr__ZN...E` -- Ghidra's
/// own auto-named data symbols -- were referenced in recovered bodies
/// but never declared anywhere else in the output, so a real compile
/// failed outright on "not declared in this scope". They must be
/// collected across every class and standalone function and declared
/// once each.
#[test]
fn ghidra_data_symbols_are_collected_and_declared() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("Drawable", "has_vtable_at", "0x9a0", 1.0, "ghidra:vtable", None);
    graph.add_observation("0x1", "has_name", "Drawable", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "void Drawable(Drawable * this, int x, int y)", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "void __thiscall Drawable::Drawable(Drawable *this,int x,int y)\n\n{\n  *(undefined ***)this = &DAT_140009a60;\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    graph.add_observation("0x1", "is_constructor_of", "Drawable", 0.95, "ghidra:function", None);

    let program = extract(&graph);
    assert_eq!(program.ghidra_data_symbols, vec!["DAT_140009a60".to_string()]);

    let header = render_ghidra_symbols_header(&program.ghidra_data_symbols, &program.unresolved_calls, "");
    assert!(header.contains("extern unsigned char DAT_140009a60;"), "header:\n{header}");

    let drawable = program.classes.iter().find(|c| c.name == "Drawable").unwrap();
    let source = render_source(drawable);
    assert!(
        source.contains("(undefined **)&DAT_140009a60"),
        "the vtable-pointer-slot assignment must get an explicit cast so it compiles \
         regardless of the placeholder symbol's declared type: {source}"
    );
}

/// PROJECT.md M18: `_initterm`/`_ismbblead` are real, statically-linked
/// MinGW CRT functions Ghidra's own decompiler calls by their real,
/// recognized name -- never a `FUN_<addr>` placeholder, so `symtab.rs`'s
/// own unresolved-call tracking never sees them. A real compile found
/// them simply undeclared once a `RequiredUnknown` function that
/// genuinely calls them got recovered for the first time.
#[test]
fn known_crt_functions_called_by_real_name_get_a_permissive_fallback_declaration() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "void FUN_1(void)\n\n{\n  _initterm(PTR_DAT_1,PTR_DAT_2);\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    anchor_as_application(&mut graph, "0x1", "0x100");

    let program = extract(&graph);

    assert!(program.unresolved_calls.contains(&"_initterm".to_string()), "{:?}", program.unresolved_calls);
    let header = render_ghidra_symbols_header(&program.ghidra_data_symbols, &program.unresolved_calls, "");
    assert!(header.contains("long long _initterm(...);"), "header:\n{header}");
}

/// A real run showed `&LAB_x` isn't a goto target at all -- it's a
/// MinGW CRT startup idiom taking a label's *address* as a function
/// pointer value (`(_invalid_parameter_handler)&LAB_140001000`). Handled
/// the same way as `DAT_`/`PTR_`: an extern placeholder declaration,
/// which can never collide with a genuine `LAB_x:` goto-label elsewhere
/// in the same function (C++ keeps labels and ordinary names in
/// separate namespaces).
#[test]
fn lab_symbols_taken_by_address_are_declared_as_placeholders() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "void FUN_1(void)", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "void FUN_1(void)\n\n{\n  registerHandler((handler_t)&LAB_140001000);\n  return;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    anchor_as_application(&mut graph, "0x1", "0xa1");
    let h = graph.propose_hypothesis("0x1", "semantic_role", "installHandler", 0.95, None);
    graph.mark_verified(h, Utc::now()).unwrap();
    graph.set_status(h, HypothesisStatus::Accepted).unwrap();

    let program = extract(&graph);
    assert_eq!(program.ghidra_data_symbols, vec!["LAB_140001000".to_string()]);

    let header = render_ghidra_symbols_header(&program.ghidra_data_symbols, &program.unresolved_calls, "");
    assert!(header.contains("extern unsigned char LAB_140001000;"), "header:\n{header}");
}

/// Itanium ABI returns `this` from `operator=` in the return register,
/// which Ghidra always decompiles as `return this;` -- but leaves the
/// declared return type as `undefined`, which can't actually hold a
/// class pointer. A real compile hit exactly this ("invalid conversion
/// from 'Drawable*' to 'undefined'").
#[test]
fn operator_equals_returns_a_pointer_to_its_own_class_not_undefined() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("Drawable", "has_vtable_at", "0x9a0", 1.0, "ghidra:vtable", None);
    graph.add_observation("0x1", "has_name", "operator=", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "undefined operator=(Drawable * this, Drawable * param_1)", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0x1",
        "decompiles_to",
        "undefined __thiscall Drawable::operator=(Drawable *this,Drawable *param_1)\n\n{\n  return this;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );
    graph.add_observation("0x1", "is_method_of", "Drawable", 0.95, "ghidra:function", None);

    let program = extract(&graph);
    let drawable = program.classes.iter().find(|c| c.name == "Drawable").unwrap();
    let op_eq = &drawable.methods[0];

    assert_eq!(op_eq.return_type, "Drawable *");
}

/// PROJECT.md M15: a real compile against Snake's stripped binary had
/// 262 "not declared" errors from exactly this shape -- every recovered
/// standalone function lands in one shared `functions.cpp`, sorted by
/// *address*, so a lower-address function calling a higher-address one
/// (an entirely ordinary thing for real code to do) failed to compile
/// for plain forward-declaration reasons once M15's symbol-resolution
/// pass (`symtab.rs`) had already renamed the raw `FUN_<addr>` call to
/// its real name. `render_function_declarations` (included via
/// `ghidra_symbols.hpp`, which every generated file already includes)
/// is the fix: declare every recovered function once, in the one place
/// every file already sees.
#[test]
fn standalone_functions_forward_declare_each_other_regardless_of_address_order() {
    let mut graph = KnowledgeGraph::new();
    // Lower address, but calls the higher-address one below.
    graph.add_observation("0x1", "has_name", "FUN_1", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "void FUN_1(void)", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "decompiles_to", "void FUN_1(void)\n\n{\n  FUN_2();\n  return;\n}", 0.95, "ghidra:decompiler", None);
    anchor_as_application(&mut graph, "0x1", "0xa1");
    let h1 = graph.propose_hypothesis("0x1", "semantic_role", "runFirst", 0.95, None);
    graph.mark_verified(h1, Utc::now()).unwrap();
    graph.set_status(h1, HypothesisStatus::Accepted).unwrap();

    graph.add_observation("0x2", "has_name", "FUN_2", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "has_signature", "void FUN_2(void)", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "decompiles_to", "void FUN_2(void)\n\n{\n  return;\n}", 0.95, "ghidra:decompiler", None);
    anchor_as_application(&mut graph, "0x2", "0xa2");
    let h2 = graph.propose_hypothesis("0x2", "semantic_role", "runSecond", 0.95, None);
    graph.mark_verified(h2, Utc::now()).unwrap();
    graph.set_status(h2, HypothesisStatus::Accepted).unwrap();

    let program = extract(&graph);
    let run_first = program.functions.iter().find(|f| f.display_name == "runFirst").unwrap();
    assert!(
        run_first.decompilation.contains("runSecond();"),
        "call site must be renamed to the real recovered name: {}",
        run_first.decompilation
    );

    let declarations: Vec<(String, String, String)> = program
        .functions
        .iter()
        .map(|f| (f.return_type.clone(), f.display_name.clone(), f.params.clone()))
        .collect();
    let header = render_function_declarations(&declarations);
    assert!(header.contains("void runSecond(void);"), "header:\n{header}");
    assert!(header.contains("void runFirst(void);"), "header:\n{header}");
}

/// A real run had a standalone function's M15-resolved body construct a
/// real recovered class (`new (ptr) Wall(...)`, from a raw `FUN_ctor`
/// call) with nothing in `functions.cpp` ever including `Wall.hpp`.
#[test]
fn standalone_functions_reference_a_class_their_resolved_body_constructs() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_vtable_at", "0x100", 1.0, "ghidra:vtable", None);
    graph.add_observation("0x1", "is_constructor_of", "Wall", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_name", "Wall", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "has_signature", "void Wall(Wall * this)", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "decompiles_to", "void Wall(Wall *this)\n\n{\n  return;\n}", 0.95, "ghidra:decompiler", None);

    graph.add_observation("0x2", "has_name", "FUN_2", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "has_signature", "void FUN_2(void * ptr)", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "decompiles_to", "void FUN_2(void *ptr)\n\n{\n  FUN_1(ptr);\n  return;\n}", 0.95, "ghidra:decompiler", None);
    // PROJECT.md M17: makes 0x2's own provenance resolve to Application
    // via its callee (0x1, Wall's constructor) rather than needing its
    // own name/owner signal -- the real relationship this fixture models.
    graph.add_observation("0x2", "calls", "0x1", 0.95, "ghidra:call_graph", None);
    let h = graph.propose_hypothesis("0x2", "semantic_role", "spawnWall", 0.95, None);
    graph.mark_verified(h, Utc::now()).unwrap();
    graph.set_status(h, HypothesisStatus::Accepted).unwrap();

    let program = extract(&graph);
    assert!(program.function_references.contains(&"Wall".to_string()), "{:?}", program.function_references);

    let spawn = program.functions.iter().find(|f| f.display_name == "spawnWall").unwrap();
    assert!(spawn.decompilation.contains("new ((void *)(ptr)) Wall()"), "{}", spawn.decompilation);
}

/// PROJECT.md M18.3: the real SDL_main case -- once `crt_boundary::find_main_equivalent`
/// structurally identifies the binary's own real `main()`, an explicitly
/// requested linker-required alias name (`SDL_main`) must resolve to that
/// exact, already-recovered function's own display name. Reuses the same
/// verified `entry -> crt_startup -> siblings incl. a dominant main` shape
/// `crt_boundary.rs`'s own tests confirm `find_main_equivalent` on.
#[test]
fn an_entry_wrapper_symbol_resolves_to_the_structurally_found_main_equivalent() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0xentry", "exports", "entry", 0.95, "ghidra:exports", None);
    graph.add_observation("0xentry", "calls", "0xcrt_startup", 0.95, "ghidra:call_graph", None);
    graph.add_observation("0xcrt_startup", "calls", "0xargv_dup", 0.95, "ghidra:call_graph", None);
    graph.add_observation("0xcrt_startup", "calls", "0xmain", 0.95, "ghidra:call_graph", None);
    // main's own large subtree, dwarfing 0xargv_dup's (a single, leaf
    // address) well past the real DOMINANCE_MARGIN.
    graph.add_observation("0xmain", "calls", "0xgame_init", 0.95, "ghidra:call_graph", None);
    graph.add_observation("0xmain", "calls", "0xgame_loop", 0.95, "ghidra:call_graph", None);
    graph.add_observation("0xgame_loop", "calls", "0xrender", 0.95, "ghidra:call_graph", None);
    graph.add_observation("0xgame_loop", "calls", "0xupdate", 0.95, "ghidra:call_graph", None);
    graph.add_observation("0xupdate", "calls", "0xcollide", 0.95, "ghidra:call_graph", None);

    graph.add_observation("0xmain", "has_name", "FUN_140003940", 0.95, "ghidra:function", None);
    graph.add_observation(
        "0xmain",
        "decompiles_to",
        "int FUN_140003940(void)\n\n{\n  return 0;\n}",
        0.95,
        "ghidra:decompiler",
        None,
    );

    let program = debura_recovery::extract_with_required_runtime_bodies(
        &graph,
        &std::collections::BTreeSet::new(),
        Some("SDL_main"),
    );

    assert_eq!(
        program.entry_wrapper,
        Some(("SDL_main".to_string(), "FUN_140003940".to_string()))
    );
}

/// No confidently-identified main-equivalent (a shallow graph with no
/// real CRT-startup fan-out, matching `crt_boundary.rs`'s own
/// `a_two_hop_chain_with_no_real_siblings_never_identifies_a_main_equivalent`)
/// must never invent an entry wrapper -- the same "no confident evidence
/// means no exclusion/alias at all" rule the CRT-boundary detector itself
/// follows.
#[test]
fn no_entry_wrapper_is_produced_when_no_main_equivalent_is_found() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0xentry", "exports", "entry", 0.95, "ghidra:exports", None);
    graph.add_observation("0xentry", "calls", "0x1", 0.95, "ghidra:call_graph", None);
    graph.add_observation("0x1", "calls", "0x2", 0.95, "ghidra:call_graph", None);

    let program = debura_recovery::extract_with_required_runtime_bodies(
        &graph,
        &std::collections::BTreeSet::new(),
        Some("SDL_main"),
    );

    assert_eq!(program.entry_wrapper, None);
}
