use chrono::Utc;
use debura_knowledge::{HypothesisStatus, KnowledgeGraph};
use debura_recovery::{
    extract, render_ghidra_symbols_header, render_header, render_source, NameSource,
    GHIDRA_COMPAT_HEADER, GHIDRA_COMPAT_HEADER_NAME,
};

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

#[test]
fn functions_without_an_accepted_hypothesis_are_not_recovered() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x99", "has_name", "FUN_99", 0.95, "ghidra:function", None);
    graph.propose_hypothesis("0x99", "semantic_role", "Guessed", 0.5, None); // PROPOSED, not ACCEPTED

    let program = extract(&graph);
    assert!(program.functions.is_empty());
    assert!(program.classes.is_empty());
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

/// A compact sanity check that the compat header actually declares what
/// this session's real compile attempt against the Snake fixture showed
/// was missing -- not exhaustive, just a guard against silently deleting
/// the entries that were verified to matter.
#[test]
fn ghidra_compat_header_declares_the_types_a_real_compile_needed() {
    for needed in ["undefined", "undefined4", "undefined8", "uint", "ulonglong", "code", "CONCAT44", "__thiscall"] {
        assert!(
            GHIDRA_COMPAT_HEADER.contains(needed),
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

    let header = render_ghidra_symbols_header(&program.ghidra_data_symbols);
    assert!(header.contains("extern unsigned char DAT_140009a60;"), "header:\n{header}");

    let drawable = program.classes.iter().find(|c| c.name == "Drawable").unwrap();
    let source = render_source(drawable);
    assert!(
        source.contains("(undefined **)&DAT_140009a60"),
        "the vtable-pointer-slot assignment must get an explicit cast so it compiles \
         regardless of the placeholder symbol's declared type: {source}"
    );
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
