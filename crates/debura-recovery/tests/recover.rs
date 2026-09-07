use chrono::Utc;
use debura_knowledge::{HypothesisStatus, KnowledgeGraph};
use debura_recovery::{extract, render_header, render_source, NameSource};

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

#[test]
fn functions_without_an_accepted_hypothesis_are_not_recovered() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x99", "has_name", "FUN_99", 0.95, "ghidra:function", None);
    graph.propose_hypothesis("0x99", "semantic_role", "Guessed", 0.5, None); // PROPOSED, not ACCEPTED

    let program = extract(&graph);
    assert!(program.functions.is_empty());
    assert!(program.classes.is_empty());
}
