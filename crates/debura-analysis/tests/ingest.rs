use debura_analysis::ingest;
use debura_ghidra::{
    AnalysisResult, ExportFact, FieldFact, FunctionFact, ImportFact, InheritanceFact, StringFact,
    VirtualMethodFact, VtableFact, XrefFact,
};
use debura_knowledge::KnowledgeGraph;

fn empty_result() -> AnalysisResult {
    AnalysisResult {
        program: "test".to_string(),
        functions: Vec::new(),
        strings: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        xrefs: Vec::new(),
        vtables: Vec::new(),
        virtual_methods: Vec::new(),
        inheritance: Vec::new(),
        fields: Vec::new(),
    }
}

/// PROJECT.md M7: vtables, inheritance, constructors/destructors and field
/// candidates all become Observations, with confidence split by how
/// certain the underlying read is (header-table read vs. Ghidra heuristic
/// vs. a regex over decompiled text).
#[test]
fn m7_facts_become_observations() {
    let mut analysis = empty_result();
    analysis.functions.push(FunctionFact {
        address: "0x1".to_string(),
        name: "Player".to_string(),
        size: 10,
        signature: "void Player(Player *this, float health)".to_string(),
        calling_convention: "__thiscall".to_string(),
        callers: Vec::new(),
        callees: Vec::new(),
        decompilation: String::new(),
        owner_class: Some("Player".to_string()),
        is_constructor: true,
        is_destructor: false,
    });
    analysis.vtables.push(VtableFact {
        class_name: "Player".to_string(),
        address: "0x100".to_string(),
    });
    analysis.virtual_methods.push(VirtualMethodFact {
        class_name: "Player".to_string(),
        slot: 0,
        function_address: "0x200".to_string(),
    });
    analysis.inheritance.push(InheritanceFact {
        derived: "Player".to_string(),
        base: "Entity".to_string(),
    });
    analysis.fields.push(FieldFact {
        class_name: "Player".to_string(),
        offset: "0xc".to_string(),
        field_type: "int".to_string(),
    });

    let mut graph = KnowledgeGraph::new();
    ingest(&mut graph, &analysis, "artifacts/analysis.json");

    let find = |subject: &str, predicate: &str| {
        graph
            .observations()
            .find(|o| o.subject == subject && o.predicate == predicate)
    };

    let ctor = find("0x1", "is_constructor_of").expect("constructor observation");
    assert_eq!(ctor.value, "Player");
    assert_eq!(ctor.confidence, 0.95);

    let vtable = find("Player", "has_vtable_at").expect("vtable observation");
    assert_eq!(vtable.value, "0x100");
    assert_eq!(vtable.confidence, 1.0, "vtable symbol is a direct table read");

    let inherits = find("Player", "inherits_from").expect("inheritance observation");
    assert_eq!(inherits.value, "Entity");

    let field = find("Player", "has_field_candidate").expect("field observation");
    assert_eq!(field.value, "0xc:int");
    assert_eq!(
        field.confidence, 0.85,
        "field candidates are a heuristic layered on decompilation"
    );

    let virtual_method = find("Player", "has_virtual_method").expect("virtual method observation");
    assert_eq!(virtual_method.value, "slot 0: 0x200");
}

/// PROJECT.md: re-running `debura analyze` now loads and merges into the
/// existing graph rather than replacing it, so `ingest` must not
/// re-duplicate facts it already recorded -- while still capturing a fact
/// that genuinely changed (e.g. a name after an M8 rename).
#[test]
fn ingest_is_idempotent_but_still_captures_real_changes() {
    let mut analysis = empty_result();
    analysis.functions.push(FunctionFact {
        address: "0x1".to_string(),
        name: "takeDamage".to_string(),
        size: 10,
        signature: "void takeDamage(Player *this)".to_string(),
        calling_convention: "__thiscall".to_string(),
        callers: Vec::new(),
        callees: Vec::new(),
        decompilation: String::new(),
        owner_class: None,
        is_constructor: false,
        is_destructor: false,
    });

    let mut graph = KnowledgeGraph::new();
    ingest(&mut graph, &analysis, "artifacts/analysis.json");
    let count_after_first = graph.observations().count();

    ingest(&mut graph, &analysis, "artifacts/analysis.json");
    assert_eq!(
        graph.observations().count(),
        count_after_first,
        "re-ingesting identical facts must not duplicate them"
    );

    analysis.functions[0].name = "ApplyDamage".to_string();
    ingest(&mut graph, &analysis, "artifacts/analysis.json");
    assert_eq!(
        graph.observations().count(),
        count_after_first + 1,
        "a genuinely changed fact must still be recorded"
    );

    let names: Vec<_> = graph
        .observations()
        .filter(|o| o.subject == "0x1" && o.predicate == "has_name")
        .map(|o| o.value.as_str())
        .collect();
    assert!(names.contains(&"takeDamage"), "old name stays as history, S4");
    assert!(names.contains(&"ApplyDamage"));
}

/// PROJECT.md M9 needs to know which class a plain (non-ctor/dtor) method
/// belongs to in order to group it under that class's recovered header.
#[test]
fn plain_methods_get_is_method_of_without_ctor_dtor_tags() {
    let mut analysis = empty_result();
    analysis.functions.push(FunctionFact {
        address: "0x1".to_string(),
        name: "describe".to_string(),
        size: 10,
        signature: "void describe(Entity *this)".to_string(),
        calling_convention: "__thiscall".to_string(),
        callers: Vec::new(),
        callees: Vec::new(),
        decompilation: String::new(),
        owner_class: Some("Entity".to_string()),
        is_constructor: false,
        is_destructor: false,
    });

    let mut graph = KnowledgeGraph::new();
    ingest(&mut graph, &analysis, "artifacts/analysis.json");

    let is_method_of = graph
        .observations()
        .find(|o| o.subject == "0x1" && o.predicate == "is_method_of")
        .expect("is_method_of observation");
    assert_eq!(is_method_of.value, "Entity");

    assert!(graph
        .observations()
        .all(|o| o.predicate != "is_constructor_of" && o.predicate != "is_destructor_of"));
}

/// A non-method function (no `this`) should produce none of the M7 facts.
#[test]
fn free_functions_produce_no_class_facts() {
    let mut analysis = empty_result();
    analysis.functions.push(FunctionFact {
        address: "0x1".to_string(),
        name: "main".to_string(),
        size: 10,
        signature: "int main(void)".to_string(),
        calling_convention: "__cdecl".to_string(),
        callers: Vec::new(),
        callees: Vec::new(),
        decompilation: String::new(),
        owner_class: None,
        is_constructor: false,
        is_destructor: false,
    });

    let mut graph = KnowledgeGraph::new();
    ingest(&mut graph, &analysis, "artifacts/analysis.json");

    assert!(graph
        .observations()
        .all(|o| o.predicate != "is_constructor_of" && o.predicate != "is_destructor_of"));
}

// Sanity: these fact/observation kinds from M1 must still round-trip
// unchanged now that AnalysisResult has grown new fields.
#[test]
fn m1_facts_are_unaffected() {
    let mut analysis = empty_result();
    analysis.strings.push(StringFact {
        address: "0x1".to_string(),
        value: "hello".to_string(),
    });
    analysis.imports.push(ImportFact {
        name: "CreateFileW".to_string(),
        namespace: "KERNEL32.DLL".to_string(),
        address: "0x2".to_string(),
    });
    analysis.exports.push(ExportFact {
        name: "DllMain".to_string(),
        address: "0x3".to_string(),
    });
    analysis.xrefs.push(XrefFact {
        from: "0x1".to_string(),
        to: "0x2".to_string(),
        kind: "CALL".to_string(),
    });

    let mut graph = KnowledgeGraph::new();
    ingest(&mut graph, &analysis, "artifacts/analysis.json");

    assert!(graph
        .observations()
        .any(|o| o.predicate == "contains_string" && o.value == "hello"));
    assert!(graph
        .observations()
        .any(|o| o.predicate == "imports" && o.value == "KERNEL32.DLL!CreateFileW"));
    assert!(graph
        .observations()
        .any(|o| o.predicate == "exports" && o.value == "DllMain"));
}
