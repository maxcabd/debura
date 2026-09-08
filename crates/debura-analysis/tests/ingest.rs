use debura_analysis::ingest;
use debura_ghidra::{
    AnalysisResult, DataObjectFact, ExportFact, FieldFact, FunctionFact, ImportFact,
    InheritanceFact, StringFact, VirtualMethodFact, VtableFact, XrefFact,
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
        data_objects: Vec::new(),
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
        installs_vtable_of: None,
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
        installs_vtable_of: None,
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
        installs_vtable_of: None,
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

/// A structurally-discovered constructor/destructor (M7 on a stripped
/// binary) can't be labeled `is_constructor_of`/`is_destructor_of` --
/// distinguishing the two needs symbol-based typing this path doesn't
/// have -- but the reasoning agent still needs *some* signal that this
/// function's body (typically just a base-class call plus a pointer
/// store) is the well-known ABI idiom rather than arbitrary code. A real
/// run showed the cost of not having this: every semantic_role guess for
/// such a function got rejected by an equally uninformed adversarial
/// challenge.
#[test]
fn structural_vtable_install_produces_a_pattern_observation_not_ctor_dtor() {
    let mut analysis = empty_result();
    analysis.functions.push(FunctionFact {
        address: "0x1".to_string(),
        name: "FUN_1".to_string(),
        size: 10,
        signature: "void FUN_1(undefined8 *param_1)".to_string(),
        calling_convention: "__fastcall".to_string(),
        callers: Vec::new(),
        callees: Vec::new(),
        decompilation: String::new(),
        owner_class: Some("Wall".to_string()),
        is_constructor: false,
        is_destructor: false,
        installs_vtable_of: Some("Wall".to_string()),
    });

    let mut graph = KnowledgeGraph::new();
    ingest(&mut graph, &analysis, "artifacts/analysis.json");

    let pattern = graph
        .observations()
        .find(|o| o.subject == "0x1" && o.predicate == "vtable_install_pattern")
        .expect("vtable_install_pattern observation");
    assert!(pattern.value.contains("Wall"));
    assert!(pattern.value.contains("constructor"));
    assert!(pattern.value.contains("destructor"));

    assert!(graph
        .observations()
        .all(|o| o.predicate != "is_constructor_of" && o.predicate != "is_destructor_of"));
}

/// A real run showed `callers` was already extracted from Ghidra but
/// never turned into an observation -- so AnalyzeFunctionTask's
/// per-subject context (every observation for that subject) could see
/// what a function calls but never who calls it, even though the raw
/// data was sitting right there in `FunctionFact`.
#[test]
fn callers_become_called_by_observations() {
    let mut analysis = empty_result();
    analysis.functions.push(FunctionFact {
        address: "0x2".to_string(),
        name: "die".to_string(),
        size: 10,
        signature: "void die(Snake *this)".to_string(),
        calling_convention: "__thiscall".to_string(),
        callers: vec!["0x1".to_string()],
        callees: vec!["0x3".to_string()],
        decompilation: String::new(),
        owner_class: Some("Snake".to_string()),
        is_constructor: false,
        is_destructor: false,
        installs_vtable_of: None,
    });

    let mut graph = KnowledgeGraph::new();
    ingest(&mut graph, &analysis, "artifacts/analysis.json");

    let called_by = graph
        .observations()
        .find(|o| o.subject == "0x2" && o.predicate == "called_by")
        .expect("called_by observation");
    assert_eq!(called_by.value, "0x1");

    let calls = graph
        .observations()
        .find(|o| o.subject == "0x2" && o.predicate == "calls")
        .expect("calls observation");
    assert_eq!(calls.value, "0x3");
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
        installs_vtable_of: None,
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

/// PROJECT.md M18.2: `DataObjectFact` restates exactly what Ghidra found
/// -- no semantic claim (no `data_kind`) is ever written here.
#[test]
fn m18_2_data_object_facts_become_observations() {
    let mut analysis = empty_result();
    analysis.data_objects.push(DataObjectFact {
        address: "0x140009a00".to_string(),
        symbol_name: Some("PTR_FUN_140009a00".to_string()),
        section: Some(".data".to_string()),
        readable: Some(true),
        writable: Some(true),
        executable: Some(false),
        initialized: Some(true),
        data_type: Some("undefined8".to_string()),
        size: Some(8),
        size_confident: true,
        bytes_hex: Some("5017001400000000".to_string()),
        inside_function: None,
        pointee_address: Some("0x140001750".to_string()),
        pointee_source: Some("reference".to_string()),
        referenced_from: vec!["0x1400030a7".to_string()],
    });
    // A second real case: no defined Data object, no confident size --
    // must not synthesize a `data_size_bytes` fact for it.
    analysis.data_objects.push(DataObjectFact {
        address: "0x14000e130".to_string(),
        symbol_name: Some("DAT_14000e130".to_string()),
        section: Some(".bss".to_string()),
        readable: Some(true),
        writable: Some(true),
        executable: Some(false),
        initialized: Some(false),
        data_type: None,
        size: None,
        size_confident: false,
        bytes_hex: None,
        inside_function: None,
        pointee_address: None,
        pointee_source: None,
        referenced_from: Vec::new(),
    });

    // A third case: a real size, but only estimated from the next
    // symbol's distance, not a defined Data object -- must land under
    // the visibly-different `data_size_bytes_estimated` predicate, never
    // silently pass as an authoritative `data_size_bytes`.
    analysis.data_objects.push(DataObjectFact {
        address: "0x140009070".to_string(),
        symbol_name: Some("DAT_140009070".to_string()),
        section: Some(".data".to_string()),
        readable: Some(true),
        writable: Some(true),
        executable: Some(false),
        initialized: Some(true),
        data_type: None,
        size: Some(16),
        size_confident: false,
        bytes_hex: None,
        inside_function: None,
        pointee_address: None,
        pointee_source: None,
        referenced_from: Vec::new(),
    });

    let mut graph = KnowledgeGraph::new();
    ingest(&mut graph, &analysis, "artifacts/analysis.json");

    let has = |subject: &str, predicate: &str, value: &str| {
        graph.observations().any(|o| o.subject == subject && o.predicate == predicate && o.value == value)
    };

    assert!(has("0x140009a00", "data_symbol_name", "PTR_FUN_140009a00"));
    assert!(has("0x140009a00", "data_section", ".data"));
    assert!(has("0x140009a00", "data_writable", "true"));
    assert!(has("0x140009a00", "data_size_bytes", "8"));
    assert!(has("0x140009a00", "data_pointee", "0x140001750 (reference)"));
    assert!(has("0x140009a00", "data_referenced_from", "0x1400030a7"));

    assert!(has("0x14000e130", "data_initialized", "false"));
    assert!(
        !graph.observations().any(|o| o.subject == "0x14000e130" && o.predicate == "data_size_bytes"),
        "an unconfident size must not be recorded as an authoritative one"
    );
    assert!(
        !graph.observations().any(|o| o.subject == "0x14000e130" && o.predicate.starts_with("data_size_bytes_estimated")),
        "no real size was known at all, so nothing -- not even an estimate -- should be recorded"
    );

    assert!(has("0x140009070", "data_size_bytes_estimated", "16"));
    assert!(
        !graph.observations().any(|o| o.subject == "0x140009070" && o.predicate == "data_size_bytes"),
        "an estimated size must never masquerade as the confident predicate"
    );
}
