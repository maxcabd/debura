use std::collections::{BTreeMap, BTreeSet};

use debura_knowledge::{Hypothesis, HypothesisStatus, KnowledgeGraph, Observation};

use crate::model::{NameSource, RecoveredClass, RecoveredField, RecoveredFunction, RecoveredMethod, RecoveredProgram};

/// `ingest` can run more than once against the same subject (M8's
/// `reextract`, or a repeated `debura analyze`), so more than one
/// observation can exist for the same (subject, predicate). The highest id
/// is the most recent -- iteration order over the graph's internal map is
/// not otherwise meaningful (learned the hard way while testing M8).
fn latest<'a>(graph: &'a KnowledgeGraph, subject: &str, predicate: &str) -> Option<&'a Observation> {
    graph
        .observations()
        .filter(|o| o.subject == subject && o.predicate == predicate)
        .max_by_key(|o| o.id.0)
}

/// The model is told to give `semantic_role` an identifier-style value,
/// but nothing enforces that at the schema level -- a value like "perform
/// graphical operations including drawing..." has been seen ACCEPTED in
/// practice. Used directly as a C++ name, that doesn't compile, so it's
/// treated the same as having no accepted hypothesis at all rather than
/// emitted as-is.
fn is_valid_cpp_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The single most-recently-ACCEPTED `semantic_role` hypothesis for
/// `subject` with a usable value, if any. More than one can exist: a
/// retry after a *sibling* hypothesis (a different predicate from the
/// same investigation) gets rejected re-runs AnalyzeFunction on the whole
/// subject, and a fresh `semantic_role` proposal that re-confirms the
/// same name is itself accepted again rather than replacing the old one
/// in place -- so only the latest counts as authoritative, matching
/// every other "most recent observation wins" lookup in this crate.
fn accepted_name<'a>(graph: &'a KnowledgeGraph, subject: &str) -> Option<&'a Hypothesis> {
    graph
        .hypotheses()
        .filter(|h| {
            h.subject == subject
                && h.predicate == "semantic_role"
                && h.status == HypothesisStatus::Accepted
                && is_valid_cpp_identifier(&h.value)
        })
        .max_by_key(|h| h.id.0)
}

fn name_source(graph: &KnowledgeGraph, subject: &str) -> Option<(String, NameSource)> {
    if let Some(h) = accepted_name(graph, subject) {
        return Some((
            h.value.clone(),
            NameSource::Accepted {
                hypothesis: h.id,
                confidence: h.confidence,
            },
        ));
    }

    latest(graph, subject, "has_name").map(|o| (o.value.clone(), NameSource::Raw))
}

struct ParsedSignature {
    return_type: String,
    params: String,
}

/// Ghidra's own signature strings look like `RETTYPE raw_name(TYPE * this,
/// TYPE2 param_1, ...)` for anything with a recognized `this` parameter.
/// This is a best-effort split, not a real C parser -- good enough for the
/// shapes Ghidra's decompiler actually produces, not a guarantee for every
/// possible one.
fn parse_signature(signature: &str, raw_name: &str) -> ParsedSignature {
    let open = signature.find('(').unwrap_or(signature.len());
    let close = signature.rfind(')').unwrap_or(signature.len());

    let prefix = signature[..open].trim();
    let return_type = prefix.strip_suffix(raw_name).unwrap_or(prefix).trim();

    let inner = if close > open {
        &signature[open + 1..close]
    } else {
        ""
    };
    let mut params: Vec<&str> = inner
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    if params.first().is_some_and(|p| p.ends_with("this")) {
        params.remove(0);
    }

    ParsedSignature {
        return_type: if return_type.is_empty() {
            "void".to_string()
        } else {
            return_type.to_string()
        },
        params: params.join(", "),
    }
}

fn build_method(graph: &KnowledgeGraph, address: &str, is_constructor: bool, is_destructor: bool) -> Option<RecoveredMethod> {
    let raw_name = latest(graph, address, "has_name")?.value.clone();
    let signature = latest(graph, address, "has_signature").map(|o| o.value.clone()).unwrap_or_default();
    let decompilation = latest(graph, address, "decompiles_to").map(|o| o.value.clone()).unwrap_or_default();
    let (display_name, name_source) = name_source(graph, address).unwrap_or_else(|| (raw_name.clone(), NameSource::Raw));
    let parsed = parse_signature(&signature, &raw_name);

    Some(RecoveredMethod {
        address: address.to_string(),
        raw_name,
        display_name,
        name_source,
        return_type: parsed.return_type,
        params: parsed.params,
        is_constructor,
        is_destructor,
        decompilation,
    })
}

fn build_class(graph: &KnowledgeGraph, name: &str) -> RecoveredClass {
    let vtable_address = latest(graph, name, "has_vtable_at")
        .map(|o| o.value.clone())
        .unwrap_or_default();
    let base = latest(graph, name, "inherits_from").map(|o| o.value.clone());

    let mut fields_by_offset: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for o in graph.observations().filter(|o| o.subject == name && o.predicate == "has_field_candidate") {
        if let Some((offset, field_type)) = o.value.split_once(':') {
            fields_by_offset
                .entry(offset.to_string())
                .or_default()
                .insert(field_type.to_string());
        }
    }
    let fields = fields_by_offset
        .into_iter()
        .map(|(offset, types)| RecoveredField {
            offset,
            candidate_types: types.into_iter().collect(),
        })
        .collect();

    let mut method_addresses: BTreeSet<String> = BTreeSet::new();
    let mut ctor_addresses: BTreeSet<String> = BTreeSet::new();
    let mut dtor_addresses: BTreeSet<String> = BTreeSet::new();
    for o in graph.observations() {
        if o.value != name {
            continue;
        }
        match o.predicate.as_str() {
            "is_method_of" => {
                method_addresses.insert(o.subject.clone());
            }
            "is_constructor_of" => {
                ctor_addresses.insert(o.subject.clone());
            }
            "is_destructor_of" => {
                dtor_addresses.insert(o.subject.clone());
            }
            _ => {}
        }
    }

    // `is_method_of` is emitted unconditionally for anything with an owner
    // class (debura-analysis), including constructors/destructors -- so
    // exclude those addresses here; they're handled by their own sets
    // below, and leaving them in `method_addresses` would render the same
    // address a second time under the generic (non-ctor/dtor) format.
    let method_addresses: BTreeSet<String> = method_addresses
        .into_iter()
        .filter(|a| !ctor_addresses.contains(a) && !dtor_addresses.contains(a))
        .collect();

    // Itanium ABI emits multiple destructor variants (deleting, complete,
    // base-object) at different addresses -- all conceptually "the"
    // destructor. A class can only declare one, so only the lowest address
    // is kept. Constructors are left alone: unlike destructors they can be
    // legitimately overloaded, so collapsing them could hide a real one.
    let dtor_addresses: BTreeSet<String> = dtor_addresses.into_iter().take(1).collect();

    let all_addresses: BTreeSet<&String> = method_addresses
        .iter()
        .chain(ctor_addresses.iter())
        .chain(dtor_addresses.iter())
        .collect();

    let methods = all_addresses
        .into_iter()
        .filter_map(|addr| build_method(graph, addr, ctor_addresses.contains(addr), dtor_addresses.contains(addr)))
        .collect();

    RecoveredClass {
        name: name.to_string(),
        base,
        vtable_address,
        fields,
        methods,
        // Filled in by `extract()` once every class's name is known --
        // finding a *reference* to another class requires the full set,
        // not just this one class's own facts.
        references: Vec::new(),
    }
}

/// Splits on anything that isn't part of a C identifier, the same shape
/// a type name or parameter list is made of (`Screen *`, `int, Screen *`,
/// ...) -- used to find other recovered classes' names inside a
/// method's params/return type/field candidate types without needing a
/// real C++ parser.
fn identifier_tokens(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|t| !t.is_empty())
}

/// Every other known class name `class` mentions in its own
/// methods'/fields' signatures -- what needs its own `#include` beyond
/// `class.base` (handled separately, since that relationship also needs
/// `class ... : public Base`, not just an include).
fn find_references(class: &RecoveredClass, class_names: &BTreeSet<String>) -> Vec<String> {
    let mut refs: BTreeSet<String> = BTreeSet::new();
    let mut consider = |text: &str| {
        for token in identifier_tokens(text) {
            if token != class.name
                && Some(token) != class.base.as_deref()
                && class_names.contains(token)
            {
                refs.insert(token.to_string());
            }
        }
    };
    for m in &class.methods {
        consider(&m.params);
        consider(&m.return_type);
        // A class can be used only inside a method's body (e.g.
        // constructing one) without ever appearing in that method's own
        // signature -- Snake's addSection doing `new Section(...)` is a
        // real instance of this, and needs the same #include.
        consider(&m.decompilation);
    }
    for f in &class.fields {
        for t in &f.candidate_types {
            consider(t);
        }
    }
    refs.into_iter().collect()
}

/// Extracts everything Debura currently has grounds to recover (PROJECT.md
/// M9): every class with a detected vtable (M7) *or* with at least one
/// method/constructor/destructor of its own (a real class the binary
/// defines, just not a polymorphic one -- `has_vtable_at` alone missed
/// this: a real run had non-polymorphic classes referenced by name in an
/// already-recovered class's method signatures, e.g. `Food::draw(Screen
/// *)`, with `Screen` itself never declared anywhere in the output), and
/// every standalone function that has actually earned an ACCEPTED
/// semantic name (M5) -- nothing else counts as "recovered".
pub fn extract(graph: &KnowledgeGraph) -> RecoveredProgram {
    let mut class_names: BTreeSet<String> = BTreeSet::new();
    let mut class_method_addresses: BTreeSet<String> = BTreeSet::new();
    for o in graph.observations() {
        match o.predicate.as_str() {
            "has_vtable_at" => {
                class_names.insert(o.subject.clone());
            }
            "is_method_of" | "is_constructor_of" | "is_destructor_of" => {
                class_method_addresses.insert(o.subject.clone());
                class_names.insert(o.value.clone());
            }
            _ => {}
        }
    }

    let mut classes: Vec<RecoveredClass> =
        class_names.iter().map(|name| build_class(graph, name)).collect();
    for class in &mut classes {
        class.references = find_references(class, &class_names);
    }

    // One entry per *subject*, not per hypothesis: several ACCEPTED
    // semantic_role hypotheses can exist for the same address (see
    // `accepted_name`'s doc comment), and rendering all of them produced
    // duplicate function definitions with identical names in the same
    // file -- not valid C++.
    let mut subjects: BTreeSet<String> = BTreeSet::new();
    for h in graph
        .hypotheses()
        .filter(|h| h.predicate == "semantic_role" && h.status == HypothesisStatus::Accepted)
    {
        subjects.insert(h.subject.clone());
    }

    let mut functions = Vec::new();
    for subject in subjects {
        if class_method_addresses.contains(&subject) {
            continue; // already represented as a class method
        }
        let Some(raw_name) = latest(graph, &subject, "has_name").map(|o| o.value.clone()) else {
            continue; // not a function subject at all
        };
        // It earned ACCEPTED on some semantic_role proposal (that's why
        // it's in `subjects`), but that specific value might not be a
        // usable identifier -- name_source() falls back to Ghidra's raw
        // name rather than losing the function entirely in that case.
        let (display_name, name_source) =
            name_source(graph, &subject).unwrap_or_else(|| (raw_name.clone(), NameSource::Raw));
        let signature = latest(graph, &subject, "has_signature")
            .map(|o| o.value.clone())
            .unwrap_or_default();
        let decompilation = latest(graph, &subject, "decompiles_to")
            .map(|o| o.value.clone())
            .unwrap_or_default();
        let parsed = parse_signature(&signature, &raw_name);

        functions.push(RecoveredFunction {
            address: subject,
            raw_name,
            display_name,
            name_source,
            return_type: parsed.return_type,
            params: parsed.params,
            decompilation,
        });
    }
    functions.sort_by(|a, b| a.address.cmp(&b.address));

    RecoveredProgram { classes, functions }
}
