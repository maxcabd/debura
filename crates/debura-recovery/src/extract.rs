use std::collections::{BTreeMap, BTreeSet, HashMap};

use debura_knowledge::{
    classify_provenance, is_reserved_identifier, Hypothesis, HypothesisStatus, KnowledgeGraph,
    Observation, Provenance,
};

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

/// `decompiles_to` specifically needs a different tiebreak than `latest`'s
/// general "highest id wins": a real case had a subject with two
/// observations, an earlier one carrying the real, full decompiled body
/// and a later one (a second Ghidra pass, M8's `reextract`) carrying a
/// degenerate `{...}` placeholder -- `latest` silently threw the real
/// body away in favor of the newer-but-worse one, rendering a body that
/// was literally the three characters `...`. Prefers the most recent
/// *substantive* decompilation over the most recent of any kind, falling
/// back to the latest overall only if every one on record is degenerate.
fn latest_decompilation<'a>(graph: &'a KnowledgeGraph, subject: &str) -> Option<&'a Observation> {
    let mut candidates: Vec<&Observation> = graph
        .observations()
        .filter(|o| o.subject == subject && o.predicate == "decompiles_to")
        .collect();
    candidates.sort_by_key(|o| o.id.0);
    candidates
        .iter()
        .rev()
        .find(|o| !is_degenerate_decompilation(&o.value))
        .or_else(|| candidates.last())
        .copied()
}

/// A decompilation whose body is empty or just an elided `{...}`
/// placeholder -- Ghidra emits this on some re-analysis passes for a
/// subject it successfully decompiled fully on an earlier pass.
fn is_degenerate_decompilation(text: &str) -> bool {
    match text.find('{') {
        Some(idx) => matches!(text[idx..].trim(), "{...}" | "{ ... }"),
        None => true,
    }
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
    /// Whether an explicit `this`-named leading parameter was found and
    /// dropped. Only true for a method Ghidra's own type system
    /// recognized (`has_signature`/`decompiles_to` then spell the
    /// receiver out as `Class *this`) -- a method M7's *structural*
    /// vtable detection found instead, never recognized by Ghidra as a
    /// method at all, has its receiver sitting in the header as an
    /// ordinary `param_1`, indistinguishable by name from a real
    /// argument, so nothing is stripped and this is `false`. Needed by
    /// `build_symbol_table`: a call site's own leading argument always
    /// supplies the receiver either way, and it must be added back to
    /// `expected_args` only when `params` doesn't already include it --
    /// a real link found this wasn't previously tracked at all, so
    /// `expected_args` double-counted the receiver for every
    /// structurally-discovered method and rejected all 3 of their real
    /// call sites as an arity mismatch, even though the methods
    /// themselves compiled fine.
    receiver_stripped: bool,
}

/// Strips a leading parameter named `this` from `params` -- the receiver
/// Ghidra's own type system explicitly recognized, as opposed to one
/// M7's structural detection found that still sits in the list as an
/// ordinary `param_1`. Returns whether it actually found and stripped
/// one, shared between `parse_signature` and `params_from_decompilation`
/// so both sources of a method's params track this the same way.
fn strip_recognized_this_param(params: &mut Vec<&str>) -> bool {
    if params.first().is_some_and(|p| p.ends_with("this")) {
        params.remove(0);
        true
    } else {
        false
    }
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
    let receiver_stripped = strip_recognized_this_param(&mut params);

    ParsedSignature {
        return_type: if return_type.is_empty() {
            "void".to_string()
        } else {
            return_type.to_string()
        },
        params: params.join(", "),
        receiver_stripped,
    }
}

/// `has_signature` and the signature line embedded at the top of
/// `decompiles_to` are supposed to describe the same function, but a real
/// compile found dozens of cases where they disagree: `has_signature`
/// claims `(void)` while `decompiles_to`'s own header -- captured
/// together with the body that follows it, so always self-consistent --
/// lists real parameters (`param_1`, `param_2`, ...) the body actually
/// references. Trusting the stale `has_signature` params rendered a
/// method whose body referenced undeclared identifiers. Preferring the
/// decompiled header's own params whenever a body is available fixes this
/// at the source instead of patching each symptom; `None` (falling back
/// to `has_signature`'s own params) only when there's no decompiled body
/// to check against at all. Returns the same `receiver_stripped` signal
/// `parse_signature` does, and for the same reason.
fn params_from_decompilation(decompilation: &str) -> Option<(String, bool)> {
    let header_end = decompilation.find('{')?;
    // Ghidra sometimes emits `/* WARNING: ... (addr, addr) */` comments
    // before the real signature line -- a real case had exactly this,
    // and a naive search for the first `(` grabbed the warning's own
    // parenthesized address pair instead of the function's parameter
    // list. Strip comments first so only real code is searched.
    let header = strip_c_comments(&decompilation[..header_end]);
    let open = header.find('(')?;
    let close = header.rfind(')')?;
    if close <= open {
        return None;
    }
    let mut params: Vec<&str> = header[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    let receiver_stripped = strip_recognized_this_param(&mut params);
    Some((params.join(", "), receiver_stripped))
}

/// Removes every `/* ... */` block from `text` -- just enough to keep
/// Ghidra's own `/* WARNING: ... */` decompiler notes from being mistaken
/// for real code when searching for the real signature's parens.
fn strip_c_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        rest = match rest[start..].find("*/") {
            Some(end) => &rest[start + end + 2..],
            None => "",
        };
    }
    out.push_str(rest);
    out
}

fn build_method(
    graph: &KnowledgeGraph,
    address: &str,
    class_name: &str,
    is_constructor: bool,
    is_destructor: bool,
) -> Option<RecoveredMethod> {
    let raw_name = latest(graph, address, "has_name")?.value.clone();
    let signature = latest(graph, address, "has_signature").map(|o| o.value.clone()).unwrap_or_default();
    let decompilation = latest_decompilation(graph, address).map(|o| o.value.clone()).unwrap_or_default();
    let (display_name, name_source) = name_source(graph, address).unwrap_or_else(|| (raw_name.clone(), NameSource::Raw));
    let parsed = parse_signature(&signature, &raw_name);

    // Itanium ABI's calling convention returns `this` in the return
    // register for `operator=`, which Ghidra always decompiles as
    // `return this;` -- but Ghidra can't tell a pointer return from a
    // reference return apart at that level, so it leaves the return
    // type as `undefined` (real compile hit exactly this: `undefined`
    // can't hold a class pointer, `invalid conversion from 'Drawable*'
    // to 'undefined'`). `ClassName *` matches what the body actually
    // returns.
    let return_type = if raw_name == "operator=" {
        format!("{class_name} *")
    } else {
        parsed.return_type
    };

    let (params, receiver_stripped) =
        params_from_decompilation(&decompilation).unwrap_or((parsed.params, parsed.receiver_stripped));

    Some(RecoveredMethod {
        address: address.to_string(),
        raw_name,
        display_name,
        name_source,
        return_type,
        params,
        is_constructor,
        is_destructor,
        receiver_stripped,
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
        .filter_map(|addr| build_method(graph, addr, name, ctor_addresses.contains(addr), dtor_addresses.contains(addr)))
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

/// Ghidra's own auto-generated names for data it found referenced but
/// couldn't otherwise identify -- `DAT_140009070` (an address holding a
/// value, type unknown), `PTR_draw_140009a40` (an address holding a
/// pointer, likely a vtable slot), `_refptr__ZN...E` (a reference thunk
/// to a relocated global). None of these are declared anywhere in
/// recovered output otherwise, so referencing one fails outright. Real
/// prefixes actually observed compiling the Snake fixture -- there are
/// other Ghidra auto-name families (`UNK_`, `s_...` string labels) not
/// included here since nothing yet demonstrated a real file needing them.
///
/// `LAB_140001000` belongs here too, handled at the renderer level
/// (PROJECT.md M15) rather than through the symbol table: a real run
/// showed it isn't a goto target at all (that shape -- `goto LAB_x;`
/// with a `LAB_x:` label already present in the same body -- was already
/// valid C++ and needed no help) but the address of a *label* taken as a
/// value (`(_invalid_parameter_handler)&LAB_140001000`, a real MinGW
/// CRT startup idiom for registering an exception/parameter handler).
/// C++ keeps goto-labels and ordinary identifiers in separate
/// namespaces, so declaring `LAB_x` as an extern placeholder here can
/// never collide with a real `LAB_x:` label statement elsewhere in the
/// same function.
const GHIDRA_DATA_SYMBOL_PREFIXES: &[&str] = &["DAT_", "PTR_", "_refptr_", "LAB_"];

fn ghidra_data_symbol_tokens(text: &str) -> impl Iterator<Item = &str> {
    identifier_tokens(text)
        .filter(|token| GHIDRA_DATA_SYMBOL_PREFIXES.iter().any(|prefix| token.starts_with(prefix)))
}

/// Ghidra's own width-combining/splitting intrinsic names -- see
/// `compat::render_ghidra_intrinsics` for what each family means.
/// Recognized structurally (a known prefix followed by exactly two
/// digits), the same reasoning as `ghidra_data_symbol_tokens`, so a new
/// width pairing this project happens to need doesn't require touching
/// this list at all.
const GHIDRA_INTRINSIC_PREFIXES: &[&str] = &["CONCAT", "ZEXT", "SEXT", "SUB"];

fn ghidra_intrinsic_tokens(text: &str) -> impl Iterator<Item = &str> {
    identifier_tokens(text).filter(|token| {
        GHIDRA_INTRINSIC_PREFIXES.iter().any(|prefix| {
            token.strip_prefix(prefix).is_some_and(|rest| {
                rest.len() == 2 && rest.chars().all(|c| c.is_ascii_digit())
            })
        })
    })
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

/// Same idea as `find_references`, for the shared `functions.cpp` file:
/// a real run had a standalone function's rewritten body doing `new
/// (ptr) Wall(...)` (M15's symbol resolution turning a raw `FUN_ctor`
/// call into a real constructor call) with nothing in `functions.cpp`
/// ever including `Wall.hpp` -- the class-reference scan only ever
/// looked at *class* methods, since standalone functions calling into a
/// class wasn't a shape that existed before call sites got resolved.
fn find_function_references(functions: &[RecoveredFunction], class_names: &BTreeSet<String>) -> Vec<String> {
    let mut refs: BTreeSet<String> = BTreeSet::new();
    for f in functions {
        for text in [&f.params, &f.return_type, &f.decompilation] {
            for token in identifier_tokens(text) {
                if class_names.contains(token) {
                    refs.insert(token.to_string());
                }
            }
        }
    }
    refs.into_iter().collect()
}

/// PROJECT.md M15: two unrelated addresses independently earning the
/// same generic mechanical_behavior-derived name (`invokeFunction`,
/// `noOperation`) is common once naming leans conservative -- a real
/// compile hit "redefinition" errors from exactly this, in
/// `functions.cpp`'s single shared scope. Renaming only the ones that
/// actually collide (same name *and* the same param list -- a genuine
/// overload, with different params, is left alone) keeps an
/// already-unique name untouched, only appending `_<address>` where two
/// recovered symbols would otherwise conflict. Must run before the
/// symbol table is built, so resolved call sites use the final,
/// disambiguated name rather than the pre-rename one.
fn disambiguate_function_names(functions: &mut [RecoveredFunction]) {
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for f in functions.iter() {
        *counts.entry((f.display_name.clone(), f.params.clone())).or_insert(0) += 1;
    }
    for f in functions.iter_mut() {
        let key = (f.display_name.clone(), f.params.clone());
        if counts[&key] > 1 {
            let suffix = f.address.trim_start_matches("0x");
            f.display_name = format!("{}_{}", f.display_name, suffix);
        }
    }
}

/// Same reasoning as `disambiguate_function_names`, scoped to one
/// class's own methods instead of the whole program -- a plain (non-
/// ctor/dtor) method name colliding with a sibling method's name and
/// param list in the same class is the same kind of C++ redefinition.
/// Constructors/destructors are skipped: their name is fixed by the
/// language (the class's own name), not something this can rename, and
/// genuine constructor overloading at different addresses is expected,
/// not a bug.
fn disambiguate_method_names(methods: &mut [RecoveredMethod]) {
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for m in methods.iter().filter(|m| !m.is_constructor && !m.is_destructor) {
        *counts.entry((m.display_name.clone(), m.params.clone())).or_insert(0) += 1;
    }
    for m in methods.iter_mut() {
        if m.is_constructor || m.is_destructor {
            continue;
        }
        let key = (m.display_name.clone(), m.params.clone());
        if counts[&key] > 1 {
            let suffix = m.address.trim_start_matches("0x");
            m.display_name = format!("{}_{}", m.display_name, suffix);
        }
    }
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
    // PROJECT.md M15: a real run found libstdc++/CRT-internal classes
    // (`_Guard`, `_Vector_impl`, `__class_type_info`) getting the exact
    // same recovery treatment as real application classes -- rendered
    // into their own .hpp/.cpp files that then fail to compile (they
    // call into MinGW runtime internals like HeapAlloc/EnterCriticalSection
    // that a normal g++ build already supplies for free, so "recovering"
    // them as if they were missing application code was never right to
    // begin with). `is_reserved_identifier` is the same C++-standard-
    // reserved-name convention `classify_subject` uses for the stats
    // split; applied here, it keeps them out of the generated output
    // entirely rather than just flagging them in a metric.
    let mut class_names: BTreeSet<String> = BTreeSet::new();
    let mut class_method_addresses: BTreeSet<String> = BTreeSet::new();
    for o in graph.observations() {
        match o.predicate.as_str() {
            "has_vtable_at" if !is_reserved_identifier(&o.subject) => {
                class_names.insert(o.subject.clone());
            }
            "is_method_of" | "is_constructor_of" | "is_destructor_of"
                if !is_reserved_identifier(&o.value) =>
            {
                class_method_addresses.insert(o.subject.clone());
                class_names.insert(o.value.clone());
            }
            _ => {}
        }
    }

    let mut classes: Vec<RecoveredClass> =
        class_names.iter().map(|name| build_class(graph, name)).collect();
    for class in &mut classes {
        disambiguate_method_names(&mut class.methods);
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
        if classify_provenance(graph, &subject) != Provenance::Application {
            // Same reasoning as the class-name filter above, extended to
            // the harder case: a standalone function whose own name
            // looks like application code, but whose behavior is really
            // an inlined library/compiler instantiation (a real run's
            // `constructString`, whose entire body was calls into
            // std::string's own private `_M_create`/`_M_data`/
            // `_M_capacity`/`_M_set_length`) doesn't need recovering
            // either -- a real g++ build already supplies whatever
            // std::string itself does. Excludes `Unknown` too (PROJECT.md
            // M17): this reevaluate_hypothesis's provenance gate should
            // already keep an Unknown-provenance subject from reaching
            // ACCEPTED at all, but a subject accepted before that gate
            // existed (an older project re-recovered) still shouldn't be
            // rendered under a name nothing ever confirmed was safe to
            // apply.
            continue;
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
        let decompilation = latest_decompilation(graph, &subject)
            .map(|o| o.value.clone())
            .unwrap_or_default();
        let parsed = parse_signature(&signature, &raw_name);
        // A standalone function has no receiver at all -- only the
        // params text matters here, never the stripped-receiver signal
        // methods need.
        let params = params_from_decompilation(&decompilation).map(|(p, _)| p).unwrap_or(parsed.params);

        functions.push(RecoveredFunction {
            address: subject,
            raw_name,
            display_name,
            name_source,
            return_type: parsed.return_type,
            params,
            decompilation,
        });
    }
    functions.sort_by(|a, b| a.address.cmp(&b.address));
    disambiguate_function_names(&mut functions);

    // PROJECT.md M15: resolve every `FUN_<addr>`/`thunk_FUN_<addr>` call
    // site against the whole-program symbol table *before* anything else
    // reads these bodies -- both `find_references` below (so a call
    // rewritten into `new (this) Section(...)` makes "Section" a token
    // `find_references` can actually see, the same way it already finds
    // a class name mentioned in a signature) and the ghidra_data_symbols
    // scan need the rewritten text, not Ghidra's raw pseudocode.
    let symbol_table = crate::symtab::build_symbol_table(&classes, &functions);
    let mut unresolved_calls: BTreeSet<String> = BTreeSet::new();
    for class in &mut classes {
        for m in &mut class.methods {
            m.decompilation =
                crate::symtab::rewrite_call_sites(&m.decompilation, &symbol_table, &mut unresolved_calls);
        }
    }
    for f in &mut functions {
        f.decompilation =
            crate::symtab::rewrite_call_sites(&f.decompilation, &symbol_table, &mut unresolved_calls);
    }

    for class in &mut classes {
        class.references = find_references(class, &class_names);
    }
    let function_references = find_function_references(&functions, &class_names);

    let mut ghidra_data_symbols: BTreeSet<String> = BTreeSet::new();
    let mut ghidra_intrinsics: BTreeSet<String> = BTreeSet::new();
    for class in &classes {
        for m in &class.methods {
            ghidra_data_symbols.extend(ghidra_data_symbol_tokens(&m.decompilation).map(str::to_string));
            ghidra_intrinsics.extend(ghidra_intrinsic_tokens(&m.decompilation).map(str::to_string));
        }
    }
    for f in &functions {
        ghidra_data_symbols.extend(ghidra_data_symbol_tokens(&f.decompilation).map(str::to_string));
        ghidra_intrinsics.extend(ghidra_intrinsic_tokens(&f.decompilation).map(str::to_string));
    }

    RecoveredProgram {
        classes,
        functions,
        function_references,
        ghidra_data_symbols: ghidra_data_symbols.into_iter().collect(),
        ghidra_intrinsics: ghidra_intrinsics.into_iter().collect(),
        unresolved_calls: unresolved_calls.into_iter().collect(),
    }
}
