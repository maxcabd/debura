use std::collections::HashMap;

use debura_knowledge::KnowledgeGraph;

use crate::forwarding_thunk::split_top_level_comma;
use crate::phantom_local::{find_calls, strip_casts_and_parens};
use crate::symtab::{SymbolKind, SymbolTable};

/// What a `DAT_*`/`PTR_*`/`LAB_*`/`_refptr_*` linker placeholder actually
/// is, derived from real Ghidra-extracted facts (PROJECT.md M18.2) --
/// never from its own name shape. `DAT_`/`PTR_` are Ghidra's own
/// renderings, not evidence of anything; the deciding signal is always a
/// `debura_knowledge` observation (section, permissions, a resolved
/// pointee, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataSymbolKind {
    /// This address's own value is a pointer to a real, recovered
    /// standalone (free) function -- safe to bind symbolically
    /// (`&recovered_name`), never to a raw address baked into the new
    /// binary (a real run's own design correction: the *original*
    /// binary's address means nothing in a freshly compiled one).
    FunctionPointerAlias { target_function: String },
    /// This address's own value points to real memory Debura has no
    /// model of at all -- not a known function, not a known import, not
    /// inside any recovered class's vtable range. Still real, resolved
    /// evidence (unlike `UnknownData`, which has no pointee at all) --
    /// just evidence that the target is genuinely outside anything
    /// Debura currently recovers (a CRT/runtime/libstdc++ global).
    /// Belongs to a real runtime/linkage resolver, not AI source
    /// recovery.
    ExternalGlobalAlias { pointee: String },
    /// This address's own value is a pointer to *another* address Ghidra
    /// gave its own real symbol name and Debura has full, confident
    /// evidence for (a real size, real captured bytes, a real sized
    /// type) -- just never independently collected, because nothing in
    /// any recovered body's own decompiled *text* ever named that
    /// pointee directly (only this pointer's own name appears there). A
    /// real run found this for every "PTR_DAT_*" wrapper around an
    /// otherwise-ordinary `.rdata` constant: not an external/runtime
    /// symbol at all, just one more hop of the same evidence this module
    /// already trusts for `ConstantData`/`MutableStaticData`. Unlike
    /// `ExternalGlobalAlias`, this always gets a real definition: both
    /// `target_symbol`'s own value (rendered from the same evidence
    /// `ConstantData`/`MutableStaticData` would be) and this pointer,
    /// bound to its address.
    DataPointerAlias { target_symbol: String },
    /// This address's own pointee is a real, well-known symbol the MinGW
    /// toolchain's own linker provides at link time -- never fabricated
    /// bytes, never a guess from this symbol's own name (only ever set
    /// from the *pointee's* independently-observed type+section, the
    /// same discipline `ExternalGlobalAlias`/`DataPointerAlias` already
    /// follow). Currently recognizes exactly one real, structural case:
    /// a pointee Ghidra typed `IMAGE_DOS_HEADER` in its own synthetic
    /// "Headers" section -- the PE image's own DOS header, always at the
    /// module's real load address, which every MinGW-linked binary
    /// exposes as `__ImageBase`. Binding to the toolchain-provided symbol
    /// (rather than emitting the *original* binary's own captured header
    /// bytes) matters: a freshly linked binary's own image base
    /// genuinely differs from the original's, so copying the old bytes
    /// would be actively wrong, not just unhelpful -- the same reasoning
    /// `crt_boundary` already applies to the binary's own CRT-startup
    /// code.
    RuntimeAlias { runtime_symbol: String, runtime_type: String },
    /// This address's own pointee is a real import Ghidra's own analysis
    /// already resolved by exact qualified name (a `debura_knowledge`
    /// `imports` fact -- Ghidra's own EXTERNAL-address-space import/
    /// relocation resolution, a structural fact about the ORIGINAL
    /// binary, never a guess from this symbol's own auto-generated
    /// `PTR_*` name shape), matching a small, fixed, real allowlist of
    /// C++ standard-library globals safe to bind to directly (currently
    /// just `std::cout`, the one real case a real run found: Ghidra
    /// resolved `PTR_cout_14000f688`'s own outgoing reference to its
    /// real EXTERNAL-space import, named `std!cout` in the extracted
    /// facts). Unlike `ExternalGlobalAlias` (a known import Debura has
    /// no safe binding for, or an import outside this allowlist), this
    /// always gets a real definition: the qualified name is already
    /// declared by whatever standard header the recovered code already
    /// includes (`<iostream>` for `std::cout`), so binding needs nothing
    /// beyond taking its address.
    KnownImportAlias { qualified_name: String },
    /// A real, bounded-size, initialized, non-pointer object with known
    /// content -- typically `.rdata` (read-only). Safe to emit its exact
    /// captured bytes: unlike an address-shaped value, raw content bytes
    /// mean the same thing regardless of where the new binary places
    /// anything.
    ConstantData { size: u64, bytes: Vec<u8> },
    /// Same as `ConstantData` but writable (`.data`/`.bss`-shaped) --
    /// real mutable global storage, not a compile-time constant.
    MutableStaticData { size: u64, bytes: Vec<u8> },
    /// Sits in the real `.CRT` section -- MinGW's own static-initializer/
    /// pseudo-relocation bookkeeping, not application data. Belongs to
    /// the runtime/linkage layer, same reasoning as `ExternalGlobalAlias`.
    RuntimeData,
    /// This address is exactly a known class's own vtable's first virtual
    /// slot (`has_vtable_at` + 0x10, the Itanium ABI's `vfunc0`) --
    /// reuses M7's own already-verified vtable model rather than
    /// re-deriving anything from this address's own raw bytes (which a
    /// real run found badly undersized here: the generic size heuristic
    /// bounds on the *next* symbol, which for a vtable slot is often the
    /// very next slot, 8 bytes later -- nowhere near this record's real
    /// significance).
    VtableData { class_name: String, slot0_target: Option<VtableSlotTarget> },
    /// This address's own section/permissions say it's real, executable
    /// code (`.text`, `executable=true`) -- a label taken as a value
    /// (a real, documented MinGW CRT idiom: registering a handler
    /// callback by address), not data at all. Correctly classified, not
    /// emitted as anything here -- see this module's own top-level doc
    /// comment on why fabricating a stub isn't attempted in this pass.
    CodeAddressAlias,
    /// No real evidence supports any of the above -- either no confident
    /// size/content is known at all, or nothing else matched. Left
    /// unresolved (a plain `extern` declaration, same as before this
    /// module existed): "Unknown is better than confidently wrong"
    /// applies to global data exactly the way it already does to
    /// semantic naming.
    UnknownData,
    /// PROJECT.md, "Deterministic string-literal extraction": this
    /// address's own real content is a string, from one of two real,
    /// deterministic sources -- Ghidra's own `contains_string` typing (a
    /// genuine `.rdata`/`.data` string constant), or a literal argument
    /// found in a real constructor call this address's own address is
    /// passed to (the confirmed real case: a global `std::string` like
    /// Snake's own `DAT_14000e0c0`, which has no static content of its
    /// own at all -- `.bss`, uninitialized -- but whose real value
    /// (`"Lives: "`) is already sitting, unused until now, in the
    /// decompiled text of the static initializer that constructs it).
    /// Never a raw-bytes decode guess (a real `contains_string` fact or a
    /// real literal argument, nothing heuristic). See
    /// `find_constructor_string_literals` below for the second source.
    StringLiteral(String),
}

/// A vtable slot's real value, once resolved (PROJECT.md M18.3). Itanium
/// ABI vtables store a plain code pointer in every slot -- true whether
/// the slot's own function is a free function or a class method -- but a
/// *portable C++ expression* can only produce that same plain pointer
/// from a free function (`&some_function`). `&Class::method` yields a
/// pointer-to-member, a different, non-portable, differently-sized
/// representation the Itanium ABI's real vtable slots never actually
/// use this way; deliberately never faked as one (the whole reason this
/// type exists instead of a bare `Option<String>` the way this field
/// used to be).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VtableSlotTarget {
    /// Safe to bind directly -- no member-function-pointer conversion
    /// needed at all.
    FreeFunction(String),
    /// The slot's real target is a recovered class method.
    /// `render_functions_source` synthesizes `trampoline_name` as a
    /// small, real, static free function in `functions.cpp` that
    /// forwards to the real method call (the exact reverse of what
    /// `symtab.rs`'s own call-site rewriting already does) -- a real,
    /// portable, plain function pointer this slot's own symbol binds to
    /// instead of the method itself.
    Method {
        trampoline_name: String,
        owner: String,
        method_name: String,
        return_type: String,
        params: String,
    },
}

/// One data symbol's classification, together with what real observation
/// predicates justified it -- so a caller can always answer "why did
/// Debura emit this" (PROJECT.md M18.2), not just "what". `confidence` is
/// currently a coarse "how many independent real facts agreed" measure,
/// not yet a calibrated probability -- source_facts is what actually
/// matters and is kept even at confidence 1.0, since a later type/alias
/// revision needs the same trail.
#[derive(Debug, Clone)]
pub struct DataResolution {
    pub address: String,
    pub symbol_name: String,
    pub kind: DataSymbolKind,
    pub source_facts: Vec<String>,
    pub confidence: f64,
}

/// The address a Ghidra-generated placeholder name embeds in its own
/// trailing hex digits -- true for every shape this project has seen
/// (`DAT_140009070`, `PTR_FUN_140009a00`, `PTR_IMAGE_DOS_HEADER_140009710`,
/// `PTR_PTR_cout_1400096e0`, `_refptr__ZN...E` is the one exception, see
/// below). Ghidra always places the address as the *last* underscore-
/// delimited run of hex digits, regardless of how many named components
/// (`IMAGE_DOS_HEADER`, `PTR_cout`, ...) come before it.
fn address_from_symbol_name(name: &str) -> Option<String> {
    let hex = name.rsplit('_').find(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_hexdigit()))?;
    if hex.chars().all(|c| c.is_ascii_digit()) {
        // All-decimal-digit runs (rare, but a real class name or a purely
        // numeric-looking component could match `is_ascii_hexdigit`)
        // aren't a real address in this codebase's own convention --
        // every real one seen has at least one a-f digit or is
        // unambiguously long enough to be a real 64-bit offset. Requiring
        // at least 6 hex digits (matching this project's own addresses,
        // all `0x14000....`-shaped) avoids misreading a short numeric
        // suffix as an address.
        if hex.len() < 6 {
            return None;
        }
    }
    Some(format!("0x{}", hex.to_lowercase()))
}

fn single_value(graph: &KnowledgeGraph, subject: &str, predicate: &str) -> Option<String> {
    graph.observations().filter(|o| o.subject == subject && o.predicate == predicate).max_by_key(|o| o.id.0).map(|o| o.value.clone())
}

fn bool_value(graph: &KnowledgeGraph, subject: &str, predicate: &str) -> Option<bool> {
    single_value(graph, subject, predicate).and_then(|v| v.parse().ok())
}

fn parse_hex_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Every known class's own vtable's `vfunc0` address (`has_vtable_at` +
/// 0x10, the Itanium ABI convention M7's own extraction already
/// documents) mapped back to the class name -- confirmed against the
/// real Snake binary: `Collideable`'s `has_vtable_at` (0x1400099d0) + 0x10
/// exactly equals `DAT_1400099e0`'s own address, and the same holds for
/// every other recovered class with a vtable.
fn vfunc0_addresses(graph: &KnowledgeGraph) -> Vec<(String, String)> {
    graph
        .observations()
        .filter(|o| o.predicate == "has_vtable_at")
        .filter_map(|o| {
            let base = u64::from_str_radix(o.value.trim_start_matches("0x"), 16).ok()?;
            Some((o.subject.clone(), format!("0x{:x}", base + 0x10)))
        })
        .collect()
}

/// Slot 0's own recovered function address for `class_name`, from
/// `has_virtual_method`'s own `"slot {n}: {address}"` value shape
/// (`debura-analysis`'s ingest of M7's `virtual_methods` fact).
fn vtable_slot0_function(graph: &KnowledgeGraph, class_name: &str) -> Option<String> {
    graph
        .observations()
        .filter(|o| o.subject == class_name && o.predicate == "has_virtual_method")
        .find_map(|o| {
            let rest = o.value.strip_prefix("slot 0: ")?;
            Some(rest.to_string())
        })
}

/// A vtable-slot trampoline's own deterministic name (PROJECT.md M18.3)
/// -- computed the same way everywhere it's needed (here, and again in
/// `extract.rs` when deduplicating the actual `VtableTrampoline` specs
/// to emit) so the two never drift apart. `owner`/`method_name` are
/// always valid C++ identifiers already (a real class name, a real
/// `FUN_<addr>`/recovered method name), so no sanitizing is needed.
pub(crate) fn vtable_trampoline_name(owner: &str, method_name: &str) -> String {
    format!("{owner}__vtable_trampoline_{method_name}")
}

/// Whether `address` is a real, Ghidra-recognized function -- present via
/// `calling_convention`, a fact `ExtractFacts.py` only ever emits for a
/// genuine `Function` object, never for data.
fn is_known_function(graph: &KnowledgeGraph, address: &str) -> bool {
    graph.observations().any(|o| o.subject == address && o.predicate == "calling_convention")
}

fn is_known_import(graph: &KnowledgeGraph, address: &str) -> bool {
    graph.observations().any(|o| o.subject == address && o.predicate == "imports")
}

/// `KnownImportAlias`'s own fixed, real allowlist -- see that variant's
/// doc comment for why this is safe to trust (Ghidra's own real
/// EXTERNAL-space import resolution, never this symbol's own name
/// shape). Deliberately narrow: `std::cout` is the one real case a real
/// run found; nothing else is added speculatively. `import_value` is
/// `debura-analysis`'s own `"{namespace}!{name}"` rendering of an
/// `imports` fact (see `ghidra/scripts/ExtractFacts.py::extract_imports`).
fn known_import_alias(import_value: Option<&str>) -> Option<String> {
    match import_value?.split_once('!')? {
        ("std", "cout") => Some("std::cout".to_string()),
        _ => None,
    }
}

/// The same "is this address's own size real evidence, not a next-symbol
/// estimate or Ghidra's bare `undefined` placeholder" check `ConstantData`/
/// `MutableStaticData` trust, factored out so `DataPointerAlias` can ask
/// the identical question about a *pointee* address without recursing
/// into `classify_data_symbol` itself (a pointer chain must never be able
/// to loop this function). Also applies the same `CodeAddressAlias` veto
/// `classify_data_symbol` checks first: a real run found a pointee that
/// passed the size+bytes check on its own (`data_size_bytes`/
/// `data_bytes_hex` are both real, unconditional facts for executable
/// bytes too) but sat in `.text` -- independently classifying *that*
/// address always resolves it as `CodeAddressAlias`, never `ConstantData`,
/// so binding to it here would have left `DataPointerAlias` pointing at a
/// symbol that's only ever `extern`-declared, never actually defined.
fn confident_size_and_bytes(graph: &KnowledgeGraph, address: &str) -> Option<(u64, Vec<u8>)> {
    let executable = bool_value(graph, address, "data_executable");
    let section = single_value(graph, address, "data_section");
    if executable == Some(true) && section.as_deref() == Some(".text") {
        return None;
    }
    let data_type = single_value(graph, address, "data_type_name");
    let size = single_value(graph, address, "data_size_bytes")
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|_| data_type.as_deref() != Some("undefined"))?;
    let bytes = single_value(graph, address, "data_bytes_hex").as_deref().and_then(parse_hex_bytes)?;
    Some((size, bytes))
}

/// Classifies one already-collected `DAT_*`/`PTR_*`/`LAB_*`/`_refptr_*`
/// symbol name (PROJECT.md M18.2). `table` is the same whole-program
/// symbol table `extract()` already builds for call-site resolution
/// (`symtab::build_symbol_table`) -- reused here so `FunctionPointerAlias`
/// binds to the exact same recovered name a real call site would.
pub fn classify_data_symbol(graph: &KnowledgeGraph, symbol_name: &str, table: &SymbolTable) -> DataResolution {
    let Some(address) = address_from_symbol_name(symbol_name) else {
        return DataResolution {
            address: String::new(),
            symbol_name: symbol_name.to_string(),
            kind: DataSymbolKind::UnknownData,
            source_facts: vec!["no address could be parsed from this symbol's own name".to_string()],
            confidence: 0.0,
        };
    };

    let mut facts = Vec::new();

    // VtableData: checked first, since a vfunc0 address's own generic
    // size/content facts (a real run found them badly undersized -- see
    // this type's own doc comment) would otherwise misroute it into
    // ConstantData/UnknownData before the much stronger, already-verified
    // M7 vtable model gets a chance.
    for (class_name, vfunc0) in vfunc0_addresses(graph) {
        if vfunc0 == address {
            facts.push(format!("has_vtable_at({class_name}) + 0x10 == {address}"));
            let slot0 = vtable_slot0_function(graph, &class_name);
            let target = slot0.as_deref().and_then(|addr| table.get(addr)).and_then(|sym| match sym.kind {
                SymbolKind::FreeFunction => Some(VtableSlotTarget::FreeFunction(sym.display_name.clone())),
                // PROJECT.md M18.3: unlike a free function, `&Class::method`
                // is a pointer-to-member, not a plain code pointer -- see
                // `VtableSlotTarget::Method`'s own doc comment. A real,
                // synthesized trampoline (emitted once per unique
                // owner+method pair by `extract.rs`) closes that gap
                // without ever faking a member-function-pointer
                // conversion.
                SymbolKind::Method => Some(VtableSlotTarget::Method {
                    trampoline_name: vtable_trampoline_name(&sym.owner, &sym.display_name),
                    owner: sym.owner.clone(),
                    method_name: sym.display_name.clone(),
                    return_type: sym.return_type.clone(),
                    params: sym.raw_params.clone(),
                }),
                // A Constructor/Destructor's address is never a real
                // Itanium vtable slot value (constructors/destructors
                // aren't virtual, and a real destructor *would* need its
                // own, differently-shaped ABI thunk this module doesn't
                // attempt) -- null is the honest choice, not a
                // wrong-shaped reference.
                _ => None,
            });
            if let Some(addr) = &slot0 {
                facts.push(format!("has_virtual_method({class_name}) slot 0 = {addr}"));
            }
            return DataResolution {
                address,
                symbol_name: symbol_name.to_string(),
                kind: DataSymbolKind::VtableData { class_name, slot0_target: target },
                source_facts: facts,
                confidence: 1.0,
            };
        }
    }

    let section = single_value(graph, &address, "data_section");
    let writable = bool_value(graph, &address, "data_writable");
    let executable = bool_value(graph, &address, "data_executable");
    let initialized = bool_value(graph, &address, "data_initialized");
    let pointee = single_value(graph, &address, "data_pointee").and_then(|v| v.split(' ').next().map(str::to_string));
    let data_type = single_value(graph, &address, "data_type_name");
    // PROJECT.md M18.2: a real compile found `data_size_bytes` alone
    // isn't always the real, committed size it looks like. Ghidra's own
    // bare `undefined` type (as opposed to a real sized variant --
    // `undefined1`/`undefined4`/`undefined8`/`pointer`/... -- which really
    // is a genuine size commitment) is its least-committal placeholder:
    // a real, defined 1-byte Data object existed at `DAT_140009121`, but
    // it was genuinely just Ghidra's own "I don't know what's here"
    // marker, not evidence the real object is only 1 byte -- the actual
    // use site (`SDL_Log(&DAT_140009121, ...)`) treats it as the start of
    // a longer C string. A `data_size_bytes` fact backed only by the bare
    // `undefined` type is treated the same as an *estimated* one below:
    // real enough to keep in `source_facts`, not confident enough to
    // emit a fixed-size definition from.
    let size_confident = single_value(graph, &address, "data_size_bytes")
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|_| data_type.as_deref() != Some("undefined"));
    let size_estimated = single_value(graph, &address, "data_size_bytes_estimated").and_then(|v| v.parse::<u64>().ok());
    let bytes_hex = single_value(graph, &address, "data_bytes_hex");

    if let Some(s) = &section {
        facts.push(format!("data_section = {s}"));
    }
    if let Some(e) = executable {
        facts.push(format!("data_executable = {e}"));
    }

    // CodeAddressAlias: real code, not data at all -- checked before any
    // pointee/size reasoning, since a code byte's own "content" isn't a
    // data value in any of the senses below.
    if executable == Some(true) && section.as_deref() == Some(".text") {
        return DataResolution {
            address,
            symbol_name: symbol_name.to_string(),
            kind: DataSymbolKind::CodeAddressAlias,
            source_facts: facts,
            confidence: 1.0,
        };
    }

    if let Some(target) = &pointee {
        facts.push(format!("data_pointee = {target}"));
        if is_known_function(graph, target) {
            if let Some(sym) = table.get(target) {
                if sym.kind == SymbolKind::FreeFunction {
                    facts.push(format!("{target} resolves to recovered free function {}", sym.display_name));
                    return DataResolution {
                        address,
                        symbol_name: symbol_name.to_string(),
                        kind: DataSymbolKind::FunctionPointerAlias { target_function: sym.display_name.clone() },
                        source_facts: facts,
                        confidence: 1.0,
                    };
                }
                facts.push(format!("{target} resolves to a recovered method/ctor/dtor, not a plain function -- no safe function-pointer representation"));
            } else {
                facts.push(format!("{target} is a known function but not itself recovered"));
            }
        } else if is_known_import(graph, target) {
            let import_value = single_value(graph, target, "imports");
            facts.push(format!("{target} is a known import ({})", import_value.as_deref().unwrap_or("?")));
            if let Some(qualified_name) = known_import_alias(import_value.as_deref()) {
                facts.push(format!("{qualified_name} is a real C++ standard-library global -- binding directly"));
                return DataResolution {
                    address,
                    symbol_name: symbol_name.to_string(),
                    kind: DataSymbolKind::KnownImportAlias { qualified_name },
                    source_facts: facts,
                    confidence: 1.0,
                };
            }
        } else if single_value(graph, target, "data_type_name").as_deref() == Some("IMAGE_DOS_HEADER")
            && single_value(graph, target, "data_section").as_deref() == Some("Headers")
        {
            // The PE image's own DOS header, at the module's real load
            // address -- see `RuntimeAlias`'s own doc comment for why
            // this binds to the toolchain-provided `__ImageBase` rather
            // than emitting the original binary's own captured bytes.
            facts.push(format!("{target} is this module's own real PE image base (IMAGE_DOS_HEADER, Headers section) -- binding to the toolchain-provided __ImageBase"));
            return DataResolution {
                address,
                symbol_name: symbol_name.to_string(),
                kind: DataSymbolKind::RuntimeAlias {
                    runtime_symbol: "__ImageBase".to_string(),
                    runtime_type: "IMAGE_DOS_HEADER".to_string(),
                },
                source_facts: facts,
                confidence: 1.0,
            };
        } else if let Some(pointee_symbol) = single_value(graph, target, "data_symbol_name") {
            // Not a known function or import, but Ghidra still gave this
            // address its own real name -- if it also has the same
            // confident size+bytes evidence `ConstantData`/
            // `MutableStaticData` trusts below, this is one more hop of
            // the same real evidence, not an unmodeled external. Checked
            // directly (not by recursing into `classify_data_symbol`) so
            // a pointer chain can never loop.
            if confident_size_and_bytes(graph, target).is_some() {
                facts.push(format!(
                    "{target} ({pointee_symbol}) has its own confident size+bytes -- binding directly rather than treating it as an unmodeled external"
                ));
                return DataResolution {
                    address,
                    symbol_name: symbol_name.to_string(),
                    kind: DataSymbolKind::DataPointerAlias { target_symbol: pointee_symbol },
                    source_facts: facts,
                    confidence: 1.0,
                };
            }
        }
        // Real memory, but outside anything Debura has a model of --
        // exactly what `ExternalGlobalAlias` means (never guessed from
        // this symbol's own name, only from the pointee's own resolved
        // identity above).
        return DataResolution {
            address,
            symbol_name: symbol_name.to_string(),
            kind: DataSymbolKind::ExternalGlobalAlias { pointee: target.clone() },
            source_facts: facts,
            confidence: 0.8,
        };
    }

    if section.as_deref() == Some(".CRT") {
        return DataResolution {
            address,
            symbol_name: symbol_name.to_string(),
            kind: DataSymbolKind::RuntimeData,
            source_facts: facts,
            confidence: 1.0,
        };
    }

    // PROJECT.md M18.2: real evidence -- never a next-symbol-distance
    // estimate, and never a bare Ghidra `undefined` marker's own size
    // (see `size_confident`'s own construction above) -- is what's
    // trusted enough to emit a real fixed-size definition from. Anything
    // less falls through to `UnknownData` below, which renders as the
    // exact same bare-`extern` scalar declaration this address had
    // before M18.2 existed -- a real regression-safety net, not a loss
    // of information (every rejected size estimate is still in
    // `source_facts` for a human to look at).
    if let (Some(size), Some(bytes)) = (size_confident, bytes_hex.as_deref().and_then(parse_hex_bytes)) {
        facts.push(format!("data_bytes_hex = {} (size {size}, confident)", bytes_hex.as_deref().unwrap()));
        if let Some(init) = initialized {
            facts.push(format!("data_initialized = {init}"));
        }
        let is_writable = writable.unwrap_or(false);
        let kind = if is_writable {
            DataSymbolKind::MutableStaticData { size, bytes }
        } else {
            DataSymbolKind::ConstantData { size, bytes }
        };
        return DataResolution { address, symbol_name: symbol_name.to_string(), kind, source_facts: facts, confidence: 1.0 };
    } else {
        if let Some(size) = size_estimated {
            facts.push(format!("data_size_bytes_estimated = {size} (not confident enough to emit a definition from)"));
        }
        if data_type.as_deref() == Some("undefined") {
            facts.push("data_type_name = undefined (Ghidra's own least-committal placeholder -- not treated as a real size commitment)".to_string());
        }
    }

    DataResolution {
        address,
        symbol_name: symbol_name.to_string(),
        kind: DataSymbolKind::UnknownData,
        source_facts: facts,
        confidence: 0.0,
    }
}

/// Ghidra's own `contains_string` observation for `address`, if any,
/// unquoted for display -- `debura-analysis::ingest` stores Ghidra's own
/// quoted display representation verbatim (`"Lives: "`, quote marks
/// included), so the surrounding quotes (never internal escapes: a real
/// check found this project's own strings never need any) are stripped
/// here once rather than by every caller.
fn contains_string_value(graph: &KnowledgeGraph, address: &str) -> Option<String> {
    let raw = single_value(graph, address, "contains_string")?;
    Some(raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(&raw).to_string())
}

/// Whether `arg` (already stripped of casts/parens) is a plain
/// double-quoted string literal -- Ghidra always renders one as ordinary
/// C string syntax, so this is a direct strip, not a parse. `None` for
/// anything else (an identifier, a cast expression, a numeric literal, a
/// nested call, ...).
fn quoted_string_literal(arg: &str) -> Option<String> {
    let arg = arg.trim();
    let inner = arg.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_string())
}

/// PROJECT.md, "Deterministic string-literal extraction": every
/// `DAT_*`/`PTR_*` symbol name whose own address is passed as the first
/// argument to some call, somewhere in `functions`' own already-
/// decompiled bodies, where another argument to that *same* call is a
/// plain quoted string literal -- real, structural evidence a global
/// C++ object (a `std::string`, most commonly) is being constructed
/// from that literal, confirmed against the real, confirmed case: Snake's
/// own static initializer, `FUN_14000227e`, decompiles as
/// `FUN_1400073b0((ulonglong *)&DAT_14000e0c0,"Lives: ",&local_29);` --
/// `DAT_14000e0c0` itself has no static content at all (`.bss`,
/// uninitialized, Ghidra never typed it a string), but the literal that
/// actually belongs to it is sitting right there, unused until this
/// pass reads it. Deliberately narrow: only the symbol's address as the
/// *first* argument (the real ABI shape for a constructor's own
/// receiver/hidden-return-slot parameter, the same convention
/// `render.rs`'s `patch_hidden_return_slot_construction` already
/// recognizes elsewhere) -- a symbol merely mentioned somewhere else in
/// a call's argument list is not this pattern, and guessing so would
/// attribute an unrelated literal to the wrong object.
///
/// Deliberately reads every subject's own `decompiles_to` text directly
/// from the graph (`latest_decompilation`, the same "prefer substantive
/// over degenerate/stale" selection every other real lookup in this
/// codebase already trusts), not `extract()`'s own recovered-functions
/// list -- a real, confirmed gap found while verifying this: Snake's own
/// `FUN_14000227e` is never *called* from anything Debura's own
/// reachability analysis recovers (it only ever runs via the CRT's own
/// static-initializer table, a data-driven mechanism outside any
/// recovered call graph), so it never clears `extract()`'s own
/// Application-provenance gate and never appears in `RecoveredFunction`s
/// at all -- yet Ghidra decompiled it just fine, and its own real
/// literal is sitting right there, unused, the moment this reads the
/// graph directly instead.
pub fn find_constructor_string_literals(graph: &KnowledgeGraph) -> HashMap<String, String> {
    let mut literals = HashMap::new();
    let subjects: std::collections::BTreeSet<&str> =
        graph.observations().filter(|o| o.predicate == "decompiles_to").map(|o| o.subject.as_str()).collect();
    for subject in subjects {
        let Some(decompilation) = debura_knowledge::latest_decompilation(graph, subject) else { continue };
        for (_, args_text) in find_calls(&decompilation.value) {
            let args = split_top_level_comma(args_text);
            let Some(first) = args.first() else { continue };
            let first = strip_casts_and_parens(first);
            let Some(symbol) = first.strip_prefix('&') else { continue };
            if !(symbol.starts_with("DAT_") || symbol.starts_with("PTR_")) {
                continue;
            }
            let Some(literal) = args.iter().skip(1).find_map(|arg| quoted_string_literal(strip_casts_and_parens(arg))) else {
                continue;
            };
            literals.entry(symbol.to_string()).or_insert(literal);
        }
    }
    literals
}

/// `symbol_name`'s own `StringLiteral` resolution, if either real source
/// applies -- `None` means the caller falls through to
/// `classify_data_symbol`'s existing, unrelated classification logic
/// unchanged. Checked ahead of everything else in `classify_data_symbols`
/// (never inside `classify_data_symbol` itself, which stays exactly as
/// every one of its own existing unit tests already exercises it).
fn classify_string_literal(
    graph: &KnowledgeGraph,
    symbol_name: &str,
    constructor_literals: &HashMap<String, String>,
) -> Option<DataResolution> {
    let address = address_from_symbol_name(symbol_name)?;
    if let Some(value) = contains_string_value(graph, &address) {
        return Some(DataResolution {
            address,
            symbol_name: symbol_name.to_string(),
            kind: DataSymbolKind::StringLiteral(value),
            source_facts: vec!["contains_string (Ghidra's own string typing)".to_string()],
            confidence: 0.99,
        });
    }
    if let Some(value) = constructor_literals.get(symbol_name) {
        return Some(DataResolution {
            address,
            symbol_name: symbol_name.to_string(),
            kind: DataSymbolKind::StringLiteral(value.clone()),
            source_facts: vec!["real literal argument to a constructor call receiving this address".to_string()],
            confidence: 0.9,
        });
    }
    None
}

/// Classifies every symbol in `symbol_names` (PROJECT.md M18.2) --
/// `extract()`'s own convenience entry point, called once per recovery
/// pass with the same symbol set `ghidra_data_symbols` already collects.
pub fn classify_data_symbols(graph: &KnowledgeGraph, symbol_names: &[String], table: &SymbolTable) -> Vec<DataResolution> {
    let constructor_literals = find_constructor_string_literals(graph);
    symbol_names
        .iter()
        .map(|name| classify_string_literal(graph, name, &constructor_literals).unwrap_or_else(|| classify_data_symbol(graph, name, table)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{NameSource, RecoveredFunction};

    fn function_table(address: &str, display_name: &str) -> SymbolTable {
        let functions = vec![RecoveredFunction {
            address: address.to_string(),
            raw_name: format!("FUN_{}", &address[2..]),
            display_name: display_name.to_string(),
            name_source: NameSource::Raw,
            return_type: "void".to_string(),
            params: String::new(),
            decompilation: String::new(),
        }];
        crate::symtab::build_symbol_table(&[], &functions)
    }

    #[test]
    fn address_is_parsed_from_the_symbols_own_trailing_hex() {
        assert_eq!(address_from_symbol_name("DAT_140009070").as_deref(), Some("0x140009070"));
        assert_eq!(address_from_symbol_name("PTR_FUN_140009a00").as_deref(), Some("0x140009a00"));
        assert_eq!(address_from_symbol_name("PTR_IMAGE_DOS_HEADER_140009710").as_deref(), Some("0x140009710"));
        assert_eq!(address_from_symbol_name("PTR_PTR_cout_1400096e0").as_deref(), Some("0x1400096e0"));
    }

    /// The real, confirmed case: `DAT_140009070`'s captured bytes decode
    /// exactly as the IEEE-754 double 2.0, `.rdata`, read-only.
    #[test]
    fn a_readonly_initialized_object_with_no_pointee_is_constant_data() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009070", "data_section", ".rdata", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009070", "data_readable", "true", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009070", "data_writable", "false", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009070", "data_initialized", "true", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009070", "data_size_bytes", "8", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009070", "data_bytes_hex", "0000000000000040", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "DAT_140009070", &table);

        match resolution.kind {
            DataSymbolKind::ConstantData { size, bytes } => {
                assert_eq!(size, 8);
                assert_eq!(bytes, vec![0, 0, 0, 0, 0, 0, 0, 0x40]);
                assert_eq!(f64::from_le_bytes(bytes.try_into().unwrap()), 2.0);
            }
            other => panic!("expected ConstantData, got {other:?}"),
        }
        assert_eq!(resolution.confidence, 1.0);
    }

    #[test]
    fn a_writable_initialized_object_is_mutable_static_data() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140011058", "data_section", ".CRT_placeholder_unused", 0.95, "ghidra:data", None);
        graph.add_observation("0x140011058", "data_writable", "true", 0.95, "ghidra:data", None);
        graph.add_observation("0x140011058", "data_initialized", "true", 0.95, "ghidra:data", None);
        graph.add_observation("0x140011058", "data_size_bytes", "8", 0.95, "ghidra:data", None);
        graph.add_observation("0x140011058", "data_bytes_hex", "0000000000000000", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "DAT_140011058", &table);

        match resolution.kind {
            DataSymbolKind::MutableStaticData { size, bytes } => {
                assert_eq!(size, 8);
                assert_eq!(bytes, vec![0u8; 8]);
            }
            other => panic!("expected MutableStaticData, got {other:?}"),
        }
    }

    /// The real, confirmed case: `DAT_140011058` genuinely sits in the
    /// `.CRT` section.
    #[test]
    fn the_crt_section_is_runtime_data_regardless_of_writability() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140011058", "data_section", ".CRT", 0.95, "ghidra:data", None);
        graph.add_observation("0x140011058", "data_writable", "true", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "DAT_140011058", &table);

        assert_eq!(resolution.kind, DataSymbolKind::RuntimeData);
    }

    /// The real, confirmed case: `PTR_FUN_140009a00` == `Food`'s own
    /// `has_vtable_at` (0x1400099f0) + 0x10.
    #[test]
    fn a_vfunc0_address_is_vtable_data_reusing_the_m7_model() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("Food", "has_vtable_at", "0x1400099f0", 1.0, "ghidra:vtable", None);
        graph.add_observation("Food", "has_virtual_method", "slot 0: 0x1400018ca", 0.95, "ghidra:vtable", None);

        let table = function_table("0x1400018ca", "draw");
        let resolution = classify_data_symbol(&graph, "PTR_FUN_140009a00", &table);

        assert_eq!(
            resolution.kind,
            DataSymbolKind::VtableData {
                class_name: "Food".to_string(),
                slot0_target: Some(VtableSlotTarget::FreeFunction("draw".to_string())),
            }
        );
        assert_eq!(resolution.confidence, 1.0);
    }

    /// PROJECT.md M18.3: the real, confirmed case -- `PTR_FUN_140009a00`'s
    /// own slot-0 target (0x1400018ca) is a recovered *method*, not a
    /// free function. Must resolve to a real `Method` target (a
    /// synthesized trampoline, never a bare function-pointer conversion
    /// of `&Food::draw`, which isn't portable C++ at all).
    #[test]
    fn a_vtable_slot_targeting_a_method_resolves_to_a_trampoline_target() {
        use crate::model::{RecoveredClass, RecoveredMethod};

        let mut graph = KnowledgeGraph::new();
        graph.add_observation("Food", "has_vtable_at", "0x1400099f0", 1.0, "ghidra:vtable", None);
        graph.add_observation("Food", "has_virtual_method", "slot 0: 0x1400018ca", 0.95, "ghidra:vtable", None);

        let classes = vec![RecoveredClass {
            name: "Food".to_string(),
            base: None,
            vtable_address: "0x1400099f0".to_string(),
            fields: Vec::new(),
            methods: vec![RecoveredMethod {
                address: "0x1400018ca".to_string(),
                raw_name: "FUN_1400018ca".to_string(),
                display_name: "draw".to_string(),
                name_source: NameSource::Raw,
                return_type: "void".to_string(),
                params: "int param_2".to_string(),
                is_constructor: false,
                is_destructor: false,
                receiver_alias: None,
                decompilation: String::new(),
            }],
            references: Vec::new(),
        }];
        let table = crate::symtab::build_symbol_table(&classes, &[]);

        let resolution = classify_data_symbol(&graph, "PTR_FUN_140009a00", &table);

        assert_eq!(
            resolution.kind,
            DataSymbolKind::VtableData {
                class_name: "Food".to_string(),
                slot0_target: Some(VtableSlotTarget::Method {
                    trampoline_name: "Food__vtable_trampoline_draw".to_string(),
                    owner: "Food".to_string(),
                    method_name: "draw".to_string(),
                    return_type: "void".to_string(),
                    params: "int param_2".to_string(),
                }),
            }
        );
    }

    /// The real, confirmed case: `PTR_IMAGE_DOS_HEADER_140009710`'s own
    /// pointee (0x140000000) is real memory but matches no known
    /// function, import, or vtable -- classified from the *pointee's*
    /// resolved identity, never from this symbol's own embedded name.
    #[test]
    fn a_pointee_matching_nothing_debura_knows_is_an_external_global_alias() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009710", "data_pointee", "0x140000000 (reference)", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "PTR_IMAGE_DOS_HEADER_140009710", &table);

        assert_eq!(resolution.kind, DataSymbolKind::ExternalGlobalAlias { pointee: "0x140000000".to_string() });
    }

    #[test]
    fn a_pointee_matching_a_recovered_free_function_is_a_function_pointer_alias() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009050", "data_pointee", "0x1400070a0 (reference)", 0.95, "ghidra:data", None);
        graph.add_observation("0x1400070a0", "calling_convention", "__fastcall", 0.95, "ghidra:function", None);

        let table = function_table("0x1400070a0", "calculateOffset");
        let resolution = classify_data_symbol(&graph, "PTR_DAT_140009050", &table);

        assert_eq!(
            resolution.kind,
            DataSymbolKind::FunctionPointerAlias { target_function: "calculateOffset".to_string() }
        );
    }

    /// PROJECT.md M18.3: the real, confirmed case a link run found --
    /// `PTR_DAT_140009660`'s pointee (`0x140009068`) matches no known
    /// function or import, but it isn't an unmodeled external either:
    /// Ghidra gave it its own real name (`DAT_140009068`) and Debura has
    /// the exact same confident size+bytes evidence for it that
    /// `ConstantData` alone would already trust. Must bind directly, not
    /// fall through to `ExternalGlobalAlias` (which a real link left
    /// permanently unresolved -- nothing ever defines an `extern`).
    #[test]
    fn a_pointee_with_its_own_confident_data_is_a_data_pointer_alias() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009660", "data_pointee", "0x140009068 (reference)", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009068", "data_symbol_name", "DAT_140009068", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009068", "data_type_name", "undefined4", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009068", "data_size_bytes", "4", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009068", "data_bytes_hex", "32000000", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "PTR_DAT_140009660", &table);

        assert_eq!(
            resolution.kind,
            DataSymbolKind::DataPointerAlias { target_symbol: "DAT_140009068".to_string() }
        );
    }

    /// A pointee with its own real name, but *not* the same confident
    /// size+bytes evidence (Ghidra's bare `undefined` placeholder, the
    /// same "not a real commitment" case `ConstantData` itself already
    /// distrusts) -- must not be bound to, the same "Unknown is better
    /// than confidently wrong" rule as everywhere else in this module.
    #[test]
    fn a_pointee_with_only_a_bare_undefined_type_stays_an_external_global_alias() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009660", "data_pointee", "0x140009068 (reference)", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009068", "data_symbol_name", "DAT_140009068", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009068", "data_type_name", "undefined", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009068", "data_size_bytes", "1", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009068", "data_bytes_hex", "32", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "PTR_DAT_140009660", &table);

        assert_eq!(resolution.kind, DataSymbolKind::ExternalGlobalAlias { pointee: "0x140009068".to_string() });
    }

    /// PROJECT.md M18.3: the real, confirmed case a first version of the
    /// `DataPointerAlias` fix got wrong -- `PTR_DAT_140009700`'s pointee
    /// (`DAT_140007ad0`) genuinely has a confident size and real bytes,
    /// but also sits in `.text` and is executable. Independently
    /// classifying that address (once it's transitively collected)
    /// always resolves it as `CodeAddressAlias`, never `ConstantData` --
    /// binding to it as a `DataPointerAlias` would leave the pointer
    /// pointing at a symbol that's only ever `extern`-declared, never
    /// defined, the same unresolved-at-link-time failure this whole fix
    /// exists to close.
    #[test]
    fn a_pointee_that_would_itself_classify_as_a_code_address_alias_stays_external() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009700", "data_pointee", "0x140007ad0 (reference)", 0.95, "ghidra:data", None);
        graph.add_observation("0x140007ad0", "data_symbol_name", "DAT_140007ad0", 0.95, "ghidra:data", None);
        graph.add_observation("0x140007ad0", "data_type_name", "undefined8", 0.95, "ghidra:data", None);
        graph.add_observation("0x140007ad0", "data_size_bytes", "8", 0.95, "ghidra:data", None);
        graph.add_observation("0x140007ad0", "data_bytes_hex", "ffffffffffffffff", 0.95, "ghidra:data", None);
        graph.add_observation("0x140007ad0", "data_section", ".text", 0.95, "ghidra:data", None);
        graph.add_observation("0x140007ad0", "data_executable", "true", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "PTR_DAT_140009700", &table);

        assert_eq!(resolution.kind, DataSymbolKind::ExternalGlobalAlias { pointee: "0x140007ad0".to_string() });
    }

    /// PROJECT.md M18.3: the real, confirmed case --
    /// `PTR_IMAGE_DOS_HEADER_140009710`'s pointee is typed
    /// `IMAGE_DOS_HEADER` in Ghidra's own synthetic "Headers" section --
    /// the PE image's own DOS header, always at the module's real load
    /// address. Must bind to the MinGW-provided `__ImageBase`, never
    /// emit the *original* binary's own captured header bytes (a freshly
    /// linked binary's own image base genuinely differs).
    #[test]
    fn an_image_dos_header_pointee_is_a_runtime_alias_to_image_base() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009710", "data_pointee", "0x140000000 (reference)", 0.95, "ghidra:data", None);
        graph.add_observation("0x140000000", "data_type_name", "IMAGE_DOS_HEADER", 0.95, "ghidra:data", None);
        graph.add_observation("0x140000000", "data_section", "Headers", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "PTR_IMAGE_DOS_HEADER_140009710", &table);

        assert_eq!(
            resolution.kind,
            DataSymbolKind::RuntimeAlias {
                runtime_symbol: "__ImageBase".to_string(),
                runtime_type: "IMAGE_DOS_HEADER".to_string(),
            }
        );
    }

    /// PROJECT.md M18.3: the real, confirmed case a real link found --
    /// `PTR_cout_14000f688`'s own outgoing reference resolves to Ghidra's
    /// synthetic EXTERNAL address space, which `debura-analysis` already
    /// ingests as a real `imports` fact (`std!cout`) at that same
    /// address. The gap wasn't in Ghidra extraction at all -- the fact
    /// was already there -- `is_known_import` found it but the
    /// classifier used to just note it and still fall through to
    /// `ExternalGlobalAlias`, which a real link can never resolve.
    #[test]
    fn a_known_std_cout_import_binds_directly() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009800", "data_pointee", "0x16 (reference)", 0.95, "ghidra:data", None);
        graph.add_observation("0x16", "imports", "std!cout", 1.0, "ghidra:imports", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "PTR_cout_140009800", &table);

        assert_eq!(resolution.kind, DataSymbolKind::KnownImportAlias { qualified_name: "std::cout".to_string() });
    }

    /// A known import outside the narrow, real allowlist (anything other
    /// than `std::cout`, the one demonstrated case) must stay an
    /// `ExternalGlobalAlias` -- never speculatively bound to a symbol
    /// name Debura hasn't actually confirmed is safe.
    #[test]
    fn a_known_import_outside_the_allowlist_stays_an_external_global_alias() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009800", "data_pointee", "0x20 (reference)", 0.95, "ghidra:data", None);
        graph.add_observation("0x20", "imports", "kernel32.dll!VirtualProtect", 1.0, "ghidra:imports", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "PTR_DAT_140009800", &table);

        assert_eq!(resolution.kind, DataSymbolKind::ExternalGlobalAlias { pointee: "0x20".to_string() });
    }

    /// The real, confirmed case: `LAB_140001000`/`LAB_140003a80` are
    /// real, executable `.text` bytes -- a label taken as a value, not
    /// data at all.
    #[test]
    fn an_executable_text_address_is_a_code_address_alias() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140001000", "data_section", ".text", 0.95, "ghidra:data", None);
        graph.add_observation("0x140001000", "data_executable", "true", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "LAB_140001000", &table);

        assert_eq!(resolution.kind, DataSymbolKind::CodeAddressAlias);
    }

    #[test]
    fn no_supporting_facts_at_all_is_unknown_data_not_a_guess() {
        let graph = KnowledgeGraph::new();
        let table = SymbolTable::new();

        let resolution = classify_data_symbol(&graph, "DAT_140012345", &table);

        assert_eq!(resolution.kind, DataSymbolKind::UnknownData);
        assert_eq!(resolution.confidence, 0.0);
    }

    /// PROJECT.md M18.2: a real compile found this exact case --
    /// `DAT_140009121`'s next-symbol-distance estimate said 1 byte, but
    /// the real use site (`SDL_Log(&DAT_140009121, ...)`) treats it as
    /// the start of a longer C string. Emitting a fixed-size definition
    /// from an *estimated* size is exactly the confidently-wrong guess
    /// this project's discipline exists to avoid -- must fall back to
    /// `UnknownData` (a bare `extern` scalar, the same as before this
    /// module existed), not a 1-byte array/scalar that breaks the real
    /// call site.
    #[test]
    fn an_estimated_size_never_produces_a_confident_data_definition() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009121", "data_section", ".rdata", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009121", "data_readable", "true", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009121", "data_writable", "false", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009121", "data_size_bytes_estimated", "1", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009121", "data_bytes_hex", "25", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "DAT_140009121", &table);

        assert_eq!(resolution.kind, DataSymbolKind::UnknownData);
        assert!(
            resolution.source_facts.iter().any(|f| f.contains("data_size_bytes_estimated")),
            "the estimate should still be on record for a human to inspect: {:?}",
            resolution.source_facts
        );
    }

    /// The real, confirmed bug: `DAT_140009121` actually had a
    /// *confident* `data_size_bytes = 1` (a real, defined Ghidra Data
    /// object, not an estimate) -- but its own `data_type_name` was the
    /// bare `undefined` marker, Ghidra's own least-committal placeholder,
    /// not a real size commitment. A real compile found emitting a
    /// 1-byte array from this broke the real use site
    /// (`SDL_Log(&DAT_140009121, ...)`, which treats it as the start of
    /// a longer C string) -- so a bare `undefined` type must be treated
    /// the same as an unconfident/estimated size, even when
    /// `data_size_bytes` itself is technically present.
    #[test]
    fn a_confident_size_backed_only_by_the_bare_undefined_type_is_not_trusted() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009121", "data_section", ".rdata", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009121", "data_readable", "true", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009121", "data_writable", "false", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009121", "data_initialized", "true", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009121", "data_type_name", "undefined", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009121", "data_size_bytes", "1", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009121", "data_bytes_hex", "25", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "DAT_140009121", &table);

        assert_eq!(resolution.kind, DataSymbolKind::UnknownData);
    }

    /// The mirror case: a real sized variant (`undefined8`, exactly what
    /// the real, correctly-handled `DAT_140009070` constant has) is a
    /// genuine size commitment and must still be trusted.
    #[test]
    fn a_confident_size_backed_by_a_real_sized_type_is_still_trusted() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009070", "data_section", ".rdata", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009070", "data_writable", "false", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009070", "data_type_name", "undefined8", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009070", "data_size_bytes", "8", 0.95, "ghidra:data", None);
        graph.add_observation("0x140009070", "data_bytes_hex", "0000000000000040", 0.95, "ghidra:data", None);

        let table = SymbolTable::new();
        let resolution = classify_data_symbol(&graph, "DAT_140009070", &table);

        assert!(matches!(resolution.kind, DataSymbolKind::ConstantData { size: 8, .. }), "{:?}", resolution.kind);
    }

    /// The real, confirmed case: Snake's own static initializer,
    /// `FUN_14000227e`, constructs two global `std::string`s from real
    /// literal arguments -- `DAT_14000e0a0` from `"Score: "`,
    /// `DAT_14000e0c0` from `"Lives: "`. Neither symbol has any static
    /// content of its own (`.bss`, uninitialized); the literals are only
    /// ever visible in this constructor's own decompiled text. Also the
    /// real, confirmed reason this reads the graph's own `decompiles_to`
    /// observations directly, not `RecoveredFunction`s: this exact
    /// constructor is never called from anything Debura's own
    /// reachability analysis recovers (only the CRT's own static-
    /// initializer table invokes it), so it never appears in a recovered
    /// function list at all -- Ghidra decompiled it just fine regardless.
    #[test]
    fn finds_the_real_constructor_string_literals() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation(
            "0x14000227e",
            "decompiles_to",
            "void FUN_14000227e(void)\n\n{\n  allocator local_2a;\n  allocator local_29;\n  \n  FUN_1400073b0((ulonglong *)&DAT_14000e0a0,\"Score: \",&local_2a);\n  FUN_140006740();\n  FUN_1400073b0((ulonglong *)&DAT_14000e0c0,\"Lives: \",&local_29);\n  FUN_140006740();\n  return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );

        let literals = find_constructor_string_literals(&graph);

        assert_eq!(literals.get("DAT_14000e0a0").map(String::as_str), Some("Score: "));
        assert_eq!(literals.get("DAT_14000e0c0").map(String::as_str), Some("Lives: "));
    }

    /// A symbol merely appearing somewhere in a call's own argument list
    /// -- not as the call's *first* argument -- must never be attributed
    /// a nearby literal: that's not the real constructor-receiver shape,
    /// and guessing so risks pairing a literal with the wrong object.
    #[test]
    fn a_symbol_that_is_not_the_first_argument_gets_no_literal() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation(
            "0x1",
            "decompiles_to",
            "void FUN_1(void)\n\n{\n  FUN_2(local_1,\"unrelated\",&DAT_140009000);\n  return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );

        let literals = find_constructor_string_literals(&graph);

        assert!(literals.get("DAT_140009000").is_none(), "{literals:?}");
    }

    /// End-to-end through `classify_data_symbols`: the real Snake case --
    /// no `contains_string` observation at all (Ghidra never typed
    /// `DAT_14000e0c0` as a string, since it's an uninitialized `.bss`
    /// object), but the constructor-literal source still resolves it.
    #[test]
    fn classify_data_symbols_resolves_a_constructor_literal_with_no_contains_string_observation() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation(
            "0x14000227e",
            "decompiles_to",
            "void FUN_14000227e(void)\n\n{\n  FUN_1400073b0((ulonglong *)&DAT_14000e0c0,\"Lives: \",&local_29);\n  return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        let table = SymbolTable::new();

        let resolutions = classify_data_symbols(&graph, &["DAT_14000e0c0".to_string()], &table);

        assert_eq!(resolutions.len(), 1);
        assert_eq!(resolutions[0].kind, DataSymbolKind::StringLiteral("Lives: ".to_string()));
        assert!((resolutions[0].confidence - 0.9).abs() < f64::EPSILON);
    }

    /// A real `contains_string` observation (Ghidra's own string typing)
    /// must be preferred over a constructor-literal match when both
    /// exist -- a deliberate precedence, not an accident of which check
    /// happens to run first.
    #[test]
    fn a_real_contains_string_observation_is_preferred_over_a_constructor_literal() {
        let mut graph = KnowledgeGraph::new();
        graph.add_observation("0x140009000", "contains_string", "\"Ghidra's own value\"", 0.95, "ghidra:data", None);
        graph.add_observation(
            "0x1",
            "decompiles_to",
            "void FUN_1(void)\n\n{\n  FUN_2((ulonglong *)&DAT_140009000,\"a different literal\",0);\n  return;\n}",
            0.95,
            "ghidra:decompiler",
            None,
        );
        let table = SymbolTable::new();

        let resolutions = classify_data_symbols(&graph, &["DAT_140009000".to_string()], &table);

        assert_eq!(resolutions[0].kind, DataSymbolKind::StringLiteral("Ghidra's own value".to_string()));
        assert!((resolutions[0].confidence - 0.99).abs() < f64::EPSILON);
    }
}
