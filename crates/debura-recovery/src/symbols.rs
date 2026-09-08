use std::collections::BTreeSet;

use crate::compat::GHIDRA_COMPAT_HEADER_NAME;
use crate::data_symbols::{DataResolution, DataSymbolKind, VtableSlotTarget};

/// Filename the per-program Ghidra data-symbol declarations are written
/// under, and the name every generated `.cpp` includes it by. Always
/// written, even with zero symbols, so the unconditional `#include`
/// every generated source file carries always resolves.
pub const GHIDRA_SYMBOLS_HEADER_NAME: &str = "ghidra_symbols.hpp";

/// Declares `extern` placeholders for every `DAT_*`/`PTR_*`/`_refptr_*`
/// name a recovered body references, so the symbol at least resolves.
/// The real type (and value) at that address isn't known, and restoring
/// it needs real data extraction from Ghidra that doesn't exist yet --
/// this only makes the *name* usable. A generic byte works for `DAT_*`
/// (an arithmetic operand implicitly converts from a byte the same as
/// any other numeric type; a vtable-pointer-slot assignment pattern gets
/// an explicit cast inserted at the call site instead of needing the
/// exact pointer type here, see `patch_known_idioms`), but `PTR_*` and
/// `_refptr_*` both specifically mean "this address holds a pointer" in
/// Ghidra's own naming convention (a plain data byte doesn't), and both
/// are seen *dereferenced* (`*PTR_DAT_...`, `*_refptr_...`) -- a real
/// compile confirmed a plain byte there fails two different ways
/// (`_refptr_*`: "invalid type argument of unary '*'"; `PTR_*`, same
/// error, found later against a different real body), so both families
/// need to be declared as pointers.
/// `unresolved_calls` are call-site names (`FUN_x`, `thunk_FUN_x`) M15's
/// symbol-resolution pass (`symtab.rs`) couldn't match to any recovered
/// class method or standalone function -- Debura found no definition for
/// them at all, not even that they're a method of some unnamed class.
/// Declaring each as a permissive, fully-variadic prototype (`long long
/// name(...);`, valid C++ for "accepts any arguments") is the same
/// graceful-degradation PROJECT.md M15 asks for: a real but generic
/// prototype that at least compiles, rather than a hard error, and
/// rather than guessing a wrong specific signature. This only makes the
/// call sites *parse* -- nothing defines these functions, so a real
/// link step still needs a definition from somewhere before the program
/// can actually run.
/// PROJECT.md M15: "declarations should be generated from the same
/// global symbol table as definitions -- then cross-file visibility
/// becomes automatic." A real compile confirmed why standalone functions
/// specifically needed this: every recovered free function is defined in
/// one shared `functions.cpp`, sorted by address -- so a call from an
/// earlier-address function to a later-address one failed to compile for
/// ordinary C++ forward-declaration reasons, and a call *into*
/// `functions.cpp` from a class's own `.cpp` had no declaration visible
/// at all. Declaring every one of them here, in the header every
/// generated source file already includes unconditionally, fixes both
/// at once. Class methods don't need the same treatment: they're already
/// declared in their own class's header, which every caller already
/// `#include`s via `references`.
pub fn render_function_declarations(functions: &[(String, String, String)]) -> String {
    let mut out = String::new();
    for (return_type, name, params) in functions {
        out.push_str(&format!("{return_type} {name}({params});\n"));
    }
    out
}

/// PROJECT.md M18.3: a real compile found the same forward-declaration
/// gap `render_function_declarations` already exists to close applies to
/// a vtable-slot trampoline too -- `functions.cpp` defines it, but this
/// header's own pointer-alias line (which binds a vtable slot's symbol
/// to it) is included *first*, in every generated file, well before
/// `functions.cpp` is even compiled as its own translation unit.
/// `extern "C"` matches `render_vtable_trampoline`'s own definition (a
/// declaration and its definition must agree on linkage, or the linker
/// looks for two different symbols).
pub fn render_vtable_trampoline_declarations(trampolines: &[crate::model::VtableTrampoline]) -> String {
    let mut out = String::new();
    for t in trampolines {
        let params = if t.params.trim().is_empty() { String::new() } else { format!(",{}", t.params) };
        out.push_str(&format!("extern \"C\" {} {}(void *debura_this{});\n", t.return_type, t.name, params));
    }
    out
}

pub fn render_ghidra_symbols_header(
    symbols: &[String],
    unresolved_calls: &[String],
    function_declarations: &str,
) -> String {
    render_ghidra_symbols_header_resolved(symbols, &[], unresolved_calls, function_declarations)
}

/// Same as `render_ghidra_symbols_header`, but real evidence (PROJECT.md
/// M18.2's `DataResolution`) can upgrade a symbol from a bare `extern`
/// placeholder to a genuine definition -- a real captured constant's
/// exact bytes, a real vtable slot's function pointer, ... `resolutions`
/// is looked up by symbol name; anything in `symbols` with no matching
/// resolution (or an `UnknownData`/`CodeAddressAlias`/`RuntimeData`/
/// `ExternalGlobalAlias` one -- none of which this pass fabricates a
/// definition for, see `DataSymbolKind`'s own doc comments) falls back to
/// the exact same bare-`extern` behavior as before this module existed.
pub fn render_ghidra_symbols_header_resolved(
    symbols: &[String],
    resolutions: &[DataResolution],
    unresolved_calls: &[String],
    function_declarations: &str,
) -> String {
    let mut out = String::new();
    out.push_str("// Generated by Debura. Declarations (and, where PROJECT.md M18.2's\n");
    out.push_str("// evidence supports one, real definitions) for Ghidra's own\n");
    out.push_str("// auto-named data symbols referenced in recovered bodies.\n");
    out.push_str("#pragma once\n\n");
    // Self-sufficient regardless of include order: `render_source`
    // includes this header *before* the class's own header (the thing
    // that otherwise pulls in ghidra_compat.hpp), and the function
    // declarations below use its types (`undefined8`, `longlong`, ...).
    // A real compile hit exactly this -- 900+ "'undefined' does not name
    // a type" errors -- before this include was added here directly.
    out.push_str(&format!("#include \"{GHIDRA_COMPAT_HEADER_NAME}\"\n\n"));
    if !function_declarations.is_empty() {
        out.push_str("// Every recovered standalone function, forward-declared here so any\n");
        out.push_str("// file that includes this header (all of them do) can call any of\n");
        out.push_str("// them regardless of definition order.\n");
        out.push_str(function_declarations);
        out.push('\n');
    }
    // Not a fixed number of passes: a pointer-alias line
    // (`DataPointerAlias`, `VtableData`'s own pointer form,
    // `FunctionPointerAlias`, `RuntimeAlias`, `KnownImportAlias`) takes
    // the address of *another* symbol -- a real dependency between two
    // lines in this generated file, not just two independent facts.
    // Every real value definition (`ConstantData`/`MutableStaticData`)
    // is emitted first, in one pass, since it can never depend on
    // anything else in this file. Every remaining, non-pointer-alias
    // kind (`ExternalGlobalAlias`, `RuntimeData`, `CodeAddressAlias`,
    // `UnknownData`, no resolution) is a bare `extern` *declaration* --
    // no initializer, so it can never depend on anything emitted after
    // it either -- and goes next. Pointer-alias lines go last, but
    // `symbols` has no guaranteed relationship between one pointer's own
    // position and its target's, and a real run found the dependency
    // isn't always one hop: `PTR_PTR_cout_1400096e0` (`DataPointerAlias`)
    // targets `PTR_cout_14000f688`, which is *itself* a pointer-alias
    // line (`KnownImportAlias`), not a value definition or bare
    // placeholder -- a fixed two-pass split got this exact case wrong.
    // Emitted via a small fixed-point loop instead: a pointer-alias
    // symbol whose own target is also a pointer-alias symbol waits until
    // that target has actually been emitted, so any real chain depth
    // resolves in true dependency order regardless of collection order.
    for symbol in symbols {
        let resolution = resolutions.iter().find(|r| &r.symbol_name == symbol);
        match resolution.map(|r| &r.kind) {
            Some(DataSymbolKind::ConstantData { size, bytes }) => {
                out.push_str(&render_scalar_or_byte_array_definition(symbol, *size, bytes, true));
            }
            Some(DataSymbolKind::MutableStaticData { size, bytes }) => {
                out.push_str(&render_scalar_or_byte_array_definition(symbol, *size, bytes, false));
            }
            _ => {}
        }
    }
    for symbol in symbols {
        let resolution = resolutions.iter().find(|r| &r.symbol_name == symbol);
        if is_pointer_alias_kind(resolution) || is_value_definition_kind(resolution) {
            continue;
        }
        // `VtableData` with no safe function-pointer representation (a
        // Method/Constructor/Destructor target -- see
        // `classify_data_symbol`'s own doc comment), and every other kind
        // this pass doesn't fabricate a definition for
        // (`ExternalGlobalAlias`, `RuntimeData`, `CodeAddressAlias`,
        // `UnknownData`), or no resolution at all: the same bare `extern`
        // placeholder as before M18.2 existed.
        if symbol.starts_with("_refptr_") || symbol.starts_with("PTR_") {
            out.push_str(&format!("extern unsigned char *{symbol};\n"));
        } else {
            out.push_str(&format!("extern unsigned char {symbol};\n"));
        }
    }

    let mut pending: Vec<&String> =
        symbols.iter().filter(|s| is_pointer_alias_kind(resolutions.iter().find(|r| &r.symbol_name == *s))).collect();
    let mut emitted: BTreeSet<&str> = BTreeSet::new();
    while !pending.is_empty() {
        let mut still_pending = Vec::new();
        let mut progressed = false;
        for symbol in pending {
            let resolution = resolutions.iter().find(|r| &r.symbol_name == symbol).map(|r| &r.kind);
            // Only `DataPointerAlias` can ever target another symbol in
            // this same pointer-alias set -- every other kind targets a
            // recovered function (already visible via
            // `function_declarations`) or a fixed external constant
            // (`__ImageBase`/`std::cout`, never a member of `symbols` at
            // all), neither of which this file's own emission order can
            // affect.
            let blocked = matches!(
                resolution,
                Some(DataSymbolKind::DataPointerAlias { target_symbol })
                    if symbols.contains(target_symbol) && !emitted.contains(target_symbol.as_str())
            );
            if blocked {
                still_pending.push(symbol);
                continue;
            }
            out.push_str(&render_pointer_alias_line(symbol, resolution));
            emitted.insert(symbol.as_str());
            progressed = true;
        }
        if !progressed {
            // A real cycle, or a target this pass's own `blocked` check
            // can't see resolved elsewhere -- shouldn't happen given how
            // `extract.rs` builds `DataPointerAlias` chains (see its own
            // fixed-point discovery loop), but emitting every remaining
            // entry anyway beats looping forever; a real compile would
            // surface a genuine "not declared" error if this ever fires.
            for symbol in &still_pending {
                let resolution = resolutions.iter().find(|r| &r.symbol_name == *symbol).map(|r| &r.kind);
                out.push_str(&render_pointer_alias_line(symbol, resolution));
            }
            break;
        }
        pending = still_pending;
    }
    if !unresolved_calls.is_empty() {
        out.push_str("\n// Call targets M15's symbol resolution pass found no recovered\n");
        out.push_str("// definition for at all -- not a class method, not a standalone\n");
        out.push_str("// function. Fully variadic so any call shape parses; still needs a\n");
        out.push_str("// real definition from somewhere before the program can link.\n");
        // PROJECT.md M18.3: a real link found this declared without
        // `extern \"C\"` gets C++-mangled (`_ismbblead` became
        // `_Z10_ismbbleadz` in the compiled object) -- for a genuine
        // MinGW CRT function like `_ismbblead`, that mangled name can
        // never match the plain C symbol the real, already-linked CRT
        // import library actually exports, so the declaration compiled
        // but the call still failed at link time. A raw `FUN_<addr>`
        // name (Debura's own placeholder, never a real overloaded C++
        // function) is unaffected either way -- `extern \"C\"` is always
        // the safe, correct choice here.
        out.push_str("extern \"C\" {\n");
        for name in unresolved_calls {
            out.push_str(&format!("long long {name}(...);\n"));
        }
        out.push_str("}\n");
    }
    out
}

fn is_value_definition_kind(resolution: Option<&DataResolution>) -> bool {
    matches!(
        resolution.map(|r| &r.kind),
        Some(DataSymbolKind::ConstantData { .. } | DataSymbolKind::MutableStaticData { .. })
    )
}

fn is_pointer_alias_kind(resolution: Option<&DataResolution>) -> bool {
    matches!(
        resolution.map(|r| &r.kind),
        Some(
            DataSymbolKind::FunctionPointerAlias { .. }
                | DataSymbolKind::VtableData { slot0_target: Some(_), .. }
                | DataSymbolKind::DataPointerAlias { .. }
                | DataSymbolKind::RuntimeAlias { .. }
                | DataSymbolKind::KnownImportAlias { .. }
        )
    )
}

/// One pointer-alias symbol's own definition line -- assumes its target
/// is already visible (a recovered function, a fixed external constant,
/// or another pointer-alias/value-definition symbol this same file
/// already emitted earlier); the caller (the fixed-point loop in
/// `render_ghidra_symbols_header_resolved`) is what actually guarantees
/// that.
fn render_pointer_alias_line(symbol: &str, resolution: Option<&DataSymbolKind>) -> String {
    // PROJECT.md M18.3: a real link found every one of these initialized,
    // non-`const` pointer variables is a full *definition* with external
    // linkage -- and this header (unlike a plain `extern` placeholder) is
    // `#include`d into every generated `.cpp` file, so the *same*
    // definition landed in seven different translation units at once:
    // "multiple definition of `PTR_FUN_140009a20`", a real ODR violation
    // that would have broken *any* project with more than one of these
    // once compiled together, not just this one. `inline` (a real C++17
    // feature, not a hint) is exactly what a header-defined global needs:
    // the linker merges identical definitions across translation units
    // instead of rejecting them, the same guarantee an inline function
    // already has.
    match resolution {
        Some(DataSymbolKind::FunctionPointerAlias { target_function }) => {
            format!("inline void *{symbol} = (void *)&{target_function};\n")
        }
        Some(DataSymbolKind::VtableData { slot0_target: Some(VtableSlotTarget::FreeFunction(target)), .. }) => {
            format!("inline void *{symbol} = (void *)&{target};\n")
        }
        Some(DataSymbolKind::VtableData { slot0_target: Some(VtableSlotTarget::Method { trampoline_name, .. }), .. }) => {
            // `functions.cpp` already emits `trampoline_name` as a real,
            // plain (non-member) function -- see
            // `VtableSlotTarget::Method`'s own doc comment -- so this
            // binds exactly like a `FreeFunction` target once that
            // trampoline exists.
            format!("inline void *{symbol} = (void *)&{trampoline_name};\n")
        }
        Some(DataSymbolKind::DataPointerAlias { target_symbol }) => {
            // `unsigned char *`, not `void *` -- unlike
            // `FunctionPointerAlias`/`VtableData` (whose call sites
            // already cast explicitly through a concrete type before
            // using the result), a real run found `PTR_*` targets
            // dereferenced directly (`*PTR_DAT_x`), which a `void *`
            // can't be (`'void*' is not a pointer-to-object type`).
            // Matches the exact type the bare-`extern` fallback already
            // declares every other `PTR_*`/`_refptr_*` symbol as, so a
            // use site behaves identically whether this symbol ended up
            // defined or left as a placeholder.
            format!("inline unsigned char *{symbol} = (unsigned char *)&{target_symbol};\n")
        }
        Some(DataSymbolKind::RuntimeAlias { runtime_symbol, runtime_type }) => {
            // `runtime_symbol` is never one of `symbols` -- it's a
            // fixed, toolchain-provided constant (currently only
            // `__ImageBase`), not a Ghidra placeholder needing the
            // generic collection/classification treatment, so its own
            // declaration is emitted directly here rather than threaded
            // through the bare-`extern` pass. `extern "C"` so C++
            // name-mangling never hides the real, unmangled symbol the
            // linker actually provides -- a plain `extern` *declaration*
            // (no initializer), so it doesn't need `inline` itself; the
            // pointer binding on the next line does.
            format!(
                "extern \"C\" {runtime_type} {runtime_symbol};\ninline unsigned char *{symbol} = (unsigned char *)&{runtime_symbol};\n"
            )
        }
        Some(DataSymbolKind::KnownImportAlias { qualified_name }) => {
            // No extra declaration needed, unlike `RuntimeAlias` --
            // `qualified_name` (currently only `std::cout`) is already
            // declared by whatever standard header the recovered code
            // already includes (`ghidra_compat.hpp` pulls in
            // `<iostream>`).
            format!("inline unsigned char *{symbol} = (unsigned char *)&{qualified_name};\n")
        }
        _ => String::new(),
    }
}

/// `unsigned char NAME[SIZE] = {0x.., ...};` (or `const unsigned char`
/// for read-only data) -- the exact captured bytes, never interpreted as
/// any specific numeric/struct type Debura doesn't have real evidence
/// for (PROJECT.md M18.2: "Unknown is better than confidently wrong"
/// applies to a global's own C++ type the same way it already applies to
/// semantic naming). A real call site that needs a specific type
/// (`*(double *)&DAT_x`) already does its own reinterpreting cast --
/// this only needs to supply real storage of the right size and content,
/// not the exact type a specific use site happens to want.
///
/// One deliberate, narrowly-scoped exception: a real compile found
/// recovered bodies that use an 8-byte constant *by value*, directly in
/// floating-point arithmetic (`- DAT_140009070`, real Food-grid scaling
/// constants) -- not through a pointer at all, so an array (which never
/// implicitly converts to a number) hard-fails to compile there, not just
/// loses precision. When the exact captured bytes decode as a finite,
/// "clean"-looking IEEE-754 double (this project's own real cases:
/// 1.0/2.0/4.0, not float-noise), a `double` definition is emitted
/// instead -- justified by two independent, real pieces of evidence
/// together (the bytes cleanly decode, *and* the only real use site
/// needs a number there), not a guess from the symbol's own name or
/// generic type. Still a real, scoped judgment call, not a certainty:
/// an 8-byte pointer stored in a genuinely address-shaped global could
/// coincidentally decode to a clean-looking double too -- `decode_as_clean_f64`
/// guards against this by magnitude, both directions: a real 64-bit
/// address in this program is always either large (>= 0x140000000, ruled
/// out by the upper bound) or -- a real test case, not a hypothetical --
/// decodes to an implausibly *tiny* denormal when its high bytes happen
/// to be zero (ruled out by the lower bound).
fn render_scalar_or_byte_array_definition(symbol: &str, size: u64, bytes: &[u8], readonly: bool) -> String {
    // PROJECT.md M18.3: `inline`, always -- a real link found a
    // `MutableStaticData` definition (no `const`, so external linkage by
    // default) landed in every translation unit this header is
    // `#include`d into, a real multiple-definition ODR violation (the
    // same one `render_pointer_alias_line`'s own doc comment explains in
    // more detail). `ConstantData`'s own `const` already implies
    // internal linkage, so it was never broken this way, but `inline` is
    // harmless there too (C++17 explicitly allows combining them) and
    // keeps both cases consistent rather than depending on which branch
    // happened to dodge the bug.
    let qualifier = if readonly { "inline const " } else { "inline " };
    if size == 8 {
        if let Some(value) = decode_as_clean_f64(bytes) {
            return format!("{qualifier}double {symbol} = {value:?};\n");
        }
    }
    let byte_list: Vec<String> = bytes.iter().map(|b| format!("0x{b:02x}")).collect();
    format!("{qualifier}unsigned char {symbol}[{size}] = {{{}}};\n", byte_list.join(","))
}

/// `bytes` (little-endian, exactly 8 of them) reinterpreted as an IEEE-754
/// double, accepted only when it's finite and small in magnitude -- real
/// pointer values in this program are always >= 0x140000000 (~5.5e9),
/// far outside any range a genuine floating-point game constant would
/// plausibly use, so this is a real, if approximate, way to tell "this
/// 8-byte value is a number" from "this 8-byte value is an address"
/// using only the bytes themselves.
fn decode_as_clean_f64(bytes: &[u8]) -> Option<f64> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    let value = f64::from_le_bytes(array);
    // A real test with a genuine address's own bytes (0x1400018ca)
    // caught a real gap here: an address's high bytes are usually zero
    // (small program addresses), which lands squarely in a double's own
    // exponent field, decoding to an implausibly *tiny* (denormal,
    // ~1e-314) value -- not just an implausibly huge one. Rejecting
    // anything closer to zero than a real game constant would plausibly
    // be (but not 0.0 itself, a real, legitimate exact value) closes
    // that gap the same way the large-magnitude bound already does.
    let magnitude_is_plausible = value == 0.0 || (1.0e-6..1.0e12).contains(&value.abs());
    if value.is_finite() && magnitude_is_plausible {
        Some(value)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real, confirmed case: `DAT_140009070`'s captured bytes decode
    /// exactly as 2.0, and the only real use site needs a number, not a
    /// pointer -- must render as a scalar, not an array (a real compile
    /// found the array form hard-fails on `- DAT_140009070`).
    #[test]
    fn an_eight_byte_constant_decoding_cleanly_renders_as_a_scalar_double() {
        let rendered = render_scalar_or_byte_array_definition("DAT_140009070", 8, &[0, 0, 0, 0, 0, 0, 0, 0x40], true);
        assert_eq!(rendered, "inline const double DAT_140009070 = 2.0;\n");
    }

    /// A real 64-bit address value (always large in this program) must
    /// never be reinterpreted as a small "clean" double just because it
    /// happens to be 8 bytes -- falls back to the honest byte array.
    #[test]
    fn an_eight_byte_value_that_looks_like_an_address_stays_a_byte_array() {
        // 0x1400018ca, a real function address from this project's own
        // fixture data, little-endian.
        let bytes = [0xca, 0x18, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00];
        let rendered = render_scalar_or_byte_array_definition("PTR_DAT_140009050", 8, &bytes, true);
        assert!(rendered.starts_with("inline const unsigned char PTR_DAT_140009050[8] = {"), "{rendered}");
        assert!(!rendered.contains("double"), "{rendered}");
    }

    #[test]
    fn a_non_eight_byte_constant_is_always_a_byte_array() {
        let rendered = render_scalar_or_byte_array_definition("DAT_1400099e0", 1, &[0x00], true);
        assert_eq!(rendered, "inline const unsigned char DAT_1400099e0[1] = {0x00};\n");
    }

    /// PROJECT.md M18.3: `symbols` carries no guaranteed relationship
    /// between a `DataPointerAlias`'s own position and its target's --
    /// deliberately adversarial here (the pointer, "AAA_PTR", sorts
    /// *before* its target, "ZZZ_DAT", the opposite of what a real
    /// `BTreeSet` collection would ever happen to produce). The target's
    /// real definition must still appear before the pointer takes its
    /// address, or a real compiler would reject this as a use of an
    /// undeclared identifier.
    #[test]
    fn a_data_pointer_alias_is_rendered_after_its_target_regardless_of_input_order() {
        let symbols = vec!["AAA_PTR".to_string(), "ZZZ_DAT".to_string()];
        let resolutions = vec![
            DataResolution {
                address: "0x1".to_string(),
                symbol_name: "AAA_PTR".to_string(),
                kind: DataSymbolKind::DataPointerAlias { target_symbol: "ZZZ_DAT".to_string() },
                source_facts: vec![],
                confidence: 1.0,
            },
            DataResolution {
                address: "0x2".to_string(),
                symbol_name: "ZZZ_DAT".to_string(),
                kind: DataSymbolKind::ConstantData { size: 1, bytes: vec![0x42] },
                source_facts: vec![],
                confidence: 1.0,
            },
        ];

        let header = render_ghidra_symbols_header_resolved(&symbols, &resolutions, &[], "");

        let target_pos = header.find("ZZZ_DAT[1]").expect("target definition present");
        let pointer_pos = header.find("AAA_PTR = ").expect("pointer alias present");
        assert!(target_pos < pointer_pos, "target must be defined before its address is taken:\n{header}");
    }

    /// PROJECT.md M18.3: the real, confirmed case a first version of the
    /// three-pass split still got wrong -- `PTR_PTR_cout_1400096e0`
    /// (`DataPointerAlias`) targets `PTR_cout_14000f688`, which isn't a
    /// value definition at all (it's an `ExternalGlobalAlias`, so only
    /// ever a bare `extern` *declaration*). Alphabetically,
    /// "PTR_PTR_cout..." sorts *before* "PTR_cout..." (uppercase `P` <
    /// lowercase `c`), so the two-pass split (value defs, then pointer
    /// aliases) put the alias before its target's own declaration --
    /// "not declared in this scope" against a real g++. The bare-`extern`
    /// pass must run before the pointer-alias pass, not just the
    /// value-definition pass.
    #[test]
    fn a_data_pointer_alias_targeting_a_bare_extern_symbol_is_rendered_after_its_declaration() {
        let symbols = vec!["PTR_PTR_cout_1400096e0".to_string(), "PTR_cout_14000f688".to_string()];
        let resolutions = vec![
            DataResolution {
                address: "0x1400096e0".to_string(),
                symbol_name: "PTR_PTR_cout_1400096e0".to_string(),
                kind: DataSymbolKind::DataPointerAlias { target_symbol: "PTR_cout_14000f688".to_string() },
                source_facts: vec![],
                confidence: 1.0,
            },
            DataResolution {
                address: "0x14000f688".to_string(),
                symbol_name: "PTR_cout_14000f688".to_string(),
                kind: DataSymbolKind::ExternalGlobalAlias { pointee: "0x16".to_string() },
                source_facts: vec![],
                confidence: 0.8,
            },
        ];

        let header = render_ghidra_symbols_header_resolved(&symbols, &resolutions, &[], "");

        let decl_pos = header.find("extern unsigned char *PTR_cout_14000f688;").expect("bare extern declaration present");
        let alias_pos = header.find("PTR_PTR_cout_1400096e0 = ").expect("pointer alias present");
        assert!(decl_pos < alias_pos, "the target must be declared before its address is taken:\n{header}");
        // A real compile also hit this: dereferenced directly
        // (`*PTR_DAT_x`), a `DataPointerAlias` must never render as
        // `void *` -- `'void*' is not a pointer-to-object type`.
        assert!(!header.contains("void *PTR_PTR_cout_1400096e0"), "{header}");
        assert!(header.contains("unsigned char *PTR_PTR_cout_1400096e0 = (unsigned char *)&PTR_cout_14000f688;"), "{header}");
    }

    /// The real, confirmed case: `__ImageBase` is a fixed,
    /// toolchain-provided constant, never a member of `symbols` itself --
    /// its own declaration must still appear (with the real type
    /// `classify_data_symbol` recorded), and `extern "C"` so C++
    /// name-mangling never hides the real, unmangled linker symbol.
    #[test]
    fn a_runtime_alias_declares_and_binds_to_its_toolchain_provided_symbol() {
        let symbols = vec!["PTR_IMAGE_DOS_HEADER_140009710".to_string()];
        let resolutions = vec![DataResolution {
            address: "0x140009710".to_string(),
            symbol_name: "PTR_IMAGE_DOS_HEADER_140009710".to_string(),
            kind: DataSymbolKind::RuntimeAlias {
                runtime_symbol: "__ImageBase".to_string(),
                runtime_type: "IMAGE_DOS_HEADER".to_string(),
            },
            source_facts: vec![],
            confidence: 1.0,
        }];

        let header = render_ghidra_symbols_header_resolved(&symbols, &resolutions, &[], "");

        assert!(header.contains("extern \"C\" IMAGE_DOS_HEADER __ImageBase;"), "{header}");
        assert!(
            header.contains("unsigned char *PTR_IMAGE_DOS_HEADER_140009710 = (unsigned char *)&__ImageBase;"),
            "{header}"
        );
    }

    /// The real, confirmed case: `std::cout` needs no extra declaration
    /// line at all (unlike `RuntimeAlias`'s `__ImageBase`) -- it's
    /// already declared by `<iostream>`, which `ghidra_compat.hpp`
    /// already includes.
    #[test]
    fn a_known_import_alias_binds_directly_with_no_extra_declaration() {
        let symbols = vec!["PTR_cout_14000f688".to_string()];
        let resolutions = vec![DataResolution {
            address: "0x14000f688".to_string(),
            symbol_name: "PTR_cout_14000f688".to_string(),
            kind: DataSymbolKind::KnownImportAlias { qualified_name: "std::cout".to_string() },
            source_facts: vec![],
            confidence: 1.0,
        }];

        let header = render_ghidra_symbols_header_resolved(&symbols, &resolutions, &[], "");

        assert!(
            header.contains("unsigned char *PTR_cout_14000f688 = (unsigned char *)&std::cout;"),
            "{header}"
        );
        assert!(!header.contains("extern"), "{header}");
    }

    /// PROJECT.md M18.3: the real, confirmed case a first version of the
    /// pointer-alias ordering fix still got wrong -- `PTR_PTR_cout_1400096e0`
    /// (`DataPointerAlias`) targets `PTR_cout_14000f688`, which is *itself*
    /// a pointer-alias line (`KnownImportAlias`), not a value definition
    /// or a bare `extern` placeholder. A fixed two-pass split (values,
    /// then bare externs, then every pointer alias in one pass) put both
    /// pointer-alias lines in the same pass, in `symbols`' own
    /// (alphabetical, not dependency) order -- "PTR_PTR_cout..." sorts
    /// before "PTR_cout...", so the alias was emitted before its own
    /// target. The fixed-point loop must wait for a pointer-alias
    /// target to be emitted first, regardless of which pass it belongs
    /// to.
    #[test]
    fn a_pointer_alias_chain_through_another_pointer_alias_resolves_in_dependency_order() {
        let symbols = vec!["PTR_PTR_cout_1400096e0".to_string(), "PTR_cout_14000f688".to_string()];
        let resolutions = vec![
            DataResolution {
                address: "0x1400096e0".to_string(),
                symbol_name: "PTR_PTR_cout_1400096e0".to_string(),
                kind: DataSymbolKind::DataPointerAlias { target_symbol: "PTR_cout_14000f688".to_string() },
                source_facts: vec![],
                confidence: 1.0,
            },
            DataResolution {
                address: "0x14000f688".to_string(),
                symbol_name: "PTR_cout_14000f688".to_string(),
                kind: DataSymbolKind::KnownImportAlias { qualified_name: "std::cout".to_string() },
                source_facts: vec![],
                confidence: 1.0,
            },
        ];

        let header = render_ghidra_symbols_header_resolved(&symbols, &resolutions, &[], "");

        let target_pos = header.find("PTR_cout_14000f688 = ").expect("target's own definition present");
        let alias_pos = header.find("PTR_PTR_cout_1400096e0 = ").expect("alias present");
        assert!(target_pos < alias_pos, "target must be defined before its address is taken:\n{header}");
    }

    /// PROJECT.md M18.3: the real, confirmed case a real link found --
    /// a vtable-slot trampoline is defined in `functions.cpp`, but this
    /// header's own pointer-alias line binding a vtable slot to it is
    /// included *first*, in every generated file, well before
    /// `functions.cpp` is compiled. Its own forward declaration must be
    /// threaded through the same `function_declarations` text
    /// `write.rs` already builds for ordinary recovered functions.
    #[test]
    fn a_vtable_trampoline_declaration_is_visible_before_the_pointer_alias_uses_it() {
        let trampolines = vec![crate::model::VtableTrampoline {
            name: "Wall__vtable_trampoline_FUN_140002f4e".to_string(),
            owner: "Wall".to_string(),
            method_name: "FUN_140002f4e".to_string(),
            return_type: "undefined".to_string(),
            params: "longlong param_2".to_string(),
        }];
        let declarations = render_vtable_trampoline_declarations(&trampolines);
        assert_eq!(
            declarations,
            "extern \"C\" undefined Wall__vtable_trampoline_FUN_140002f4e(void *debura_this,longlong param_2);\n"
        );

        let symbols = vec!["PTR_FUN_140009a20".to_string()];
        let resolutions = vec![DataResolution {
            address: "0x140009a20".to_string(),
            symbol_name: "PTR_FUN_140009a20".to_string(),
            kind: DataSymbolKind::VtableData {
                class_name: "Wall".to_string(),
                slot0_target: Some(VtableSlotTarget::Method {
                    trampoline_name: "Wall__vtable_trampoline_FUN_140002f4e".to_string(),
                    owner: "Wall".to_string(),
                    method_name: "FUN_140002f4e".to_string(),
                    return_type: "undefined".to_string(),
                    params: "longlong param_2".to_string(),
                }),
            },
            source_facts: vec![],
            confidence: 1.0,
        }];

        let header = render_ghidra_symbols_header_resolved(&symbols, &resolutions, &[], &declarations);

        let decl_pos = header.find("extern \"C\" undefined Wall__vtable_trampoline_FUN_140002f4e").unwrap();
        let use_pos = header.find("PTR_FUN_140009a20 = ").expect("pointer alias present");
        assert!(decl_pos < use_pos, "the trampoline must be declared before its address is taken:\n{header}");
    }

    /// PROJECT.md M18.3: the real, confirmed bug a real link found --
    /// this header is `#include`d into every generated `.cpp` file, so
    /// a non-`const`, initialized global (a pointer-alias line, or a
    /// `MutableStaticData` definition) without `inline` is a full
    /// definition with external linkage repeated in every one of them:
    /// "multiple definition of `PTR_FUN_140009a20`", a real link
    /// failure across a 7-file project, not a hypothetical. Every real
    /// definition this module ever emits must be `inline`.
    #[test]
    fn every_real_definition_is_inline_so_multiple_translation_units_can_include_it() {
        let symbols = vec!["DAT_CONST".to_string(), "DAT_MUTABLE".to_string(), "PTR_ALIAS".to_string()];
        let resolutions = vec![
            DataResolution {
                address: "0x1".to_string(),
                symbol_name: "DAT_CONST".to_string(),
                kind: DataSymbolKind::ConstantData { size: 1, bytes: vec![0x01] },
                source_facts: vec![],
                confidence: 1.0,
            },
            DataResolution {
                address: "0x2".to_string(),
                symbol_name: "DAT_MUTABLE".to_string(),
                kind: DataSymbolKind::MutableStaticData { size: 1, bytes: vec![0x00] },
                source_facts: vec![],
                confidence: 1.0,
            },
            DataResolution {
                address: "0x3".to_string(),
                symbol_name: "PTR_ALIAS".to_string(),
                kind: DataSymbolKind::DataPointerAlias { target_symbol: "DAT_CONST".to_string() },
                source_facts: vec![],
                confidence: 1.0,
            },
        ];

        let header = render_ghidra_symbols_header_resolved(&symbols, &resolutions, &[], "");

        assert!(header.contains("inline const unsigned char DAT_CONST[1]"), "{header}");
        assert!(header.contains("inline unsigned char DAT_MUTABLE[1]"), "{header}");
        assert!(header.contains("inline unsigned char *PTR_ALIAS ="), "{header}");
    }
}
