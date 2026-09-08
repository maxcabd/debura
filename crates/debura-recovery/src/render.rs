use crate::compat::GHIDRA_COMPAT_HEADER_NAME;
use crate::model::{NameSource, RecoveredClass, RecoveredFunction, RecoveredMethod};
use crate::symbols::GHIDRA_SYMBOLS_HEADER_NAME;

/// Ghidra's vtable-pointer-slot idiom assigns the *address* of a
/// synthesized data symbol to a pointer-to-pointer lvalue
/// (`*(undefined ***)this = &PTR_draw_140009a40;`), but the symbol
/// itself is only ever declared as a generic placeholder byte (its real
/// type isn't known -- see `symbols.rs`'s `render_ghidra_symbols_header`),
/// so `&SYMBOL` doesn't have the exact pointer type the assignment
/// needs. Inserting the cast the assignment's own left-hand side already
/// implies makes it compile regardless of what type the symbol is
/// actually declared as -- verified by compiling this exact
/// substitution. Real, observed shape from the Snake fixture; other
/// pointer-depth variants of the same idiom aren't handled yet.
fn patch_known_idioms(text: &str) -> String {
    let prefix = "*(undefined ***)this = ";
    let needle = format!("{prefix}&");
    let text = text.replace(&needle, &format!("{prefix}(undefined **)&"));

    // Ghidra decompiles `std::cout << x` (real signature: `ostream&
    // operator<<(ostream&, ...)`) as `std::operator<<(&cout, x)` --
    // references are raw pointers at the ABI level, which the real,
    // reference-taking overloads don't match at all. C++ also forbids
    // declaring a pointer-taking `operator<<` overload to catch this (a
    // non-member operator<< needs at least one class/enum/reference
    // parameter, which `(ostream *, T *)` never has); `compat.rs`'s
    // `debura_stream_output`/`debura_stream_endl` are ordinary functions
    // instead, which carry no such restriction, so the call sites are
    // renamed to them here rather than declaring an operator that could
    // never legally exist.
    let text = text.replace("std::operator<<(", "debura_stream_output(");
    let text = text.replace("std::endl<char,std::char_traits<char>>(", "debura_stream_endl(");
    // The *other* half of the chained-manipulator idiom
    // (`std::cout << msg << std::endl;`): the outer `operator<<` --
    // the overload that accepts a manipulator function pointer, which
    // really is a *member* of basic_ostream in the real ABI, unlike the
    // free-function overloads for ordinary values -- decompiles as a
    // qualified call to this exact class-scoped name, not
    // `std::operator<<`. `compat.rs`'s `debura_stream_manip` takes over
    // from here (and declares the function-pointer typedef this call's
    // own argument cast needs).
    // No trailing `(` in the needle: Ghidra sometimes wraps a long call
    // expression across lines, with the open paren on its own line --
    // a real case had exactly this, which an earlier version of this
    // replace (requiring an immediately-following `(`) silently missed.
    // Whitespace/a newline between a function name and its `(` is valid
    // C++ regardless, so dropping it from the needle is enough.
    let text = text.replace(
        "std::basic_ostream<char,std::char_traits<char>>::operator<<",
        "debura_stream_manip",
    );
    // Ghidra's decompiler occasionally names a local variable holding an
    // intermediate value literally `this` -- unrelated to the enclosing
    // function's own implicit `this`, but a hard conflict regardless,
    // since `this` is a reserved keyword. A real case had a
    // `basic_ostream *this;` local holding a chained `operator<<`
    // call's return value. Detected narrowly, only when an actual
    // declaration line names it, so a body that legitimately uses the
    // real, implicit `this` (never re-declared as a local) is untouched.
    let text = rename_this_local_variable(&text);

    // Ghidra decompiles non-static member calls on real std:: types
    // (`c_str`/`str`/`~basic_string`/`~basic_stringstream`, and a
    // redundant explicit default-constructor call on an already-declared
    // local) as `Type::member(receiver, ...)` -- not real, compilable C++
    // syntax for a non-static member. Must run before the template-
    // argument stripping below, which would otherwise remove the exact
    // bare-templated type names this looks for from each paired local
    // declaration.
    let text = fix_qualified_member_calls(
        &text,
        "std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>",
        "basic_string<char,std::char_traits<char>,std::allocator<char>>",
        "basic_string",
    );
    let text = fix_qualified_member_calls(
        &text,
        "std::__cxx11::basic_stringstream<char,std::char_traits<char>,std::allocator<char>>",
        "basic_stringstream<char,std::char_traits<char>,std::allocator<char>>",
        "basic_stringstream",
    );

    // Two specific SDL API calls decompile with an `undefined`-typed
    // local where the real signature needs a struct value/pointer --
    // `local_3c = 0xffffff;` (a packed color, wrong type: `undefined4`
    // instead of `SDL_Color`) and four separate `undefined4` locals used
    // as an `SDL_Rect`'s x/y/w/h fields via `&local_58` (wrong type:
    // `undefined4*` instead of `const SDL_Rect*`). Both are exactly
    // Ghidra's own byte-for-byte layout of the real struct, so
    // reinterpreting through a pointer/reference cast is safe and
    // preserves exactly the value Ghidra computed -- the same "insert the
    // cast the call site already implies" approach as this function's own
    // vtable-pointer-slot fix above, scoped to these two well-known,
    // fixed SDL function names rather than a generic pattern.
    let text = cast_last_call_argument(&text, "TTF_RenderText_Solid", "*(SDL_Color*)&");
    let text = cast_last_call_argument(&text, "SDL_RenderCopy", "(const SDL_Rect*)");
    // `__stdio_common_vfprintf` is a real UCRT function (real signature
    // ends `..., va_list arglist)`); Ghidra decompiles its own captured
    // argument list as a plain `undefined8 *` pointer -- the same 8
    // bytes `va_list` (a bare `char *` on this target) already is, just
    // the wrong C++ type for an implicit conversion.
    let text = cast_last_call_argument(&text, "__stdio_common_vfprintf", "(va_list)");

    // Ghidra always writes these STL types out with their real,
    // explicit (and in this codebase, always `char`-based) template
    // arguments -- valid against the *real* std:: templates, but not
    // against `ghidra_compat.hpp`'s own bare-name aliases (declared as
    // plain, non-template `using` aliases specifically so a bare
    // `basic_ostream *pbVar1;` -- Ghidra's *other* common shape for the
    // same type, with no template arguments at all -- also resolves). A
    // real compile hit "is not a template" for exactly this: a local
    // variable declared `basic_stringstream<char,...> local_1a8 [16];`.
    // Dropping the redundant explicit arguments (they name the exact
    // instantiation the bare alias already is) satisfies both shapes --
    // but only for the *bare* occurrence: a `std::`/`std::__cxx11::`-
    // qualified one names the real template directly, which does need
    // its arguments, and a first version of this that stripped them
    // unconditionally broke exactly that (`std::basic_ostream::
    // operator<<` with no arguments at all, "used without template
    // arguments").
    let text = strip_redundant_template_args(
        &text,
        "basic_stringstream<char,std::char_traits<char>,std::allocator<char>>",
        "basic_stringstream",
    );
    let text = strip_redundant_template_args(
        &text,
        "basic_string<char,std::char_traits<char>,std::allocator<char>>",
        "basic_string",
    );
    strip_redundant_template_args(&text, "basic_ostream<char,std::char_traits<char>>", "basic_ostream")
}

/// Renames a local variable literally declared `this` (e.g.
/// `basic_ostream *this;`) to `debura_local_this`, throughout the body --
/// but only when such a declaration line actually exists. A genuine,
/// implicit `this` is never re-declared this way, so its absence is a
/// reliable signal this body doesn't have the bug at all.
fn rename_this_local_variable(text: &str) -> String {
    let has_this_declaration = text.lines().any(|line| {
        let trimmed = line.trim();
        // A real declaration is bare (`TYPE *this;`, no `=`) and never a
        // `return`/assignment statement that merely *uses* a genuine,
        // implicit `this` and happens to also end the same way (`return
        // this;`, `pbVar1 = this;`).
        !trimmed.starts_with("return")
            && !trimmed.contains('=')
            && (trimmed.ends_with("*this;") || trimmed.ends_with(" this;"))
    });
    if !has_this_declaration {
        return text.to_string();
    }
    replace_whole_word(text, "this", "debura_local_this")
}

/// Ghidra decompiles a non-static member call on a real `std::` type as
/// `Type::member(receiver, args...)` -- valid-looking C-shaped text, but
/// not real, compilable C++ for a non-static member (needs
/// `receiver->member(args...)` instead). A real compile found three
/// distinct shapes of this, all fixed here uniformly, for any method
/// name, against `bare_type` (a `using` alias in `ghidra_compat.hpp`,
/// e.g. `basic_string`) qualified as `qualified_type` (the real template
/// Ghidra names, e.g. `std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>`):
/// - A destructor call (`~Bare(receiver)`) -> `receiver->~Bare()`.
/// - A redundant explicit call to the type's own default constructor on
///   an already-declared local (`Type::Bare();`) -- deleted outright,
///   statement and all: the local's own declaration (`Bare local [N];`)
///   already default-constructs it, so this is pure Ghidra ABI-level
///   narration with nothing left for real C++ to do.
/// - An ordinary accessor (`member(receiver, rest...)`) ->
///   `receiver->member(rest...)`, or, when Ghidra's own raw decompilation
///   dropped the receiver argument entirely (a real, observed case),
///   recovered from the body's own single same-`bare_type` local when
///   exactly one exists -- guessing wrong here is worse than a visible
///   compile error, so anything less unambiguous is left alone.
fn fix_qualified_member_calls(text: &str, qualified_type: &str, decl_type: &str, bare_type: &str) -> String {
    let prefix = format!("{qualified_type}::");
    if !text.contains(&prefix) {
        return text.to_string();
    }

    let decl_needle = format!("{decl_type} ");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(&prefix) {
        out.push_str(&rest[..pos]);
        let after_prefix = &rest[pos + prefix.len()..];
        // A real case had the member name wrapped onto the next line
        // (Ghidra sometimes breaks a long qualified call across lines
        // right after the `::`) -- skip leading whitespace/newlines
        // before looking for the member name itself.
        let member_start = after_prefix.trim_start();
        let name_end = member_start
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '~'))
            .unwrap_or(member_start.len());
        let member = &member_start[..name_end];
        let after_name = member_start[name_end..].trim_start();
        if member.is_empty() || !after_name.starts_with('(') {
            // Not a call shape this understands -- leave the prefix as
            // literal text and keep scanning past it.
            out.push_str(&prefix);
            rest = after_prefix;
            continue;
        }
        let call_rest = &after_name[1..];
        let Some(close) = find_matching_close_paren(call_rest) else {
            out.push_str(&prefix);
            rest = after_prefix;
            continue;
        };
        let args_text = call_rest[..close].trim();
        let after_call = &call_rest[close + 1..];

        if member == bare_type && args_text.is_empty() {
            match after_call.find(';') {
                Some(semi) => rest = &after_call[semi + 1..],
                None => rest = after_call,
            }
            continue;
        }

        let (mut receiver, remaining_args) = split_first_arg(args_text);
        if receiver.is_empty() {
            let decl_matches: Vec<&str> = find_declared_local_names(text, &decl_needle);
            match decl_matches.as_slice() {
                [name] => {
                    receiver = name;
                }
                _ => {
                    out.push_str(&prefix);
                    rest = after_prefix;
                    continue;
                }
            }
        }

        if member.starts_with('~') {
            out.push_str(&format!("{receiver}->~{bare_type}()"));
        } else {
            out.push_str(&format!("{receiver}->{member}({remaining_args})"));
        }
        rest = after_call;
    }
    out.push_str(rest);
    out
}

/// Splits `args` on its first top-level (paren/bracket-depth-0) comma --
/// enough to separate a qualified member call's own receiver from its
/// remaining, untouched arguments, without needing a full argument-list
/// parser (`symtab.rs`'s `split_args` solves the same problem for a
/// different caller, generalized to every comma; this only ever needs
/// the first).
fn split_first_arg(args: &str) -> (&str, &str) {
    let mut depth = 0i32;
    for (i, c) in args.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => return (args[..i].trim(), args[i + 1..].trim()),
            _ => {}
        }
    }
    (args, "")
}

/// Wraps a call site's own last (comma-separated, top-level) argument in
/// `cast`, for every call to `function` in `text`. Finds the argument
/// list with a balanced-parenthesis scan (an argument can itself contain
/// parenthesized casts/expressions, e.g. `*(undefined8 *)(param_1 +
/// 0x28)`, which a plain search for the next `)` would stop at
/// prematurely) but splits on the *last* comma without itself tracking
/// nesting -- correct for every call this is actually used against (a
/// bare identifier or `&identifier` as the final argument), not a
/// general-purpose argument parser.
fn cast_last_call_argument(text: &str, function: &str, cast: &str) -> String {
    let needle = format!("{function}(");
    if !text.contains(&needle) {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(&needle) {
        out.push_str(&rest[..pos + needle.len()]);
        let after = &rest[pos + needle.len()..];
        let Some(close) = find_matching_close_paren(after) else {
            out.push_str(after);
            return out;
        };
        let args = &after[..close];
        match args.rfind(',') {
            Some(comma) => {
                out.push_str(&args[..=comma]);
                out.push_str(cast);
                out.push_str(args[comma + 1..].trim());
            }
            None => out.push_str(args),
        }
        out.push(')');
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// The index of the `)` that closes the `(` immediately preceding
/// `text[0..]` (already consumed by the caller), accounting for nested
/// parentheses.
fn find_matching_close_paren(text: &str) -> Option<usize> {
    let mut depth = 1;
    for (i, c) in text.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Every local variable Ghidra declared as a stack-allocated
/// `basic_string<char,std::char_traits<char>,std::allocator<char>> NAME
/// [N];` -- the shape a decompiled `std::string` local always has.
/// Every local variable declared `{decl_needle}NAME [N];` -- the shape
/// Ghidra always uses for a stack-allocated instance of a std:: type it
/// otherwise renders with real template arguments (`decl_needle` already
/// carries its own trailing space, e.g. `"basic_string<char,std::char_traits<char>,std::allocator<char>> "`).
fn find_declared_local_names<'a>(text: &'a str, decl_needle: &str) -> Vec<&'a str> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find(decl_needle) {
        let after = &rest[pos + decl_needle.len()..];
        if let Some(name) = after.split(|c: char| c == ' ' || c == '[').next() {
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                names.push(name);
            }
        }
        rest = after;
    }
    names
}

/// Replaces every whole-word occurrence of `word` with `replacement` --
/// unlike a plain substring replace, doesn't also match `word` as part of
/// a longer identifier.
fn replace_whole_word(text: &str, word: &str, replacement: &str) -> String {
    fn is_word_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(rel) = text[i..].find(word) {
        let start = i + rel;
        let end = start + word.len();
        let before_ok = start == 0 || !is_word_byte(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_word_byte(bytes[end]);
        out.push_str(&text[i..start]);
        out.push_str(if before_ok && after_ok { replacement } else { word });
        i = end;
    }
    out.push_str(&text[i..]);
    out
}

/// Replaces `templated` with `bare` everywhere it appears *without* a
/// `::`-qualification immediately before it (a bare occurrence, meant
/// for `ghidra_compat.hpp`'s own non-template alias) -- leaving any
/// `std::`/`std::__cxx11::`-qualified occurrence (naming the real
/// template directly, which still needs its arguments) untouched.
fn strip_redundant_template_args(text: &str, templated: &str, bare: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(templated) {
        let (before, after) = (&rest[..pos], &rest[pos + templated.len()..]);
        out.push_str(before);
        out.push_str(if before.ends_with("::") { templated } else { bare });
        rest = after;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod idiom_tests {
    use super::*;

    /// PROJECT.md M18: a real recovery run (only exposed once a function
    /// with no accepted name could be recovered at all -- it was never
    /// compiled before) hit exactly this shape from Ghidra's own raw
    /// decompilation: `Type::c_str()` with no argument at all, and
    /// `Type::~basic_string(local_38)` -- syntactically has its receiver,
    /// but `Type::method(receiver)` is not real, callable C++ for a
    /// non-static member either way. Both need rewriting to
    /// `receiver->method()`.
    #[test]
    fn bare_std_string_member_calls_are_rewritten_to_real_member_call_syntax() {
        let text = "void FUN_1(longlong param_1)\n\n{\n  undefined8 uVar1;\n  basic_string<char,std::char_traits<char>,std::allocator<char>> local_38 [40];\n  FUN_2(local_38,param_1);\n  uVar1 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str();\n  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(local_38);\n  return;\n}";
        let patched = patch_known_idioms(text);
        assert!(patched.contains("local_38->c_str()"), "{patched}");
        assert!(patched.contains("local_38->~basic_string()"), "{patched}");
        assert!(!patched.contains("::c_str("), "{patched}");
        assert!(!patched.contains("::~basic_string("), "{patched}");
    }

    /// Guessing wrong is worse than a visible compile error: with two
    /// candidate locals, a missing `c_str()` receiver is left alone
    /// rather than picking one arbitrarily.
    #[test]
    fn a_bare_c_str_call_is_left_alone_when_more_than_one_basic_string_local_exists() {
        let text = "basic_string<char,std::char_traits<char>,std::allocator<char>> local_38 [40]; basic_string<char,std::char_traits<char>,std::allocator<char>> local_58 [40]; uVar1 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str();";
        let patched = patch_known_idioms(text);
        assert!(patched.contains("::c_str();"), "{patched}");
    }

    /// PROJECT.md M18: the same qualified-member-call problem recurs for
    /// `basic_stringstream`, with a third shape not seen for
    /// `basic_string`: Ghidra decompiles a local's own default
    /// construction as an explicit, redundant `Type::Type();` call --
    /// invalid as a call (no object, and "protected constructor" errors
    /// from the real compiler trying to resolve it some other way) and
    /// pointless anyway, since the local's own declaration already
    /// default-constructs it.
    #[test]
    fn a_stringstream_local_does_not_get_an_explicit_redundant_construction_call() {
        let text = "basic_stringstream<char,std::char_traits<char>,std::allocator<char>> local_1a8 [16];\n  std::__cxx11::basic_stringstream<char,std::char_traits<char>,std::allocator<char>>::\n  basic_stringstream();\n  return;";
        let patched = patch_known_idioms(text);
        assert!(!patched.contains("basic_stringstream::"), "{patched}");
        assert!(!patched.contains("basic_stringstream()"), "{patched}");
        // The declaration itself (already valid, already constructs it)
        // must survive untouched.
        assert!(patched.contains("local_1a8 [16];"), "{patched}");
    }

    /// The same missing-receiver recovery `c_str()` gets, generalized: a
    /// bare `str()` on the body's own single `basic_stringstream` local.
    #[test]
    fn a_bare_stringstream_str_call_is_given_the_bodys_own_local_name() {
        let text = "basic_stringstream<char,std::char_traits<char>,std::allocator<char>> local_1a8 [16]; x = std::__cxx11::basic_stringstream<char,std::char_traits<char>,std::allocator<char>>::str();";
        let patched = patch_known_idioms(text);
        assert!(patched.contains("local_1a8->str()"), "{patched}");
    }

    #[test]
    fn a_stringstream_destructor_call_becomes_real_member_call_syntax() {
        let text = "std::__cxx11::basic_stringstream<char,std::char_traits<char>,std::allocator<char>>::\n  ~basic_stringstream(local_1a8);";
        let patched = patch_known_idioms(text);
        assert_eq!(patched, "local_1a8->~basic_stringstream();");
    }

    /// PROJECT.md M18: `TTF_RenderText_Solid`'s real third parameter is
    /// an `SDL_Color` *value*, but Ghidra decompiles the packed color as
    /// a plain `undefined4` local -- the exact same 4 bytes, just the
    /// wrong C++ type. Reinterpreting through a pointer cast preserves
    /// the value Ghidra computed.
    #[test]
    fn ttf_rendertext_solids_color_argument_is_cast_from_a_packed_undefined4() {
        let text = "TTF_RenderText_Solid(*(undefined8 *)(param_1 + 0x28),uVar1,local_3c);";
        let patched = patch_known_idioms(text);
        assert!(
            patched.contains("TTF_RenderText_Solid(*(undefined8 *)(param_1 + 0x28),uVar1,*(SDL_Color*)&local_3c);"),
            "{patched}"
        );
    }

    /// Same idea for `SDL_RenderCopy`'s `const SDL_Rect*` parameter, where
    /// Ghidra passes the address of four separate `undefined4` locals
    /// laid out as the rect's own x/y/w/h fields.
    #[test]
    fn sdl_rendercopys_rect_argument_is_cast_from_an_undefined4_pointer() {
        let text = "SDL_RenderCopy(*(undefined8 *)(param_1 + 8),*(undefined8 *)(param_1 + 0x20),0,&local_58);";
        let patched = patch_known_idioms(text);
        assert!(
            patched.contains("SDL_RenderCopy(*(undefined8 *)(param_1 + 8),*(undefined8 *)(param_1 + 0x20),0,(const SDL_Rect*)&local_58);"),
            "{patched}"
        );
    }

    #[test]
    fn bare_occurrence_loses_its_redundant_template_args() {
        let text = "basic_ostream<char,std::char_traits<char>> *pbVar1;";
        assert_eq!(patch_known_idioms(text), "basic_ostream *pbVar1;");
    }

    /// A real compile hit this as a regression: the first version of
    /// this fix stripped template arguments unconditionally, breaking a
    /// fully `std::`-qualified reference to the real template (which
    /// still needs them) into `std::basic_ostream::flush` -- "used
    /// without template arguments". `operator<<` specifically is no
    /// longer a case this could even happen to (see the manipulator test
    /// below), so this uses a different qualified member reference to
    /// keep covering the general rule.
    #[test]
    fn std_qualified_occurrence_keeps_its_template_args() {
        let text = "std::basic_ostream<char,std::char_traits<char>>::flush(x);";
        assert_eq!(
            patch_known_idioms(text),
            "std::basic_ostream<char,std::char_traits<char>>::flush(x);"
        );
    }

    /// The chained-manipulator idiom (`std::cout << msg << std::endl;`):
    /// the outer `operator<<` decompiles as a qualified call to
    /// basic_ostream's own `operator<<`, not `std::operator<<` -- a real
    /// compile found this call form entirely unhandled ("not declared in
    /// this scope" for the argument's own function-pointer cast target).
    #[test]
    fn qualified_ostream_operator_shift_becomes_debura_stream_manip() {
        let text = "std::basic_ostream<char,std::char_traits<char>>::operator<<(x, y);";
        assert_eq!(patch_known_idioms(text), "debura_stream_manip(x, y);");
    }

    /// A real compile hit this: Ghidra wrapped a long call expression
    /// across lines, with the qualified name on one line and its `(` on
    /// the next -- an earlier version of this replace required an
    /// immediately-following `(` and silently missed it.
    #[test]
    fn qualified_ostream_operator_shift_is_replaced_even_when_line_wrapped() {
        let text = "std::basic_ostream<char,std::char_traits<char>>::operator<<\n          (x, y);";
        assert_eq!(patch_known_idioms(text), "debura_stream_manip\n          (x, y);");
    }

    /// The exact real case: a local variable Ghidra's decompiler named
    /// literally `this`, holding a chained `operator<<` call's return
    /// value -- a hard conflict with the reserved keyword regardless of
    /// what it means, caught by a real compile ("expected unqualified-id
    /// before 'this'").
    #[test]
    fn a_this_named_local_variable_is_renamed() {
        let text = "basic_ostream *this;\nthis = f(x);\ng(this);\n";
        assert_eq!(
            patch_known_idioms(text),
            "basic_ostream *debura_local_this;\ndebura_local_this = f(x);\ng(debura_local_this);\n"
        );
    }

    /// The real, implicit `this` parameter -- never re-declared as a
    /// local variable -- must be left completely untouched, including
    /// when a `return this;` statement (not a declaration) happens to
    /// end the same way a declaration line would.
    #[test]
    fn a_genuine_implicit_this_is_not_renamed() {
        let text = "undefined *Drawable::operator=(Drawable *this,Drawable *param_1)\n\n{\n  return this;\n}";
        assert_eq!(patch_known_idioms(text), text);
    }

    /// Same false-positive risk, the assignment-statement shape: `pbVar1
    /// = this;` also ends with `" this;"` without being a declaration.
    #[test]
    fn an_assignment_from_a_genuine_this_is_not_mistaken_for_a_declaration() {
        let text = "basic_ostream *pbVar1;\npbVar1 = this;\n";
        assert_eq!(patch_known_idioms(text), text);
    }
}

fn name_comment(source: &NameSource) -> String {
    match source {
        NameSource::Accepted { hypothesis, confidence } => {
            format!("{hypothesis}, ACCEPTED, confidence {confidence:.2}")
        }
        NameSource::Raw => "no accepted hypothesis -- Ghidra's raw name, unverified".to_string(),
    }
}

/// A constructor or destructor's name is fixed by the language to the
/// class's own name (`ClassName`/`~ClassName`) -- never `m.display_name`,
/// even when a `semantic_role` hypothesis renamed it to something else
/// (e.g. "initializeFood"). Rendering the renamed value there produces a
/// declaration C++ doesn't recognize as a constructor at all (GCC parses
/// it as an ordinary method with an implicit `int` return type instead),
/// which is exactly what a real compile of this output hit.
fn method_declaration(m: &RecoveredMethod, class_name: &str) -> String {
    if m.is_constructor {
        format!("{class_name}({});", m.params)
    } else if m.is_destructor {
        format!("~{class_name}();")
    } else {
        format!("{} {}({});", m.return_type, m.display_name, m.params)
    }
}

/// A real run had methods (e.g. a destructor-variant thunk) whose
/// `decompiles_to` observation was only ever a bare signature -- Ghidra
/// never produced a real body for that address. Rendering that text
/// as-is left a floating signature line with no braces, which doesn't
/// parse as anything.
fn extract_body(decompilation: &str) -> String {
    match decompilation.find('{') {
        Some(idx) => decompilation[idx..].trim_end().to_string(),
        None => "{\n  // Ghidra provided no decompiled body for this address.\n}".to_string(),
    }
}

pub fn render_header(class: &RecoveredClass) -> String {
    let mut out = String::new();
    out.push_str("// Recovered by Debura.\n");
    out.push_str("// Structural facts (vtable presence, inheritance, field offsets) are\n");
    out.push_str("// deterministic Ghidra observations, trusted without a verification pass\n");
    out.push_str("// (PROJECT.md S21). Member names are ACCEPTED hypotheses where noted;\n");
    out.push_str("// otherwise they are Ghidra's own unverified names, not Debura's judgment.\n");
    if class.vtable_address.is_empty() {
        out.push_str("// no vtable observed -- not a polymorphic class\n");
    } else {
        out.push_str(&format!("// vtable observed at {}\n", class.vtable_address));
    }
    out.push_str(&format!("\n#pragma once\n\n#include \"{GHIDRA_COMPAT_HEADER_NAME}\"\n\n"));
    // Forward-declared, not #include'd: every real reference from this
    // codebase is by pointer (Ghidra passes objects by pointer/this
    // throughout its decompiled output), which a forward declaration is
    // enough for -- and a real run showed two classes referencing each
    // other (Section <-> Screen <-> Snake) turns a full #include here
    // into a circular one, where whichever header starts the cycle
    // sees the other as still-incomplete. render_source() includes the
    // full header instead, where the class's members are actually used.
    for reference in &class.references {
        out.push_str(&format!("class {reference};\n"));
    }
    if !class.references.is_empty() {
        out.push('\n');
    }

    match &class.base {
        Some(base) => {
            out.push_str(&format!("#include \"{base}.hpp\"\n\n"));
            out.push_str(&format!("class {} : public {} {{\n", class.name, base));
        }
        None => out.push_str(&format!("class {} {{\n", class.name)),
    }

    if !class.methods.is_empty() {
        out.push_str("public:\n");
        for m in &class.methods {
            out.push_str(&format!("    // {}\n", name_comment(&m.name_source)));
            out.push_str(&format!("    {}\n\n", method_declaration(m, &class.name)));
        }
    }

    if !class.fields.is_empty() {
        out.push_str("private:\n");
        for f in &class.fields {
            let chosen = f.candidate_types.first().map(String::as_str).unwrap_or("undefined");
            out.push_str(&format!("    // offset {}: {}", f.offset, chosen));
            if f.candidate_types.len() > 1 {
                out.push_str(&format!(
                    " (other candidates seen: {})",
                    f.candidate_types[1..].join(", ")
                ));
            }
            out.push('\n');
            out.push_str(&format!("    {} field_{};\n", chosen, f.offset));
        }
    }

    out.push_str("};\n");
    out
}

/// A real run had every derived-class constructor's decompiled body
/// open by calling its base's constructor directly on `this`
/// (`Collideable::Collideable((Collideable *)this,0,0);`) -- valid
/// Ghidra pseudocode (the base subobject really is initialized there in
/// the compiled code), but not legal C++: you can't call a constructor
/// like an ordinary function on an object that already exists, and a
/// real C++ constructor already default-constructs its base *before*
/// the body even runs, so the call would be redundant even if it
/// somehow compiled. Finds exactly that call statement -- anywhere in
/// the body, not just as the very first statement: a real run had
/// constructors that hoist local variable declarations (Ghidra's usual
/// C89-style convention) before the base-constructor call, which the
/// first version of this only matching a leading statement missed
/// entirely -- and splits it into (initializer-list args, body with
/// that one statement spliced out, everything else left in place). Only
/// a call shaped exactly like Ghidra's own idiom counts; anything else
/// returns `None` and the body is left untouched, narrower than a real
/// C parser but matching what Ghidra actually produces for this.
fn extract_base_constructor_call(body: &str, base: &str) -> Option<(String, String)> {
    let needle = format!("{base}::{base}(");
    let start = body.find(&needle)?;
    let call_args = &body[start + needle.len()..];

    let mut depth = 1i32;
    let close = call_args.char_indices().find_map(|(i, c)| match c {
        '(' => {
            depth += 1;
            None
        }
        ')' => {
            depth -= 1;
            (depth == 0).then_some(i)
        }
        _ => None,
    })?;

    let after_semicolon = call_args[close + 1..].strip_prefix(';')?;
    let args = call_args[..close]
        .strip_prefix(&format!("({base} *)this"))?
        .trim_start_matches(',')
        .trim()
        .to_string();

    let mut remaining_body = body[..start].to_string();
    remaining_body.push_str(after_semicolon);
    Some((args, remaining_body))
}

pub fn render_source(class: &RecoveredClass) -> String {
    let mut out = String::new();
    out.push_str("// Recovered by Debura. Method bodies are Ghidra's decompiled output\n");
    out.push_str("// with the recovered name substituted in -- this is annotated decompiler\n");
    out.push_str("// output, not hand-lifted C++. Field accesses still show raw pointer\n");
    out.push_str("// arithmetic (`this + N`) rather than named members: Debura hasn't applied\n");
    out.push_str("// recovered field types back into Ghidra yet (that's a natural extension of\n");
    out.push_str("// M8's Ghidra feedback loop, not yet implemented for fields/structs).\n");
    out.push_str(&format!("#include \"{GHIDRA_SYMBOLS_HEADER_NAME}\"\n"));
    out.push_str(&format!("#include \"{}.hpp\"\n", class.name));
    // The header only forward-declares these (see render_header) -- the
    // full definition is needed here since method bodies actually call
    // into them.
    for reference in &class.references {
        out.push_str(&format!("#include \"{reference}.hpp\"\n"));
    }
    out.push('\n');

    for m in &class.methods {
        // Same rule as method_declaration(): a constructor/destructor's
        // name and the absence of a return type are fixed by the
        // language, not by any semantic_role rename.
        let (return_prefix, name) = if m.is_constructor {
            (String::new(), class.name.clone())
        } else if m.is_destructor {
            (String::new(), format!("~{}", class.name))
        } else {
            (format!("{} ", m.return_type), m.display_name.clone())
        };
        // `patch_known_idioms` must run before `receiver_alias` is
        // spliced in, not after: that pass separately renames a
        // *different*, unrelated local variable Ghidra's decompiler
        // sometimes names literally `this` (`rename_this_local_variable`)
        // -- doing that after splicing would rename this alias's own use
        // of the real keyword right along with it (a real regression, see
        // `RecoveredMethod::receiver_alias`'s own doc comment).
        let mut decompilation = patch_known_idioms(&m.decompilation);
        if let Some(alias) = &m.receiver_alias {
            if let Some(brace) = decompilation.find('{') {
                decompilation.insert_str(brace + 1, alias);
            }
        }
        let base_init = m.is_constructor.then(|| {
            class.base.as_ref().and_then(|base| extract_base_constructor_call(&decompilation, base))
        }).flatten();

        let (initializer_list, body) = match base_init {
            Some((args, patched)) => (
                format!(" : {}({args})", class.base.as_ref().unwrap()),
                extract_body(&patched),
            ),
            None => (String::new(), extract_body(&decompilation)),
        };

        out.push_str(&format!("// {}\n", name_comment(&m.name_source)));
        out.push_str(&format!(
            "{return_prefix}{}::{name}({}){initializer_list}\n{body}\n\n",
            class.name,
            m.params,
        ));
    }

    out
}

pub fn render_functions_source(functions: &[RecoveredFunction], references: &[String]) -> String {
    let mut out = String::new();
    out.push_str("// Recovered by Debura: standalone functions with an ACCEPTED semantic\n");
    out.push_str("// name (PROJECT.md M5). Bodies are Ghidra's decompiled output, unmodified\n");
    out.push_str("// beyond substituting the recovered name for Ghidra's raw one.\n");
    out.push_str(&format!("#include \"{GHIDRA_COMPAT_HEADER_NAME}\"\n"));
    out.push_str(&format!("#include \"{GHIDRA_SYMBOLS_HEADER_NAME}\"\n"));
    // A real run had a standalone function's M15-resolved body construct
    // a real class (`new (ptr) Wall(...)`) with nothing including
    // `Wall.hpp` anywhere in this file.
    for reference in references {
        out.push_str(&format!("#include \"{reference}.hpp\"\n"));
    }
    out.push('\n');

    for f in functions {
        out.push_str(&format!("// {}\n", name_comment(&f.name_source)));
        out.push_str(&format!(
            "// Ghidra's raw name: {}\n{} {}({})\n{}\n\n",
            f.raw_name,
            f.return_type,
            f.display_name,
            f.params,
            extract_body(&patch_known_idioms(&f.decompilation))
        ));
    }

    out
}
