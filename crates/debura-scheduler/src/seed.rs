use std::collections::HashSet;

use debura_knowledge::KnowledgeGraph;

use crate::task::Task;

/// Leaf-name patterns that are essentially always C++ runtime/STL/CRT
/// support code, not application logic (PROJECT.md M10). Ghidra strips the
/// `std::`/namespace qualifier from a function's own name -- it becomes
/// the *owner* (see `NOISE_OWNERS` below) -- so matching only works
/// against libstdc++'s actual internal method-naming convention
/// (`_M_`/`_S_` for "member"/"static", template helpers like
/// `__copy_move_a`, etc.), not against "std::" itself.
///
/// This whole list was derived by actually inspecting a real MinGW-built
/// binary (the Snake fixture), not guessed: the first version (matching
/// "std::" directly) caught 8/321 functions, because that prefix never
/// actually appears in a leaf name; the second pass, after adding `_M_`/
/// `_S_`, still let 267/321 through because a MinGW binary statically
/// links its own CRT startup path and pulls in a long tail of libstdc++
/// container/iterator template helpers with no `std::`-shaped name at all
/// (`__tmainCRTStartup`, `__copy_move_a<...>`, `__niter_base<...>`, etc).
///
/// This is a name-pattern heuristic, not a real classifier: it costs
/// nothing (no model call), but it will miss runtime code that doesn't
/// match one of these patterns, and (for the STL container/string method
/// names in `KNOWN_STL_METHOD_NAMES_WITHOUT_OWNER`) it could in principle
/// skip a same-named free function the binary's own author wrote with no
/// receiver type we could resolve. A structural classifier (CFG shape,
/// library fingerprinting) would catch more precisely and is real future
/// work, not a quick filter.
const NOISE_PREFIXES: &[&str] = &[
    "std::",
    "__gnu_cxx::",
    "__cxxabiv1::",
    "__gnu_",
    "__mingw_",
    "operator new",
    "operator delete",
    "operator.new",
    "operator.delete",
    "_Unwind_",
    "_ZN", // still-mangled Itanium names (demangling failed) are never
    // application code we asked the compiler to name ourselves
    "_M_",   // libstdc++ "member" implementation methods
    "_S_",   // libstdc++ "static member" implementation methods
    "_Destroy",
    "_Construct",
    "__throw_", // libstdc++'s <bits/functexcept.h> out-of-line throw helpers
    "_GLOBAL__sub_I_", // per-translation-unit static initializer
    ".weak.",
    // libstdc++ <bits/stl_uninitialized.h>/<bits/stl_algobase.h> internal
    // template helpers for containers/iterators, observed instantiated
    // over the binary's own element types (so they don't start with
    // "std::" or contain any std-looking token at all).
    "__copy_",
    "__niter_",
    "__miter_",
    "__relocate_",
    "__to_address",
    "__destroy",
    "__assign_one",
    "__new_allocator",
    "__normal_iterator",
    "_Vector_base",
    "forward<",
    "move<",
    "max<",
    "min<",
    "basic_string",
    "endl<",
    "allocator<",
    // SDL2/SDL2_ttf are external libraries whenever this binary is a
    // fresh SDL app -- never functions this project's own author wrote.
    "SDL_",
    "TTF_",
];

const NOISE_EXACT: &[&str] = &[
    "_start",
    "frame_dummy",
    "register_tm_clones",
    "deregister_tm_clones",
    "__do_global_dtors_aux",
    "__libc_csu_init",
    "__libc_csu_fini",
    "_init",
    "_fini",
    "__gcc_register_frame",
    "__gcc_deregister_frame",
    "__main",
    "mark_section_writable",
    "_FindPESection",
    "atexit",
    "__mingw_GetSectionForAddress",
    "_Alloc_hider",
    "_GetPEImageBase",
    "_IsNonwritableInCurrentImage",
    "_ValidateImageBase",
    "vector",
    // MinGW-w64 CRT startup chain (crt0/crtexe.c) and the ucrt/msvcrt
    // shims it calls through -- runs before `main`/`WinMain`, never
    // application logic.
    "__tmainCRTStartup",
    "mainCRTStartup",
    "main_getcmdline",
    "__getmainargs",
    "__p___argc",
    "__p___argv",
    "__p___wargv",
    "__p__acmdln",
    "__p__commode",
    "__p__environ",
    "__p__fmode",
    "__p__wenviron",
    "_configure_narrow_argv",
    "_configure_wide_argv",
    "_setargv",
    "__set_app_type",
    "_initialize_narrow_environment",
    "_initialize_wide_environment",
    "_initterm",
    "_cexit",
    "_crt_atexit",
    "_crt_at_quick_exit",
    "_onexit",
    "_exit",
    "exit",
    "abort",
    "_amsg_exit",
    "_set_new_mode",
    "_set_invalid_parameter_handler",
    "_matherr",
    "__setusermatherr",
    "fpreset",
    "__daylight",
    "__timezone",
    "__tzname",
    "tzset",
    "_tzset",
    "_time64",
    "_ismbblead",
    "__do_global_ctors",
    "__dyn_tls_init",
    "__dyn_tls_dtor",
    "__mingwthr_run_key_dtors",
    "_pei386_runtime_relocator",
    "do_pseudo_reloc",
    "restore_modified_sections",
    "check_managed_app",
    "duplicate_ppstrings",
    "__write_memory",
    "__report_error",
    "_get_output_format",
    "__acrt_iob_func",
    "__stdio_common_vfprintf",
    "__stdio_common_vfwprintf",
    "__static_initialization_and_destruction_0",
    "___chkstk_ms",
    "__C_specific_handler",
    "signal",
    "calloc",
    "malloc",
    "free",
    "memcpy",
    "memmove",
    "memset",
    "strlen",
    "strncmp",
    "rand",
    "srand",
    "fprintf",
    "fwrite",
    "vfprintf",
    // Win32 API imports the MinGW CRT startup path itself calls through
    // to (module/heap/TLS/critical-section setup, argv parsing).
    "CommandLineToArgvW",
    "DeleteCriticalSection",
    "EnterCriticalSection",
    "FreeLibrary",
    "GetCommandLineW",
    "GetLastError",
    "GetModuleHandleA",
    "GetProcAddress",
    "GetProcessHeap",
    "GetStartupInfoA",
    "HeapAlloc",
    "HeapFree",
    "InitializeCriticalSection",
    "LeaveCriticalSection",
    "LoadLibraryA",
    "LocalFree",
    "SetUnhandledExceptionFilter",
    "Sleep",
    "TlsGetValue",
    "VirtualProtect",
    "VirtualQuery",
];

/// Substrings that mark a name as a garbled/truncated fragment of a
/// longer demangled template signature (Ghidra's demangler emits the
/// tail of the argument list as the "name" when it can't fully resolve
/// the symbol) -- never something the binary's author named themselves.
const NOISE_CONTAINS: &[&str] = &["*>&)"];

/// Owner/namespace names (from `is_method_of`) that mark libstdc++'s own
/// internal helper classes, distinct from the binary's actual classes --
/// these showed up as real `is_method_of` values in the Snake fixture
/// alongside genuine game classes like `Screen`/`Snake`/`Wall`.
const NOISE_OWNERS: &[&str] = &["_Alloc_hider", "_Guard", "_Vector_impl", "_Vector_impl_data"];

/// Common container/string API leaf names that only count as noise when
/// they have no resolved owner at all -- M7's "this"-parameter owner
/// detection reliably resolves the binary's own classes (a same-named
/// method on a real class, e.g. `Screen::clear`, always has an owner), so
/// an owner-less occurrence of one of these is std::vector/std::string's
/// own unqualified method, not application code.
const KNOWN_STL_METHOD_NAMES_WITHOUT_OWNER: &[&str] = &[
    "push_back",
    "size",
    "begin",
    "end",
    "cbegin",
    "clear",
    "erase",
    "c_str",
    "str",
    "length",
    "max_size",
    "deallocate",
    "allocate",
    "eq",
    "base",
    "operator!=",
    "operator*",
    "operator+",
    "operator++",
    "operator-",
    "operator<<",
    "operator[]",
];

fn is_likely_runtime_noise(name: &str) -> bool {
    let bare = name.strip_prefix('~').unwrap_or(name);
    for candidate in [name, bare] {
        if NOISE_EXACT.contains(&candidate)
            || NOISE_PREFIXES.iter().any(|prefix| candidate.starts_with(prefix))
        {
            return true;
        }
    }
    NOISE_CONTAINS.iter().any(|needle| name.contains(needle))
}

fn latest_value<'a>(graph: &'a KnowledgeGraph, subject: &str, predicate: &str) -> Option<&'a str> {
    graph
        .observations()
        .filter(|o| o.subject == subject && o.predicate == predicate)
        .max_by_key(|o| o.id.0)
        .map(|o| o.value.as_str())
}

fn owner<'a>(graph: &'a KnowledgeGraph, subject: &str) -> Option<&'a str> {
    ["is_method_of", "is_constructor_of", "is_destructor_of"]
        .into_iter()
        .find_map(|predicate| latest_value(graph, subject, predicate))
}

fn is_noise(graph: &KnowledgeGraph, subject: &str) -> bool {
    let Some(name) = latest_value(graph, subject, "has_name") else {
        return false;
    };
    if is_likely_runtime_noise(name) {
        return true;
    }
    match owner(graph, subject) {
        Some(owner) => NOISE_OWNERS.contains(&owner),
        None => KNOWN_STL_METHOD_NAMES_WITHOUT_OWNER.contains(&name),
    }
}

/// Finds every known function (a subject with a `has_name` observation --
/// M1/M3's deterministic extraction) that has no hypothesis yet and isn't
/// obviously runtime noise, and proposes AnalyzeFunction for it. This is
/// the only source of brand-new work; everything else the scheduler ever
/// runs is a follow-up produced by a task that already ran (PROJECT.md
/// S24's `enqueue_followups`).
pub fn seed_initial_tasks(graph: &KnowledgeGraph) -> Vec<Task> {
    let already_analyzed: HashSet<&str> =
        graph.hypotheses().map(|h| h.subject.as_str()).collect();

    let mut subjects: Vec<&str> = graph
        .observations()
        .filter(|o| o.predicate == "has_name")
        .map(|o| o.subject.as_str())
        .collect();
    subjects.sort_unstable();
    subjects.dedup();

    let mut skipped_as_noise = 0u64;
    let tasks: Vec<Task> = subjects
        .into_iter()
        .filter(|subject| !already_analyzed.contains(subject))
        .filter(|subject| {
            let keep = !is_noise(graph, subject);
            if !keep {
                skipped_as_noise += 1;
            }
            keep
        })
        .map(|subject| Task::AnalyzeFunction {
            subject: subject.to_string(),
        })
        .collect();

    if skipped_as_noise > 0 {
        tracing::info!(
            skipped_as_noise,
            seeded = tasks.len(),
            "skipped likely runtime/STL noise before seeding"
        );
    }

    tasks
}
