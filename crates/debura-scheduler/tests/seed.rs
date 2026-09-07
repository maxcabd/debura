use debura_knowledge::KnowledgeGraph;
use debura_scheduler::{seed_initial_tasks, Task};

#[test]
fn seeds_analyze_function_for_unanalyzed_subjects_only() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "compute", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "has_name", "add", 0.95, "ghidra:function", None);
    graph.propose_hypothesis("0x2", "semantic_role", "add", 0.5, None);

    let tasks = seed_initial_tasks(&graph);

    assert_eq!(
        tasks,
        vec![Task::AnalyzeFunction {
            subject: "0x1".to_string()
        }]
    );
}

#[test]
fn ignores_observations_that_are_not_has_name() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "contains_string", "hello", 0.95, "ghidra:strings", None);

    assert!(seed_initial_tasks(&graph).is_empty());
}

/// PROJECT.md M10: a real C++ binary's function list is dominated by
/// STL/CRT/runtime support code, not application logic -- spending a full
/// model chain on each one is what turned a Snake game into ~3000
/// iterations. These are real names this project's own runs have seen.
#[test]
fn skips_likely_runtime_and_stl_noise() {
    let mut graph = KnowledgeGraph::new();
    let noisy = [
        "std::vector<int, std::allocator<int> >::push_back",
        "__gnu_cxx::__normal_iterator<int*, std::vector<int> >::operator++",
        "__cxxabiv1::__si_class_type_info::~__si_class_type_info",
        "operator new",
        "operator delete[]",
        "_Unwind_Resume",
        "frame_dummy",
        "register_tm_clones",
        "__gcc_register_frame",
        "mark_section_writable",
        "_ZN6PlayerC1Efi", // demangling failed -- still-mangled name
    ];
    for (i, name) in noisy.iter().enumerate() {
        let addr = format!("0x{i:x}");
        graph.add_observation(&addr, "has_name", *name, 0.95, "ghidra:function", None);
    }
    graph.add_observation("0xreal", "has_name", "takeDamage", 0.95, "ghidra:function", None);

    let tasks = seed_initial_tasks(&graph);

    assert_eq!(
        tasks,
        vec![Task::AnalyzeFunction {
            subject: "0xreal".to_string()
        }]
    );
}

/// Ghidra strips the `std::`/namespace qualifier from a leaf name entirely
/// (a function shows up as `_M_allocate`, not `std::...::_M_allocate`), so
/// matching on "std::" alone misses almost everything -- this is what the
/// real Snake fixture's 321 functions actually looked like, and is the
/// case the first version of this filter (8/321 skipped) got wrong.
#[test]
fn skips_libstdcxx_internals_that_have_no_std_prefix_in_their_leaf_name() {
    let mut graph = KnowledgeGraph::new();
    let noisy = [
        "_M_allocate",
        "_M_deallocate",
        "_M_construct<char_const*>",
        "_M_check_len",
        "_M_data",
        "_M_dispose",
        "_M_get_Tp_allocator",
        "_M_erase",
        "_M_erase_at_end",
        "_M_capacity",
        "_M_local_data",
        "_M_create",
        "_M_set_length",
        "_M_realloc_append<char_const*&>",
        "_S_copy_chars",
        "_S_max_size",
        "_S_relocate",
        "_Destroy<SnakeGame::Section**>",
        "_GetPEImageBase",
        "_IsNonwritableInCurrentImage",
        "_ValidateImageBase",
        "_GLOBAL__sub_I_S_WIDTH",
        ".weak.__register_frame_info.hmod_libgcc",
    ];
    for (i, name) in noisy.iter().enumerate() {
        let addr = format!("0xa{i:x}");
        graph.add_observation(&addr, "has_name", *name, 0.95, "ghidra:function", None);
    }
    graph.add_observation("0xreal", "has_name", "takeDamage", 0.95, "ghidra:function", None);

    let tasks = seed_initial_tasks(&graph);

    assert_eq!(
        tasks,
        vec![Task::AnalyzeFunction {
            subject: "0xreal".to_string()
        }]
    );
}

/// A second real-world tail this project's own run against the Snake
/// fixture turned up: a MinGW-w64 binary statically links its own CRT
/// startup path and libstdc++'s uninitialized-copy/iterator template
/// helpers, none of which are shaped like `std::`/`_M_`/`_S_` names.
#[test]
fn skips_mingw_crt_startup_and_libstdcxx_template_helpers() {
    let mut graph = KnowledgeGraph::new();
    let noisy = [
        "__tmainCRTStartup",
        "mainCRTStartup",
        "__getmainargs",
        "_initterm",
        "_cexit",
        "__dyn_tls_init",
        "__mingwthr_run_key_dtors",
        "do_pseudo_reloc",
        "__acrt_iob_func",
        "___chkstk_ms",
        "__C_specific_handler",
        "calloc",
        "memcpy",
        "strncmp",
        "GetProcAddress",
        "HeapAlloc",
        "InitializeCriticalSection",
        "SDL_CreateWindow",
        "TTF_OpenFont",
        "__throw_bad_alloc",
        "__throw_length_error",
        "__set_app_type",
        "_setargv",
        "__copy_move_a1<true,SnakeGame::Section**,SnakeGame::Section**>",
        "__niter_base<SnakeGame::Wall**>",
        "__relocate_a_1<SnakeGame::Section*,SnakeGame::Section*>",
        "__to_address<SnakeGame::Wall*>",
        "__destroy<SnakeGame::Section**>",
        "__assign_one<SnakeGame::Section*,SnakeGame::Section*>",
        "__new_allocator",
        "__normal_iterator<SnakeGame::Section**,void>",
        "_Vector_base",
        "forward<SnakeGame::Section*const&>",
        "move<SnakeGame::Section*&>",
        "max<unsigned_long_long>",
        "min<unsigned_long_long>",
        "basic_stringstream",
        "endl<char,std::char_traits<char>>",
        "allocator<char>_>*)",
        "vector",
        "~vector",
        "~_Vector_base",
        "~__new_allocator",
        "Section*>&)",
    ];
    for (i, name) in noisy.iter().enumerate() {
        let addr = format!("0xb{i:x}");
        graph.add_observation(&addr, "has_name", *name, 0.95, "ghidra:function", None);
    }
    // Owner-less occurrences of common container/string API names are
    // std::vector/std::string's own methods, not application code --
    // but the SAME name on a real, resolved class must be kept.
    graph.add_observation("0xstlpush", "has_name", "push_back", 0.95, "ghidra:function", None);
    graph.add_observation("0xrealclear", "has_name", "clear", 0.95, "ghidra:function", None);
    graph.add_observation("0xrealclear", "is_method_of", "Screen", 0.9, "ghidra:vtable", None);
    graph.add_observation("0xreal", "has_name", "drawWalls", 0.95, "ghidra:function", None);

    let mut tasks = seed_initial_tasks(&graph);
    tasks.sort_by_key(|t| format!("{t:?}"));

    assert_eq!(
        tasks,
        vec![
            Task::AnalyzeFunction {
                subject: "0xreal".to_string()
            },
            Task::AnalyzeFunction {
                subject: "0xrealclear".to_string()
            },
        ]
    );
}

/// Some libstdc++ internal helper "classes" (`_Alloc_hider`, `_Guard`,
/// `_Vector_impl`, `_Vector_impl_data`) only show up as an `is_method_of`
/// owner value -- the method's own leaf name (e.g. a constructor) doesn't
/// look noisy on its own, so the owner has to be checked too.
#[test]
fn skips_functions_whose_owner_is_a_libstdcxx_internal_helper_class() {
    let mut graph = KnowledgeGraph::new();
    graph.add_observation("0x1", "has_name", "_Alloc_hider", 0.95, "ghidra:function", None);
    graph.add_observation("0x1", "is_method_of", "_Alloc_hider", 0.9, "ghidra:vtable", None);
    graph.add_observation("0x2", "has_name", "_Vector_impl_data", 0.95, "ghidra:function", None);
    graph.add_observation("0x2", "is_method_of", "_Vector_impl_data", 0.9, "ghidra:vtable", None);
    graph.add_observation("0xreal", "has_name", "Snake", 0.95, "ghidra:function", None);
    graph.add_observation("0xreal", "is_method_of", "Snake", 0.9, "ghidra:vtable", None);

    let tasks = seed_initial_tasks(&graph);

    assert_eq!(
        tasks,
        vec![Task::AnalyzeFunction {
            subject: "0xreal".to_string()
        }]
    );
}
