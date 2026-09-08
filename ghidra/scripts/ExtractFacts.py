#@category Debura

# Deterministic fact extraction for Debura's M1 (Ghidra Intake) and M7
# (Type Recovery).
#
# Extracts functions, strings, imports, exports, xrefs, decompilation,
# vtables, single-inheritance edges and virtual method tables from the
# current program and writes them as a single JSON document to the path
# passed as the first script argument. No semantic interpretation happens
# here -- everything emitted is a raw observation (PROJECT.md S21).
#
# The vtable/RTTI layout below is Itanium C++ ABI (GCC/Clang), matching
# what a MinGW-compiled binary produces. MSVC's RTTI layout is different
# and unsupported here. Only single, non-virtual inheritance is handled --
# multiple/virtual inheritance uses a different (__vmi_class_type_info)
# layout this script doesn't parse.

import json
import re

from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def addr_str(addr):
    return "0x%x" % addr.getOffset()


THIS_PARAM_PATTERN = re.compile(r"\(\s*([A-Za-z_]\w*)\s*\*\s*this\b")

# Matches `*(TYPE *)(this + OFFSET)`, as it appears in decompiled output
# before any class type has been applied back to Ghidra (M8). OFFSET may be
# decimal or hex depending on the decompiler's own formatting choice.
FIELD_ACCESS_PATTERN = re.compile(
    r"\(([A-Za-z_][A-Za-z0-9_ ]*?)\s*\*+\)\(this \+ (0x[0-9a-fA-F]+|\d+)\)"
)


def owner_class_of(signature):
    match = THIS_PARAM_PATTERN.search(signature)
    return match.group(1) if match else None


# --- Structural vtable/RTTI discovery (PROJECT.md M7, stripped-binary case) ---
#
# Everything above (and the original extract_vtables/extract_type_info below)
# depends on Ghidra's own demangler having already labeled "vtable"/
# "typeinfo" symbols and typed `this` parameters -- which it only does from
# the ORIGINAL binary's own symbol table. A real run confirmed this: on a
# properly stripped binary, that whole path recovers zero of the binary's
# real classes (only libstdc++'s own RTTI base types, which Ghidra
# recognizes via a built-in library-signature database, not the stripped
# binary's own symbols).
#
# The RTTI/vtable *data* itself is untouched by stripping -- it's real
# program data needed at runtime for dynamic_cast/typeid/exception
# matching, not debug info -- so it can still be found structurally:
#
#  1. Every constructor (and destructor) writes its own class's vptr
#     value into offset 0 of `this` early on (`this->vptr = vfunc0`, the
#     Itanium ABI's own convention -- `this->vptr` points directly at
#     the first virtual function slot, not at the 2-slot offset-to-top/
#     RTTI header that precedes it in memory, despite Ghidra's own
#     "vtable" symbol conventionally being placed at that header instead;
#     see is_plausible_vtable_start's docstring, which got this backwards
#     on the first attempt). Confirmed on the real stripped Snake binary:
#     `Wall`'s constructor decompiles to `*param_1 = &PTR_LAB_140009a20;`
#     -- found via a plain cross-reference from the function's own early
#     instructions, no symbol involved.
#  2. A candidate address is confirmed as vfunc0 (not some other data
#     reference) by checking for a real function pointer AT that exact
#     address -- the one part of a vtable's shape unlikely to appear by
#     coincidence.
#  3. The RTTI pointer one slot before vfunc0 leads to a typeinfo
#     record, whose own name field (the slot right after its own vtable
#     pointer) points at the class's raw mangled type name (e.g.
#     "9SnakeGame4Food") -- also real program data, so a real class name
#     is recoverable with no symbol at any step, not just a synthetic
#     placeholder.
#
# Deliberately scoped narrower than a real class recoverer: this finds
# vtables, their owning constructor/destructor addresses (not
# distinguished from each other -- a materially harder problem, deferred)
# and their virtual method slots. It does not attempt to find a class's
# *non-virtual* methods (PROJECT.md M7's `is_method_of` for those still
# needs the this-param typing above) or inheritance edges.

POINTER_SIZE = 8  # x64 only, matching the rest of this script's assumptions
# Generous on purpose: unoptimized (-O0) GCC prologues -- stack canary
# setup, spilling every parameter to its own stack slot -- can easily run
# 15-20+ instructions before a small constructor reaches its first real
# statement. This scan is pure instruction/reference iteration (no
# decompiler call), so a larger limit is cheap.
EARLY_INSTRUCTION_LIMIT = 48
MAX_VTABLE_SLOTS = 64


def ensure_function_at(target, mem, fm):
    """A vtable slot's target can be real code Ghidra's own auto-analysis
    already disassembled -- it just never registered a Function boundary
    there, since nothing else called it directly enough to trigger that
    (only ever reached indirectly, through the vtable). Confirmed on the
    real stripped Snake binary: `Wall::draw`'s own address had a real
    disassembled `PUSH RBP` prologue sitting there, but
    `getFunctionAt`/`getFunctionContaining` both returned None until this
    was added. `CreateFunctionCmd` is the same command Ghidra's own
    scripts use for exactly this -- it computes the function's body via
    flow analysis from the entry point, the same as if a human had
    pressed "create function" in the GUI."""
    existing = fm.getFunctionAt(target)
    if existing is not None:
        return existing
    block = mem.getBlock(target)
    if block is None or not block.isExecute():
        return None
    try:
        CreateFunctionCmd(target).applyTo(currentProgram)
    except:
        return None
    return fm.getFunctionAt(target)


def is_plausible_vtable_start(vfunc0_addr, mem, addr_factory, fm, sym_table):
    """A real function pointer *at this exact address* is the structural
    signature confirming it's genuinely what a constructor's vtable-
    pointer-slot store targets. Per the Itanium ABI, `this->vptr` points
    directly at the first virtual function slot (vfunc0) -- NOT at the
    2-slot offset-to-top/RTTI header before it, despite that header
    coming first in memory and being where Ghidra's own "vtable" symbol
    (see extract_vtables() below) is conventionally placed. Confirmed
    against the real stripped Wall constructor: its `this[0] = &X` store
    targets an X where `mem.getLong(X)` itself -- not `X + 0x10` -- is a
    real function pointer; checking `+ 0x10` here (as a first version of
    this did) missed every real class that has fewer than 2 virtual
    methods, which is most of them.

    That function-pointer check alone still misses a real case: a class
    that overrides nothing of its own can have its vtable's function
    slots come out as genuine null bytes rather than a function pointer
    or even a `__cxa_pure_virtual` thunk. Confirmed against the real
    stripped Snake binary cross-checked byte-for-byte with the
    unstripped build's own linker symbols: `Collideable`'s vtable --
    `_ZTVN9SnakeGame11CollideableE`, at exactly the address this
    function's caller computes as its true vtable start -- has all-zero
    bytes at both vfunc0 and vfunc0+8 in *both* binaries, so it's not a
    stripping artifact. Falling back to the RTTI chain (one slot before
    vfunc0) as an independent confirming signal recovers this case: a
    well-formed, demanglable Itanium typeinfo name one slot back is not
    something a coincidental data/function-pointer array would also
    have, so it's a comparably strong signal even when vfunc0 itself is
    unusable."""
    try:
        value = mem.getLong(vfunc0_addr)
    except:
        value = None
    if value is not None:
        target = resolve_pointer(mem, addr_factory, value)
        if target is not None and ensure_function_at(target, mem, fm) is not None:
            return True
    real_name, _base_name = class_name_from_vtable(vfunc0_addr, mem, addr_factory, sym_table)
    return real_name is not None


def find_early_vtable_store(func, listing, ref_manager, mem, addr_factory, fm, sym_table, monitor):
    """The vfunc0 address (see is_plausible_vtable_start's docstring)
    this function's own early instructions reference -- the Itanium ABI
    idiom every constructor/destructor performs to (re-)initialize its
    own vtable-pointer slot. Limited to the first several instructions:
    a vtable store is always one of the first things a constructor does,
    and restricting the search avoids picking up an unrelated later
    reference (e.g. to a member's own vtable during that member's
    construction) instead of this function's own."""
    instructions = listing.getInstructions(func.getBody(), True)
    checked = 0
    while instructions.hasNext() and checked < EARLY_INSTRUCTION_LIMIT:
        monitor.checkCancelled()
        instruction = instructions.next()
        checked += 1
        for ref in ref_manager.getReferencesFrom(instruction.getAddress()):
            if not ref.isMemoryReference():
                continue
            target = ref.getToAddress()
            if is_plausible_vtable_start(target, mem, addr_factory, fm, sym_table):
                return target
    return None


def read_cstring(mem, addr, max_len=256):
    try:
        out = []
        for i in range(max_len):
            b = mem.getByte(addr.add(i))
            if b == 0:
                break
            out.append(chr(b & 0xff))
        return "".join(out)
    except:
        return None


NAME_COMPONENT_PATTERN = re.compile(r"^(\d+)")


def demangle_itanium_type_name(raw):
    """The Itanium ABI's typeinfo `name` field is the class's own <name>
    mangling component -- not a full mangled symbol, just length-prefixed
    identifiers, optionally wrapped in N...E for a qualified (namespaced)
    name, e.g. "9SnakeGame4Food" -> "Food". Only the last component is
    kept, dropping any enclosing namespace -- matching extract_vtables()'s
    own symbol-based convention below (Ghidra's "vtable for X" labels are
    already namespace-stripped the same way), which every downstream
    consumer -- render.rs's file names and `class X {`/`~X()` syntax
    included -- was written against. A real run confirmed why this
    matters: emitting the full "SnakeGame::Food" here instead produced a
    `::` in a Windows file name (an OS error) and an illegal
    `class SnakeGame::Food {` class-opening line, neither of which
    render.rs was ever built to handle, and neither of which the
    symbol-based path could ever have produced in the first place. Only
    handles the plain nested-name shape; template names mangle very
    differently and fall back to None here, same as any other unparseable
    case -- narrower than a real demangler, but this is the shape a
    user's own class produces."""
    if not raw:
        return None
    body = raw[1:-1] if raw.startswith("N") and raw.endswith("E") else raw
    parts = []
    rest = body
    while rest:
        match = NAME_COMPONENT_PATTERN.match(rest)
        if not match:
            return None
        length = int(match.group(1))
        rest = rest[match.end():]
        if length <= 0 or length > len(rest):
            return None
        parts.append(rest[:length])
        rest = rest[length:]
    return parts[-1] if parts else None


def class_name_from_vtable(vfunc0_addr, mem, addr_factory, sym_table):
    """`vfunc0_addr` is what `this->vptr` itself points at (see
    is_plausible_vtable_start), so the RTTI pointer -- one slot *before*
    vfunc0 in memory -- is read at `vfunc0_addr - POINTER_SIZE`, and the
    typeinfo record's own name field is the slot right after its own
    vtable pointer. Entirely structural, no symbol needed at any step.

    Also resolves the base class name, PROJECT.md M17's prerequisite for
    vtable-slot role propagation across sibling classes: exactly the
    same real program data `extract_type_info()` below reads from
    Ghidra's own "typeinfo" symbol name (a `__si_class_type_info`
    record's third slot, one pointer past the name, points at the base
    class's own typeinfo record) -- reached here structurally instead,
    since M7's structural path otherwise doesn't find inheritance edges
    at all, only symbol-based extraction did. Doesn't attempt to
    distinguish a genuine `__class_type_info` (no base) from a
    `__si_class_type_info` with an unreadable base pointer -- both just
    come back with `base_name = None`, which is the same "no inheritance
    edge recovered" outcome for this script's purposes either way.
    Returns `(class_name, base_name)`; either may be `None`."""
    try:
        rtti_ptr_value = mem.getLong(vfunc0_addr.subtract(POINTER_SIZE))
    except:
        return None, None
    rtti_addr = resolve_pointer(mem, addr_factory, rtti_ptr_value)
    if rtti_addr is None:
        return None, None
    try:
        name_ptr_value = mem.getLong(rtti_addr.add(POINTER_SIZE))
    except:
        return None, None
    name_addr = resolve_pointer(mem, addr_factory, name_ptr_value)
    if name_addr is None:
        return None, None
    class_name = demangle_itanium_type_name(read_cstring(mem, name_addr))

    # Bounds-checked the same way `extract_type_info` already checks its
    # own read of this exact field (a __si_class_type_info record is
    # 0x18 bytes; anything shorter is a plain __class_type_info with no
    # base to read) -- a real run found *why* this matters structurally,
    # not just for tidiness: reading past a genuine __class_type_info's
    # 0x10-byte record without this check landed on whatever data
    # happens to follow it, and once in a while that garbage still
    # resolved to *something* address-shaped, cascading into a wave of
    # false-positive vtable/class detections elsewhere in the binary.
    base_name = None
    boundary = next_symbol_boundary(sym_table, rtti_addr)
    available = boundary.subtract(rtti_addr) if boundary is not None else 3 * POINTER_SIZE
    if available >= 3 * POINTER_SIZE:
        try:
            base_typeinfo_value = mem.getLong(rtti_addr.add(2 * POINTER_SIZE))
            base_typeinfo_addr = resolve_pointer(mem, addr_factory, base_typeinfo_value)
            if base_typeinfo_addr is not None:
                base_name_ptr_value = mem.getLong(base_typeinfo_addr.add(POINTER_SIZE))
                base_name_addr = resolve_pointer(mem, addr_factory, base_name_ptr_value)
                if base_name_addr is not None:
                    base_name = demangle_itanium_type_name(read_cstring(mem, base_name_addr))
        except:
            pass

    return class_name, base_name


def discover_classes_structurally(fm, listing, ref_manager, sym_table, mem, addr_factory, monitor):
    """Returns (class_names, ctor_or_dtor_addrs, virtual_methods,
    inheritance), the first three keyed by the *true* vtable start (as
    an int offset) -- 2 slots before vfunc0 (offset-to-top, then RTTI),
    matching has_vtable_at's existing convention from the symbol-based
    path below, even though what's actually found via cross-references
    is vfunc0's own address. class_names maps to a real recovered name
    where the RTTI name string parsed, else a synthetic
    "Class_<hex address>"; ctor_or_dtor maps to the set of function
    entry-point Addresses that store that vtable early on (constructors
    and destructors both -- not distinguished, see the module-level
    comment); virtual_methods maps to the ordered list of function
    entry-point Addresses found in that vtable's own slots.
    `inheritance` (PROJECT.md M17) is a flat list of
    `{"derived": ..., "base": ...}` dicts -- one entry per class whose
    RTTI base-type pointer resolved to another class's real (not
    synthetic) name; a class with no resolvable base, or whose own name
    didn't parse, contributes nothing here rather than a partial/
    synthetic edge."""
    ctors_by_vfunc0 = {}
    for func in fm.getFunctions(True):
        monitor.checkCancelled()
        if func.isExternal():
            continue
        vfunc0_addr = find_early_vtable_store(func, listing, ref_manager, mem, addr_factory, fm, sym_table, monitor)
        if vfunc0_addr is None:
            continue
        ctors_by_vfunc0.setdefault(vfunc0_addr.getOffset(), set()).add(func.getEntryPoint())

    class_names = {}
    ctor_or_dtor = {}
    virtual_methods = {}
    inheritance = []
    for vfunc0_key, ctor_addrs in ctors_by_vfunc0.items():
        vfunc0_addr = addr_factory.getDefaultAddressSpace().getAddress(vfunc0_key)
        true_key = vfunc0_addr.subtract(2 * POINTER_SIZE).getOffset()

        real_name, base_name = class_name_from_vtable(vfunc0_addr, mem, addr_factory, sym_table)
        class_names[true_key] = real_name if real_name else "Class_%x" % true_key
        ctor_or_dtor[true_key] = ctor_addrs
        if real_name and base_name:
            inheritance.append({"derived": real_name, "base": base_name})

        boundary = next_symbol_boundary(sym_table, vfunc0_addr)
        available = boundary.subtract(vfunc0_addr) if boundary is not None else MAX_VTABLE_SLOTS * POINTER_SIZE

        methods = []
        offset = 0
        slot = 0
        while offset < available and slot < MAX_VTABLE_SLOTS:
            try:
                value = mem.getLong(vfunc0_addr.add(offset))
            except:
                break
            if value == 0:
                break
            target = resolve_pointer(mem, addr_factory, value)
            func_at = ensure_function_at(target, mem, fm) if target is not None else None
            if func_at is not None:
                methods.append(func_at.getEntryPoint())
            slot += 1
            offset += POINTER_SIZE
        virtual_methods[true_key] = methods

    return class_names, ctor_or_dtor, virtual_methods, inheritance


def extract_field_accesses(owner_class, decompilation):
    fields = []
    for match in FIELD_ACCESS_PATTERN.finditer(decompilation):
        field_type = match.group(1).strip()
        offset = int(match.group(2), 0)
        if offset == 0:
            # Offset 0 is the vtable pointer slot for single/no inheritance,
            # never a real user-declared field.
            continue
        fields.append({
            "class_name": owner_class,
            "offset": "0x%x" % offset,
            "type": field_type,
        })
    return fields


def extract_functions(decompiler, monitor, structural_owner_of, structural_vtable_installers):
    """`structural_owner_of` (address string -> class name) is
    discover_classes_structurally()'s finding of which functions are a
    vtable's constructor/destructor or one of its virtual method slots
    -- consulted only when `owner_class_of(signature)` (Ghidra's own
    this-param typing, which needs a symbol somewhere upstream) found
    nothing, so a stripped binary still gets an owner class where the
    structural pass found one, without disturbing the symbol-based
    result where it's already available.

    Constructor/destructor status is intentionally NOT set from
    `structural_owner_of` -- distinguishing the two structurally is a
    materially harder, separate problem (see discover_classes_
    structurally's docstring), so these come through as regular methods
    of the class rather than guessing ctor vs dtor and risking debura-
    recovery applying the wrong one's special rendering. `installs_vtable_of`
    (set only for `structural_vtable_installers` -- the ctor/dtor
    addresses specifically, not every structurally-owned method) makes
    that ABI idiom visible to the reasoning agent anyway, without
    claiming to know which of the two it is: a real run showed that
    without it, a constructor/destructor found this way reads as
    unremarkable code (a call plus a pointer store) with no signal that
    it's the well-known pattern, and every semantic_role guess for it got
    rejected by an equally uninformed adversarial challenge."""
    functions = []
    all_fields = []
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        if func.isExternal():
            continue

        callers = set()
        for caller in func.getCallingFunctions(monitor):
            callers.add(addr_str(caller.getEntryPoint()))

        callees = set()
        for callee in func.getCalledFunctions(monitor):
            callees.add(addr_str(callee.getEntryPoint()))

        decompilation = ""
        result = decompiler.decompileFunction(func, 30, monitor)
        if result is not None and result.decompileCompleted():
            decompiled = result.getDecompiledFunction()
            if decompiled is not None:
                decompilation = decompiled.getC()

        signature = func.getSignature().getPrototypeString()
        address = addr_str(func.getEntryPoint())
        owner_class = owner_class_of(signature)
        structural_owner = owner_class is None
        if structural_owner:
            owner_class = structural_owner_of.get(address)
        name = func.getName()

        if owner_class is not None and decompilation:
            all_fields.extend(extract_field_accesses(owner_class, decompilation))

        installs_vtable_of = owner_class if (
            structural_owner and owner_class is not None and address in structural_vtable_installers
        ) else None

        functions.append({
            "address": address,
            "name": name,
            "size": int(func.getBody().getNumAddresses()),
            "signature": signature,
            "calling_convention": func.getCallingConventionName(),
            "callers": sorted(callers),
            "callees": sorted(callees),
            "decompilation": decompilation,
            "owner_class": owner_class,
            "is_constructor": (not structural_owner) and owner_class is not None and name == owner_class,
            "is_destructor": (not structural_owner) and owner_class is not None and name == "~" + owner_class,
            "installs_vtable_of": installs_vtable_of,
        })

    return functions, all_fields


def extract_strings():
    strings = []
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        if data.hasStringValue():
            strings.append({
                "address": addr_str(data.getAddress()),
                "value": data.getDefaultValueRepresentation(),
            })
    return strings


def extract_imports():
    imports = []
    sym_table = currentProgram.getSymbolTable()
    for symbol in sym_table.getExternalSymbols():
        namespace = symbol.getParentNamespace()
        imports.append({
            "name": symbol.getName(),
            "namespace": namespace.getName() if namespace is not None else "",
            "address": addr_str(symbol.getAddress()),
        })
    return imports


def extract_exports():
    exports = []
    sym_table = currentProgram.getSymbolTable()
    entry_points = sym_table.getExternalEntryPointIterator()
    while entry_points.hasNext():
        addr = entry_points.next()
        symbol = sym_table.getPrimarySymbol(addr)
        name = symbol.getName() if symbol is not None else addr_str(addr)
        exports.append({
            "name": name,
            "address": addr_str(addr),
        })
    return exports


def extract_xrefs():
    xrefs = []
    ref_manager = currentProgram.getReferenceManager()
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        if func.isExternal():
            continue
        addr_iter = func.getBody().getAddresses(True)
        while addr_iter.hasNext():
            addr = addr_iter.next()
            for ref in ref_manager.getReferencesFrom(addr):
                xrefs.append({
                    "from": addr_str(addr),
                    "to": addr_str(ref.getToAddress()),
                    "type": ref.getReferenceType().getName(),
                })
    return xrefs


DATA_OBJECT_MAX_BYTES = 64  # deliberately small -- see extract_data_objects's own docstring
DATA_OBJECT_BOUNDARY_SEARCH_LIMIT = 256  # only trust a next-symbol-derived size this close


def read_bytes_hex(mem, addr, length):
    try:
        raw = []
        for i in range(length):
            raw.append(mem.getByte(addr.add(i)) & 0xff)
        return "".join("%02x" % b for b in raw)
    except:
        return None


def extract_data_objects(sym_table, mem, addr_factory, fm, ref_manager):
    """Deterministic facts about every address recovered code actually
    references that isn't itself a known function's entry point (PROJECT.md
    M18.2) -- i.e. exactly the `DAT_*`/`PTR_*`/`LAB_*`-shaped placeholder
    names a real recovery/link attempt runs into, scoped to what's
    genuinely used rather than a whole-binary data dump. Reuses
    `extract_xrefs()`'s own reference-target set as that scope: every
    `to` address any recovered function's own instructions reference.

    Deliberately facts only, no interpretation (PROJECT.md S21) -- this
    was a real design correction mid-build: an earlier draft would have
    written `kind = MutableGlobal`/`PointerToFunction` here directly, but
    that's exactly the kind of premature semantic claim this whole
    project's own discipline exists to avoid making from Ghidra's naming
    convention alone (`DAT_`/`PTR_` are Ghidra's own renderings, not
    proof of anything). What's recorded instead: this address's own
    section/permissions/initialization state, its real size and raw
    bytes *only* when a real extent is known (a defined Data object, or a
    next symbol close enough to trust as a bound -- never a blind,
    unbounded read past whatever the object's true size actually is),
    whether it falls inside a known function's own body (the concrete,
    checkable question behind "is this actually a code label, not
    data"), and -- when Ghidra's own reference analysis or a bounds-
    checked raw 8-byte read plausibly resolves to another address in the
    program -- that address as a candidate pointee, tagged with which of
    the two ways it was found. `debura-analysis`'s Rust-side classifier
    derives everything else (mutable-global vs. constant, pointer-to-
    function vs. pointer-to-import, ...) from these facts, never
    guessed here.
    """
    fm_get_function_at = fm.getFunctionAt
    fm_get_function_containing = fm.getFunctionContaining

    candidates = set()
    for func in fm.getFunctions(True):
        if func.isExternal():
            continue
        addr_iter = func.getBody().getAddresses(True)
        while addr_iter.hasNext():
            addr = addr_iter.next()
            for ref in ref_manager.getReferencesFrom(addr):
                to = ref.getToAddress()
                if fm_get_function_at(to) is not None:
                    continue  # a real function entry point -- already covered by extract_functions
                candidates.add(to)

    objects = []
    for addr in candidates:
        symbol = sym_table.getPrimarySymbol(addr)
        symbol_name = symbol.getName() if symbol is not None else None

        block = mem.getBlock(addr)
        section = block.getName() if block is not None else None
        readable = block.isRead() if block is not None else None
        writable = block.isWrite() if block is not None else None
        executable = block.isExecute() if block is not None else None
        initialized = block.isInitialized() if block is not None else None

        data_type = None
        size = None
        size_confident = False
        data = None
        try:
            data = mem.getBlock(addr) and currentProgram.getListing().getDataAt(addr)
        except:
            data = None
        if data is not None:
            data_type = data.getDataType().getDisplayName()
            size = data.getLength()
            size_confident = True
        else:
            boundary = next_symbol_boundary(sym_table, addr)
            if boundary is not None:
                distance = boundary.subtract(addr)
                if 0 < distance <= DATA_OBJECT_BOUNDARY_SEARCH_LIMIT:
                    size = distance

        bytes_hex = None
        if size is not None and 0 < size <= DATA_OBJECT_MAX_BYTES:
            bytes_hex = read_bytes_hex(mem, addr, size)

        containing_func = fm_get_function_containing(addr)
        inside_function = addr_str(containing_func.getEntryPoint()) if containing_func is not None else None

        pointee_address = None
        pointee_source = None
        outgoing = ref_manager.getReferencesFrom(addr)
        if outgoing.hasNext():
            pointee_address = addr_str(outgoing.next().getToAddress())
            pointee_source = "reference"
        elif bytes_hex is not None and size == 8:
            try:
                raw_value = mem.getLong(addr)
                candidate = resolve_pointer(mem, addr_factory, raw_value)
                if candidate is not None and mem.contains(candidate):
                    pointee_address = addr_str(candidate)
                    pointee_source = "raw_bytes"
            except:
                pass

        referenced_from = sorted(set(
            addr_str(ref.getFromAddress()) for ref in ref_manager.getReferencesTo(addr)
        ))

        objects.append({
            "address": addr_str(addr),
            "symbol_name": symbol_name,
            "section": section,
            "readable": readable,
            "writable": writable,
            "executable": executable,
            "initialized": initialized,
            "data_type": data_type,
            "size": size,
            "size_confident": size_confident,
            "bytes_hex": bytes_hex,
            "inside_function": inside_function,
            "pointee_address": pointee_address,
            "pointee_source": pointee_source,
            "referenced_from": referenced_from,
        })

    return objects


def next_symbol_boundary(sym_table, addr):
    """The address of the next symbol strictly after `addr`, or None at the
    end of the symbol table. Used to bound reads into a vtable/typeinfo
    record so they never run into whatever unrelated data happens to
    follow it in the section (there is no explicit length field for
    either). On a stripped binary there are far fewer real symbols, so
    walking forward can run the iterator off the end of the program's
    real address space and into Ghidra's synthetic EXTERNAL space
    instead of just exhausting cleanly -- a real run hit exactly this
    ("Invalid memory address: EXTERNAL:...", an IllegalArgumentException
    thrown from inside getSymbolIterator itself, not from iterating).
    Treated the same as "no next symbol": there's nothing meaningful to
    bound against either way. A bare `except`, not `except Exception`:
    this specific exception crosses a Java reflection boundary
    (getSymbolIterator is invoked via NativeMethodAccessorImpl.invoke in
    the real stack trace) and a real run showed Jython does not
    consistently surface that as a catchable `Exception` instance."""
    try:
        it = sym_table.getSymbolIterator(addr.add(1), True)
        return it.next().getAddress() if it.hasNext() else None
    except:
        return None


def resolve_pointer(mem, addr_factory, value):
    try:
        return addr_factory.getDefaultAddressSpace().getAddress(value)
    except Exception:
        return None


def extract_type_info(sym_table, mem, addr_factory):
    """Single-inheritance edges (PROJECT.md M7), read directly from each
    class's Itanium `typeinfo` record: slot 0 is the type_info subobject's
    own vtable pointer (ignored here), slot 1 is the class name (already
    covered by the `typeinfo-name` symbol Ghidra creates), and slot 2 --
    present only for __si_class_type_info, i.e. exactly one non-virtual
    public base -- points at the base class's own typeinfo record."""
    inheritance = []
    for sym in sym_table.getAllSymbols(True):
        if sym.getName() != "typeinfo":
            continue

        derived = sym.getParentNamespace().getName()
        addr = sym.getAddress()
        boundary = next_symbol_boundary(sym_table, addr)
        available = boundary.subtract(addr) if boundary is not None else 0x18

        if available < 0x18:
            continue  # __class_type_info: no base

        # Same risk as extract_vtables(): `available` falls back to a
        # fixed guess when there's no next symbol to bound against,
        # which a stripped binary can make wrong.
        try:
            base_ptr_value = mem.getLong(addr.add(0x10))
        except:
            continue
        base_addr = resolve_pointer(mem, addr_factory, base_ptr_value)
        if base_addr is None:
            continue

        for base_sym in sym_table.getSymbols(base_addr):
            if base_sym.getName() == "typeinfo":
                inheritance.append({
                    "derived": derived,
                    "base": base_sym.getParentNamespace().getName(),
                })
                break

    return inheritance


def extract_vtables(sym_table, mem, addr_factory, fm):
    """Vtable addresses and virtual method slots (PROJECT.md M7). A
    `vtable` symbol's address is the start of the record: offset-to-top
    (slot 0), the RTTI pointer (slot 1), then virtual function pointers in
    declaration/override order (slot 2 onward) -- including inherited,
    non-overridden ones, so a derived class's vtable already reflects the
    full flattened method set."""
    vtables = []
    virtual_methods = []
    max_slots = 64  # safety bound against corrupt/unbounded data

    for sym in sym_table.getAllSymbols(True):
        if sym.getName() != "vtable":
            continue

        class_name = sym.getParentNamespace().getName()
        addr = sym.getAddress()
        vtables.append({
            "class_name": class_name,
            "address": addr_str(addr),
        })

        boundary = next_symbol_boundary(sym_table, addr)
        available = boundary.subtract(addr) if boundary is not None else max_slots * 8

        slot = 0
        offset = 0x10  # skip offset-to-top and the RTTI pointer
        while offset < available and slot < max_slots:
            # `available` is a real bound when a next symbol was found,
            # but falls back to a fixed guess (max_slots * 8) when there
            # wasn't one -- true on a stripped binary near the end of a
            # section, where that guess can walk past real memory into
            # Ghidra's synthetic EXTERNAL space. A real run crashed
            # extraction outright here; unreadable memory means there's
            # no more real vtable data, the same as hitting a boundary.
            try:
                value = mem.getLong(addr.add(offset))
            except:
                break
            if value == 0:
                break
            target = resolve_pointer(mem, addr_factory, value)
            func = fm.getFunctionAt(target) if target is not None else None
            if func is not None:
                virtual_methods.append({
                    "class_name": class_name,
                    "slot": slot,
                    "function_address": addr_str(func.getEntryPoint()),
                })
            slot += 1
            offset += 8

    return vtables, virtual_methods


def merge_structural_vtables(vtables, virtual_methods, struct_class_names, struct_virtual_methods):
    """Adds a structurally-discovered vtable/class only if nothing at
    that address was already found via symbols -- the symbol-based
    result (already tested, and able to demangle template names this
    module's simplified decoder can't) wins wherever both find the same
    address."""
    existing_addrs = set(v["address"] for v in vtables)
    for key, class_name in struct_class_names.items():
        address = "0x%x" % key
        if address in existing_addrs:
            continue
        vtables.append({"class_name": class_name, "address": address})
        for slot, func_addr in enumerate(struct_virtual_methods.get(key, [])):
            virtual_methods.append({
                "class_name": class_name,
                "slot": slot,
                "function_address": addr_str(func_addr),
            })
    return vtables, virtual_methods


def merge_inheritance(inheritance, struct_inheritance):
    """PROJECT.md M17: adds a structurally-found `(derived, base)` edge
    only if that exact pair isn't already present from the symbol-based
    side -- same "symbol-based wins on overlap" reasoning as
    `merge_structural_vtables`, deduplicated on the full pair rather
    than just `derived` since (unlike vtables) nothing here should ever
    produce two different bases for the same derived class."""
    existing = set((edge["derived"], edge["base"]) for edge in inheritance)
    for edge in struct_inheritance:
        pair = (edge["derived"], edge["base"])
        if pair not in existing:
            inheritance.append(edge)
            existing.add(pair)
    return inheritance


def run():
    args = getScriptArgs()
    if len(args) < 1:
        raise Exception("ExtractFacts.py requires an output path argument")
    output_path = args[0]

    monitor = ConsoleTaskMonitor()
    sym_table = currentProgram.getSymbolTable()
    mem = currentProgram.getMemory()
    addr_factory = currentProgram.getAddressFactory()
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    ref_manager = currentProgram.getReferenceManager()

    struct_class_names, struct_ctor_or_dtor, struct_virtual_methods, struct_inheritance = (
        discover_classes_structurally(fm, listing, ref_manager, sym_table, mem, addr_factory, monitor)
    )

    structural_owner_of = {}
    structural_vtable_installers = set()
    for key, class_name in struct_class_names.items():
        for addr in struct_ctor_or_dtor.get(key, ()):
            structural_owner_of[addr_str(addr)] = class_name
            structural_vtable_installers.add(addr_str(addr))
        for addr in struct_virtual_methods.get(key, ()):
            structural_owner_of[addr_str(addr)] = class_name

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    try:
        functions, fields = extract_functions(
            decompiler, monitor, structural_owner_of, structural_vtable_installers
        )
        vtables, virtual_methods = extract_vtables(sym_table, mem, addr_factory, fm)
        vtables, virtual_methods = merge_structural_vtables(
            vtables, virtual_methods, struct_class_names, struct_virtual_methods
        )

        result = {
            "program": currentProgram.getName(),
            "functions": functions,
            "strings": extract_strings(),
            "imports": extract_imports(),
            "exports": extract_exports(),
            "xrefs": extract_xrefs(),
            "vtables": vtables,
            "virtual_methods": virtual_methods,
            "inheritance": merge_inheritance(
                extract_type_info(sym_table, mem, addr_factory), struct_inheritance
            ),
            "fields": fields,
            "data_objects": extract_data_objects(sym_table, mem, addr_factory, fm, ref_manager),
        }
    finally:
        decompiler.dispose()

    out = open(output_path, "w")
    try:
        out.write(json.dumps(result))
    finally:
        out.close()


run()
