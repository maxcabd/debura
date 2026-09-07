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


def extract_functions(decompiler, monitor):
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
        owner_class = owner_class_of(signature)
        name = func.getName()

        if owner_class is not None and decompilation:
            all_fields.extend(extract_field_accesses(owner_class, decompilation))

        functions.append({
            "address": addr_str(func.getEntryPoint()),
            "name": name,
            "size": int(func.getBody().getNumAddresses()),
            "signature": signature,
            "calling_convention": func.getCallingConventionName(),
            "callers": sorted(callers),
            "callees": sorted(callees),
            "decompilation": decompilation,
            "owner_class": owner_class,
            "is_constructor": owner_class is not None and name == owner_class,
            "is_destructor": owner_class is not None and name == "~" + owner_class,
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

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    try:
        functions, fields = extract_functions(decompiler, monitor)
        vtables, virtual_methods = extract_vtables(sym_table, mem, addr_factory, fm)

        result = {
            "program": currentProgram.getName(),
            "functions": functions,
            "strings": extract_strings(),
            "imports": extract_imports(),
            "exports": extract_exports(),
            "xrefs": extract_xrefs(),
            "vtables": vtables,
            "virtual_methods": virtual_methods,
            "inheritance": extract_type_info(sym_table, mem, addr_factory),
            "fields": fields,
        }
    finally:
        decompiler.dispose()

    out = open(output_path, "w")
    try:
        out.write(json.dumps(result))
    finally:
        out.close()


run()
