#@category Debura

# Deterministic fact extraction for Debura's M1 (Ghidra Intake).
#
# Extracts functions, strings, imports, exports, xrefs and decompilation
# from the current program and writes them as a single JSON document to
# the path passed as the first script argument. No semantic interpretation
# happens here -- everything emitted is a raw observation (PROJECT.md S21).

import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def addr_str(addr):
    return "0x%x" % addr.getOffset()


def extract_functions(decompiler, monitor):
    functions = []
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

        functions.append({
            "address": addr_str(func.getEntryPoint()),
            "name": func.getName(),
            "size": int(func.getBody().getNumAddresses()),
            "signature": func.getSignature().getPrototypeString(),
            "calling_convention": func.getCallingConventionName(),
            "callers": sorted(callers),
            "callees": sorted(callees),
            "decompilation": decompilation,
        })

    return functions


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


def run():
    args = getScriptArgs()
    if len(args) < 1:
        raise Exception("ExtractFacts.py requires an output path argument")
    output_path = args[0]

    monitor = ConsoleTaskMonitor()

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    try:
        result = {
            "program": currentProgram.getName(),
            "functions": extract_functions(decompiler, monitor),
            "strings": extract_strings(),
            "imports": extract_imports(),
            "exports": extract_exports(),
            "xrefs": extract_xrefs(),
        }
    finally:
        decompiler.dispose()

    out = open(output_path, "w")
    try:
        out.write(json.dumps(result))
    finally:
        out.close()


run()
