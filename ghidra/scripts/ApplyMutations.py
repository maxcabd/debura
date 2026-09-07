#@category Debura

# Ghidra feedback for Debura's M8: applies function renames requested by
# Debura and reports what actually happened. Run with -process (not
# -import) against an already-analyzed project -- this never re-imports or
# re-runs full auto-analysis, it only mutates symbols that already exist.
#
# Input: a JSON array of {"address": "0x...", "new_name": "..."}, path
# given as the first script argument.
# Output: a JSON array of outcomes, written to the path given as the
# second script argument.

import json

from ghidra.program.model.symbol import SourceType


def addr_of(s):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(s)


def run():
    args = getScriptArgs()
    if len(args) < 2:
        raise Exception("ApplyMutations.py requires <input.json> <output.json>")
    input_path = args[0]
    output_path = args[1]

    in_file = open(input_path, "r")
    try:
        renames = json.loads(in_file.read())
    finally:
        in_file.close()

    fm = currentProgram.getFunctionManager()
    results = []

    for entry in renames:
        addr_str = entry["address"]
        new_name = entry["new_name"]

        func = fm.getFunctionAt(addr_of(addr_str))
        if func is None:
            results.append({
                "address": addr_str,
                "applied": False,
                "previous_name": None,
                "new_name": None,
                "error": "no function at address",
            })
            continue

        previous_name = func.getName()
        try:
            func.setName(new_name, SourceType.USER_DEFINED)
            results.append({
                "address": addr_str,
                "applied": True,
                "previous_name": previous_name,
                "new_name": new_name,
                "error": None,
            })
        except Exception as e:
            results.append({
                "address": addr_str,
                "applied": False,
                "previous_name": previous_name,
                "new_name": None,
                "error": str(e),
            })

    out_file = open(output_path, "w")
    try:
        out_file.write(json.dumps(results))
    finally:
        out_file.close()


run()
