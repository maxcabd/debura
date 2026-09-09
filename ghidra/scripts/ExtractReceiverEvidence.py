# -*- coding: utf-8 -*-
# PROJECT.md M20, Round B: for a fixed list of zero-argument member-call
# sites (identified by containing function address + ordinal position
# among that function's own calls to the same external symbol -- stable
# across re-decompiles, unlike a line number in Debura's own rendered
# text), extracts real P-code/SSA facts a decompiled-text regex can
# never see: the receiver's actual backward def-use chain, traced at the
# RAW instruction/register level (the level the decompiler's own
# high-level signature inference already dropped the receiver at, which
# is why the decompiled C shows zero arguments in the first place -- so
# this deliberately does NOT start from the decompiler's own HighFunction
# call-op inputs, which have nothing left to trace).
#
# Emits typed structural facts (JSON), not pretty-printed text -- the
# reasoning model gets the raw def-use chain, alias list, and competing
# construction-site candidates, and decides the receiver itself; this
# script never decides call X = object Y on its own.

import json

from ghidra.program.model.block import SimpleBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface

monitor = ConsoleTaskMonitor()
listing = currentProgram.getListing()
func_manager = currentProgram.getFunctionManager()
addr_factory = currentProgram.getAddressFactory()
block_model = SimpleBlockModel(currentProgram)

RECEIVER_REG_NAMES = ["RCX", "ECX", "CX", "CL"]  # x64 MS ABI: 1st integer/pointer arg


def addr(hexstr):
    return addr_factory.getAddress(hexstr)


def reg_of(instr, names):
    """The Register object for the first name in `names` this
    program's language actually defines (sub-register width varies by
    binary/toolchain)."""
    lang = currentProgram.getLanguage()
    for n in names:
        r = lang.getRegister(n)
        if r is not None:
            return r
    return None


def writes_to_register(instr, reg):
    """Whether `instr` has an output that overlaps `reg` -- checked via
    the instruction's own low-level Pcode, which is accurate regardless
    of mnemonic (covers MOV, LEA, XOR reg,reg idioms, etc.)."""
    for op in instr.getPcode():
        out = op.getOutput()
        if out is not None and out.isRegister():
            out_reg = currentProgram.getLanguage().getRegister(out.getAddress(), out.getSize())
            if out_reg is not None and (out_reg == reg or reg.contains(out_reg) or out_reg.contains(reg)):
                return True
    return False


def find_last_write(before_addr, reg, containing_func, max_back=400):
    """Walks backward through the *raw* instruction stream (not the
    decompiler's own SSA) from `before_addr`, for the nearest
    instruction that writes `reg`. Bounded to whichever real Function
    object *actually* contains each instruction along the way -- NOT
    `containing_func`'s own `getBody()` -- because GCC splits
    exception-only code into a separate `.cold`-partition Function
    Ghidra models discretely (its addresses sit far from the hot
    path's own); the decompiler transparently stitches both into one
    C view, but the raw instruction/body model does not, so bounding
    to the ORIGINAL function's body silently walked past real code
    inside the same logical function -- a real bug this exact
    experiment surfaced when every `_M_dispose()` target (all of them
    inside a `.cold` partition) came back "call not found". Still
    stops at any address outside the union of hot+cold partitions
    entirely (a real function boundary, not a same-function split).
    Deliberately bounded and straight-line otherwise -- a real
    block-CFG walk would need to fan out across predecessors, which
    this first, narrowly-scoped pass doesn't attempt; a call whose
    defining write isn't found this way is reported as such, not
    guessed at."""
    instr = listing.getInstructionBefore(before_addr)
    steps = 0
    while instr is not None and steps < max_back:
        owner = func_manager.getFunctionContaining(instr.getMinAddress())
        if owner is None:
            return None
        if writes_to_register(instr, reg):
            return instr
        instr = listing.getInstructionBefore(instr.getMinAddress())
        steps += 1
    return None


def describe_pcode_inputs(instr):
    """Raw operand text for every Pcode op this instruction lowers to --
    the actual RHS Ghidra's own P-code model assigns, not a decompiler
    guess. Kept as structured, addressable facts (opcode name + operand
    strings), not prose."""
    ops = []
    for op in instr.getPcode():
        inputs = []
        for i in range(op.getNumInputs()):
            vn = op.getInput(i)
            inputs.append(describe_varnode(vn))
        ops.append({
            "opcode": op.getMnemonic(),
            "inputs": inputs,
            "output": describe_varnode(op.getOutput()) if op.getOutput() is not None else None,
        })
    return ops


def describe_varnode(vn):
    if vn is None:
        return None
    if vn.isConstant():
        return "const:0x%x" % vn.getOffset()
    if vn.isRegister():
        reg = currentProgram.getLanguage().getRegister(vn.getAddress(), vn.getSize())
        return "reg:%s" % (reg.getName() if reg is not None else vn.getAddress().toString())
    if vn.isUnique():
        return "tmp:0x%x" % vn.getOffset()
    if vn.getAddress() is not None and vn.getAddress().getAddressSpace().getName() == "stack":
        return "stack:0x%x" % vn.getAddress().getOffset()
    return "mem:%s" % vn.getAddress().toString()


def defining_op_for(instr, reg):
    """The SPECIFIC Pcode op within `instr`'s own translation whose
    output actually defines `reg` -- not just any op the instruction
    happens to also emit. A real, confirmed case this distinction
    matters for: `POP RBX` lowers to a `LOAD` (the real data movement,
    restoring whatever was previously saved -- RBX's real value) *and*
    a separate `INT_ADD RSP,8` (the stack-pointer's own bookkeeping,
    nothing to do with what value RBX now holds). Treating the first
    `INT_ADD` found anywhere in the instruction as "the address" --
    an earlier version of this script did exactly that -- silently
    resolved a POP's own stack-pointer adjustment as if it were a real
    `&local_slot` computation: confidently wrong evidence, not missing
    evidence, which is worse."""
    for op in instr.getPcode():
        out = op.getOutput()
        if out is not None and out.isRegister():
            out_reg = currentProgram.getLanguage().getRegister(out.getAddress(), out.getSize())
            if out_reg is not None and (out_reg == reg or reg.contains(out_reg) or out_reg.contains(reg)):
                return op
    return None


def resolve_unique_within_instruction(instr, varnode, seen=None):
    """A single x86 instruction routinely lowers to a short CHAIN of
    Pcode ops feeding each other through `unique` temporaries -- `LEA
    RCX,[RSP+0x40]` is `INT_ADD(RSP,0x40) -> tmp` then `COPY(tmp) ->
    RCX`, two ops, not one. `defining_op_for` correctly finds the
    `COPY`, but its own input is that `unique` temp, not a register or
    constant -- stopping there (an earlier version of this script did)
    reports a real LEA as unresolved. Chases the SAME instruction's own
    other ops for whichever one actually defines that temp, bounded to
    avoid a cycle."""
    if seen is None:
        seen = set()
    if varnode is None or not varnode.isUnique():
        return None
    key = (varnode.getAddress().getOffset(), varnode.getSize())
    if key in seen:
        return None
    seen.add(key)
    for op in instr.getPcode():
        out = op.getOutput()
        if out is not None and out.isUnique() and out.getAddress().getOffset() == varnode.getAddress().getOffset() and out.getSize() == varnode.getSize():
            return op
    return None


def trace_receiver(call_instr, containing_func, max_hops=15):
    """Backward def-use chain for the receiver register, starting at
    the call site. Each hop records the defining instruction's own real
    Pcode (never a decompiler paraphrase). Stops -- with a real
    resolution -- only at a genuine address-of-stack-slot computation
    (`INT_ADD(RSP, const)` whose OWN output is what feeds the traced
    register, the real LEA idiom); stops WITHOUT a resolution, honestly,
    at a memory LOAD (a spilled/restored value -- correlating it back to
    whichever earlier write filled that exact memory location is real,
    separate work this first pass doesn't attempt) or when no further
    defining write can be found at all."""
    reg = reg_of(currentProgram, RECEIVER_REG_NAMES)
    chain = []
    cur_reg = reg
    cur_addr = call_instr.getMinAddress()
    stack_location = None
    for hop in range(max_hops):
        defining = find_last_write(cur_addr, cur_reg, containing_func)
        if defining is None:
            chain.append({"hop": hop, "found": False, "reason": "no defining write found"})
            break
        op = defining_op_for(defining, cur_reg)
        # Chase same-instruction `unique`-temp chains (LEA's own
        # INT_ADD-then-COPY shape) to the op that actually computes the
        # value, not just the last op that happens to write the register.
        chase_guard = 0
        while op is not None and op.getMnemonic() == "COPY" and chase_guard < 8:
            src = op.getInput(0)
            if src is None or not src.isUnique():
                break
            deeper = resolve_unique_within_instruction(defining, src)
            if deeper is None:
                break
            op = deeper
            chase_guard += 1
        pcode_ops = describe_pcode_inputs(defining)
        chain.append({
            "hop": hop,
            "found": True,
            "address": defining.getMinAddress().toString(),
            "mnemonic": defining.toString(),
            "defining_opcode": op.getMnemonic() if op is not None else None,
            "pcode": pcode_ops,
        })
        if op is None:
            chain[-1]["reason"] = "instruction writes register but no single defining pcode op found"
            break

        mnem = op.getMnemonic()
        if mnem == "INT_ADD":
            a, b = op.getInput(0), op.getInput(1)
            # Ghidra's own operand order for this op varies by instruction
            # (a real case had `(const, register)`, not the `(register,
            # const)` order an earlier version of this script assumed
            # fixed, and silently fell through the whole real LEA
            # resolution as a result) -- check both positions.
            reg_operand, const_operand = None, None
            for cand in (a, b):
                if cand is not None and cand.isRegister() and reg_operand is None:
                    reg_operand = cand
                elif cand is not None and cand.isConstant() and const_operand is None:
                    const_operand = cand
            if reg_operand is not None and const_operand is not None:
                base_reg = currentProgram.getLanguage().getRegister(reg_operand.getAddress(), reg_operand.getSize())
                if base_reg is not None and base_reg.getName() in ("RSP", "ESP"):
                    offset = const_operand.getOffset()
                    if offset >= 0x8000000000000000:
                        offset -= 0x10000000000000000
                    stack_location = "RSP + 0x%x" % offset if offset >= 0 else "RSP - 0x%x" % (-offset)
                    break
            # Not a stack-relative LEA -- an ordinary add feeding this
            # register (e.g. pointer arithmetic on something else).
            # Continue tracing whichever operand is itself a register.
            moved_from = None
            for cand in (a, b):
                if cand is not None and cand.isRegister():
                    moved_from = currentProgram.getLanguage().getRegister(cand.getAddress(), cand.getSize())
            if moved_from is None:
                chain[-1]["reason"] = "INT_ADD with no traceable register operand"
                break
            cur_reg = moved_from
            cur_addr = defining.getMinAddress()
            continue
        if mnem == "COPY":
            src = op.getInput(0)
            if src is not None and src.isRegister():
                cur_reg = currentProgram.getLanguage().getRegister(src.getAddress(), src.getSize())
                cur_addr = defining.getMinAddress()
                continue
            chain[-1]["reason"] = "COPY from a non-register source (constant/unique)"
            break
        if mnem == "LOAD":
            chain[-1]["reason"] = "register restored from memory (spill slot or real field load) -- not traced further"
            break
        chain[-1]["reason"] = "unhandled defining opcode %s" % mnem
        break
    return chain, stack_location


def find_construction_sites(containing_func, decompiler, exclude_addr):
    """Real construction-site evidence: every OTHER call in this same
    function whose own (decompiler-recognized) first argument resolves,
    by the SAME backward stack-relative trace used for the receiver
    above, to a real stack location -- reused as `competing_candidates`
    for whichever target this doesn't end up matching."""
    sites = []
    result = decompiler.decompileFunction(containing_func, 30, monitor)
    if result is None or not result.decompileCompleted():
        return sites
    high = result.getHighFunction()
    if high is None:
        return sites
    op_iter = high.getPcodeOps()
    while op_iter.hasNext():
        op = op_iter.next()
        if op.getMnemonic() != "CALL":
            continue
        if op.getSeqnum().getTarget().equals(exclude_addr):
            continue
        target_vn = op.getInput(0)
        target_addr = target_vn.getAddress() if target_vn is not None else None
        called = func_manager.getFunctionAt(target_addr) if target_addr is not None else None
        if called is None or op.getNumInputs() < 2:
            continue
        # Only meaningful when the decompiler kept this as a real
        # varnode with a traceable register origin at this call site.
        call_instr = listing.getInstructionAt(op.getSeqnum().getTarget())
        if call_instr is None:
            continue
        # Reuses `trace_receiver`'s own (bug-fixed, tested) backward
        # trace rather than a second, independent copy of the same
        # logic -- an earlier version of this function had its own,
        # separately-broken copy of exactly the two bugs `trace_receiver`
        # itself hit and fixed (blind first-INT_ADD-found, and assuming
        # a fixed register/constant operand order).
        _, stack_loc = trace_receiver(call_instr, containing_func)
        sites.append({
            "call_address": op.getSeqnum().getTarget().toString(),
            "called_function": called.getName(),
            "receiver_stack_location": stack_loc,
        })
    return sites


def block_info(target_addr):
    try:
        blocks = block_model.getCodeBlocksContaining(target_addr, monitor)
        if blocks is not None and len(blocks) > 0:
            b = blocks[0]
            preds = []
            src_it = b.getSources(monitor)
            while src_it.hasNext():
                preds.append(src_it.next().getSourceAddress().toString())
            succs = []
            dst_it = b.getDestinations(monitor)
            while dst_it.hasNext():
                succs.append(dst_it.next().getDestinationAddress().toString())
            return {"block_start": b.getFirstStartAddress().toString(), "predecessors": preds, "successors": succs}
    except Exception as e:
        return {"error": str(e)}
    return None


def find_nth_call_to(containing_func, decompiler, callee_name_substr, n):
    """The n-th (0-indexed) call, in real address order, whose target
    resolves to a function/thunk whose name contains
    `callee_name_substr` -- the stable identity Round A's line-numbered
    selection is re-expressed against here. Walks the DECOMPILER's own
    merged HighFunction pcode, not raw per-instruction references:
    GCC's `.cold`-partition split (see `find_last_write`'s own comment)
    means a call site's real address can sit in a Function object the
    ORIGINAL function's own raw instruction listing never visits at
    all, but the decompiler already knows to include it -- confirmed
    directly against this exact binary, where every real `_M_dispose`
    call site the decompiled C text shows lives in the `.cold`
    partition and is invisible to a raw-listing walk."""
    result = decompiler.decompileFunction(containing_func, 30, monitor)
    if result is None or not result.decompileCompleted():
        return None
    high = result.getHighFunction()
    if high is None:
        return None
    matches = []
    op_iter = high.getPcodeOps()
    while op_iter.hasNext():
        op = op_iter.next()
        if op.getMnemonic() != "CALL":
            continue
        target_vn = op.getInput(0)
        if target_vn is None or not target_vn.isAddress():
            continue
        target = func_manager.getFunctionAt(target_vn.getAddress())
        if target is not None and callee_name_substr in target.getName():
            matches.append(op.getSeqnum().getTarget())
    matches.sort(key=lambda a: a.getOffset())
    if n < len(matches):
        return listing.getInstructionAt(matches[n])
    return None


def main():
    args = getScriptArgs()
    targets_path = args[0]
    output_path = args[1]
    with open(targets_path, "r") as f:
        targets = json.load(f)

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    results = []
    try:
        for t in targets:
            func = func_manager.getFunctionAt(addr(t["func_addr"]))
            if func is None:
                results.append({"id": t["id"], "error": "function not found at %s" % t["func_addr"]})
                continue
            call_instr = find_nth_call_to(func, decompiler, t["callee_substr"], t["ordinal"])
            if call_instr is None:
                results.append({"id": t["id"], "error": "call not found (ordinal %d)" % t["ordinal"]})
                continue

            chain, stack_location = trace_receiver(call_instr, func)
            constructions = find_construction_sites(func, decompiler, call_instr.getMinAddress())
            competing = [c for c in constructions if c["receiver_stack_location"] != stack_location]
            matching = [c for c in constructions if c["receiver_stack_location"] == stack_location and stack_location is not None]

            results.append({
                "id": t["id"],
                "call_address": call_instr.getMinAddress().toString(),
                "containing_function": func.getName(),
                "def_use_chain": chain,
                "resolved_stack_location": stack_location,
                "matching_construction_sites": matching,
                "all_construction_sites_in_function": constructions,
                "competing_candidates": competing,
                "cfg_block": block_info(call_instr.getMinAddress()),
            })
    finally:
        decompiler.dispose()

    with open(output_path, "w") as f:
        f.write(json.dumps(results, indent=2))


main()
