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


def base_and_offset_of_address(instr, addr_vn):
    """The general form: if `addr_vn` resolves to `BASE_REG + const` --
    directly, or via a same-instruction `unique` temp computed by an
    `INT_ADD` (the `[REG+0xNN]` addressing idiom) -- returns
    `(base_register, offset)`. A bare register with no addition
    resolves to `(that_register, 0)` (covers PUSH/POP's own `[RSP]`
    shape, and a plain `[RDI]` field-0 access equally). `(None, None)`
    for any other address expression -- deliberately not guessed at.
    Unlike the RSP-only check an earlier version of this had, `BASE_REG`
    here can be *any* register -- RSP for a stack spill, or RDI/RSI/etc.
    for a real pointer/field access, which `trace_receiver`'s own
    pointer-alias handling below distinguishes by what the base
    register itself turns out to be, not by hard-coding which register
    names count."""
    if addr_vn is None:
        return None, None
    if addr_vn.isRegister():
        r = currentProgram.getLanguage().getRegister(addr_vn.getAddress(), addr_vn.getSize())
        return (r, 0) if r is not None else (None, None)
    if addr_vn.isUnique():
        defining = resolve_unique_within_instruction(instr, addr_vn)
        if defining is None or defining.getMnemonic() != "INT_ADD":
            return None, None
        a, b = defining.getInput(0), defining.getInput(1)
        reg_operand, const_operand = None, None
        for cand in (a, b):
            if cand is not None and cand.isRegister() and reg_operand is None:
                reg_operand = cand
            elif cand is not None and cand.isConstant() and const_operand is None:
                const_operand = cand
        if reg_operand is None or const_operand is None:
            return None, None
        base_reg = currentProgram.getLanguage().getRegister(reg_operand.getAddress(), reg_operand.getSize())
        if base_reg is None:
            return None, None
        offset = const_operand.getOffset()
        if offset >= 0x8000000000000000:
            offset -= 0x10000000000000000
        return base_reg, offset
    return None, None


def stack_offset_of_address(instr, addr_vn):
    """`base_and_offset_of_address`, narrowed to a real RSP/ESP-relative
    stack access specifically -- the shape `find_matching_store`'s own
    spill/restore correlation needs. `None` for any other base register
    (a real pointer/field access, handled separately by
    `trace_receiver`'s own generalized-base branch, not this function)."""
    base_reg, offset = base_and_offset_of_address(instr, addr_vn)
    if base_reg is not None and base_reg.getName() in ("RSP", "ESP"):
        return offset
    return None


def forward_stack_effect(instr):
    """The signed change `instr` makes to RSP when it actually executes
    (forward, real program order) -- 0 for anything that isn't a stack
    push/pop or an explicit `ADD/SUB RSP,const`. Used to normalize a
    spill's own literal `[RSP+K]` offset against a load's literal
    `[RSP+K']` offset when they're NOT the same K -- a real, confirmed
    case (PROJECT.md M20 Round C's own honest negative result): a
    `SUB RSP,N` sitting between a store and its later matching load
    shifts the SAME logical slot's own literal constant, and comparing
    the two K's directly (an earlier version of this script did exactly
    that) misses a real match instead of finding one."""
    mnem = instr.getMnemonicString().upper()
    if mnem.startswith("PUSH"):
        return -currentProgram.getDefaultPointerSize()
    if mnem.startswith("POP"):
        return currentProgram.getDefaultPointerSize()
    for op in instr.getPcode():
        m = op.getMnemonic()
        if m not in ("INT_ADD", "INT_SUB"):
            continue
        out = op.getOutput()
        if out is None or not out.isRegister():
            continue
        out_reg = currentProgram.getLanguage().getRegister(out.getAddress(), out.getSize())
        if out_reg is None or out_reg.getName() not in ("RSP", "ESP"):
            continue
        a, b = op.getInput(0), op.getInput(1)
        const_operand = b if (b is not None and b.isConstant()) else (a if a is not None and a.isConstant() else None)
        if const_operand is None:
            continue
        magnitude = const_operand.getOffset()
        if magnitude >= 0x8000000000000000:
            magnitude -= 0x10000000000000000
        return -magnitude if m == "INT_SUB" else magnitude
    return 0


def find_matching_store(load_instr, load_offset, containing_func, max_back=400):
    """PROJECT.md M20 Round D1: real spill/restore correlation, frame-
    normalized -- not a literal-offset comparison. For a LOAD reading
    `RSP + load_offset`, walks backward accumulating the REAL, signed
    RSP delta contributed by every push/pop/explicit stack adjustment
    passed along the way (`forward_stack_effect`), and looks for the
    nearest STORE whose own literal offset, once shifted by that
    accumulated delta, lands on the SAME logical slot `load_offset`
    identifies -- not merely the same literal text. A real, confirmed
    case this fixes (Round C's own honest negative result): a
    `SUB RSP,N` between a store and its later matching load shifts the
    same logical slot's own literal constant, so comparing the two
    literal K's directly missed a real match. By construction (the
    nearest normalized match wins, straight-line), nothing else touches
    that same logical slot in between on this walked path -- the "no
    intervening conflicting store" requirement for this bounded,
    single-path search. Does NOT fan out across CFG predecessors (same,
    already-named limitation as `find_last_write`'s own straight-line
    walk) -- a load whose real definition sits down a different
    control-flow path than this backward address-order walk happens to
    take is reported as unresolved, not guessed at."""
    instr = listing.getInstructionBefore(load_instr.getMinAddress())
    steps = 0
    running_delta = 0
    while instr is not None and steps < max_back:
        owner = func_manager.getFunctionContaining(instr.getMinAddress())
        if owner is None:
            return None, None
        for op in instr.getPcode():
            if op.getMnemonic() != "STORE":
                continue
            # A `CALL` instruction's own Pcode always includes a STORE
            # of the real return address onto the stack (its own
            # implicit push) -- a real, confirmed false match: it can
            # coincidentally normalize to the exact same logical slot a
            # real value spill would, but its VALUE operand is always a
            # bare constant (the return address itself), never a
            # register -- never real application data. Skipped outright
            # so the search continues past it to a real store, rather
            # than reporting a spurious "match" whose value can't be
            # (and shouldn't be) used anyway.
            if op.getNumInputs() >= 3 and op.getInput(2) is not None and op.getInput(2).isConstant():
                continue
            off = stack_offset_of_address(instr, op.getInput(1))
            if off is not None and off == load_offset + running_delta:
                return instr, op
        running_delta += forward_stack_effect(instr)
        instr = listing.getInstructionBefore(instr.getMinAddress())
        steps += 1
    return None, None


def find_matching_push(pop_instr, containing_func, max_back=400):
    """The PUSH/POP-specific case of the same spill/restore
    correlation: PUSH/POP always address the CURRENT top of stack, so
    `RSP + 0` alone can't distinguish one save/restore pair from
    another the way a `[RSP+const]` spill's own fixed offset can.
    Balances real stack depth instead -- walking backward, every POP
    seen adds one slot back, every PUSH removes one; the PUSH where
    that running count first reaches zero is the one THIS pop restores,
    because everything between them (any other, already-balanced
    push/pop pairs) nets to zero depth change by construction, the
    same 'nothing else could have touched this exact slot' guarantee
    `find_matching_store` gets from a literal matching offset instead."""
    depth = 1
    instr = listing.getInstructionBefore(pop_instr.getMinAddress())
    steps = 0
    while instr is not None and steps < max_back:
        owner = func_manager.getFunctionContaining(instr.getMinAddress())
        if owner is None:
            return None
        mnem = instr.getMnemonicString().upper()
        if mnem.startswith("POP"):
            depth += 1
        elif mnem.startswith("PUSH"):
            depth -= 1
            if depth == 0:
                return instr
        instr = listing.getInstructionBefore(instr.getMinAddress())
        steps += 1
    return None


PARAMETER_REGISTERS = ("RCX", "RDX", "R8", "R9")  # x64 MS ABI: 1st-4th integer/pointer args, in order


def trace_receiver(call_instr, containing_func, max_hops=15):
    """Backward def-use chain for the receiver register, starting at
    the call site. Each hop records the defining instruction's own real
    Pcode (never a decompiler paraphrase). Stops -- with a real
    resolution (`stack_location`) -- only at a genuine
    address-of-stack-slot computation (`INT_ADD(RSP, const)` whose OWN
    output is what feeds the traced register, the real LEA idiom).
    Real spill/restore correlation (`find_matching_store`/
    `find_matching_push`) and real pointer/field dereference tracing
    (any non-RSP base register) both continue the SAME chain rather
    than stopping -- PROJECT.md M20 Round D: no separate mechanism for
    "one more hop", just the existing loop allowed to keep going, bounded
    by `max_hops`. `deref_path` records every dereference step taken
    along the way (through_register + field_offset) -- kept SEPARATE
    from `stack_location` on purpose: a dereferenced pointer's own
    address is a categorically different fact from where the pointer
    itself is stored, and conflating the two would be the exact same
    class of confidently-wrong evidence this file has already caught
    and fixed twice."""
    reg = reg_of(currentProgram, RECEIVER_REG_NAMES)
    chain = []
    cur_reg = reg
    cur_addr = call_instr.getMinAddress()
    stack_location = None
    deref_path = []
    for hop in range(max_hops):
        defining = find_last_write(cur_addr, cur_reg, containing_func)
        if defining is None:
            reg_name = cur_reg.getName() if cur_reg is not None else "?"
            if reg_name in PARAMETER_REGISTERS:
                reason = (
                    "no defining write found, and %s is an x64-ABI parameter register -- "
                    "real evidence this is likely one of the function's own incoming parameters, "
                    "never reassigned before this point, not merely a dead end" % reg_name
                )
            else:
                reason = "no defining write found"
            chain.append({"hop": hop, "found": False, "reason": reason})
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
            addr_vn = op.getInput(1)
            base_reg, offset = base_and_offset_of_address(defining, addr_vn)
            if base_reg is None:
                chain[-1]["reason"] = "loaded through an address expression this pass can't resolve at all -- not traced further"
                break
            if base_reg.getName() not in ("RSP", "ESP"):
                # PROJECT.md M20 Round D2: a real pointer/field
                # dereference, not a stack spill -- generalized rather
                # than special-cased to RDI. Deliberately does NOT
                # collapse this into `stack_location` (which means
                # "the receiver's own address IS this stack slot"): a
                # dereferenced pointer's OWN address is a categorically
                # different fact from where the *pointer itself* lives,
                # and conflating the two would repeat the exact class of
                # confidently-wrong-evidence bug this whole file has
                # already caught and fixed twice. Continues tracing the
                # BASE register instead -- "what does base_reg hold" is
                # itself answerable by the same backward trace, possibly
                # bottoming out at a real stack slot, a genuine function
                # parameter (see the `found is None` handling below), or
                # its own dead end.
                deref_path.append({
                    "through_register": base_reg.getName(),
                    "field_offset": offset,
                    "at_address": defining.getMinAddress().toString(),
                })
                cur_reg = base_reg
                cur_addr = defining.getMinAddress()
                chain[-1]["reason"] = "dereferences %s + 0x%x -- continuing trace on %s itself, not a stack spill" % (
                    base_reg.getName(), offset if offset >= 0 else offset, base_reg.getName(),
                )
                continue
            load_offset = offset
            is_pop = defining.getMnemonicString().upper().startswith("POP")
            if is_pop:
                match_instr = find_matching_push(defining, containing_func)
                match_kind = "push/pop depth-balanced"
            else:
                match_instr, _ = find_matching_store(defining, load_offset, containing_func)
                match_kind = "matching-offset store"
            if match_instr is None:
                chain[-1]["reason"] = (
                    "spill/restore correlation attempted (%s) but no matching earlier write was "
                    "found within the search window -- not traced further" % match_kind
                )
                break
            # The matching write's own STORE op -- for both PUSH and a
            # plain `[RSP+const] = reg` spill, this is simply "the
            # STORE op this instruction's own Pcode contains" (STORE has
            # no register output, so `defining_op_for`'s own
            # output-matching search doesn't apply here at all).
            store_op = None
            for cand_op in match_instr.getPcode():
                if cand_op.getMnemonic() == "STORE":
                    store_op = cand_op
                    break
            if store_op is None or store_op.getNumInputs() < 3:
                chain[-1]["reason"] = "matching write found (%s @ %s) but its stored value could not be read" % (
                    match_kind, match_instr.getMinAddress().toString(),
                )
                break
            stored_value = store_op.getInput(2)
            chain[-1]["reason"] = "resolved via spill/restore correlation (%s) to the write at %s" % (
                match_kind, match_instr.getMinAddress().toString(),
            )
            if stored_value is not None and stored_value.isRegister():
                cur_reg = currentProgram.getLanguage().getRegister(stored_value.getAddress(), stored_value.getSize())
                cur_addr = match_instr.getMinAddress()
                continue
            if stored_value is not None and stored_value.isUnique():
                # `resolve_unique_within_instruction` finds the op that
                # DEFINES this temp (e.g. `PUSH RBX`'s own `COPY(RBX) ->
                # tmp` feeding its `STORE(tmp)`) -- that op's OUTPUT is
                # tautologically the same temp we started from; the real
                # value is its INPUT (an earlier version of this code
                # checked the output instead, which can never be a
                # register by construction, and always fell through here).
                deeper = resolve_unique_within_instruction(match_instr, stored_value)
                if deeper is not None and deeper.getMnemonic() == "COPY":
                    src = deeper.getInput(0)
                    if src is not None and src.isRegister():
                        cur_reg = currentProgram.getLanguage().getRegister(src.getAddress(), src.getSize())
                        cur_addr = match_instr.getMinAddress()
                        continue
            chain[-1]["reason"] += " (stored value itself is not a simple register -- not traced further)"
            break
        chain[-1]["reason"] = "unhandled defining opcode %s" % mnem
        break
    return chain, stack_location, deref_path


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
        _, stack_loc, _ = trace_receiver(call_instr, containing_func)
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

            chain, stack_location, deref_path = trace_receiver(call_instr, func)
            constructions = find_construction_sites(func, decompiler, call_instr.getMinAddress())
            competing = [c for c in constructions if c["receiver_stack_location"] != stack_location]
            matching = [c for c in constructions if c["receiver_stack_location"] == stack_location and stack_location is not None]

            results.append({
                "id": t["id"],
                "call_address": call_instr.getMinAddress().toString(),
                "containing_function": func.getName(),
                "def_use_chain": chain,
                "resolved_stack_location": stack_location,
                # PROJECT.md M20 Round D2: non-empty only when the chain
                # passed through one or more real pointer/field
                # dereferences (a non-RSP base register) -- deliberately
                # separate from `resolved_stack_location`, never merged
                # into it (see `trace_receiver`'s own docstring for why).
                "pointer_dereference_path": deref_path,
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
