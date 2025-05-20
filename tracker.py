import angr
import claripy


#stdin setup is pretty sketch at the moment and probably only works for the short test binary I've been using (if that)
#TODO: figure out a cleaner way to do symbolic stdin 
proj = angr.Project("test_program", auto_load_libs = False)
sym_val = claripy.BVS("SymbolicInput", 8)
stream = angr.SimFileStream(name="stdin", content=sym_val, has_end=True);



def disasm(state):
    rip = state.solver.eval(state.regs.rip)
    block = state.project.factory.block(rip)
    print(f"Disassembly at RIP = {rip:#x}")
    for insn in block.capstone.insns:
        print(f"{insn.address:#x}:\t{insn.mnemonic}\t{insn.op_str}")



def symAddr(state):
    if isinstance(state.inspect.mem_write_address, claripy.ast.bv.BV) and state.inspect.mem_write_address.symbolic:
        return True;
    return False;

def symData(state):
    if isinstance(state.inspect.mem_write_expr, claripy.ast.bv.BV) and state.inspect.mem_write_expr.symbolic:
        return True;
    return False;

def shouldTrack(state):
    if symAddr(state) or symData(state):
        return True;
    return False;




class MemoryWrite:
    def __init__(self, state):
        self.startAddr = state.solver.min(state.inspect.mem_write_address);
        self.endAddr = state.solver.max(state.inspect.mem_write_address);
        self.len = state.solver.eval(state.inspect.mem_write_length);
        self.symData = symData(state);
        self.rip = state.solver.eval(state.regs.rip);
        self.state = state
    
    def __repr__(self):
        return "<Memory write at RIP = " + hex(self.rip) + ">"


    def __eq__(self, other):
        if self.startAddr == other.startAddr and self.endAddr == other.endAddr and self.len == other.len and self.symData == other.symData and self.rip == other.rip:
            return True
        return False;


    def debugPrint(self):
        print(f"MEMORY WRITE AT {hex(self.rip)}:")
        print(f"\tMemory details:")
        print(f"\t\tStart: {hex(self.startAddr)}")
        print(f"\t\tEnd:   {hex(self.endAddr)}")
        print(f"\t\tSize:  {hex(self.len)}")
        print(f"\t\tSymbolic data: {self.symData}")
        print(f"\tState details:")
        print(self.state.solver.constraints)







def write_bp(state):
    
    if not shouldTrack(state):
        return
        
    write = MemoryWrite(state)
    write.debugPrint()
    disasm(state)
    state.globals["writes"].append(write)


def find_writes(proj):

    entry_state = proj.factory.entry_state(stdin=stream)
    entry_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=write_bp)

    entry_state.globals["writes"] = []
    simgr = proj.factory.simgr(entry_state);

    simgr.explore()
    print(simgr)

    writes = []
    for state in simgr.deadended:
        for write in state.globals["writes"]:
            if write in writes:
                print("DUPLICATE");
            else:
                writes.append(write)

    return writes


