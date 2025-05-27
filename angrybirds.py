import angr
import claripy

proj = angr.Project("test_program", auto_load_libs = False)

#Just for debugging purposes
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


#If write address and write data are both not symbolic, it's probably nothing interesting
def shouldTrack(state):
    if symAddr(state) or symData(state):
        return True;
    return False;




class MemoryWrite:
    def __init__(self, state):
        
        #There's probably a cute way to do this instead of a fuck ton of instance variables all together
        self.len = state.solver.eval(state.inspect.mem_write_length);
        self.minAddr = state.solver.min(state.inspect.mem_write_address);
        self.maxAddr = state.solver.max(state.inspect.mem_write_address);
        self.maxReach = min(0xFFFFFFFFFFFFFFFF, self.maxAddr + self.len);

        self.symData = symData(state);
        self.rip = state.solver.eval(state.regs.rip);
        self.state = state
        
    
    def __repr__(self):
        return "<Memory write at RIP = " + hex(self.rip) + ">"


    def __eq__(self, other):
        #This is mainly for checking duplicates, and might cause problems later, remember to check on this if something starts acting fishy
        if self.minAddr == other.minAddr and self.maxAddr == other.maxAddr and self.len == other.len and self.symData == other.symData and self.rip == other.rip  and self.len == other.len:
            return True
        return False;


    def debugPrint(self):
        print(f"MEMORY WRITE AT {hex(self.rip)}:")
        print(f"\tMemory details:")
        print(f"\t\tStart: {hex(self.minAddr)}")
        print(f"\t\tEnd:   {hex(self.maxAddr)}")
        print(f"\t\tSize:  {hex(self.len)}")
        print(f"\t\tSymbolic data: {self.symData}")
        print(f"\tState details:")
        print(self.state.solver.constraints)



def write_bp(state):
    
    if not shouldTrack(state):
        return


    write = MemoryWrite(state)
    #TODO: Set up an actual system for logs & debug prints
    #write.debugPrint()
    #disasm(state)
    
    #Tracked memory writes are stored in state globals, and then all put together after the program is explored.
    state.globals["writes"].append(write)


def find_writes(proj):

    entry_state = proj.factory.entry_state()
    entry_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=write_bp)

    entry_state.globals["writes"] = []
    simgr = proj.factory.simgr(entry_state);

    simgr.explore()

    writes = []

    for state in simgr.deadended:
        #TODO: make sure simgr.deadened is actually what we want, and that we're not missing any states that don't end up there
        for write in state.globals["writes"]:
            if write not in writes:
                writes.append(write)
    return writes


writes = find_writes(proj)

print("Memory writes detected: ")
for write in writes:
    print(f"\tRIP {hex(write.rip)}:\t{hex(write.minAddr)} to {hex(write.maxReach)}")
