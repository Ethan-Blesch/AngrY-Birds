import angr
import claripy
import threading
import time
import archinfo
from .issue import *




def functionEnd(addr, proj):
    function = proj.kb.functions.floor_func(addr)
    if function is None:
        print(f"No function found containing address 0x{address:x}")
    else:
        print(f"Function found: {function.name} at 0x{function.addr:x}")

        # Get the end of the function by examining its basic blocks
        block_addrs = [block.addr for block in function.blocks]

        # Calculate the last instruction address in the last block
        last_block = max(function.blocks, key=lambda b: b.addr)
        last_insn_addr = last_block.addr + last_block.size

        return last_insn_addr
    #TODO: add error handling here

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

def symLen(state):
    if isinstance(state.inspect.mem_write_length, claripy.ast.bv.BV) and state.inspect.mem_write_length.symbolic:
        return True;
    return False;

#If write address and write data are both not symbolic, it's probably nothing interesting
def shouldTrack(state):
    if symAddr(state) or symData(state) or symLen(state):
        return True;
    return False;




def hasPerm(bitfield, perm):
    if perm == 'r':
        return (bitfield & 1 == 1)
    if perm == 'w': 
        return (bitfield & 2 == 2)
    if perm == 'x': 
        return (bitfield & 4 == 4)

def getMapping(addr, state):
    try:
        perms = state.memory.permissions(addr)
        return state.solver.eval(perms)
    except angr.SimMemoryError:
        return -1

def backtrace(state, project):
    bt = ""
    for i, frame in enumerate(state.callstack):
        try:
            func = project.kb.functions.floor_func(frame.func_addr).name
        except:
            func = "Unknown"
        rip = frame.ret_addr
        bt += f"Frame {i}: {hex(rip)} in {func}\n"
    return bt


def get_saved_frames(state):
    frames = []
    for i, frame in enumerate(state.callstack):
        try:
            #Subtract 8 to include saved RBP as well
            frames.append(frame.stack_ptr - 8) 
        except:
            pass
    return frames


def bufferHasSymbolic(state, start, end):
    for addr in range(start, end):
        if state.solver.symbolic(state.memory.load(addr, 1)):
            return True
    return False

class MemoryWrite:
    def __init__(self, state, brokeOn):
        
        #There's probably a cute way to do this instead of a fuck ton of instance variables all together

        if brokeOn == "write":
            self.rip = state.solver.eval(state.regs.rip);

            if state.inspect.mem_write_length is None:
                self.minLen = state.inspect.mem_write_expr.size()
                self.maxLen = self.minLen
            else:
                self.minLen = state.solver.min(state.inspect.mem_write_length);
                self.maxLen = state.solver.max(state.inspect.mem_write_length);
            self.minAddr = state.solver.min(state.inspect.mem_write_address);
            self.maxAddr = state.solver.max(state.inspect.mem_write_address);
            self.rangeStart = self.minAddr
            #TODO: This falls apart if the conditions for address and length are dependent, e.g. max length makes max addr impossible
            self.rangeEnd = min(0xFFFFFFFFFFFFFFFF, self.maxAddr + self.maxLen);
            self.function = state.project.kb.functions.floor_func(self.rip)
            self.symData = symData(state);
            self.symLen = symLen(state);
            self.symAddr = symAddr(state);


        elif brokeOn == "memcpy":
            dst_arg = state.regs.rdi
            src_arg = state.regs.rsi
            num_arg = state.regs.rdx

            self.rip = state.solver.eval(state.regs.rip);
            self.minLen = state.solver.min(num_arg)
            self.maxLen = state.solver.max(num_arg)
            self.minAddr = state.solver.min(dst_arg)
            self.maxAddr = state.solver.max(dst_arg)
            self.rangeStart = self.minAddr
            self.rangeEnd = min(0xFFFFFFFFFFFFFFFF, self.maxAddr + self.maxLen);
            self.function = state.project.kb.functions.floor_func(self.rip)
            self.symData = bufferHasSymbolic(state, state.solver.min(src_arg), state.solver.max(src_arg) + self.maxLen);
            self.symAddr = state.solver.symbolic(dst_arg)
            self.symLen = state.solver.symbolic(num_arg)

        self.state = state
        self.backtrace = backtrace(self.state, self.state.project)


        self.stdin = state.posix.dumps(0)

        self.issues = []

        if self.minAddr == 0 and self.maxAddr == 0xffffffffffffffff:
            self.issues.append(ArbitraryWrite())
            return

        #Check for saved rbp/rip overwrites
        for frame in get_saved_frames(state):
            if self.couldContain(frame + 7, 16):
                self.issues.append(SavedRipOverwrite(frame))
                print("WEE WOO WEE WOO")
                print(f"found issue in {self}")
                break


        #Check for possible access to unmapped/unwritable memory
        foundUnmapped = False
        foundUnwritable = False
        for page in range(self.minAddr, self.maxAddr + self.maxLen, 0x1000):
            mapping = getMapping(page, self.state)
            if mapping == -1:
                self.issues.append(PossibleUnmapped(page)) 
                foundUnmapped = True
            elif not hasPerm(mapping, 'w'):
                self.issues.append(PossibleReadonly(page))
                foundUnwritable = True

            if foundUnmapped and foundUnwritable:
                break
            



            
    
    def __repr__(self):
        return "<Memory write at RIP = " + hex(self.rip) + ">"


    def __eq__(self, other):
        #This is mainly for checking duplicates, and might cause problems later, remember to check on this if something starts acting fishy
        #TODO: Maybe this could be replaced with self.state == other.state?
        if self.minAddr == other.minAddr and self.maxAddr == other.maxAddr and self.minLen == other.minLen and self.maxLen == other.maxLen and self.symData == other.symData and self.symLen == other.symLen and self.symAddr == other.symAddr and self.rip == other.rip  and self.len == other.len:
            return True
        return False;


    def score(self):
        points = 0
        for issue in self.issues:
            points += issue.severity
        return points

    def debugPrint(self):

        #TODO: This needs to be updated

        print(f"MEMORY WRITE AT {hex(self.rip)}:")
        print(f"\tMemory details:")
        print(f"\t\tStart: {hex(self.minAddr)}")
        print(f"\t\tEnd:   {hex(self.maxAddr)}")
        print(f"\t\tSize:  {hex(self.len)}")
        print(f"\t\tSymbolic data: {self.symData}")
        print(f"\tState details:")
        print(self.state.solver.constraints)

    def couldContain(self, addr, length):
        constraint = claripy.And(self.minAddr <= addr + length, self.maxAddr + self.maxLen >= addr)
        
        result = self.state.solver.satisfiable(extra_constraints=[constraint])

        if result:
            print(f"{self.state.inspect.mem_write_address} could be between {hex(addr)} and {hex(addr + length)}")

        return result


def write_bp(state):
    
    if not shouldTrack(state):
        return


    write = MemoryWrite(state, "write")
    #TODO: Set up an actual system for logs & debug prints
    #write.debugPrint()
    #disasm(state)
    
    #Tracked memory writes are stored in state globals, and then all put together after the program is explored.
    state.globals["writes"].append(write)


def memcpy_bp(state):
    write = MemoryWrite(state, "memcpy")
    #TODO: implement shouldTrack for memcpy calls

    state.globals["writes"].append(write)






def find_writes(proj, tableCallback):
    memcpy_addr = proj.loader.find_symbol('memcpy').rebased_addr
    print(f"Memcpy: {hex(memcpy_addr)}")
    entry_state = proj.factory.entry_state()
    entry_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=write_bp)
    entry_state.inspect.b('call', when=angr.BP_BEFORE, action=memcpy_bp)
    entry_state.globals["writes"] = []
    simgr = proj.factory.simgr(entry_state);

    exploreThread = threading.Thread(target=simgr.explore)
    exploreThread.start()


    writes = []
    while exploreThread.is_alive():
        time.sleep(0.5);
        for state in (simgr.active + simgr.deadended + simgr.found + simgr.unconstrained):
            #TODO: make sure simgr.deadened is actually what we want, and that we're not missing any states that don't end up there
            for write in state.globals["writes"]:
                if write not in writes:
                    writes.append(write)
        tableCallback(writes)
    print(writes)
    return writes
