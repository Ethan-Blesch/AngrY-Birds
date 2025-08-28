import angr
import claripy

class Issue:
        def __init__(self, description, severity):
                self.description = description
                self.severity = severity
        def __str__(self): 
                return self.description


class SavedRipOverwrite(Issue):
        def __init__(self, frame):
                super().__init__(f"Possible stack pointer overwrite for saved RBP/RIP at {hex(frame)}", 5)



class PossibleUnmapped(Issue):
        def __init__(self, addr):
                super().__init__(f"Possible unmapped memory access at {hex(addr)}", 2)


class PossibleReadonly(Issue):
        def __init__(self, addr):
                super().__init__(f"Possible write to readonly memory at {hex(addr)}", 2)


class ArbitraryWrite(Issue):
        def __init__(self):
                super().__init__("Arbitrary write", 100) 
