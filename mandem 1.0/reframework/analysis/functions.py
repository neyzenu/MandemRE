"""
Function Detection

MINIMAL BUT CORRECT implementation:
1. Entry point is a function
2. CALL targets are functions
3. Function boundary = recursive descent until RET

No heuristics stacking. No prologue detection.
Simple, correct, verifiable.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from enum import IntEnum, auto

from ..loader.binary import Binary
from ..disasm.decoder import X86Decoder
from ..disasm.instruction import Instruction, FlowType
from .cfg import CFGBuilder, CFG


class FunctionSource(IntEnum):
    """How function was discovered."""
    ENTRY_POINT = auto()
    SYMBOL = auto()
    CALL_TARGET = auto()


@dataclass
class Function:
    """A discovered function."""
    address: int
    name: str = ""
    size: int = 0
    end_address: int = 0
    source: FunctionSource = FunctionSource.CALL_TARGET
    
    cfg: Optional[CFG] = None
    calls: Set[int] = field(default_factory=set)
    called_by: Set[int] = field(default_factory=set)
    
    is_leaf: bool = True
    is_noreturn: bool = False
    
    def __repr__(self) -> str:
        name = self.name or f"sub_{self.address:x}"
        return f"Function({name}, 0x{self.address:x})"


class FunctionAnalyzer:
    """
    Discovers functions using a simple, correct algorithm:
    
    1. Start with known entry points (binary entry, symbols)
    2. Scan for CALL instructions
    3. Build CFG for each function
    4. Extract call targets as new functions
    
    No prologue heuristics. No stack analysis.
    """
    
    def __init__(self, binary: Binary):
        self.binary = binary
        self.decoder = X86Decoder(mode=binary.bits)
        self.cfg_builder = CFGBuilder(binary, self.decoder)
        self.functions: Dict[int, Function] = {}
    
    def analyze(self) -> Dict[int, Function]:
        """
        Run function analysis.
        
        Returns:
            Dict mapping address to Function
        """
        # Phase 1: Collect seeds
        seeds: Set[int] = set()
        
        # Entry point
        if self.binary.entry_point:
            seeds.add(self.binary.entry_point)
            self.functions[self.binary.entry_point] = Function(
                address=self.binary.entry_point,
                name="_start",
                source=FunctionSource.ENTRY_POINT
            )
        
        # Symbols
        for sym in self.binary.symbols:
            if sym.is_function() and sym.value and sym.section_index != 0:
                if self.binary.is_executable_addr(sym.value):
                    seeds.add(sym.value)
                    if sym.value not in self.functions:
                        self.functions[sym.value] = Function(
                            address=sym.value,
                            name=sym.name,
                            source=FunctionSource.SYMBOL
                        )
        
        # Phase 2: Process functions and discover call targets
        processed: Set[int] = set()
        worklist = list(seeds)
        
        while worklist:
            addr = worklist.pop(0)
            
            if addr in processed:
                continue
            processed.add(addr)
            
            if addr not in self.functions:
                self.functions[addr] = Function(
                    address=addr,
                    name=f"sub_{addr:x}",
                    source=FunctionSource.CALL_TARGET
                )
            
            func = self.functions[addr]
            
            # Build CFG
            try:
                func.cfg = self.cfg_builder.build(addr, func.name)
                
                # Calculate size
                if func.cfg.blocks:
                    min_addr = min(b.address for b in func.cfg.blocks.values())
                    max_addr = max(b.end_address for b in func.cfg.blocks.values())
                    func.size = max_addr - min_addr
                    func.end_address = max_addr
                
                # Extract call targets
                for block in func.cfg.blocks.values():
                    for insn in block.instructions:
                        if insn.flow_type == FlowType.CALL and insn.branch_target:
                            target = insn.branch_target
                            func.calls.add(target)
                            func.is_leaf = False
                            
                            if target not in processed and self.binary.is_executable_addr(target):
                                worklist.append(target)
                
                # Check noreturn
                func.is_noreturn = len(func.cfg.get_block(addr).successors if func.cfg.get_block(addr) else []) == 0
                
            except Exception as e:
                # Failed to analyze - skip
                pass
        
        # Phase 3: Build call graph
        for func in self.functions.values():
            for target in func.calls:
                if target in self.functions:
                    self.functions[target].called_by.add(func.address)
        
        return self.functions
    
    def print_functions(self) -> None:
        """Print function list."""
        print(f"\n{'Address':<18} {'Size':<8} {'Source':<12} {'Name'}")
        print("=" * 60)
        
        for addr in sorted(self.functions.keys()):
            func = self.functions[addr]
            print(f"0x{addr:016x} {func.size:<8} {func.source.name:<12} {func.name}")
        
        print(f"\nTotal: {len(self.functions)} functions")
