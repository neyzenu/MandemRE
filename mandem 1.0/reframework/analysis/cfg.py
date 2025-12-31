"""
Control Flow Graph Construction
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from enum import IntEnum, auto

from ..disasm.instruction import Instruction
from ..disasm.opcodes import FlowType
from ..disasm.decoder import X86Decoder


class EdgeType(IntEnum):
    """Type of CFG edge."""
    FALL_THROUGH = auto()
    UNCONDITIONAL = auto()
    CONDITIONAL_TRUE = auto()
    CONDITIONAL_FALSE = auto()


@dataclass
class Edge:
    """A control flow edge."""
    source: int
    target: int
    edge_type: EdgeType


@dataclass
class BasicBlock:
    """A basic block in the CFG."""
    address: int
    end_address: int = 0
    instructions: List[Instruction] = field(default_factory=list)
    predecessors: Set[int] = field(default_factory=set)
    successors: Set[int] = field(default_factory=set)
    is_entry: bool = False
    is_exit: bool = False
    
    @property
    def terminator(self) -> Optional[Instruction]:
        return self.instructions[-1] if self.instructions else None


@dataclass
class CFG:
    """Control Flow Graph."""
    entry: int
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    name: str = ""


class CFGBuilder:
    """Builds CFGs using recursive descent."""
    
    def __init__(self, binary, decoder: X86Decoder = None):
        self.binary = binary
        self.decoder = decoder or X86Decoder(mode=getattr(binary, 'bits', 64))
    
    def build(self, entry: int, name: str = "") -> CFG:
        """Build CFG from entry point."""
        cfg = CFG(entry=entry, name=name)
        
        instructions: Dict[int, Instruction] = {}
        block_starts: Set[int] = {entry}
        worklist = [entry]
        visited = set()
        
        # Phase 1: Discover instructions
        while worklist:
            addr = worklist.pop()
            if addr in visited:
                continue
            if not self.binary.is_executable_addr(addr):
                continue
            
            visited.add(addr)
            
            data = self.binary.read_bytes_at_vaddr(addr, 15)
            if not data:
                continue
            
            insn = self.decoder.decode(data, 0, addr)
            if not insn.valid:
                continue
            
            instructions[addr] = insn
            
            for succ in insn.get_successors():
                if succ not in visited and self.binary.is_executable_addr(succ):
                    worklist.append(succ)
                    block_starts.add(succ)
            
            if insn.flow_type == FlowType.SEQUENTIAL:
                next_addr = insn.next_address
                if next_addr not in visited and self.binary.is_executable_addr(next_addr):
                    worklist.append(next_addr)
        
        # Phase 2: Build blocks
        sorted_starts = sorted(block_starts)
        for i, start in enumerate(sorted_starts):
            if start not in instructions:
                continue
            
            block = BasicBlock(address=start, is_entry=(start == entry))
            next_start = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else float('inf')
            
            current = start
            while current < next_start and current in instructions:
                insn = instructions[current]
                block.instructions.append(insn)
                block.end_address = insn.next_address
                
                if insn.flow_type != FlowType.SEQUENTIAL:
                    break
                current = insn.next_address
            
            if block.instructions:
                cfg.blocks[start] = block
                term = block.terminator
                if term and term.flow_type in (FlowType.RET, FlowType.TRAP):
                    block.is_exit = True
        
        # Phase 3: Create edges
        for block in cfg.blocks.values():
            term = block.terminator
            if not term:
                continue
            
            for succ in term.get_successors():
                if succ in cfg.blocks:
                    block.successors.add(succ)
                    cfg.blocks[succ].predecessors.add(block.address)
                    
                    if term.flow_type == FlowType.UNCOND_BRANCH:
                        edge_type = EdgeType.UNCONDITIONAL
                    elif term.flow_type == FlowType.COND_BRANCH:
                        edge_type = EdgeType.CONDITIONAL_TRUE if succ == term.branch_target else EdgeType.CONDITIONAL_FALSE
                    else:
                        edge_type = EdgeType.FALL_THROUGH
                    
                    cfg.edges.append(Edge(block.address, succ, edge_type))
        
        return cfg
    
    def print_cfg(self, cfg: CFG) -> None:
        """Print CFG for debugging."""
        print(f"\nCFG: {cfg.name or hex(cfg.entry)}")
        print(f"Blocks: {len(cfg.blocks)}, Edges: {len(cfg.edges)}")
        
        for addr in sorted(cfg.blocks.keys()):
            block = cfg.blocks[addr]
            flags = []
            if block.is_entry:
                flags.append("ENTRY")
            if block.is_exit:
                flags.append("EXIT")
            
            print(f"\nBlock 0x{addr:x} {' '.join(flags)}")
            for insn in block.instructions:
                print(f"  {insn.format_full()}")


# Alias for backwards compatibility
ControlFlowAnalyzer = CFGBuilder
