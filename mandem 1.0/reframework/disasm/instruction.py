"""
Instruction Representation
"""

from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import List, Optional

# Import FlowType from opcodes
from .opcodes import FlowType


class OperandType(IntEnum):
    """Type of instruction operand."""
    NONE = 0
    REGISTER = auto()
    IMMEDIATE = auto()
    MEMORY = auto()
    RELATIVE = auto()


class RegisterClass(IntEnum):
    """Register class."""
    NONE = 0
    GPR = auto()
    SEGMENT = auto()
    RIP = auto()


@dataclass(frozen=True)
class Register:
    """Register descriptor."""
    index: int
    size: int
    reg_class: RegisterClass = RegisterClass.GPR
    high_byte: bool = False
    
    def __str__(self) -> str:
        return get_register_name(self)


@dataclass
class MemoryOperand:
    """Memory addressing descriptor."""
    base: Optional[Register] = None
    index: Optional[Register] = None
    scale: int = 1
    displacement: int = 0
    segment: Optional[Register] = None
    size: int = 0
    rip_relative: bool = False
    absolute_address: Optional[int] = None
    
    def __str__(self) -> str:
        return format_memory_operand(self)


@dataclass
class Operand:
    """Universal operand container."""
    type: OperandType = OperandType.NONE
    size: int = 0
    reg: Optional[Register] = None
    mem: Optional[MemoryOperand] = None
    imm: int = 0
    rel_offset: int = 0
    absolute_target: int = 0
    
    def __str__(self) -> str:
        if self.type == OperandType.REGISTER and self.reg:
            return str(self.reg)
        elif self.type == OperandType.IMMEDIATE:
            return format_immediate(self.imm)
        elif self.type == OperandType.MEMORY and self.mem:
            return str(self.mem)
        elif self.type == OperandType.RELATIVE:
            return f"0x{self.absolute_target:x}"
        return ""


@dataclass
class Instruction:
    """Complete decoded instruction."""
    address: int = 0
    size: int = 0
    raw_bytes: bytes = b''
    mnemonic: str = ""
    operands: List[Operand] = field(default_factory=list)
    prefix_lock: bool = False
    prefix_rep: bool = False
    prefix_repne: bool = False
    prefix_segment: Optional[Register] = None
    flow_type: FlowType = FlowType.SEQUENTIAL
    branch_target: Optional[int] = None
    valid: bool = True
    decode_error: str = ""
    
    @property
    def next_address(self) -> int:
        return self.address + self.size
    
    def get_successors(self) -> List[int]:
        """Get possible successor addresses."""
        if self.flow_type in (FlowType.RET, FlowType.TRAP):
            return []
        if self.flow_type == FlowType.UNCOND_BRANCH:
            return [self.branch_target] if self.branch_target else []
        if self.flow_type == FlowType.COND_BRANCH:
            succs = [self.next_address]
            if self.branch_target:
                succs.append(self.branch_target)
            return succs
        return [self.next_address]
    
    def __str__(self) -> str:
        prefix = ""
        if self.prefix_lock:
            prefix = "lock "
        elif self.prefix_rep:
            prefix = "rep "
        elif self.prefix_repne:
            prefix = "repne "
        ops = ", ".join(str(op) for op in self.operands if op.type != OperandType.NONE)
        return f"{prefix}{self.mnemonic} {ops}".strip()
    
    def format_full(self) -> str:
        hex_bytes = self.raw_bytes.hex()
        return f"0x{self.address:08x}:  {hex_bytes:<24}  {self}"


# Register name tables
GPR_NAMES_64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
GPR_NAMES_32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
                'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']
GPR_NAMES_16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
                'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']
GPR_NAMES_8 = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
               'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']
SEGMENT_NAMES = ['es', 'cs', 'ss', 'ds', 'fs', 'gs']


def get_register_name(reg: Register) -> str:
    if reg.reg_class == RegisterClass.GPR and reg.index < 16:
        if reg.size == 64:
            return GPR_NAMES_64[reg.index]
        elif reg.size == 32:
            return GPR_NAMES_32[reg.index]
        elif reg.size == 16:
            return GPR_NAMES_16[reg.index]
        elif reg.size == 8:
            return GPR_NAMES_8[reg.index]
    elif reg.reg_class == RegisterClass.SEGMENT and reg.index < 6:
        return SEGMENT_NAMES[reg.index]
    elif reg.reg_class == RegisterClass.RIP:
        return "rip"
    return f"reg{reg.index}"


def make_gpr(index: int, size: int, high_byte: bool = False) -> Register:
    return Register(index=index, size=size, reg_class=RegisterClass.GPR, high_byte=high_byte)


def make_segment(index: int) -> Register:
    return Register(index=index, size=16, reg_class=RegisterClass.SEGMENT)


def format_immediate(value: int) -> str:
    if value < 0:
        return f"-0x{-value:x}"
    return f"0x{value:x}"


def format_memory_operand(mem: MemoryOperand) -> str:
    size_names = {8: 'byte', 16: 'word', 32: 'dword', 64: 'qword'}
    prefix = size_names.get(mem.size, '')
    
    parts = []
    if mem.rip_relative:
        parts.append("rip")
    elif mem.base:
        parts.append(str(mem.base))
    
    if mem.index:
        idx_str = str(mem.index)
        if mem.scale > 1:
            idx_str += f"*{mem.scale}"
        parts.append(idx_str)
    
    if mem.displacement != 0 or not parts:
        if mem.displacement >= 0:
            parts.append(f"0x{mem.displacement:x}")
        else:
            parts.append(f"-0x{-mem.displacement:x}")
    
    inner = " + ".join(parts).replace(" + -", " - ")
    return f"{prefix} ptr [{inner}]".strip()
