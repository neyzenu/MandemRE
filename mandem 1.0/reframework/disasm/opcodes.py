"""
x86-64 Opcode Metadata Tables
"""

from dataclasses import dataclass
from enum import IntEnum, auto
from typing import Optional, Dict, Tuple


class FlowType(IntEnum):
    """Control flow semantics."""
    SEQUENTIAL = auto()
    COND_BRANCH = auto()
    UNCOND_BRANCH = auto()
    CALL = auto()
    RET = auto()
    TRAP = auto()
    UNKNOWN = auto()


class OperandEncoding(IntEnum):
    """How operands are encoded."""
    NONE = 0
    MODRM_RM = auto()
    MODRM_REG = auto()
    MODRM_BOTH = auto()
    OPCODE_REG = auto()
    IMM8 = auto()
    IMM16 = auto()
    IMM32 = auto()
    IMM64 = auto()
    IMMZ = auto()
    REL8 = auto()
    REL32 = auto()
    MOFFS = auto()
    IMPLICIT = auto()


class OperandOrder(IntEnum):
    """Order of operands."""
    RM_REG = 0
    REG_RM = 1


@dataclass(frozen=True)
class OpcodeEntry:
    """Metadata for a single opcode."""
    mnemonic: str
    has_modrm: bool = False
    encoding: OperandEncoding = OperandEncoding.NONE
    op_order: OperandOrder = OperandOrder.RM_REG
    op_size: int = 0
    imm_size: int = 0
    flow: FlowType = FlowType.SEQUENTIAL
    is_group: bool = False


# =============================================================================
# Opcode Maps
# =============================================================================

ONEBYTE_MAP: Dict[int, OpcodeEntry] = {}
TWOBYTE_MAP: Dict[int, OpcodeEntry] = {}


def _add(opcode: int, entry: OpcodeEntry) -> None:
    """Add entry to one-byte opcode map."""
    ONEBYTE_MAP[opcode] = entry


def _add2(opcode: int, entry: OpcodeEntry) -> None:
    """Add entry to two-byte opcode map (0F XX)."""
    TWOBYTE_MAP[opcode] = entry


# =============================================================================
# One-Byte Opcodes
# =============================================================================

# 00-05: ADD
_add(0x00, OpcodeEntry('add', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_size=8))
_add(0x01, OpcodeEntry('add', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH))
_add(0x02, OpcodeEntry('add', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM, op_size=8))
_add(0x03, OpcodeEntry('add', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))
_add(0x04, OpcodeEntry('add', has_modrm=False, encoding=OperandEncoding.IMM8, op_size=8))
_add(0x05, OpcodeEntry('add', has_modrm=False, encoding=OperandEncoding.IMMZ))

# 08-0D: OR
_add(0x08, OpcodeEntry('or', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_size=8))
_add(0x09, OpcodeEntry('or', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH))
_add(0x0A, OpcodeEntry('or', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM, op_size=8))
_add(0x0B, OpcodeEntry('or', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))
_add(0x0C, OpcodeEntry('or', has_modrm=False, encoding=OperandEncoding.IMM8, op_size=8))
_add(0x0D, OpcodeEntry('or', has_modrm=False, encoding=OperandEncoding.IMMZ))

# 0F: Two-byte escape
_add(0x0F, OpcodeEntry('escape', has_modrm=False))

# 10-15: ADC
_add(0x10, OpcodeEntry('adc', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_size=8))
_add(0x11, OpcodeEntry('adc', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH))
_add(0x12, OpcodeEntry('adc', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM, op_size=8))
_add(0x13, OpcodeEntry('adc', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))
_add(0x14, OpcodeEntry('adc', has_modrm=False, encoding=OperandEncoding.IMM8, op_size=8))
_add(0x15, OpcodeEntry('adc', has_modrm=False, encoding=OperandEncoding.IMMZ))

# 18-1D: SBB
_add(0x18, OpcodeEntry('sbb', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_size=8))
_add(0x19, OpcodeEntry('sbb', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH))
_add(0x1A, OpcodeEntry('sbb', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM, op_size=8))
_add(0x1B, OpcodeEntry('sbb', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))
_add(0x1C, OpcodeEntry('sbb', has_modrm=False, encoding=OperandEncoding.IMM8, op_size=8))
_add(0x1D, OpcodeEntry('sbb', has_modrm=False, encoding=OperandEncoding.IMMZ))

# 20-25: AND
_add(0x20, OpcodeEntry('and', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_size=8))
_add(0x21, OpcodeEntry('and', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH))
_add(0x22, OpcodeEntry('and', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM, op_size=8))
_add(0x23, OpcodeEntry('and', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))
_add(0x24, OpcodeEntry('and', has_modrm=False, encoding=OperandEncoding.IMM8, op_size=8))
_add(0x25, OpcodeEntry('and', has_modrm=False, encoding=OperandEncoding.IMMZ))

# 26-27: Prefix/Invalid
_add(0x26, OpcodeEntry('prefix_es', has_modrm=False))
_add(0x27, OpcodeEntry('daa', has_modrm=False, flow=FlowType.TRAP))

# 28-2D: SUB
_add(0x28, OpcodeEntry('sub', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_size=8))
_add(0x29, OpcodeEntry('sub', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH))
_add(0x2A, OpcodeEntry('sub', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM, op_size=8))
_add(0x2B, OpcodeEntry('sub', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))
_add(0x2C, OpcodeEntry('sub', has_modrm=False, encoding=OperandEncoding.IMM8, op_size=8))
_add(0x2D, OpcodeEntry('sub', has_modrm=False, encoding=OperandEncoding.IMMZ))

# 2E-2F: Prefix/Invalid
_add(0x2E, OpcodeEntry('prefix_cs', has_modrm=False))
_add(0x2F, OpcodeEntry('das', has_modrm=False, flow=FlowType.TRAP))

# 30-35: XOR
_add(0x30, OpcodeEntry('xor', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_size=8))
_add(0x31, OpcodeEntry('xor', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH))
_add(0x32, OpcodeEntry('xor', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM, op_size=8))
_add(0x33, OpcodeEntry('xor', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))
_add(0x34, OpcodeEntry('xor', has_modrm=False, encoding=OperandEncoding.IMM8, op_size=8))
_add(0x35, OpcodeEntry('xor', has_modrm=False, encoding=OperandEncoding.IMMZ))

# 36-37: Prefix/Invalid
_add(0x36, OpcodeEntry('prefix_ss', has_modrm=False))
_add(0x37, OpcodeEntry('aaa', has_modrm=False, flow=FlowType.TRAP))

# 38-3D: CMP
_add(0x38, OpcodeEntry('cmp', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_size=8))
_add(0x39, OpcodeEntry('cmp', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH))
_add(0x3A, OpcodeEntry('cmp', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM, op_size=8))
_add(0x3B, OpcodeEntry('cmp', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))
_add(0x3C, OpcodeEntry('cmp', has_modrm=False, encoding=OperandEncoding.IMM8, op_size=8))
_add(0x3D, OpcodeEntry('cmp', has_modrm=False, encoding=OperandEncoding.IMMZ))

# 3E-3F: Prefix/Invalid
_add(0x3E, OpcodeEntry('prefix_ds', has_modrm=False))
_add(0x3F, OpcodeEntry('aas', has_modrm=False, flow=FlowType.TRAP))

# 40-4F: REX prefixes (in 64-bit mode)
for i in range(0x40, 0x50):
    _add(i, OpcodeEntry('rex', has_modrm=False))

# 50-57: PUSH r64
for i in range(8):
    _add(0x50 + i, OpcodeEntry('push', has_modrm=False, encoding=OperandEncoding.OPCODE_REG, op_size=64))

# 58-5F: POP r64
for i in range(8):
    _add(0x58 + i, OpcodeEntry('pop', has_modrm=False, encoding=OperandEncoding.OPCODE_REG, op_size=64))

# 63: MOVSXD
_add(0x63, OpcodeEntry('movsxd', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))

# 68: PUSH imm32
_add(0x68, OpcodeEntry('push', has_modrm=False, encoding=OperandEncoding.IMMZ, op_size=64))

# 69: IMUL r, r/m, imm
_add(0x69, OpcodeEntry('imul', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM, imm_size=-1))

# 6A: PUSH imm8
_add(0x6A, OpcodeEntry('push', has_modrm=False, encoding=OperandEncoding.IMM8, op_size=64))

# 6B: IMUL r, r/m, imm8
_add(0x6B, OpcodeEntry('imul', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM, imm_size=8))

# 70-7F: Jcc rel8
JCC_MNEMONICS = ['jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja',
                 'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg']
for i in range(16):
    _add(0x70 + i, OpcodeEntry(JCC_MNEMONICS[i], has_modrm=False, encoding=OperandEncoding.REL8, flow=FlowType.COND_BRANCH))

# 80-83: Group 1
_add(0x80, OpcodeEntry('grp1', has_modrm=True, encoding=OperandEncoding.MODRM_RM, op_size=8, imm_size=8, is_group=True))
_add(0x81, OpcodeEntry('grp1', has_modrm=True, encoding=OperandEncoding.MODRM_RM, imm_size=-1, is_group=True))
_add(0x83, OpcodeEntry('grp1', has_modrm=True, encoding=OperandEncoding.MODRM_RM, imm_size=8, is_group=True))

# 84-85: TEST
_add(0x84, OpcodeEntry('test', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_size=8))
_add(0x85, OpcodeEntry('test', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH))

# 86-87: XCHG
_add(0x86, OpcodeEntry('xchg', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_size=8))
_add(0x87, OpcodeEntry('xchg', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH))

# 88-8B: MOV
_add(0x88, OpcodeEntry('mov', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_size=8))
_add(0x89, OpcodeEntry('mov', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH))
_add(0x8A, OpcodeEntry('mov', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM, op_size=8))
_add(0x8B, OpcodeEntry('mov', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))

# 8D: LEA
_add(0x8D, OpcodeEntry('lea', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))

# 8F: POP r/m
_add(0x8F, OpcodeEntry('pop', has_modrm=True, encoding=OperandEncoding.MODRM_RM, op_size=64))

# 90: NOP
_add(0x90, OpcodeEntry('nop', has_modrm=False))

# 91-97: XCHG rax, r
for i in range(1, 8):
    _add(0x90 + i, OpcodeEntry('xchg', has_modrm=False, encoding=OperandEncoding.OPCODE_REG))

# 98-99: CBW/CWD family
_add(0x98, OpcodeEntry('cdqe', has_modrm=False))
_add(0x99, OpcodeEntry('cqo', has_modrm=False))

# 9C-9D: PUSHF/POPF
_add(0x9C, OpcodeEntry('pushfq', has_modrm=False))
_add(0x9D, OpcodeEntry('popfq', has_modrm=False))

# A0-A3: MOV moffs
_add(0xA0, OpcodeEntry('mov', has_modrm=False, encoding=OperandEncoding.MOFFS, op_size=8))
_add(0xA1, OpcodeEntry('mov', has_modrm=False, encoding=OperandEncoding.MOFFS))
_add(0xA2, OpcodeEntry('mov', has_modrm=False, encoding=OperandEncoding.MOFFS, op_size=8))
_add(0xA3, OpcodeEntry('mov', has_modrm=False, encoding=OperandEncoding.MOFFS))

# A8-A9: TEST AL/AX, imm
_add(0xA8, OpcodeEntry('test', has_modrm=False, encoding=OperandEncoding.IMM8, op_size=8))
_add(0xA9, OpcodeEntry('test', has_modrm=False, encoding=OperandEncoding.IMMZ))

# B0-B7: MOV r8, imm8
for i in range(8):
    _add(0xB0 + i, OpcodeEntry('mov', has_modrm=False, encoding=OperandEncoding.OPCODE_REG, op_size=8, imm_size=8))

# B8-BF: MOV r64, imm64
for i in range(8):
    _add(0xB8 + i, OpcodeEntry('mov', has_modrm=False, encoding=OperandEncoding.OPCODE_REG, imm_size=-1))

# C0-C1: Group 2 (shifts)
_add(0xC0, OpcodeEntry('grp2', has_modrm=True, encoding=OperandEncoding.MODRM_RM, op_size=8, imm_size=8, is_group=True))
_add(0xC1, OpcodeEntry('grp2', has_modrm=True, encoding=OperandEncoding.MODRM_RM, imm_size=8, is_group=True))

# C2-C3: RET
_add(0xC2, OpcodeEntry('ret', has_modrm=False, encoding=OperandEncoding.IMM16, flow=FlowType.RET))
_add(0xC3, OpcodeEntry('ret', has_modrm=False, flow=FlowType.RET))

# C6-C7: MOV r/m, imm
_add(0xC6, OpcodeEntry('mov', has_modrm=True, encoding=OperandEncoding.MODRM_RM, op_size=8, imm_size=8))
_add(0xC7, OpcodeEntry('mov', has_modrm=True, encoding=OperandEncoding.MODRM_RM, imm_size=-1))

# C9: LEAVE
_add(0xC9, OpcodeEntry('leave', has_modrm=False))

# CC-CD: INT
_add(0xCC, OpcodeEntry('int3', has_modrm=False, flow=FlowType.TRAP))
_add(0xCD, OpcodeEntry('int', has_modrm=False, encoding=OperandEncoding.IMM8, flow=FlowType.TRAP))

# D0-D3: Group 2 by 1/CL
_add(0xD0, OpcodeEntry('grp2', has_modrm=True, encoding=OperandEncoding.MODRM_RM, op_size=8, is_group=True))
_add(0xD1, OpcodeEntry('grp2', has_modrm=True, encoding=OperandEncoding.MODRM_RM, is_group=True))
_add(0xD2, OpcodeEntry('grp2', has_modrm=True, encoding=OperandEncoding.MODRM_RM, op_size=8, is_group=True))
_add(0xD3, OpcodeEntry('grp2', has_modrm=True, encoding=OperandEncoding.MODRM_RM, is_group=True))

# E0-E3: Loop/JCXZ
_add(0xE0, OpcodeEntry('loopne', has_modrm=False, encoding=OperandEncoding.REL8, flow=FlowType.COND_BRANCH))
_add(0xE1, OpcodeEntry('loope', has_modrm=False, encoding=OperandEncoding.REL8, flow=FlowType.COND_BRANCH))
_add(0xE2, OpcodeEntry('loop', has_modrm=False, encoding=OperandEncoding.REL8, flow=FlowType.COND_BRANCH))
_add(0xE3, OpcodeEntry('jrcxz', has_modrm=False, encoding=OperandEncoding.REL8, flow=FlowType.COND_BRANCH))

# E8-EB: CALL/JMP
_add(0xE8, OpcodeEntry('call', has_modrm=False, encoding=OperandEncoding.REL32, flow=FlowType.CALL))
_add(0xE9, OpcodeEntry('jmp', has_modrm=False, encoding=OperandEncoding.REL32, flow=FlowType.UNCOND_BRANCH))
_add(0xEB, OpcodeEntry('jmp', has_modrm=False, encoding=OperandEncoding.REL8, flow=FlowType.UNCOND_BRANCH))

# F0-F3: Prefixes
_add(0xF0, OpcodeEntry('lock', has_modrm=False))
_add(0xF2, OpcodeEntry('repne', has_modrm=False))
_add(0xF3, OpcodeEntry('rep', has_modrm=False))

# F4: HLT
_add(0xF4, OpcodeEntry('hlt', has_modrm=False, flow=FlowType.TRAP))

# F6-F7: Group 3
_add(0xF6, OpcodeEntry('grp3', has_modrm=True, encoding=OperandEncoding.MODRM_RM, op_size=8, is_group=True))
_add(0xF7, OpcodeEntry('grp3', has_modrm=True, encoding=OperandEncoding.MODRM_RM, is_group=True))

# F8-FD: Flag ops
_add(0xF8, OpcodeEntry('clc', has_modrm=False))
_add(0xF9, OpcodeEntry('stc', has_modrm=False))
_add(0xFA, OpcodeEntry('cli', has_modrm=False))
_add(0xFB, OpcodeEntry('sti', has_modrm=False))
_add(0xFC, OpcodeEntry('cld', has_modrm=False))
_add(0xFD, OpcodeEntry('std', has_modrm=False))

# FE-FF: Group 4/5
_add(0xFE, OpcodeEntry('grp4', has_modrm=True, encoding=OperandEncoding.MODRM_RM, op_size=8, is_group=True))
_add(0xFF, OpcodeEntry('grp5', has_modrm=True, encoding=OperandEncoding.MODRM_RM, is_group=True))


# =============================================================================
# Two-Byte Opcodes (0F XX)
# =============================================================================

# 0F 05: SYSCALL
_add2(0x05, OpcodeEntry('syscall', has_modrm=False))

# 0F 0B: UD2
_add2(0x0B, OpcodeEntry('ud2', has_modrm=False, flow=FlowType.TRAP))

# 0F 1E: ENDBR (with F3 prefix)
_add2(0x1E, OpcodeEntry('nop', has_modrm=True, encoding=OperandEncoding.MODRM_RM))

# 0F 1F: Multi-byte NOP
_add2(0x1F, OpcodeEntry('nop', has_modrm=True, encoding=OperandEncoding.MODRM_RM))

# 0F 31: RDTSC
_add2(0x31, OpcodeEntry('rdtsc', has_modrm=False))

# 0F 40-4F: CMOVcc
CMOVCC = ['cmovo', 'cmovno', 'cmovb', 'cmovae', 'cmove', 'cmovne', 'cmovbe', 'cmova',
          'cmovs', 'cmovns', 'cmovp', 'cmovnp', 'cmovl', 'cmovge', 'cmovle', 'cmovg']
for i in range(16):
    _add2(0x40 + i, OpcodeEntry(CMOVCC[i], has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))

# 0F 80-8F: Jcc rel32
for i in range(16):
    _add2(0x80 + i, OpcodeEntry(JCC_MNEMONICS[i], has_modrm=False, encoding=OperandEncoding.REL32, flow=FlowType.COND_BRANCH))

# 0F 90-9F: SETcc
SETCC = ['seto', 'setno', 'setb', 'setae', 'sete', 'setne', 'setbe', 'seta',
         'sets', 'setns', 'setp', 'setnp', 'setl', 'setge', 'setle', 'setg']
for i in range(16):
    _add2(0x90 + i, OpcodeEntry(SETCC[i], has_modrm=True, encoding=OperandEncoding.MODRM_RM, op_size=8))

# 0F A2: CPUID
_add2(0xA2, OpcodeEntry('cpuid', has_modrm=False))

# 0F AF: IMUL
_add2(0xAF, OpcodeEntry('imul', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))

# 0F B6-B7: MOVZX
_add2(0xB6, OpcodeEntry('movzx', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))
_add2(0xB7, OpcodeEntry('movzx', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))

# 0F BE-BF: MOVSX
_add2(0xBE, OpcodeEntry('movsx', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))
_add2(0xBF, OpcodeEntry('movsx', has_modrm=True, encoding=OperandEncoding.MODRM_BOTH, op_order=OperandOrder.REG_RM))

# 0F C8-CF: BSWAP
for i in range(8):
    _add2(0xC8 + i, OpcodeEntry('bswap', has_modrm=False, encoding=OperandEncoding.OPCODE_REG))


# =============================================================================
# Group Mnemonics
# =============================================================================

GROUP1_MNEMONICS = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
GROUP2_MNEMONICS = ['rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'sal', 'sar']
GROUP3_MNEMONICS = ['test', 'test', 'not', 'neg', 'mul', 'imul', 'div', 'idiv']
GROUP4_MNEMONICS = ['inc', 'dec', None, None, None, None, None, None]
GROUP5_MNEMONICS = ['inc', 'dec', 'call', 'call', 'jmp', 'jmp', 'push', None]
GROUP5_FLOW = [FlowType.SEQUENTIAL, FlowType.SEQUENTIAL, FlowType.CALL, FlowType.CALL,
               FlowType.UNCOND_BRANCH, FlowType.UNCOND_BRANCH, FlowType.SEQUENTIAL, FlowType.TRAP]


def get_group_info(group_name: str, reg: int) -> Tuple[Optional[str], FlowType]:
    """Get mnemonic and flow type for a group instruction."""
    if group_name == 'grp1':
        return GROUP1_MNEMONICS[reg], FlowType.SEQUENTIAL
    elif group_name == 'grp2':
        return GROUP2_MNEMONICS[reg], FlowType.SEQUENTIAL
    elif group_name == 'grp3':
        return GROUP3_MNEMONICS[reg], FlowType.SEQUENTIAL
    elif group_name == 'grp4':
        mnem = GROUP4_MNEMONICS[reg]
        return mnem, FlowType.SEQUENTIAL if mnem else FlowType.TRAP
    elif group_name == 'grp5':
        return GROUP5_MNEMONICS[reg], GROUP5_FLOW[reg]
    return None, FlowType.TRAP


def get_opcode_entry(opcode: int, is_twobyte: bool = False) -> Optional[OpcodeEntry]:
    """Look up opcode metadata."""
    if is_twobyte:
        return TWOBYTE_MAP.get(opcode)
    return ONEBYTE_MAP.get(opcode)