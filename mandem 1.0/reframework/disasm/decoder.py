"""
x86-64 Instruction Decoder
"""

import struct
from dataclasses import dataclass
from typing import Optional, List

from .instruction import (
    Instruction, Operand, OperandType, MemoryOperand,
    Register, RegisterClass, make_gpr, make_segment
)
from .opcodes import (
    OpcodeEntry, OperandEncoding, OperandOrder, FlowType,
    get_opcode_entry, get_group_info
)


@dataclass
class DecoderState:
    """Mutable state during decode."""
    data: bytes
    pos: int
    start_pos: int
    base_addr: int
    
    # Prefixes
    rex: int = 0
    rex_w: bool = False
    rex_r: bool = False
    rex_x: bool = False
    rex_b: bool = False
    has_rex: bool = False
    
    prefix_66: bool = False
    prefix_67: bool = False
    prefix_lock: bool = False
    prefix_rep: bool = False
    prefix_repne: bool = False
    segment_override: Optional[Register] = None
    
    # Computed sizes
    operand_size: int = 32
    address_size: int = 64
    
    # Opcode
    opcode: int = 0
    opcode2: int = 0
    is_twobyte: bool = False
    entry: Optional[OpcodeEntry] = None
    
    # MODRM
    modrm: int = 0
    modrm_mod: int = 0
    modrm_reg: int = 0
    modrm_rm: int = 0
    has_modrm: bool = False
    
    # SIB
    sib: int = 0
    sib_scale: int = 1
    sib_index: int = 0
    sib_base: int = 0
    has_sib: bool = False
    
    # Displacement
    displacement: int = 0
    disp_size: int = 0
    rip_relative: bool = False
    
    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise IndexError("End of data")
        b = self.data[self.pos]
        self.pos += 1
        return b
    
    def peek_byte(self) -> int:
        if self.pos >= len(self.data):
            raise IndexError("End of data")
        return self.data[self.pos]
    
    def read_signed(self, size: int) -> int:
        if self.pos + size > len(self.data):
            raise IndexError("End of data")
        fmt = {1: '<b', 2: '<h', 4: '<i', 8: '<q'}[size]
        val = struct.unpack(fmt, self.data[self.pos:self.pos + size])[0]
        self.pos += size
        return val
    
    def read_unsigned(self, size: int) -> int:
        if self.pos + size > len(self.data):
            raise IndexError("End of data")
        fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}[size]
        val = struct.unpack(fmt, self.data[self.pos:self.pos + size])[0]
        self.pos += size
        return val
    
    @property
    def bytes_consumed(self) -> int:
        return self.pos - self.start_pos
    
    @property
    def instruction_address(self) -> int:
        return self.base_addr


class X86Decoder:
    """x86-64 instruction decoder."""
    
    def __init__(self, mode: int = 64):
        if mode not in (32, 64):
            raise ValueError("Mode must be 32 or 64")
        self.mode = mode
    
    def decode(self, data: bytes, offset: int = 0, address: int = 0) -> Instruction:
        """Decode a single instruction."""
        if offset >= len(data):
            return self._make_invalid(address, b'', "No data")
        
        state = DecoderState(
            data=data,
            pos=offset,
            start_pos=offset,
            base_addr=address
        )
        
        try:
            # Stage 1: Parse prefixes
            self._parse_prefixes(state)
            
            # Stage 2: Compute sizes
            self._compute_sizes(state)
            
            # Stage 3: Parse opcode
            self._parse_opcode(state)
            
            if state.entry is None:
                raw = data[offset:state.pos]
                return self._make_invalid(address, raw, "Unknown opcode")
            
            # Stage 4: Parse MODRM if required
            if state.entry.has_modrm:
                self._parse_modrm(state)
            
            # Stage 5: Parse SIB if required
            if state.has_sib:
                self._parse_sib(state)
            
            # Stage 6: Parse displacement
            if state.disp_size > 0:
                state.displacement = state.read_signed(state.disp_size)
            
            # Stage 7: Build instruction
            return self._build_instruction(state)
            
        except (IndexError, struct.error) as e:
            raw = data[offset:min(offset + 15, len(data))]
            return self._make_invalid(address, raw, str(e))
    
    def decode_block(self, data: bytes, address: int, max_insns: int = 1000) -> List[Instruction]:
        """Decode a block of instructions."""
        instructions = []
        offset = 0
        
        while offset < len(data) and len(instructions) < max_insns:
            insn = self.decode(data, offset, address + offset)
            
            if not insn.valid or insn.size == 0:
                break
            
            instructions.append(insn)
            offset += insn.size
            
            if insn.flow_type in (FlowType.UNCOND_BRANCH, FlowType.RET, FlowType.TRAP):
                break
        
        return instructions
    
    def _make_invalid(self, address: int, raw: bytes, error: str) -> Instruction:
        return Instruction(
            address=address,
            size=max(1, len(raw)),
            raw_bytes=raw[:1] if raw else b'\x00',
            mnemonic='db',
            valid=False,
            decode_error=error,
            flow_type=FlowType.UNKNOWN
        )
    
    def _parse_prefixes(self, state: DecoderState) -> None:
        """Parse instruction prefixes."""
        while state.pos < len(state.data):
            b = state.peek_byte()
            
            if b == 0xF0:
                state.prefix_lock = True
                state.pos += 1
            elif b == 0xF2:
                state.prefix_repne = True
                state.prefix_rep = False
                state.pos += 1
            elif b == 0xF3:
                state.prefix_rep = True
                state.prefix_repne = False
                state.pos += 1
            elif b == 0x26:
                state.segment_override = make_segment(0)
                state.pos += 1
            elif b == 0x2E:
                state.segment_override = make_segment(1)
                state.pos += 1
            elif b == 0x36:
                state.segment_override = make_segment(2)
                state.pos += 1
            elif b == 0x3E:
                state.segment_override = make_segment(3)
                state.pos += 1
            elif b == 0x64:
                state.segment_override = make_segment(4)
                state.pos += 1
            elif b == 0x65:
                state.segment_override = make_segment(5)
                state.pos += 1
            elif b == 0x66:
                state.prefix_66 = True
                state.pos += 1
            elif b == 0x67:
                state.prefix_67 = True
                state.pos += 1
            elif self.mode == 64 and 0x40 <= b <= 0x4F:
                state.rex = b
                state.has_rex = True
                state.rex_w = bool(b & 0x08)
                state.rex_r = bool(b & 0x04)
                state.rex_x = bool(b & 0x02)
                state.rex_b = bool(b & 0x01)
                state.pos += 1
                break  # REX must be last prefix
            else:
                break
    
    def _compute_sizes(self, state: DecoderState) -> None:
        """Compute effective operand and address sizes."""
        if self.mode == 64:
            if state.rex_w:
                state.operand_size = 64
            elif state.prefix_66:
                state.operand_size = 16
            else:
                state.operand_size = 32
            state.address_size = 32 if state.prefix_67 else 64
        else:
            state.operand_size = 16 if state.prefix_66 else 32
            state.address_size = 16 if state.prefix_67 else 32
    
    def _parse_opcode(self, state: DecoderState) -> None:
        """Parse opcode and look up metadata."""
        state.opcode = state.read_byte()
        
        if state.opcode == 0x0F:
            state.is_twobyte = True
            state.opcode2 = state.read_byte()
            state.entry = get_opcode_entry(state.opcode2, is_twobyte=True)
        else:
            state.entry = get_opcode_entry(state.opcode, is_twobyte=False)
    
    def _parse_modrm(self, state: DecoderState) -> None:
        """
        Parse MODRM byte.
        
        MODRM layout:
        +-----+-----+-----+
        | mod | reg | r/m |
        | 7-6 | 5-3 | 2-0 |
        +-----+-----+-----+
        
        Key cases:
        - mod=11: r/m is register
        - mod=00, rm=101: RIP-relative (64-bit) with disp32
        - mod=00, rm=100: SIB follows, no displacement
        - mod=01, rm=100: SIB + disp8
        - mod=10, rm=100: SIB + disp32
        """
        state.modrm = state.read_byte()
        state.has_modrm = True
        
        state.modrm_mod = (state.modrm >> 6) & 0x03
        state.modrm_reg = (state.modrm >> 3) & 0x07
        state.modrm_rm = state.modrm & 0x07
        
        # Apply REX extensions to reg
        if state.rex_r:
            state.modrm_reg |= 0x08
        
        # Check for memory operand (mod != 11)
        if state.modrm_mod != 0x03:
            rm_3bit = state.modrm & 0x07  # Unextended for SIB/RIP check
            
            # Check for SIB byte (rm=100)
            if rm_3bit == 0x04:
                state.has_sib = True
            
            # Determine displacement size
            if state.modrm_mod == 0x00:
                if rm_3bit == 0x05:
                    # RIP-relative in 64-bit mode
                    state.disp_size = 4
                    state.rip_relative = (self.mode == 64)
                else:
                    state.disp_size = 0
            elif state.modrm_mod == 0x01:
                state.disp_size = 1
            elif state.modrm_mod == 0x02:
                state.disp_size = 4
        
        # Apply REX.B to r/m for register operands
        if state.rex_b:
            state.modrm_rm |= 0x08
    
    def _parse_sib(self, state: DecoderState) -> None:
        """
        Parse SIB byte.
        
        SIB layout:
        +-------+-------+------+
        | scale | index | base |
        |  7-6  |  5-3  | 2-0  |
        +-------+-------+------+
        
        Special cases:
        - index=100: no index register
        - base=101 with mod=00: disp32 only (no base)
        """
        state.sib = state.read_byte()
        
        state.sib_scale = 1 << ((state.sib >> 6) & 0x03)
        state.sib_index = (state.sib >> 3) & 0x07
        state.sib_base = state.sib & 0x07
        
        # Apply REX extensions
        if state.rex_x:
            state.sib_index |= 0x08
        if state.rex_b:
            state.sib_base |= 0x08
        
        # Check for base=101 with mod=00 (disp32, no base)
        base_3bit = state.sib & 0x07
        if base_3bit == 0x05 and state.modrm_mod == 0x00:
            state.disp_size = 4
    
    def _build_instruction(self, state: DecoderState) -> Instruction:
        """Build instruction from decoded state."""
        entry = state.entry
        
        # Handle group instructions
        mnemonic = entry.mnemonic
        flow_type = entry.flow
        
        if entry.is_group and state.has_modrm:
            reg_3bit = (state.modrm >> 3) & 0x07
            grp_mnem, grp_flow = get_group_info(mnemonic, reg_3bit)
            if grp_mnem:
                mnemonic = grp_mnem
                flow_type = grp_flow
            else:
                return self._make_invalid(
                    state.instruction_address,
                    state.data[state.start_pos:state.pos],
                    f"Invalid group reg={reg_3bit}"
                )
        
        # Handle special mnemonics based on prefix
        if state.prefix_rep and mnemonic == 'nop' and state.is_twobyte and state.opcode2 == 0x1E:
            # F3 0F 1E = ENDBR32/ENDBR64
            mnemonic = 'endbr64' if self.mode == 64 else 'endbr32'
        
        # Determine operand size
        op_size = entry.op_size if entry.op_size else state.operand_size
        
        # Build operands
        operands = self._build_operands(state, entry, op_size)
        
        # Read immediate if needed
        imm_op = self._read_immediate(state, entry, op_size)
        if imm_op:
            operands.append(imm_op)
        
        # Get raw bytes
        raw = state.data[state.start_pos:state.pos]
        
        insn = Instruction(
            address=state.instruction_address,
            size=state.bytes_consumed,
            raw_bytes=raw,
            mnemonic=mnemonic,
            operands=operands,
            prefix_lock=state.prefix_lock,
            prefix_rep=state.prefix_rep,
            prefix_repne=state.prefix_repne,
            prefix_segment=state.segment_override,
            flow_type=flow_type,
            valid=True
        )
        
        # Fix up RIP-relative addresses
        self._fixup_rip_relative(insn, state)
        
        # Calculate branch target
        self._calculate_branch_target(insn)
        
        return insn
    
    def _build_operands(self, state: DecoderState, entry: OpcodeEntry, op_size: int) -> List[Operand]:
        """Build operand list."""
        operands = []
        encoding = entry.encoding
        
        if encoding == OperandEncoding.NONE:
            pass
        
        elif encoding == OperandEncoding.MODRM_RM:
            operands.append(self._make_rm_operand(state, op_size))
        
        elif encoding == OperandEncoding.MODRM_REG:
            operands.append(self._make_reg_operand(state, op_size))
        
        elif encoding == OperandEncoding.MODRM_BOTH:
            rm_op = self._make_rm_operand(state, op_size)
            reg_size = state.operand_size if entry.mnemonic == 'lea' else op_size
            reg_op = self._make_reg_operand(state, reg_size)
            
            if entry.op_order == OperandOrder.RM_REG:
                operands = [rm_op, reg_op]
            else:
                operands = [reg_op, rm_op]
        
        elif encoding == OperandEncoding.OPCODE_REG:
            reg_idx = (state.opcode if not state.is_twobyte else state.opcode2) & 0x07
            if state.rex_b:
                reg_idx |= 0x08
            reg = make_gpr(reg_idx, op_size)
            operands.append(Operand(type=OperandType.REGISTER, reg=reg, size=op_size))
        
        elif encoding in (OperandEncoding.IMM8, OperandEncoding.IMM16, 
                          OperandEncoding.IMM32, OperandEncoding.IMMZ):
            # Accumulator for certain instructions
            if entry.mnemonic in ('add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp', 'test'):
                acc_size = 8 if op_size == 8 else state.operand_size
                acc = make_gpr(0, acc_size)
                operands.append(Operand(type=OperandType.REGISTER, reg=acc, size=acc_size))
        
        return operands
    
    def _make_reg_operand(self, state: DecoderState, size: int) -> Operand:
        """Create operand from MODRM.reg."""
        reg = make_gpr(state.modrm_reg, size)
        return Operand(type=OperandType.REGISTER, reg=reg, size=size)
    
    def _make_rm_operand(self, state: DecoderState, size: int) -> Operand:
        """Create operand from MODRM.rm."""
        if state.modrm_mod == 0x03:
            # Register operand
            reg = make_gpr(state.modrm_rm, size)
            return Operand(type=OperandType.REGISTER, reg=reg, size=size)
        
        # Memory operand
        mem = MemoryOperand(size=size, segment=state.segment_override)
        
        if state.rip_relative:
            mem.rip_relative = True
            mem.displacement = state.displacement
        elif state.has_sib:
            # SIB addressing
            base_3bit = state.sib & 0x07
            index_3bit = (state.sib >> 3) & 0x07
            
            if not (base_3bit == 0x05 and state.modrm_mod == 0x00):
                mem.base = make_gpr(state.sib_base, 64)
            
            if index_3bit != 0x04:
                mem.index = make_gpr(state.sib_index, 64)
                mem.scale = state.sib_scale
            
            mem.displacement = state.displacement
        else:
            # Simple addressing
            mem.base = make_gpr(state.modrm_rm, 64)
            mem.displacement = state.displacement
        
        return Operand(type=OperandType.MEMORY, mem=mem, size=size)
    
    def _read_immediate(self, state: DecoderState, entry: OpcodeEntry, op_size: int) -> Optional[Operand]:
        """Read immediate value if required."""
        encoding = entry.encoding
        
        if encoding == OperandEncoding.REL8:
            rel = state.read_signed(1)
            return Operand(type=OperandType.RELATIVE, rel_offset=rel, size=8)
        
        if encoding == OperandEncoding.REL32:
            rel = state.read_signed(4)
            return Operand(type=OperandType.RELATIVE, rel_offset=rel, size=32)
        
        if encoding == OperandEncoding.IMM8:
            imm = state.read_signed(1)
            return Operand(type=OperandType.IMMEDIATE, imm=imm, size=8)
        
        if encoding == OperandEncoding.IMM16:
            imm = state.read_unsigned(2)
            return Operand(type=OperandType.IMMEDIATE, imm=imm, size=16)
        
        if encoding == OperandEncoding.IMMZ:
            size = 16 if state.prefix_66 else 32
            imm = state.read_signed(size // 8)
            return Operand(type=OperandType.IMMEDIATE, imm=imm, size=size)
        
        if encoding == OperandEncoding.MOFFS:
            addr_size = state.address_size // 8
            addr = state.read_unsigned(addr_size)
            mem = MemoryOperand(displacement=addr, size=op_size, segment=state.segment_override)
            return Operand(type=OperandType.MEMORY, mem=mem, size=op_size)
        
        # Handle imm_size from entry
        imm_size = entry.imm_size
        if imm_size > 0:
            imm = state.read_signed(imm_size // 8)
            return Operand(type=OperandType.IMMEDIATE, imm=imm, size=imm_size)
        
        if imm_size == -1:
            size = min(op_size, 32)
            if state.rex_w and encoding == OperandEncoding.OPCODE_REG:
                size = 64
            imm = state.read_signed(size // 8)
            return Operand(type=OperandType.IMMEDIATE, imm=imm, size=size)
        
        # Group 3 TEST needs immediate
        if entry.is_group and entry.mnemonic == 'grp3':
            reg_3bit = (state.modrm >> 3) & 0x07
            if reg_3bit in (0, 1):
                size = 8 if entry.op_size == 8 else min(op_size, 32)
                imm = state.read_signed(size // 8)
                return Operand(type=OperandType.IMMEDIATE, imm=imm, size=size)
        
        return None
    
    def _fixup_rip_relative(self, insn: Instruction, state: DecoderState) -> None:
        """Fix up RIP-relative addresses."""
        next_addr = insn.address + insn.size
        
        for op in insn.operands:
            if op.type == OperandType.MEMORY and op.mem and op.mem.rip_relative:
                op.mem.absolute_address = next_addr + op.mem.displacement
    
    def _calculate_branch_target(self, insn: Instruction) -> None:
        """Calculate branch target for control flow instructions."""
        for op in insn.operands:
            if op.type == OperandType.RELATIVE:
                op.absolute_target = insn.next_address + op.rel_offset
                insn.branch_target = op.absolute_target
