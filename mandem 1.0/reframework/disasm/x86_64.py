# x86-64 Instruction Decoder
# 
# This module implements an x86-64 instruction decoder, capable of decoding
# raw binary instruction streams into structured Instruction objects. The
# decoder is designed to closely follow Intel's encoding rules and
# documentation.
# 
# Usage:
# 
# decoder = X86Decoder()
# instruction = decoder.decode(data, offset, address)
# 
# Where `data` is a byte string containing the instruction stream, `offset`
# is the starting point within that stream, and `address` is the virtual
# address of the instruction (useful for display and branch target
# calculation).
# 
# The decoder also supports segment overrides, operand size overrides, and
# address size overrides, as per the x86-64 architecture specifications.
# 
# Limitations:
# 
# - This is a work-in-progress. Not all opcodes and addressing modes are
#   implemented.
# - Some complex instructions and combinations may not be decoded
#   correctly.
# - Error handling is basic; malformed instruction streams may cause
#   exceptions.
# 
# For detailed information on the x86-64 instruction set, refer to the
# Intel 64 and IA-32 Architectures Software Developer's Manual.
# 
# Author: [Your Name]
# Date: [Date]
# 
# =============================================================================
# Imports
# =============================================================================

from typing import List, Optional
import struct

# =============================================================================
# Constants
# =============================================================================

# Opcode information structure
class OpcodeInfo:
    def __init__(self, mnemonic: str, operands: str, flags: int = 0, op_size: int = 0):
        self.mnemonic = mnemonic      # Instruction mnemonic (e.g., 'add', 'sub')
        self.operands = operands      # Operand encoding string (e.g., 'rm', 'r,imm')
        self.flags = flags            # Instruction flags (e.g., CALL, JUMP)
        self.op_size = op_size        # Operand size (in bits), 0 if not applicable

# Instruction flags (for distinguishing between different types of instructions)
class InstructionFlags:
    NONE = 0
    CALL = 1
    JUMP = 2
    BRANCH = 4
    STACK_OP = 8

# Register enumeration (partial)
class Register:
    NONE = 0
    RAX = 1
    RCX = 2
    RDX = 3
    RBX = 4
    RSP = 5
    RBP = 6
    RSI = 7
    RDI = 8
    RIP = 9
    # Segment registers
    ES = 16
    CS = 17
    SS = 18
    DS = 19
    FS = 20
    GS = 21

# Operand types
class OperandType:
    IMM = 0      # Immediate value
    REG = 1      # Register
    MEM = 2      # Memory operand
    REL = 3      # Relative offset

# Operand structure
class Operand:
    def __init__(self, type: int, value: int = 0, size: int = 0, reg: Register = Register.NONE):
        self.type = type              # Operand type (IMM, REG, MEM, REL)
        self.value = value            # Operand value (immediate data, address, etc.)
        self.size = size              # Size of the operand (in bits)
        self.reg = reg                # Register (if applicable)

# Instruction structure
class Instruction:
    def __init__(self):
        self.mnemonic = ""            # Instruction mnemonic
        self.operands = []            # List of operands
        self.address = 0              # Virtual address of the instruction
        self.size = 0                 # Size of the instruction (in bytes)
        self.raw_bytes = b""          # Raw bytes of the instruction
        self.flags = 0                # Instruction flags
        self.segment_override = Register.NONE  # Segment override (if any)
        self.branch_target = 0         # Calculated branch target (for jumps/calls)

    def format_with_address(self) -> str:
        """Format the instruction for display, including address and raw bytes."""
        addr_str = f"{self.address:016X}"
        bytes_str = " ".join(f"{b:02X}" for b in self.raw_bytes)
        return f"{addr_str}  {bytes_str}  {self.mnemonic} {' '.join(str(op) for op in self.operands)}"

# =============================================================================
# Opcode Tables
# =============================================================================

# One-byte opcodes (partial)
ONE_BYTE_OPCODES = {
    0x00: OpcodeInfo('add', 'rm,r'),
    0x01: OpcodeInfo('add', 'r,rm'),
    0x02: OpcodeInfo('add', '+r,rm'),
    0x03: OpcodeInfo('add', 'rm,+r'),
    0x04: OpcodeInfo('add', 'al,imm8'),
    0x05: OpcodeInfo('add', 'ax,imm'),
    0x06: OpcodeInfo('push', 'es'),
    0x07: OpcodeInfo('pop', 'es'),
    0x08: OpcodeInfo('or', 'rm,r'),
    0x09: OpcodeInfo('or', 'r,rm'),
    0x0A: OpcodeInfo('or', '+r,rm'),
    0x0B: OpcodeInfo('or', 'rm,+r'),
    0x0C: OpcodeInfo('or', 'al,imm8'),
    0x0D: OpcodeInfo('or', 'ax,imm'),
    0x0E: OpcodeInfo('push', 'cs'),
    0x0F: OpcodeInfo('grp', 'rm,r'),  # Group 1 (see GROUP1_MNEMONICS)
}

# Two-byte opcodes (partial)
TWO_BYTE_OPCODES = {
    0x00: OpcodeInfo('add', 'rm,r'),
    0x01: OpcodeInfo('add', 'r,rm'),
    0x02: OpcodeInfo('add', '+r,rm'),
    0x03: OpcodeInfo('add', 'rm,+r'),
    0x04: OpcodeInfo('add', 'al,imm8'),
    0x05: OpcodeInfo('add', 'ax,imm'),
    0x06: OpcodeInfo('push', 'es'),
    0x07: OpcodeInfo('pop', 'es'),
    0x08: OpcodeInfo('or', 'rm,r'),
    0x09: OpcodeInfo('or', 'r,rm'),
    0x0A: OpcodeInfo('or', '+r,rm'),
    0x0B: OpcodeInfo('or', 'rm,+r'),
    0x0C: OpcodeInfo('or', 'al,imm8'),
    0x0D: OpcodeInfo('or', 'ax,imm'),
    0x0E: OpcodeInfo('push', 'cs'),
    0x0F: OpcodeInfo('grp', 'rm,r'),  # Group 1 (see GROUP1_MNEMONICS)
}

# Group instruction mnemonics (selected by ModRM.reg field)
GROUP1_MNEMONICS = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
GROUP2_MNEMONICS = ['rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'sal', 'sar']
GROUP3_MNEMONICS = ['test', 'test', 'not', 'neg', 'mul', 'imul', 'div', 'idiv']
GROUP4_MNEMONICS = ['inc', 'dec', '', '', '', '', '', '']
GROUP5_MNEMONICS = ['inc', 'dec', 'call', 'call', 'jmp', 'jmp', 'push', '']
GROUP8_MNEMONICS = ['', '', '', '', 'bt', 'bts', 'btr', 'btc']


# =============================================================================
# Instruction Decoder
# =============================================================================

class X86Decoder:
    """
    x86-64 instruction decoder.
    
    Decodes raw bytes into Instruction objects. This is a hand-written
    decoder that processes each byte according to Intel's encoding rules.
    
    Usage:
        decoder = X86Decoder()
        instruction = decoder.decode(data, offset, address)
    """
    
    def __init__(self, mode: int = 64):
        """
        Initialize decoder.
        
        Args:
            mode: CPU mode (32 or 64)
        """
        self.mode = mode
        self._default_operand_size = 32 if mode == 64 else 32
        self._default_address_size = 64 if mode == 64 else 32
        
        # Current instruction state (reset for each decode)
        self._data: bytes = b''
        self._offset: int = 0
        self._start_offset: int = 0
        self._address: int = 0
        
        # Prefix state
        self._rex: int = 0          # REX prefix byte (0 if none)
        self._rex_w: bool = False   # REX.W bit
        self._rex_r: bool = False   # REX.R bit
        self._rex_x: bool = False   # REX.X bit
        self._rex_b: bool = False   # REX.B bit
        self._has_rex: bool = False
        
        self._operand_size_override: bool = False
        self._address_size_override: bool = False
        self._segment_override: Register = Register.NONE
        self._has_lock: bool = False
        self._has_rep: bool = False
        self._has_repne: bool = False
        
        # Computed sizes
        self._operand_size: int = 32
        self._address_size: int = 64
    
    def decode(self, data: bytes, offset: int = 0, address: int = 0) -> Optional[Instruction]:
        """
        Decode a single instruction.
        
        Args:
            data: Byte buffer containing instruction
            offset: Offset into buffer where instruction starts
            address: Virtual address of instruction (for display and branch calculation)
            
        Returns:
            Decoded Instruction, or None if decoding failed
        """
        if offset >= len(data):
            return None
        
        # Initialize state
        self._data = data
        self._offset = offset
        self._start_offset = offset
        self._address = address
        self._reset_prefix_state()
        
        try:
            # Step 1: Parse prefixes
            self._parse_prefixes()
            
            # Step 2: Calculate operand/address sizes
            self._calculate_sizes()
            
            # Step 3: Parse opcode and decode instruction
            instruction = self._decode_opcode()
            
            if instruction:
                # Fill in common fields
                instruction.address = address
                instruction.size = self._offset - self._start_offset
                instruction.raw_bytes = data[self._start_offset:self._offset]
                instruction.has_lock = self._has_lock
                instruction.has_rep = self._has_rep
                instruction.has_repne = self._has_repne
                instruction.segment_override = self._segment_override
            
            return instruction
            
        except (IndexError, struct.error):
            return None
    
    def decode_all(self, data: bytes, start_address: int = 0) -> List[Instruction]:
        """
        Decode all instructions in a buffer (linear sweep).
        
        Args:
            data: Byte buffer
            start_address: Virtual address of first byte
            
        Returns:
            List of decoded instructions
        """
        instructions = []
        offset = 0
        
        while offset < len(data):
            insn = self.decode(data, offset, start_address + offset)
            if insn is None or insn.size == 0:
                # Failed to decode - skip one byte
                offset += 1
            else:
                instructions.append(insn)
                offset += insn.size
        
        return instructions
    
    def _reset_prefix_state(self) -> None:
        """Reset all prefix-related state."""
        self._rex = 0
        self._rex_w = False
        self._rex_r = False
        self._rex_x = False
        self._rex_b = False
        self._has_rex = False
        self._operand_size_override = False
        self._address_size_override = False
        self._segment_override = Register.NONE
        self._has_lock = False
        self._has_rep = False
        self._has_repne = False
    
    def _read_byte(self) -> int:
        """Read and consume one byte."""
        if self._offset >= len(self._data):
            raise IndexError("End of data")
        byte = self._data[self._offset]
        self._offset += 1
        return byte
    
    def _peek_byte(self) -> int:
        """Peek at next byte without consuming it."""
        if self._offset >= len(self._data):
            raise IndexError("End of data")
        return self._data[self._offset]
    
    def _read_bytes(self, count: int) -> bytes:
        """Read and consume multiple bytes."""
        if self._offset + count > len(self._data):
            raise IndexError("End of data")
        data = self._data[self._offset:self._offset + count]
        self._offset += count
        return data
    
    def _read_imm8(self) -> int:
        """Read 8-bit signed immediate."""
        data = self._read_bytes(1)
        return struct.unpack('<b', data)[0]
    
    def _read_imm8u(self) -> int:
        """Read 8-bit unsigned immediate."""
        return self._read_byte()
    
    def _read_imm16(self) -> int:
        """Read 16-bit signed immediate."""
        data = self._read_bytes(2)
        return struct.unpack('<h', data)[0]
    
    def _read_imm16u(self) -> int:
        """Read 16-bit unsigned immediate."""
        data = self._read_bytes(2)
        return struct.unpack('<H', data)[0]
    
    def _read_imm32(self) -> int:
        """Read 32-bit signed immediate."""
        data = self._read_bytes(4)
        return struct.unpack('<i', data)[0]
    
    def _read_imm32u(self) -> int:
        """Read 32-bit unsigned immediate."""
        data = self._read_bytes(4)
        return struct.unpack('<I', data)[0]
    
    def _read_imm64(self) -> int:
        """Read 64-bit signed immediate."""
        data = self._read_bytes(8)
        return struct.unpack('<q', data)[0]
    
    def _parse_prefixes(self) -> None:
        """
        Parse instruction prefixes.
        
        Prefixes are 1-byte values that modify instruction behavior.
        They can appear in any order, but there are rules about conflicts.
        
        In 64-bit mode, bytes 0x40-0x4F are REX prefixes, not INC/DEC.
        """
        while self._offset < len(self._data):
            byte = self._peek_byte()
            
            # Legacy prefixes (Groups 1-4)
            if byte == 0xF0:  # LOCK
                self._has_lock = True
                self._offset += 1
            elif byte == 0xF2:  # REPNE/REPNZ
                self._has_repne = True
                self._offset += 1
            elif byte == 0xF3:  # REP/REPE/REPZ
                self._has_rep = True
                self._offset += 1
            elif byte == 0x2E:  # CS segment override
                self._segment_override = Register.CS
                self._offset += 1
            elif byte == 0x36:  # SS segment override
                self._segment_override = Register.SS
                self._offset += 1
            elif byte == 0x3E:  # DS segment override
                self._segment_override = Register.DS
                self._offset += 1
            elif byte == 0x26:  # ES segment override
                self._segment_override = Register.ES
                self._offset += 1
            elif byte == 0x64:  # FS segment override
                self._segment_override = Register.FS
                self._offset += 1
            elif byte == 0x65:  # GS segment override
                self._segment_override = Register.GS
                self._offset += 1
            elif byte == 0x66:  # Operand-size override
                self._operand_size_override = True
                self._offset += 1
            elif byte == 0x67:  # Address-size override
                self._address_size_override = True
                self._offset += 1
            elif self.mode == 64 and 0x40 <= byte <= 0x4F:
                # REX prefix (64-bit mode only)
                self._rex = byte
                self._has_rex = True
                self._rex_w = bool(byte & 0x08)  # Bit 3: W
                self._rex_r = bool(byte & 0x04)  # Bit 2: R
                self._rex_x = bool(byte & 0x02)  # Bit 1: X
                self._rex_b = bool(byte & 0x01)  # Bit 0: B
                self._offset += 1
                # REX must be last prefix
                break
            else:
                # Not a prefix, we're done
                break
    
    def _calculate_sizes(self) -> None:
        """
        Calculate effective operand and address sizes.
        
        In 64-bit mode:
        - Default operand size is 32 bits
        - REX.W makes it 64 bits
        - 66h prefix makes it 16 bits
        
        Address size:
        - Default is 64 bits
        - 67h prefix makes it 32 bits
        """
        if self.mode == 64:
            # Operand size
            if self._rex_w:
                self._operand_size = 64
            elif self._operand_size_override:
                self._operand_size = 16
            else:
                self._operand_size = 32
            
            # Address size
            if self._address_size_override:
                self._address_size = 32
            else:
                self._address_size = 64
        else:
            # 32-bit mode
            if self._operand_size_override:
                self._operand_size = 16
            else:
                self._operand_size = 32
            
            if self._address_size_override:
                self._address_size = 16
            else:
                self._address_size = 32
    
    def _decode_opcode(self) -> Optional[Instruction]:
        """
        Decode the opcode and create instruction.
        
        The opcode determines:
        - Instruction mnemonic
        - How many operands
        - How operands are encoded
        """
        opcode = self._read_byte()
        
        # Check for two-byte opcode escape
        if opcode == 0x0F:
            return self._decode_two_byte_opcode()
        
        # One-byte opcode
        info = ONE_BYTE_OPCODES.get(opcode)
        
        if info is None:
            # Unknown opcode
            return self._make_unknown_instruction(opcode)
        
        return self._decode_instruction(opcode, info, is_two_byte=False)
    
    def _decode_two_byte_opcode(self) -> Optional[Instruction]:
        """Decode a two-byte opcode (0F XX)."""
        opcode2 = self._read_byte()
        
        # Check for three-byte opcode escapes
        if opcode2 == 0x38 or opcode2 == 0x3A:
            # Three-byte opcode - not fully implemented
            return self._make_unknown_instruction(0x0F, opcode2)
        
        info = TWO_BYTE_OPCODES.get(opcode2)
        
        if info is None:
            return self._make_unknown_instruction(0x0F, opcode2)
        
        return self._decode_instruction(opcode2, info, is_two_byte=True)
    
    def _make_unknown_instruction(self, *opcodes) -> Instruction:
        """Create an instruction for unknown opcodes."""
        insn = Instruction()
        insn.mnemonic = "db"
        
        # Add each opcode byte as an immediate operand
        for op in opcodes:
            operand = Operand(type=OperandType.IMM, value=op, size=8)
            insn.operands.append(operand)
        
        return insn
    
    def _decode_instruction(
        self, opcode: int, info: OpcodeInfo, is_two_byte: bool
    ) -> Instruction:
        """
        Decode an instruction based on opcode info.
        
        Args:
            opcode: The opcode byte
            info: Opcode information from table
            is_two_byte: Whether this is a two-byte opcode
        """
        insn = Instruction()
        insn.mnemonic = info.mnemonic
        insn.flags = info.flags
        
        # Handle group instructions (opcode extension in ModRM.reg)
        if info.mnemonic.startswith('grp'):
            return self._decode_group_instruction(opcode, info, insn)
        
        # Parse operands based on encoding string
        self._decode_operands(insn, info, opcode)
        
        return insn
    
    def _decode_group_instruction(
        self, opcode: int, info: OpcodeInfo, insn: Instruction
    ) -> Instruction:
        """
        Decode group instructions where ModRM.reg selects the mnemonic.
        
        Groups are a space-saving technique where multiple instructions
        share an opcode, differentiated by the ModRM.reg field.
        """
        # Read ModRM byte
        modrm = self._read_byte()
        mod = (modrm >> 6) & 0x03
        reg = (modrm >> 3) & 0x07
        rm = modrm & 0x07
        
        # Select mnemonic based on group and reg field
        group_name = info.mnemonic
        
        if group_name == 'grp1':
            insn.mnemonic = GROUP1_MNEMONICS[reg]
        elif group_name == 'grp2':
            insn.mnemonic = GROUP2_MNEMONICS[reg]
        elif group_name == 'grp3':
            insn.mnemonic = GROUP3_MNEMONICS[reg]
            # TEST in grp3 has immediate
            if reg <= 1:  # test
                insn.flags = InstructionFlags.NONE
        elif group_name == 'grp4':
            insn.mnemonic = GROUP4_MNEMONICS[reg]
        elif group_name == 'grp5':
            insn.mnemonic = GROUP5_MNEMONICS[reg]
            # Update flags for different grp5 operations
            if reg == 2:  # call near
                insn.flags = InstructionFlags.CALL
            elif reg == 3:  # call far
                insn.flags = InstructionFlags.CALL
            elif reg == 4:  # jmp near
                insn.flags = InstructionFlags.JUMP
            elif reg == 5:  # jmp far
                insn.flags = InstructionFlags.JUMP
            elif reg == 6:  # push
                insn.flags = InstructionFlags.STACK_OP
        elif group_name == 'grp8':
            insn.mnemonic = GROUP8_MNEMONICS[reg]
        
        if not insn.mnemonic:
            insn.mnemonic = f"{group_name}_{reg}"
        
        # Determine operand size
        if info.op_size:
            op_size = info.op_size
        else:
            op_size = self._operand_size
        
        # Decode the r/m operand
        rm_operand = self._decode_modrm_rm(modrm, op_size)
        insn.operands.append(rm_operand)
        
        # Handle second operand based on encoding
        operands_str = info.operands
        if ',i8' in operands_str:
            imm = self._read_imm8()
            insn.operands.append(Operand(type=OperandType.IMM, value=imm, size=8))
        elif ',iz' in operands_str:
            imm = self._read_imm32() if op_size >= 32 else self._read_imm16()
            insn.operands.append(Operand(type=OperandType.IMM, value=imm, size=min(op_size, 32)))
        elif ',1' in operands_str:
            insn.operands.append(Operand(type=OperandType.IMM, value=1, size=8))
        elif ',cl' in operands_str:
            insn.operands.append(Operand(type=OperandType.REG, reg=Register.RCX, size=8))
        
        # For grp3 TEST, add immediate
        if group_name == 'grp3' and reg <= 1:
            if info.op_size == 8:
                imm = self._read_imm8u()
                insn.operands.append(Operand(type=OperandType.IMM, value=imm, size=8))
            else:
                imm = self._read_imm32() if op_size >= 32 else self._read_imm16()
                insn.operands.append(Operand(type=OperandType.IMM, value=imm, size=min(op_size, 32)))
        
        # Calculate branch target for CALL/JMP in grp5
        if group_name == 'grp5' and reg in (2, 4) and rm_operand.type == OperandType.MEM:
            insn.flags |= InstructionFlags.BRANCH
        
        return insn
    
    def _decode_operands(
        self, insn: Instruction, info: OpcodeInfo, opcode: int
    ) -> None:
        """
        Decode operands based on the encoding string.
        
        Encoding strings describe how operands are encoded:
        - 'rm,r': ModRM.rm and ModRM.reg operands
        - 'r,rm': Same but order swapped
        - '+r': Register in low 3 bits of opcode
        - 'rel8', 'rel32': Relative offset
        - 'i8', 'iz', 'iv': Immediate values
        - 'al', 'ax': Implicit accumulator
        """
        operands_str = info.operands
        if not operands_str:
            return
        
        # Determine operand size
        if info.op_size:
            op_size = info.op_size
        else:
            op_size = self._operand_size
        
        parts = operands_str.split(',')
        
        modrm = None
        if info.has_modrm:
            modrm = self._read_byte()
        
        for part in parts:
            part = part.strip()
            
            if part == 'rm':
                # ModRM.rm operand only
                operand = self._decode_modrm_rm(modrm, op_size)
                insn.operands.append(operand)
                
            elif part == 'r':
                # ModRM.reg operand
                reg = ((modrm >> 3) & 0x07) | (0x08 if self._rex_r else 0)
                operand = Operand(type=OperandType.REG, reg=Register(reg), size=op_size)
                insn.operands.append(operand)
                
            elif part == 'm':
                # Memory operand (LEA, etc.)
                operand = self._decode_modrm_rm(modrm, op_size)
                operand.size = op_size
                insn.operands.append(operand)
                
            elif part == 'rm,r' or part == 'r,rm':
                # Both operands from ModRM - handled as pair
                pass  # Will be handled by individual parts
                
            elif part == '+r':
                # Register in opcode bits 0-2
                reg = (opcode & 0x07) | (0x08 if self._rex_b else 0)
                insn.operands.append(Operand(type=OperandType.REG, reg=Register(reg), size=op_size))
                
            elif part == 'al':
                insn.operands.append(Operand(type=OperandType.REG, reg=Register.RAX, size=8))
                
            elif part == 'ax':
                insn.operands.append(Operand(type=OperandType.REG, reg=Register.RAX, size=op_size))
                
            elif part == 'ax,+r':
                # XCHG rax, r encoding
                insn.operands.append(Operand(type=OperandType.REG, reg=Register.RAX, size=op_size))
                reg = (opcode & 0x07) | (0x08 if self._rex_b else 0)
                insn.operands.append(Operand(type=OperandType.REG, reg=Register(reg), size=op_size))
                
            elif part == '+r,i8':
                # MOV r8, imm8
                reg = (opcode & 0x07) | (0x08 if self._rex_b else 0)
                insn.operands.append(Operand(type=OperandType.REG, reg=Register(reg), size=8))
                imm = self._read_imm8u()
                insn.operands.append(Operand(type=OperandType.IMM, value=imm, size=8))
                
            elif part == '+r,iv':
                # MOV r, imm (size based on REX.W)
                reg = (opcode & 0x07) | (0x08 if self._rex_b else 0)
                if self._rex_w:
                    size = 64
                    imm = self._read_imm64()
                else:
                    size = op_size
                    imm = self._read_imm32() if size >= 32 else self._read_imm16()
                insn.operands.append(Operand(type=OperandType.REG, reg=Register(reg), size=size))
                insn.operands.append(Operand(type=OperandType.IMM, value=imm, size=size))
                
            elif part == 'i8':
                imm = self._read_imm8()
                insn.operands.append(Operand(type=OperandType.IMM, value=imm, size=8))
                
            elif part == 'i16':
                imm = self._read_imm16u()
                insn.operands.append(Operand(type=OperandType.IMM, value=imm, size=16))
                
            elif part == 'iz':
                # Immediate: 32-bit in 64/32 mode, 16-bit in 16-bit mode
                if op_size == 16:
                    imm = self._read_imm16()
                else:
                    imm = self._read_imm32()
                insn.operands.append(Operand(type=OperandType.IMM, value=imm, size=min(op_size, 32)))
                
            elif part == 'rel8':
                # 8-bit relative offset
                rel = self._read_imm8()
                next_ip = self._address + (self._offset - self._start_offset)
                target = next_ip + rel
                insn.operands.append(Operand(type=OperandType.REL, value=target, size=64))
                insn.branch_target = target
                
            elif part == 'rel32':
                # 32-bit relative offset
                rel = self._read_imm32()
                next_ip = self._address + (self._offset - self._start_offset)
                target = next_ip + rel
                insn.operands.append(Operand(type=OperandType.REL, value=target, size=64))
                insn.branch_target = target
                
            elif part == 'moffs':
                # Direct memory offset (no ModRM)
                if self._address_size == 64:
                    addr = self._read_imm64()
                else:
                    addr = self._read_imm32u()
                operand = Operand(
                    type=OperandType.MEM,
                    displacement=addr,
                    size=op_size,
                    segment=self._segment_override
                )
                insn.operands.append(operand)
                
            elif part == 'fs':
                insn.operands.append(Operand(type=OperandType.REG, reg=Register.FS, size=16))
                
            elif part == 'gs':
                insn.operands.append(Operand(type=OperandType.REG, reg=Register.GS, size=16))
                
            elif part == 'sreg':
                # Segment register in ModRM.reg
                sreg = (modrm >> 3) & 0x07
                if sreg < 6:
                    reg = Register(16 + sreg)  # ES, CS, SS, DS, FS, GS
                else:
                    reg = Register.NONE
                insn.operands.append(Operand(type=OperandType.REG, reg=reg, size=16))
                
            elif part == 'cl':
                insn.operands.append(Operand(type=OperandType.REG, reg=Register.RCX, size=8))
                
            elif part == 'dx':
                insn.operands.append(Operand(type=OperandType.REG, reg=Register.RDX, size=16))
    
    def _decode_modrm_rm(self, modrm: int, op_size: int) -> Operand:
        """
        Decode the ModRM.rm operand (register or memory).
        
        ModRM byte layout:
        +-----+-----+-----+
        | mod | reg | r/m |
        | 7-6 | 5-3 | 2-0 |
        +-----+-----+-----+
        
        mod = 11: r/m is a register
        mod != 11: r/m specifies memory addressing
        
        Memory addressing modes (64-bit):
        - mod=00, r/m=101: RIP-relative (disp32)
        - mod=00, r/m=100: SIB with no displacement
        - mod=01, r/m=100: SIB with disp8
        - mod=10, r/m=100: SIB with disp32
        - Otherwise: [base + disp]
        """
        mod = (modrm >> 6) & 0x03
        rm = (modrm & 0x07) | (0x08 if self._rex_b else 0)
        
        if mod == 0x03:
            # Register operand
            return Operand(type=OperandType.REG, reg=Register(rm), size=op_size)
        
        # Memory operand
        operand = Operand(type=OperandType.MEM, size=op_size)
        operand.segment = self._segment_override
        
        # Check for SIB byte
        rm_3bit = modrm & 0x07
        if rm_3bit == 0x04:  # SIB follows
            sib = self._read_byte()
            scale = 1 << ((sib >> 6) & 0x03)  # 1, 2, 4, 8
            index = ((sib >> 3) & 0x07) | (0x08 if self._rex_x else 0)
            base = (sib & 0x07) | (0x08 if self._rex_b else 0)
            
            # Index = RSP (4) means no index
            if (sib >> 3) & 0x07 != 0x04:
                operand.index = Register(index)
                operand.scale = scale
            
            # Base = RBP (5) with mod=00 means no base, just disp32
            if (sib & 0x07) == 0x05 and mod == 0x00:
                operand.displacement = self._read_imm32()
            else:
                operand.base = Register(base)
                
                if mod == 0x01:
                    operand.displacement = self._read_imm8()
                elif mod == 0x02:
                    operand.displacement = self._read_imm32()
        
        elif rm_3bit == 0x05 and mod == 0x00:
            # RIP-relative addressing (64-bit mode)
            disp = self._read_imm32()
            operand.base = Register.RIP
            operand.displacement = disp
        
        else:
            # Simple [base + disp]
            operand.base = Register(rm)
            
            if mod == 0x01:
                operand.displacement = self._read_imm8()
            elif mod == 0x02:
                operand.displacement = self._read_imm32()
        
        return operand
    
    def format_instruction(self, insn: Instruction) -> str:
        """Format an instruction for display."""
        return insn.format_with_address()