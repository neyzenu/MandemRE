"""
ELF (Executable and Linkable Format) Parser

This module parses ELF files WITHOUT using any external libraries.
Every byte is explained and processed manually using struct.

ELF is the standard binary format for Linux/BSD/etc. Understanding it
deeply is essential for reverse engineering.

Key concepts:
- ELF Header: File metadata (architecture, entry point, header locations)
- Program Headers: Describe how to load the binary into memory (segments)
- Section Headers: Describe logical divisions of the binary (sections)
- Segments vs Sections: Segments are for runtime, sections are for linking
"""

import struct
from typing import Dict, List, Optional, Tuple
from enum import IntEnum

from .binary import (
    Binary, BinaryType, Architecture, Endianness,
    Segment, Section, Symbol, Relocation, SegmentFlags,
    ImportedFunction, ExportedFunction
)


# =============================================================================
# ELF Constants
# =============================================================================

# e_ident indices
EI_MAG0 = 0        # File identification
EI_MAG1 = 1
EI_MAG2 = 2
EI_MAG3 = 3
EI_CLASS = 4       # File class (32/64 bit)
EI_DATA = 5        # Data encoding (endianness)
EI_VERSION = 6     # ELF version
EI_OSABI = 7       # OS/ABI identification
EI_ABIVERSION = 8  # ABI version
EI_PAD = 9         # Start of padding bytes
EI_NIDENT = 16     # Size of e_ident[]

# ELF Magic
ELFMAG = b'\x7fELF'

# e_ident[EI_CLASS]
class ELFClass(IntEnum):
    ELFCLASSNONE = 0   # Invalid class
    ELFCLASS32 = 1     # 32-bit objects
    ELFCLASS64 = 2     # 64-bit objects

# e_ident[EI_DATA]
class ELFData(IntEnum):
    ELFDATANONE = 0    # Invalid data encoding
    ELFDATA2LSB = 1    # Little endian
    ELFDATA2MSB = 2    # Big endian

# e_type (object file type)
class ELFType(IntEnum):
    ET_NONE = 0        # No file type
    ET_REL = 1         # Relocatable file (.o)
    ET_EXEC = 2        # Executable file
    ET_DYN = 3         # Shared object file (.so) or PIE
    ET_CORE = 4        # Core file

# e_machine (architecture)
class ELFMachine(IntEnum):
    EM_NONE = 0        # No machine
    EM_386 = 3         # Intel 80386
    EM_ARM = 40        # ARM
    EM_X86_64 = 62     # AMD x86-64
    EM_AARCH64 = 183   # ARM 64-bit

# Program header types (p_type)
class PHType(IntEnum):
    PT_NULL = 0        # Unused entry
    PT_LOAD = 1        # Loadable segment
    PT_DYNAMIC = 2     # Dynamic linking info
    PT_INTERP = 3      # Interpreter path
    PT_NOTE = 4        # Auxiliary info
    PT_SHLIB = 5       # Reserved
    PT_PHDR = 6        # Program header table
    PT_TLS = 7         # Thread-local storage
    PT_GNU_EH_FRAME = 0x6474e550  # Exception handling
    PT_GNU_STACK = 0x6474e551     # Stack permissions
    PT_GNU_RELRO = 0x6474e552     # Read-only after relocation

# Program header flags (p_flags)
class PHFlags(IntEnum):
    PF_X = 1           # Execute
    PF_W = 2           # Write
    PF_R = 4           # Read

# Section header types (sh_type)
class SHType(IntEnum):
    SHT_NULL = 0           # Inactive
    SHT_PROGBITS = 1       # Program data
    SHT_SYMTAB = 2         # Symbol table
    SHT_STRTAB = 3         # String table
    SHT_RELA = 4           # Relocation with addends
    SHT_HASH = 5           # Symbol hash table
    SHT_DYNAMIC = 6        # Dynamic linking info
    SHT_NOTE = 7           # Notes
    SHT_NOBITS = 8         # No space in file (bss)
    SHT_REL = 9            # Relocation without addends
    SHT_SHLIB = 10         # Reserved
    SHT_DYNSYM = 11        # Dynamic linker symbol table
    SHT_INIT_ARRAY = 14    # Array of constructors
    SHT_FINI_ARRAY = 15    # Array of destructors
    SHT_GNU_HASH = 0x6ffffff6  # GNU hash table
    SHT_GNU_VERNEED = 0x6ffffffe  # Version needs
    SHT_GNU_VERSYM = 0x6fffffff   # Version symbols

# Section header flags (sh_flags)
class SHFlags(IntEnum):
    SHF_WRITE = 1          # Writable
    SHF_ALLOC = 2          # Occupies memory during execution
    SHF_EXECINSTR = 4      # Executable
    SHF_MERGE = 16         # Might be merged
    SHF_STRINGS = 32       # Contains strings
    SHF_INFO_LINK = 64     # sh_info contains section index
    SHF_LINK_ORDER = 128   # Preserve order after combining
    SHF_TLS = 1024         # Thread local storage

# Symbol binding (high 4 bits of st_info)
class STB(IntEnum):
    STB_LOCAL = 0      # Local symbol
    STB_GLOBAL = 1     # Global symbol
    STB_WEAK = 2       # Weak symbol

# Symbol type (low 4 bits of st_info)
class STT(IntEnum):
    STT_NOTYPE = 0     # Unspecified
    STT_OBJECT = 1     # Data object
    STT_FUNC = 2       # Function
    STT_SECTION = 3    # Section
    STT_FILE = 4       # Source file name
    STT_COMMON = 5     # Common data object
    STT_TLS = 6        # Thread-local data

# Dynamic section tags (d_tag)
class DT(IntEnum):
    DT_NULL = 0            # End of dynamic section
    DT_NEEDED = 1          # Name of needed library
    DT_PLTRELSZ = 2        # Size of PLT relocs
    DT_PLTGOT = 3          # Address of PLT/GOT
    DT_HASH = 4            # Address of symbol hash table
    DT_STRTAB = 5          # Address of string table
    DT_SYMTAB = 6          # Address of symbol table
    DT_RELA = 7            # Address of Rela relocs
    DT_RELASZ = 8          # Size of Rela relocs
    DT_RELAENT = 9         # Size of one Rela reloc
    DT_STRSZ = 10          # Size of string table
    DT_SYMENT = 11         # Size of one symbol entry
    DT_INIT = 12           # Address of init function
    DT_FINI = 13           # Address of fini function
    DT_SONAME = 14         # Name of shared object
    DT_RPATH = 15          # Library search path
    DT_SYMBOLIC = 16       # Symbol resolution flag
    DT_REL = 17            # Address of Rel relocs
    DT_RELSZ = 18          # Size of Rel relocs
    DT_RELENT = 19         # Size of one Rel reloc
    DT_PLTREL = 20         # Type of PLT relocs
    DT_DEBUG = 21          # Debug info
    DT_TEXTREL = 22        # Reloc might modify .text
    DT_JMPREL = 23         # Address of PLT relocs
    DT_BIND_NOW = 24       # Bind symbols at load time
    DT_INIT_ARRAY = 25     # Array of init functions
    DT_FINI_ARRAY = 26     # Array of fini functions
    DT_INIT_ARRAYSZ = 27   # Size of init array
    DT_FINI_ARRAYSZ = 28   # Size of fini array
    DT_GNU_HASH = 0x6ffffef5  # GNU hash table
    DT_VERNEED = 0x6ffffffe   # Version needs
    DT_VERNEEDNUM = 0x6fffffff  # Number of version needs

# x86_64 relocation types
class R_X86_64(IntEnum):
    R_X86_64_NONE = 0
    R_X86_64_64 = 1           # Direct 64-bit
    R_X86_64_PC32 = 2         # PC relative 32-bit signed
    R_X86_64_GOT32 = 3        # 32-bit GOT entry
    R_X86_64_PLT32 = 4        # 32-bit PLT address
    R_X86_64_COPY = 5         # Copy symbol at runtime
    R_X86_64_GLOB_DAT = 6     # Create GOT entry
    R_X86_64_JUMP_SLOT = 7    # Create PLT entry
    R_X86_64_RELATIVE = 8     # Adjust by program base
    R_X86_64_GOTPCREL = 9     # 32-bit PC relative GOT


# =============================================================================
# ELF Parser Implementation
# =============================================================================

class ELFParser:
    """
    Pure Python ELF parser.
    
    This parser reads ELF files byte by byte using the struct module.
    No external dependencies are used.
    
    Usage:
        parser = ELFParser()
        binary = parser.parse("/path/to/binary")
    """
    
    def __init__(self):
        """Initialize the parser."""
        self._data: bytes = b''
        self._endian_char: str = '<'  # '<' for little, '>' for big
        self._is_64bit: bool = True
        
        # Parsed ELF header fields
        self._e_type: int = 0
        self._e_machine: int = 0
        self._e_version: int = 0
        self._e_entry: int = 0
        self._e_phoff: int = 0
        self._e_shoff: int = 0
        self._e_flags: int = 0
        self._e_ehsize: int = 0
        self._e_phentsize: int = 0
        self._e_phnum: int = 0
        self._e_shentsize: int = 0
        self._e_shnum: int = 0
        self._e_shstrndx: int = 0
        
        # Section header string table (cached)
        self._shstrtab: bytes = b''
        
        # Dynamic string table (cached)
        self._dynstr: bytes = b''
        
        # Dynamic symbol table info
        self._dynsym_offset: int = 0
        self._dynsym_size: int = 0
        self._dynsym_entsize: int = 0
    
    def parse(self, filepath: str) -> Binary:
        """
        Parse an ELF file and return a Binary object.
        
        This is the main entry point. It:
        1. Loads the file
        2. Validates the ELF magic
        3. Parses the ELF header
        4. Parses program headers (segments)
        5. Parses section headers
        6. Parses symbol tables
        7. Parses relocations and resolves PLT/GOT
        
        Args:
            filepath: Path to the ELF file
            
        Returns:
            Fully populated Binary object
        """
        # Create binary object (loads file data)
        binary = Binary(filepath)
        self._data = binary.data
        
        # Step 1: Validate and parse identification bytes
        self._parse_ident(binary)
        
        # Step 2: Parse ELF header (rest of it)
        self._parse_elf_header(binary)
        
        # Step 3: Parse program headers (segments)
        self._parse_program_headers(binary)
        
        # Step 4: Parse section headers
        self._parse_section_headers(binary)
        
        # Step 5: Parse symbol tables
        self._parse_symbol_tables(binary)
        
        # Step 6: Parse relocations and resolve imports
        self._parse_relocations(binary)
        self._resolve_plt_got(binary)
        
        # Build lookup tables for fast access
        binary.build_lookup_tables()
        
        return binary
    
    def _parse_ident(self, binary: Binary) -> None:
        """
        Parse e_ident (first 16 bytes).
        
        This determines:
        - If it's a valid ELF file (magic number)
        - 32-bit or 64-bit
        - Endianness
        
        Layout of e_ident:
        +-------+-------+-------+-------+-------+-------+-------+-------+
        | MAG0  | MAG1  | MAG2  | MAG3  | CLASS | DATA  | VER   | OSABI |
        | 0x7f  |  'E'  |  'L'  |  'F'  | 1/2   | 1/2   |   1   |  0-18 |
        +-------+-------+-------+-------+-------+-------+-------+-------+
        |ABIVER |  PAD  |  PAD  |  PAD  |  PAD  |  PAD  |  PAD  |  PAD  |
        +-------+-------+-------+-------+-------+-------+-------+-------+
        """
        if len(self._data) < EI_NIDENT:
            raise ValueError("File too small to be an ELF file")
        
        # Check magic number (bytes 0-3)
        magic = self._data[EI_MAG0:EI_MAG3+1]
        if magic != ELFMAG:
            raise ValueError(
                f"Invalid ELF magic: {magic.hex()} "
                f"(expected {ELFMAG.hex()})"
            )
        
        binary.binary_type = BinaryType.ELF
        
        # Check class (byte 4): 32-bit or 64-bit
        elf_class = self._data[EI_CLASS]
        if elf_class == ELFClass.ELFCLASS32:
            self._is_64bit = False
            binary.bits = 32
        elif elf_class == ELFClass.ELFCLASS64:
            self._is_64bit = True
            binary.bits = 64
        else:
            raise ValueError(f"Invalid ELF class: {elf_class}")
        
        # Check data encoding (byte 5): endianness
        elf_data = self._data[EI_DATA]
        if elf_data == ELFData.ELFDATA2LSB:
            self._endian_char = '<'
            binary.endian = Endianness.LITTLE
        elif elf_data == ELFData.ELFDATA2MSB:
            self._endian_char = '>'
            binary.endian = Endianness.BIG
        else:
            raise ValueError(f"Invalid ELF data encoding: {elf_data}")
        
        # ELF version (byte 6) - must be 1
        elf_version = self._data[EI_VERSION]
        if elf_version != 1:
            raise ValueError(f"Invalid ELF version: {elf_version}")
    
    def _parse_elf_header(self, binary: Binary) -> None:
        """
        Parse the rest of the ELF header (after e_ident).
        
        64-bit ELF header layout (total 64 bytes):
        Offset  Size  Name
        0x00    16    e_ident      (already parsed)
        0x10    2     e_type       Object file type
        0x12    2     e_machine    Architecture
        0x14    4     e_version    ELF version
        0x18    8     e_entry      Entry point address
        0x20    8     e_phoff      Program header offset
        0x28    8     e_shoff      Section header offset
        0x30    4     e_flags      Processor flags
        0x34    2     e_ehsize     ELF header size
        0x36    2     e_phentsize  Program header entry size
        0x38    2     e_phnum      Program header count
        0x3A    2     e_shentsize  Section header entry size
        0x3C    2     e_shnum      Section header count
        0x3E    2     e_shstrndx   Section name string table index
        
        32-bit differs: addresses and offsets are 4 bytes instead of 8.
        """
        if self._is_64bit:
            # 64-bit: 'HHIQQQIHHHHHH'
            # H = 2 bytes, I = 4 bytes, Q = 8 bytes
            header_fmt = f'{self._endian_char}HHIQQQIHHHHHH'
            header_size = 64
            offset = EI_NIDENT
        else:
            # 32-bit: 'HHIIIIIHHHHHH'
            header_fmt = f'{self._endian_char}HHIIIIIHHHHHH'
            header_size = 52
            offset = EI_NIDENT
        
        if len(self._data) < header_size:
            raise ValueError(
                f"File too small for ELF header: "
                f"{len(self._data)} < {header_size}"
            )
        
        # Unpack header fields after e_ident
        header_data = self._data[offset:header_size]
        fields = struct.unpack(header_fmt, header_data)
        
        self._e_type = fields[0]
        self._e_machine = fields[1]
        self._e_version = fields[2]
        self._e_entry = fields[3]
        self._e_phoff = fields[4]
        self._e_shoff = fields[5]
        self._e_flags = fields[6]
        self._e_ehsize = fields[7]
        self._e_phentsize = fields[8]
        self._e_phnum = fields[9]
        self._e_shentsize = fields[10]
        self._e_shnum = fields[11]
        self._e_shstrndx = fields[12]
        
        # Set entry point
        binary.entry_point = self._e_entry
        
        # Determine architecture
        if self._e_machine == ELFMachine.EM_X86_64:
            binary.arch = Architecture.X86_64
        elif self._e_machine == ELFMachine.EM_386:
            binary.arch = Architecture.X86
        elif self._e_machine == ELFMachine.EM_ARM:
            binary.arch = Architecture.ARM
        elif self._e_machine == ELFMachine.EM_AARCH64:
            binary.arch = Architecture.ARM64
        else:
            binary.arch = Architecture.UNKNOWN
    
    def _parse_program_headers(self, binary: Binary) -> None:
        """
        Parse program headers (segments).
        
        Program headers tell the kernel HOW to load the binary:
        - Which parts of the file go into memory
        - At what addresses
        - With what permissions
        
        64-bit program header layout (56 bytes each):
        Offset  Size  Name
        0x00    4     p_type      Segment type
        0x04    4     p_flags     Segment flags (RWX)
        0x08    8     p_offset    File offset
        0x10    8     p_vaddr     Virtual address
        0x18    8     p_paddr     Physical address
        0x20    8     p_filesz    Size in file
        0x28    8     p_memsz     Size in memory
        0x30    8     p_align     Alignment
        
        Note: 32-bit has flags at the end, not after type!
        
        Key insight: p_memsz can be > p_filesz. The extra space is
        zero-filled (this is how .bss works - uninitialized data).
        """
        if self._e_phoff == 0 or self._e_phnum == 0:
            return  # No program headers (e.g., relocatable object)
        
        # Define format based on architecture
        if self._is_64bit:
            # 64-bit: type(4), flags(4), offset(8), vaddr(8), paddr(8),
            #         filesz(8), memsz(8), align(8)
            ph_fmt = f'{self._endian_char}IIQQQQQQ'
            ph_size = 56
        else:
            # 32-bit: type(4), offset(4), vaddr(4), paddr(4),
            #         filesz(4), memsz(4), flags(4), align(4)
            ph_fmt = f'{self._endian_char}IIIIIIII'
            ph_size = 32
        
        # Parse each program header
        for i in range(self._e_phnum):
            offset = self._e_phoff + (i * self._e_phentsize)
            
            if offset + ph_size > len(self._data):
                break
            
            ph_data = self._data[offset:offset + ph_size]
            fields = struct.unpack(ph_fmt, ph_data)
            
            if self._is_64bit:
                p_type = fields[0]
                p_flags = fields[1]
                p_offset = fields[2]
                p_vaddr = fields[3]
                p_paddr = fields[4]
                p_filesz = fields[5]
                p_memsz = fields[6]
                p_align = fields[7]
            else:
                p_type = fields[0]
                p_offset = fields[1]
                p_vaddr = fields[2]
                p_paddr = fields[3]
                p_filesz = fields[4]
                p_memsz = fields[5]
                p_flags = fields[6]
                p_align = fields[7]
            
            # Convert ELF flags to our flags
            seg_flags = SegmentFlags.NONE
            if p_flags & PHFlags.PF_R:
                seg_flags |= SegmentFlags.READ
            if p_flags & PHFlags.PF_W:
                seg_flags |= SegmentFlags.WRITE
            if p_flags & PHFlags.PF_X:
                seg_flags |= SegmentFlags.EXECUTE
            
            # Get segment name based on type
            try:
                seg_name = PHType(p_type).name
            except ValueError:
                seg_name = f"UNKNOWN_{p_type:#x}"
            
            # Read segment data from file
            seg_data = b''
            if p_filesz > 0 and p_offset + p_filesz <= len(self._data):
                seg_data = self._data[p_offset:p_offset + p_filesz]
            
            segment = Segment(
                name=seg_name,
                vaddr=p_vaddr,
                paddr=p_paddr,
                file_offset=p_offset,
                file_size=p_filesz,
                mem_size=p_memsz,
                flags=seg_flags,
                align=p_align,
                data=seg_data
            )
            binary.segments.append(segment)
    
    def _parse_section_headers(self, binary: Binary) -> None:
        """
        Parse section headers.
        
        Section headers are OPTIONAL for execution but useful for:
        - Debugging
        - Static analysis
        - Linking
        
        Malware often strips section headers to hinder analysis.
        
        64-bit section header layout (64 bytes each):
        Offset  Size  Name
        0x00    4     sh_name      Name (offset into shstrtab)
        0x04    4     sh_type      Section type
        0x08    8     sh_flags     Section flags
        0x10    8     sh_addr      Virtual address
        0x18    8     sh_offset    File offset
        0x20    8     sh_size      Section size
        0x28    4     sh_link      Link to another section
        0x2C    4     sh_info      Additional info
        0x30    8     sh_addralign Alignment
        0x38    8     sh_entsize   Entry size if section holds table
        """
        if self._e_shoff == 0 or self._e_shnum == 0:
            return  # No section headers (stripped)
        
        # First, we need to load the section header string table
        # so we can get section names
        self._load_shstrtab()
        
        # Define format
        if self._is_64bit:
            sh_fmt = f'{self._endian_char}IIQQQQIIQQ'
            sh_size = 64
        else:
            sh_fmt = f'{self._endian_char}IIIIIIIIII'
            sh_size = 40
        
        # Parse each section header
        for i in range(self._e_shnum):
            offset = self._e_shoff + (i * self._e_shentsize)
            
            if offset + sh_size > len(self._data):
                break
            
            sh_data = self._data[offset:offset + sh_size]
            fields = struct.unpack(sh_fmt, sh_data)
            
            if self._is_64bit:
                sh_name_offset = fields[0]
                sh_type = fields[1]
                sh_flags = fields[2]
                sh_addr = fields[3]
                sh_offset = fields[4]
                sh_size_val = fields[5]
                sh_link = fields[6]
                sh_info = fields[7]
                sh_addralign = fields[8]
                sh_entsize = fields[9]
            else:
                sh_name_offset = fields[0]
                sh_type = fields[1]
                sh_flags = fields[2]
                sh_addr = fields[3]
                sh_offset = fields[4]
                sh_size_val = fields[5]
                sh_link = fields[6]
                sh_info = fields[7]
                sh_addralign = fields[8]
                sh_entsize = fields[9]
            
            # Get section name from string table
            section_name = self._read_string_from_table(
                self._shstrtab, sh_name_offset
            )
            
            # Read section data
            section_data = b''
            if sh_type != SHType.SHT_NOBITS and sh_size_val > 0:
                if sh_offset + sh_size_val <= len(self._data):
                    section_data = self._data[sh_offset:sh_offset + sh_size_val]
            
            section = Section(
                name=section_name,
                vaddr=sh_addr,
                file_offset=sh_offset,
                size=sh_size_val,
                type_id=sh_type,
                flags=sh_flags,
                link=sh_link,
                info=sh_info,
                align=sh_addralign,
                entry_size=sh_entsize,
                data=section_data
            )
            binary.sections.append(section)
            
            # Cache dynamic string table for symbol resolution
            if section_name == '.dynstr':
                self._dynstr = section_data
    
    def _load_shstrtab(self) -> None:
        """
        Load the section header string table.
        
        This table contains the names of all sections as null-terminated
        strings. sh_name in each section header is an offset into this table.
        """
        if self._e_shstrndx == 0 or self._e_shstrndx >= self._e_shnum:
            return
        
        # Calculate offset of shstrtab section header
        sh_offset = self._e_shoff + (self._e_shstrndx * self._e_shentsize)
        
        if self._is_64bit:
            # Read sh_offset and sh_size from section header
            # sh_offset is at offset 24 (0x18), sh_size at offset 32 (0x20)
            fmt = f'{self._endian_char}QQ'
            data_offset = sh_offset + 24
            if data_offset + 16 <= len(self._data):
                strtab_offset, strtab_size = struct.unpack(
                    fmt, self._data[data_offset:data_offset + 16]
                )
                if strtab_offset + strtab_size <= len(self._data):
                    self._shstrtab = self._data[strtab_offset:strtab_offset + strtab_size]
        else:
            fmt = f'{self._endian_char}II'
            data_offset = sh_offset + 16
            if data_offset + 8 <= len(self._data):
                strtab_offset, strtab_size = struct.unpack(
                    fmt, self._data[data_offset:data_offset + 8]
                )
                if strtab_offset + strtab_size <= len(self._data):
                    self._shstrtab = self._data[strtab_offset:strtab_offset + strtab_size]
    
    def _read_string_from_table(self, table: bytes, offset: int) -> str:
        """
        Read a null-terminated string from a string table.
        
        String tables in ELF are simple: packed null-terminated strings.
        Example: "\\x00.text\\x00.data\\x00.bss\\x00"
        
        To get ".text", you'd read from offset 1 until the null byte.
        """
        if offset >= len(table):
            return ""
        
        end = table.find(b'\x00', offset)
        if end == -1:
            return table[offset:].decode('utf-8', errors='replace')
        
        return table[offset:end].decode('utf-8', errors='replace')
    
    def _parse_symbol_tables(self, binary: Binary) -> None:
        """
        Parse symbol tables (.symtab and .dynsym).
        
        Symbol table entry (64-bit, 24 bytes):
        Offset  Size  Name
        0x00    4     st_name     Symbol name (offset into strtab)
        0x04    1     st_info     Type and binding
        0x05    1     st_other    Visibility
        0x06    2     st_shndx    Section index
        0x08    8     st_value    Symbol value (address)
        0x10    8     st_size     Symbol size
        
        st_info encoding:
        - High 4 bits: binding (LOCAL, GLOBAL, WEAK)
        - Low 4 bits: type (NOTYPE, OBJECT, FUNC, SECTION, FILE)
        
        Key sections:
        - .symtab: All symbols (may be stripped)
        - .dynsym: Dynamic symbols (never stripped, needed for dynamic linking)
        """
        for section in binary.sections:
            if section.type_id in (SHType.SHT_SYMTAB, SHType.SHT_DYNSYM):
                # Find associated string table
                strtab = self._find_string_table_for_section(
                    binary, section.link
                )
                
                # Parse symbols
                self._parse_symbol_table_section(binary, section, strtab)
    
    def _find_string_table_for_section(
        self, binary: Binary, link_idx: int
    ) -> bytes:
        """Find the string table associated with a symbol table."""
        if link_idx < len(binary.sections):
            strtab_section = binary.sections[link_idx]
            return strtab_section.data
        return b''
    
    def _parse_symbol_table_section(
        self, binary: Binary, section: Section, strtab: bytes
    ) -> None:
        """Parse a single symbol table section."""
        if section.entry_size == 0:
            return
        
        if self._is_64bit:
            sym_fmt = f'{self._endian_char}IBBHQQ'
            sym_size = 24
        else:
            sym_fmt = f'{self._endian_char}IIIBBH'
            sym_size = 16
        
        num_symbols = section.size // sym_size
        
        for i in range(num_symbols):
            offset = i * sym_size
            if offset + sym_size > len(section.data):
                break
            
            sym_data = section.data[offset:offset + sym_size]
            fields = struct.unpack(sym_fmt, sym_data)
            
            if self._is_64bit:
                st_name = fields[0]
                st_info = fields[1]
                st_other = fields[2]
                st_shndx = fields[3]
                st_value = fields[4]
                st_size = fields[5]
            else:
                st_name = fields[0]
                st_value = fields[1]
                st_size = fields[2]
                st_info = fields[3]
                st_other = fields[4]
                st_shndx = fields[5]
            
            # Decode st_info
            sym_binding = st_info >> 4
            sym_type = st_info & 0xf
            
            # Get symbol name
            sym_name = self._read_string_from_table(strtab, st_name)
            
            symbol = Symbol(
                name=sym_name,
                value=st_value,
                size=st_size,
                type_id=sym_type,
                binding=sym_binding,
                visibility=st_other,
                section_index=st_shndx
            )
            binary.symbols.append(symbol)
            
            # Add to exports if it's a defined global function
            if (sym_binding == STB.STB_GLOBAL and 
                sym_type == STT.STT_FUNC and
                st_shndx != 0 and st_value != 0):
                export = ExportedFunction(
                    name=sym_name,
                    address=st_value,
                    size=st_size
                )
                binary.exports.append(export)
    
    def _parse_relocations(self, binary: Binary) -> None:
        """
        Parse relocation entries.
        
        Relocations tell the loader how to patch addresses at load time.
        Critical for:
        - Position-independent code (PIE)
        - Dynamic linking
        - PLT/GOT resolution
        
        Two types:
        - REL: Just offset and info
        - RELA: offset, info, and addend (more common on x86-64)
        
        RELA entry (64-bit, 24 bytes):
        Offset  Size  Name
        0x00    8     r_offset    Address to patch
        0x08    8     r_info      Symbol index and reloc type
        0x10    8     r_addend    Value to add
        
        r_info encoding (64-bit):
        - High 32 bits: symbol table index
        - Low 32 bits: relocation type
        """
        for section in binary.sections:
            if section.type_id == SHType.SHT_RELA:
                self._parse_rela_section(binary, section)
            elif section.type_id == SHType.SHT_REL:
                self._parse_rel_section(binary, section)
    
    def _parse_rela_section(self, binary: Binary, section: Section) -> None:
        """Parse a RELA relocation section."""
        if self._is_64bit:
            rela_fmt = f'{self._endian_char}QQq'  # q = signed 64-bit
            rela_size = 24
        else:
            rela_fmt = f'{self._endian_char}IIi'
            rela_size = 12
        
        num_relocs = section.size // rela_size
        
        # Find associated symbol table
        sym_section = None
        if section.link < len(binary.sections):
            sym_section = binary.sections[section.link]
        
        for i in range(num_relocs):
            offset = i * rela_size
            if offset + rela_size > len(section.data):
                break
            
            rela_data = section.data[offset:offset + rela_size]
            fields = struct.unpack(rela_fmt, rela_data)
            
            r_offset = fields[0]
            r_info = fields[1]
            r_addend = fields[2]
            
            if self._is_64bit:
                r_sym = r_info >> 32
                r_type = r_info & 0xffffffff
            else:
                r_sym = r_info >> 8
                r_type = r_info & 0xff
            
            # Get symbol name
            sym_name = ""
            if r_sym < len(binary.symbols):
                sym_name = binary.symbols[r_sym].name
            
            reloc = Relocation(
                offset=r_offset,
                type_id=r_type,
                symbol_index=r_sym,
                addend=r_addend,
                symbol_name=sym_name
            )
            binary.relocations.append(reloc)
    
    def _parse_rel_section(self, binary: Binary, section: Section) -> None:
        """Parse a REL relocation section (no addend)."""
        if self._is_64bit:
            rel_fmt = f'{self._endian_char}QQ'
            rel_size = 16
        else:
            rel_fmt = f'{self._endian_char}II'
            rel_size = 8
        
        num_relocs = section.size // rel_size
        
        for i in range(num_relocs):
            offset = i * rel_size
            if offset + rel_size > len(section.data):
                break
            
            rel_data = section.data[offset:offset + rel_size]
            fields = struct.unpack(rel_fmt, rel_data)
            
            r_offset = fields[0]
            r_info = fields[1]
            
            if self._is_64bit:
                r_sym = r_info >> 32
                r_type = r_info & 0xffffffff
            else:
                r_sym = r_info >> 8
                r_type = r_info & 0xff
            
            sym_name = ""
            if r_sym < len(binary.symbols):
                sym_name = binary.symbols[r_sym].name
            
            reloc = Relocation(
                offset=r_offset,
                type_id=r_type,
                symbol_index=r_sym,
                addend=0,
                symbol_name=sym_name
            )
            binary.relocations.append(reloc)
    
    def _resolve_plt_got(self, binary: Binary) -> None:
        """
        Resolve PLT/GOT entries to identify imported functions.
        
        This is CRITICAL for understanding dynamic linking.
        
        How PLT/GOT works on x86-64:
        
        1. When code calls printf(), it actually calls printf@plt
        2. PLT entry does: jmp *GOT[printf]
        3. Initially, GOT[printf] points back to PLT (lazy binding)
        4. First call triggers dynamic linker to resolve real address
        5. Dynamic linker updates GOT[printf] with real address
        6. Subsequent calls jump directly to printf
        
        PLT structure (typical):
        ```
        .plt:
          push    [GOT+8]       ; Push link_map
          jmp     [GOT+16]      ; Jump to resolver
          nop...
        
        printf@plt:
          jmp     [GOT+24]      ; Jump through GOT
          push    0             ; Relocation index
          jmp     plt_start     ; Go to resolver
        ```
        
        We find imports by:
        1. Looking at .rela.plt relocations (type R_X86_64_JUMP_SLOT)
        2. Each relocation's offset points to a GOT entry
        3. The symbol gives us the function name
        """
        plt_section = binary.get_section('.plt')
        got_section = binary.get_section('.got.plt') or binary.get_section('.got')
        rela_plt = binary.get_section('.rela.plt')
        
        if rela_plt is None:
            return
        
        # Parse .rela.plt to find imports
        for reloc in binary.relocations:
            if reloc.type_id == R_X86_64.R_X86_64_JUMP_SLOT:
                # This is a PLT relocation
                got_addr = reloc.offset
                func_name = reloc.symbol_name
                
                if func_name:
                    # Calculate PLT address (approximate)
                    # Each PLT entry is typically 16 bytes after the header
                    plt_addr = 0
                    if plt_section:
                        # Find which PLT entry corresponds to this GOT slot
                        # This requires parsing PLT instructions - simplified here
                        plt_addr = plt_section.vaddr  # Would need proper resolution
                    
                    imported = ImportedFunction(
                        name=func_name,
                        library="",  # Would need to parse DT_NEEDED
                        plt_address=plt_addr,
                        got_address=got_addr
                    )
                    binary.imports.append(imported)


# =============================================================================
# Malware Anti-Analysis Techniques in ELF
# =============================================================================

"""
Common ELF tricks used by malware:

1. STRIPPED SECTION HEADERS
   - Section headers are optional for execution
   - Malware removes them to hinder static analysis
   - Detection: e_shnum = 0 or e_shoff = 0
   - Counter: Use program headers and heuristics

2. FAKE SECTION HEADERS
   - Section headers point to wrong data
   - Names are misleading (.text contains encrypted data)
   - Counter: Cross-reference with program headers

3. OVERLAPPING SEGMENTS/SECTIONS
   - Same file bytes mapped to multiple memory regions
   - Confuses disassemblers
   - Counter: Track all mappings, analyze each context

4. SELF-MODIFYING CODE
   - .text section marked writable (PF_W flag)
   - Code decrypts itself at runtime
   - Counter: Check for W+X segments (security violation anyway)

5. ANTI-DEBUG IN CONSTRUCTORS
   - Code in .init_array runs before main()
   - Checks for debuggers, exits if found
   - Counter: Parse .init_array and .fini_array

6. FAKE ENTRY POINT
   - e_entry points to decoy code
   - Real entry is via .init or constructor
   - Counter: Analyze all code paths

7. UPX AND OTHER PACKERS
   - Entire binary compressed/encrypted
   - Small stub unpacks at runtime
   - Counter: Entropy analysis, packer signatures

8. PTRACE TRAP
   - Binary ptrace()s itself
   - Prevents debugger attachment (only one tracer allowed)
   - Counter: Detect ptrace calls in static analysis
"""
