"""
Abstract binary representation.
This provides a unified interface regardless of binary format (ELF/PE).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import IntEnum, IntFlag, auto


class BinaryType(IntEnum):
    """Type of binary file."""
    UNKNOWN = 0
    ELF = 1
    PE = 2
    MACHO = 3


class Architecture(IntEnum):
    """Target CPU architecture."""
    UNKNOWN = 0
    X86 = 1
    X86_64 = 2
    ARM = 3
    ARM64 = 4


class Endianness(IntEnum):
    """Byte order."""
    LITTLE = 1
    BIG = 2


class SegmentFlags(IntFlag):
    """Memory segment permissions."""
    NONE = 0
    EXECUTE = 1
    WRITE = 2
    READ = 4


@dataclass
class Segment:
    """
    A loadable memory segment.
    
    This represents a contiguous region of memory that the OS loader
    will map into the process address space.
    
    Attributes:
        name: Human-readable name (e.g., "LOAD", "INTERP")
        vaddr: Virtual address where segment is loaded
        paddr: Physical address (usually same as vaddr on modern systems)
        file_offset: Offset in file where segment data begins
        file_size: Size of segment data in file
        mem_size: Size of segment in memory (may be > file_size for .bss)
        flags: Permission flags (R/W/X)
        align: Alignment requirement
    """
    name: str
    vaddr: int
    paddr: int
    file_offset: int
    file_size: int
    mem_size: int
    flags: SegmentFlags
    align: int
    data: bytes = field(default=b'', repr=False)


@dataclass
class Section:
    """
    A named section within the binary.
    
    Sections provide more granular information than segments.
    They're used by the linker and debugger, not the loader.
    
    Attributes:
        name: Section name (e.g., ".text", ".data")
        vaddr: Virtual address
        file_offset: Offset in file
        size: Section size
        type_id: Section type (platform-specific)
        flags: Section flags
        link: Link to another section (section-type dependent)
        info: Additional info (section-type dependent)
        align: Alignment requirement
        entry_size: Size of entries if section holds a table
    """
    name: str
    vaddr: int
    file_offset: int
    size: int
    type_id: int
    flags: int
    link: int
    info: int
    align: int
    entry_size: int
    data: bytes = field(default=b'', repr=False)


@dataclass
class Symbol:
    """
    A symbol (function, variable, etc.) in the binary.
    
    Attributes:
        name: Symbol name
        value: Symbol value (usually address)
        size: Size of the symbol (0 if unknown)
        type_id: Symbol type (function, object, etc.)
        binding: Symbol binding (local, global, weak)
        visibility: Symbol visibility
        section_index: Index of section containing this symbol
    """
    name: str
    value: int
    size: int
    type_id: int
    binding: int
    visibility: int
    section_index: int
    
    def is_function(self) -> bool:
        """Check if this symbol represents a function."""
        # STT_FUNC = 2 in ELF
        return self.type_id == 2
    
    def is_global(self) -> bool:
        """Check if this is a global symbol."""
        # STB_GLOBAL = 1 in ELF
        return self.binding == 1


@dataclass
class Relocation:
    """
    A relocation entry.
    
    Relocations tell the loader how to patch addresses at load time.
    Critical for understanding PLT/GOT and dynamic linking.
    
    Attributes:
        offset: Address to patch
        type_id: Relocation type (architecture-specific)
        symbol_index: Index of symbol this relocation refers to
        addend: Value to add during relocation calculation
    """
    offset: int
    type_id: int
    symbol_index: int
    addend: int
    symbol_name: str = ""


@dataclass
class ImportedFunction:
    """
    A function imported from a shared library.
    
    Attributes:
        name: Function name
        library: Library name (if known)
        plt_address: Address in PLT (Procedure Linkage Table)
        got_address: Address in GOT (Global Offset Table)
    """
    name: str
    library: str
    plt_address: int
    got_address: int


@dataclass
class ExportedFunction:
    """
    A function exported by this binary.
    
    Attributes:
        name: Function name
        address: Virtual address of function
        size: Function size (if known)
    """
    name: str
    address: int
    size: int


class Binary:
    """
    Abstract binary representation.
    
    This class provides a unified interface for working with binary files
    regardless of their format (ELF, PE, Mach-O).
    
    The Binary object is the central data structure passed to all analysis
    modules. It contains:
    - Raw file data
    - Parsed metadata (headers, sections, symbols)
    - Memory mapping information
    - Resolved imports/exports
    """
    
    def __init__(self, filepath: str):
        """
        Initialize binary from file path.
        
        Args:
            filepath: Path to the binary file
        """
        self.filepath = filepath
        self.data: bytes = b''
        
        # Basic properties
        self.binary_type = BinaryType.UNKNOWN
        self.arch = Architecture.UNKNOWN
        self.endian = Endianness.LITTLE
        self.bits = 64  # 32 or 64
        self.entry_point = 0
        
        # Parsed structures
        self.segments: List[Segment] = []
        self.sections: List[Section] = []
        self.symbols: List[Symbol] = []
        self.relocations: List[Relocation] = []
        
        # Resolved imports/exports
        self.imports: List[ImportedFunction] = []
        self.exports: List[ExportedFunction] = []
        
        # Lookup tables (populated after parsing)
        self._section_by_name: Dict[str, Section] = {}
        self._section_by_addr: Dict[int, Section] = {}
        self._symbol_by_name: Dict[str, Symbol] = {}
        self._symbol_by_addr: Dict[int, Symbol] = {}
        
        # Load the file
        self._load_file()
    
    def _load_file(self) -> None:
        """Load raw binary data from file."""
        with open(self.filepath, 'rb') as f:
            self.data = f.read()
    
    def build_lookup_tables(self) -> None:
        """Build lookup tables for fast access."""
        self._section_by_name = {s.name: s for s in self.sections}
        self._section_by_addr = {s.vaddr: s for s in self.sections if s.vaddr}
        self._symbol_by_name = {s.name: s for s in self.symbols if s.name}
        self._symbol_by_addr = {s.value: s for s in self.symbols if s.value}
    
    def get_section(self, name: str) -> Optional[Section]:
        """Get section by name."""
        return self._section_by_name.get(name)
    
    def get_section_at(self, addr: int) -> Optional[Section]:
        """Get section containing the given address."""
        for section in self.sections:
            if section.vaddr <= addr < section.vaddr + section.size:
                return section
        return None
    
    def get_symbol(self, name: str) -> Optional[Symbol]:
        """Get symbol by name."""
        return self._symbol_by_name.get(name)
    
    def get_symbol_at(self, addr: int) -> Optional[Symbol]:
        """Get symbol at exact address."""
        return self._symbol_by_addr.get(addr)
    
    def get_segment_at(self, addr: int) -> Optional[Segment]:
        """Get segment containing the given address."""
        for seg in self.segments:
            if seg.vaddr <= addr < seg.vaddr + seg.mem_size:
                return seg
        return None
    
    def vaddr_to_file_offset(self, vaddr: int) -> Optional[int]:
        """
        Convert virtual address to file offset.
        
        This is CRITICAL for disassembly. Instructions exist at virtual
        addresses, but we need file offsets to read the bytes.
        
        The formula is:
            file_offset = vaddr - segment.vaddr + segment.file_offset
        
        Args:
            vaddr: Virtual address to convert
            
        Returns:
            File offset, or None if address not in any segment
        """
        for seg in self.segments:
            # Check if vaddr falls within this segment's virtual range
            if seg.vaddr <= vaddr < seg.vaddr + seg.mem_size:
                # Calculate offset within segment
                offset_in_segment = vaddr - seg.vaddr
                
                # Check if this offset has backing file data
                # (addresses beyond file_size are zero-filled, like .bss)
                if offset_in_segment < seg.file_size:
                    return seg.file_offset + offset_in_segment
                else:
                    # Address is in zero-filled region
                    return None
        return None
    
    def file_offset_to_vaddr(self, offset: int) -> Optional[int]:
        """
        Convert file offset to virtual address.
        
        Args:
            offset: File offset to convert
            
        Returns:
            Virtual address, or None if offset not in any segment
        """
        for seg in self.segments:
            if seg.file_offset <= offset < seg.file_offset + seg.file_size:
                offset_in_segment = offset - seg.file_offset
                return seg.vaddr + offset_in_segment
        return None
    
    def read_bytes_at_vaddr(self, vaddr: int, size: int) -> Optional[bytes]:
        """
        Read bytes from the binary at a virtual address.
        
        Args:
            vaddr: Virtual address to read from
            size: Number of bytes to read
            
        Returns:
            Bytes read, or None if address is invalid
        """
        file_offset = self.vaddr_to_file_offset(vaddr)
        if file_offset is None:
            return None
        
        if file_offset + size > len(self.data):
            return None
        
        return self.data[file_offset:file_offset + size]
    
    def read_cstring_at_vaddr(self, vaddr: int, max_len: int = 4096) -> Optional[str]:
        """
        Read a null-terminated C string from virtual address.
        
        Args:
            vaddr: Virtual address of string start
            max_len: Maximum length to read
            
        Returns:
            Decoded string, or None if invalid
        """
        data = self.read_bytes_at_vaddr(vaddr, max_len)
        if data is None:
            return None
        
        # Find null terminator
        try:
            null_pos = data.index(b'\x00')
            return data[:null_pos].decode('utf-8', errors='replace')
        except ValueError:
            return data.decode('utf-8', errors='replace')
    
    def is_executable_addr(self, addr: int) -> bool:
        """Check if address is in executable memory."""
        seg = self.get_segment_at(addr)
        return seg is not None and bool(seg.flags & SegmentFlags.EXECUTE)
    
    def is_writable_addr(self, addr: int) -> bool:
        """Check if address is in writable memory."""
        seg = self.get_segment_at(addr)
        return seg is not None and bool(seg.flags & SegmentFlags.WRITE)
    
    def get_executable_ranges(self) -> List[Tuple[int, int]]:
        """
        Get all executable memory ranges.
        
        Returns:
            List of (start_addr, end_addr) tuples
        """
        ranges = []
        for seg in self.segments:
            if seg.flags & SegmentFlags.EXECUTE:
                ranges.append((seg.vaddr, seg.vaddr + seg.mem_size))
        return ranges
    
    def __repr__(self) -> str:
        return (
            f"Binary(type={self.binary_type.name}, "
            f"arch={self.arch.name}, "
            f"bits={self.bits}, "
            f"entry=0x{self.entry_point:x})"
        )
