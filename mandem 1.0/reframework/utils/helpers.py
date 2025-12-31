"""
Utility functions for binary analysis.
"""

from typing import Tuple, List, Optional


def hexdump(data: bytes, start_addr: int = 0, width: int = 16) -> str:
    """
    Generate a hex dump of binary data.
    
    Format:
    00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 21 00 00 00 00  |Hello World!....|
    
    Args:
        data: Bytes to dump
        start_addr: Starting address for display
        width: Bytes per line (default 16)
        
    Returns:
        Formatted hex dump string
    """
    lines = []
    
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        addr = start_addr + offset
        
        # Hex part
        hex_parts = []
        for i in range(width):
            if i < len(chunk):
                hex_parts.append(f'{chunk[i]:02x}')
            else:
                hex_parts.append('  ')
            if i == width // 2 - 1:
                hex_parts.append('')  # Extra space in middle
        
        hex_str = ' '.join(hex_parts)
        
        # ASCII part
        ascii_chars = []
        for b in chunk:
            if 0x20 <= b < 0x7f:
                ascii_chars.append(chr(b))
            else:
                ascii_chars.append('.')
        ascii_str = ''.join(ascii_chars)
        
        lines.append(f'{addr:08x}  {hex_str}  |{ascii_str}|')
    
    return '\n'.join(lines)


def read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Read an unsigned LEB128 (Little Endian Base 128) encoded integer.
    
    LEB128 is a variable-length encoding used in DWARF debug info and
    other formats. Each byte has 7 data bits and 1 continuation bit.
    
    Encoding:
    - Bit 7 (high bit): 1 = more bytes follow, 0 = last byte
    - Bits 0-6: 7 bits of the value
    
    Example: 624485 (0x98765) encodes as:
    - 0xE5 0x8E 0x26
    - Binary: 1_1100101  1_0001110  0_0100110
    - Value bits: 1100101 + 0001110<<7 + 0100110<<14 = 624485
    
    Args:
        data: Byte buffer
        offset: Starting offset
        
    Returns:
        Tuple of (decoded value, number of bytes consumed)
    """
    result = 0
    shift = 0
    bytes_read = 0
    
    while offset + bytes_read < len(data):
        byte = data[offset + bytes_read]
        bytes_read += 1
        
        # Extract 7 data bits
        result |= (byte & 0x7f) << shift
        shift += 7
        
        # Check continuation bit
        if (byte & 0x80) == 0:
            break
        
        # Prevent infinite loops on malformed data
        if shift > 64:
            raise ValueError("LEB128 value too large")
    
    return result, bytes_read


def read_sleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Read a signed LEB128 encoded integer.
    
    Similar to unsigned LEB128, but the final byte's sign bit
    is extended to fill the remaining bits.
    
    Args:
        data: Byte buffer
        offset: Starting offset
        
    Returns:
        Tuple of (decoded value, number of bytes consumed)
    """
    result = 0
    shift = 0
    bytes_read = 0
    byte = 0
    
    while offset + bytes_read < len(data):
        byte = data[offset + bytes_read]
        bytes_read += 1
        
        result |= (byte & 0x7f) << shift
        shift += 7
        
        if (byte & 0x80) == 0:
            break
        
        if shift > 64:
            raise ValueError("LEB128 value too large")
    
    # Sign extend if the high bit of the last byte is set
    if shift < 64 and (byte & 0x40):
        result |= -(1 << shift)
    
    return result, bytes_read


def align_up(value: int, alignment: int) -> int:
    """Align value up to the next multiple of alignment."""
    if alignment == 0:
        return value
    return (value + alignment - 1) & ~(alignment - 1)


def align_down(value: int, alignment: int) -> int:
    """Align value down to the previous multiple of alignment."""
    if alignment == 0:
        return value
    return value & ~(alignment - 1)


def extract_bits(value: int, start: int, length: int) -> int:
    """
    Extract a bit field from a value.
    
    Args:
        value: The value to extract from
        start: Starting bit position (0 = LSB)
        length: Number of bits to extract
        
    Returns:
        Extracted bits as an integer
    """
    mask = (1 << length) - 1
    return (value >> start) & mask


def sign_extend(value: int, bits: int) -> int:
    """
    Sign extend a value from 'bits' width to Python integer.
    
    Args:
        value: The value to sign extend
        bits: Original bit width
        
    Returns:
        Sign extended value
    """
    sign_bit = 1 << (bits - 1)
    if value & sign_bit:
        # Negative: extend with 1s
        return value - (1 << bits)
    return value


def find_strings(data: bytes, min_length: int = 4) -> List[Tuple[int, str]]:
    """
    Extract printable ASCII strings from binary data.
    
    Args:
        data: Binary data to search
        min_length: Minimum string length
        
    Returns:
        List of (offset, string) tuples
    """
    strings = []
    current_start = None
    current_chars = []
    
    for i, byte in enumerate(data):
        # Printable ASCII range (space to tilde) plus tab and newline
        if 0x20 <= byte < 0x7f or byte in (0x09, 0x0a, 0x0d):
            if current_start is None:
                current_start = i
                current_chars = []
            current_chars.append(chr(byte))
        else:
            # Check if we have a valid string
            if current_start is not None and len(current_chars) >= min_length:
                # Check for null terminator
                if byte == 0:
                    strings.append((current_start, ''.join(current_chars)))
            current_start = None
            current_chars = []
    
    # Handle string at end of data
    if current_start is not None and len(current_chars) >= min_length:
        strings.append((current_start, ''.join(current_chars)))
    
    return strings


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    
    Entropy measures randomness/information density:
    - 0.0 = completely uniform (all same byte)
    - 8.0 = maximum randomness (for bytes)
    
    High entropy (>7.0) often indicates:
    - Encrypted data
    - Compressed data
    - Packed executables
    
    Args:
        data: Bytes to analyze
        
    Returns:
        Entropy value (0.0 to 8.0)
    """
    import math
    
    if len(data) == 0:
        return 0.0
    
    # Count byte frequencies
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    
    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    
    for count in freq:
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)
    
    return entropy


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    XOR data with a repeating key.
    
    Common in malware for simple obfuscation.
    
    Args:
        data: Data to XOR
        key: Key to XOR with (repeats if shorter than data)
        
    Returns:
        XORed bytes
    """
    if len(key) == 0:
        return data
    
    result = bytearray(len(data))
    for i, byte in enumerate(data):
        result[i] = byte ^ key[i % len(key)]
    
    return bytes(result)
