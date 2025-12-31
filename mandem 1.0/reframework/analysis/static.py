"""
Static Analysis Module - Strings and Entropy
"""

import math
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ExtractedString:
    """A string extracted from the binary."""
    address: int
    value: str
    encoding: str = "ascii"
    section: str = ""
    is_url: bool = False
    is_path: bool = False
    is_ip: bool = False


@dataclass
class SectionEntropy:
    """Entropy information for a section."""
    name: str
    entropy: float
    size: int
    is_suspicious: bool = False


class StringExtractor:
    """Extract strings from binary."""
    
    def __init__(self, binary, min_length: int = 4):
        self.binary = binary
        self.min_length = min_length
        
        # Patterns for classification
        self._url_pattern = re.compile(
            rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
        )
        self._ip_pattern = re.compile(
            rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        )
        self._path_pattern = re.compile(
            rb'(?:[A-Za-z]:\\|/(?:usr|etc|var|home|tmp|bin|lib|opt))[^\x00\n\r]*'
        )
        self._registry_pattern = re.compile(
            rb'(?:HKEY_|HKLM|HKCU|SOFTWARE\\|SYSTEM\\)[^\x00\n\r]*',
            re.IGNORECASE
        )
    
    def extract_all(self) -> List[ExtractedString]:
        """Extract all strings from binary."""
        strings = []
        
        for section in self.binary.sections:
            if not section.data or len(section.data) == 0:
                continue
            
            # Extract ASCII strings
            ascii_strings = self._extract_ascii(section)
            strings.extend(ascii_strings)
            
            # Extract UTF-16 LE strings (common in Windows binaries)
            utf16_strings = self._extract_utf16(section)
            strings.extend(utf16_strings)
        
        return sorted(strings, key=lambda s: s.address)
    
    def _extract_ascii(self, section) -> List[ExtractedString]:
        """Extract ASCII strings from a section."""
        strings = []
        data = section.data
        
        current_start = None
        current_chars = []
        
        for i, byte in enumerate(data):
            # Printable ASCII range plus common whitespace
            if 0x20 <= byte < 0x7f or byte in (0x09, 0x0a, 0x0d):
                if current_start is None:
                    current_start = i
                    current_chars = []
                current_chars.append(chr(byte))
            else:
                # Check if we have a valid string
                if current_start is not None and len(current_chars) >= self.min_length:
                    if byte == 0:  # Null terminated
                        addr = section.vaddr + current_start
                        value = ''.join(current_chars)
                        s = ExtractedString(
                            address=addr,
                            value=value,
                            encoding="ascii",
                            section=section.name
                        )
                        self._classify_string(s)
                        strings.append(s)
                current_start = None
                current_chars = []
        
        # Handle string at end of section
        if current_start is not None and len(current_chars) >= self.min_length:
            addr = section.vaddr + current_start
            value = ''.join(current_chars)
            s = ExtractedString(
                address=addr,
                value=value,
                encoding="ascii",
                section=section.name
            )
            self._classify_string(s)
            strings.append(s)
        
        return strings
    
    def _extract_utf16(self, section) -> List[ExtractedString]:
        """Extract UTF-16 LE strings from a section."""
        strings = []
        data = section.data
        
        i = 0
        while i < len(data) - 1:
            # Look for potential UTF-16 LE start (ASCII char followed by 0x00)
            if 0x20 <= data[i] < 0x7f and data[i + 1] == 0x00:
                start = i
                chars = []
                
                while i < len(data) - 1:
                    if data[i + 1] == 0x00 and (0x20 <= data[i] < 0x7f or data[i] in (0x09, 0x0a, 0x0d)):
                        chars.append(chr(data[i]))
                        i += 2
                    elif data[i] == 0x00 and data[i + 1] == 0x00:
                        # Null terminator
                        break
                    else:
                        break
                
                if len(chars) >= self.min_length:
                    addr = section.vaddr + start
                    value = ''.join(chars)
                    s = ExtractedString(
                        address=addr,
                        value=value,
                        encoding="utf-16le",
                        section=section.name
                    )
                    self._classify_string(s)
                    strings.append(s)
            else:
                i += 1
        
        return strings
    
    def _classify_string(self, s: ExtractedString) -> None:
        """Classify string type."""
        value_bytes = s.value.encode('utf-8', errors='ignore')
        
        if self._url_pattern.search(value_bytes):
            s.is_url = True
        if self._ip_pattern.search(value_bytes):
            s.is_ip = True
        if self._path_pattern.search(value_bytes):
            s.is_path = True
        if self._registry_pattern.search(value_bytes):
            s.is_registry = True


class EntropyAnalyzer:
    """Analyze entropy of binary sections."""
    
    def __init__(self, binary):
        self.binary = binary
    
    def analyze_sections(self) -> List[SectionEntropy]:
        """Calculate entropy for all sections."""
        results = []
        
        for section in self.binary.sections:
            if not section.data or len(section.data) == 0:
                continue
            
            entropy = self._calculate_entropy(section.data)
            
            is_suspicious = False
            if section.name in ('.text', '.code'):
                if entropy > 7.0:
                    is_suspicious = True
            elif entropy > 7.5:
                is_suspicious = True
            
            results.append(SectionEntropy(
                name=section.name,
                entropy=entropy,
                size=len(section.data),
                is_suspicious=is_suspicious
            ))
        
        return results
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if len(data) == 0:
            return 0.0
        
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in freq:
            if count > 0:
                p = count / data_len
                entropy -= p * math.log2(p)
        
        return entropy
    
    def is_likely_packed(self) -> tuple:
        """Check if binary is likely packed."""
        results = self.analyze_sections()
        reasons = []
        
        for r in results:
            if r.is_suspicious:
                reasons.append(f"High entropy in {r.name}: {r.entropy:.2f}")
        
        if len(self.binary.sections) <= 2:
            reasons.append("Very few sections")
        
        return (len(reasons) > 0, "; ".join(reasons) if reasons else "No packing detected")
