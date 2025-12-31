"""
RE Framework - A Pure Python Reverse Engineering Toolkit

This framework provides:
- ELF binary parsing (no external dependencies)
- x86-64 instruction decoding (custom implementation)
- Control flow graph analysis
- Function detection and analysis
- Static analysis (strings, entropy, patterns)
- Plugin system for extensibility

Usage:
    from reframework import ELFParser, X86Decoder, FunctionAnalyzer
    
    parser = ELFParser()
    binary = parser.parse("/path/to/binary")
    
    decoder = X86Decoder(mode=64)
    insn = decoder.decode(data, 0, address)
"""

__version__ = "0.2.0"
__author__ = "RE Framework"

# Core loader
from .loader.binary import Binary, Section, Segment, Symbol
from .loader.elf import ELFParser

# Disassembler (new architecture)
from .disasm import X86Decoder, Instruction, Operand, FlowType

# Analysis
from .analysis import (
    CFGBuilder, ControlFlowAnalyzer, CFG, BasicBlock,
    StringExtractor, EntropyAnalyzer
)

# Plugins
from .plugins import Plugin, PluginManager, PluginContext, PluginResult

__all__ = [
    # Version
    '__version__',
    
    # Loader
    'Binary', 'Section', 'Segment', 'Symbol', 'ELFParser',
    
    # Disassembler
    'X86Decoder', 'Instruction', 'Operand', 'FlowType',
    
    # Analysis
    'CFGBuilder', 'ControlFlowAnalyzer', 'CFG', 'BasicBlock',
    'StringExtractor', 'EntropyAnalyzer',
    
    # Plugins
    'Plugin', 'PluginManager', 'PluginContext', 'PluginResult',
]
