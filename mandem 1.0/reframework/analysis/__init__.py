"""Analysis modules."""

from .cfg import CFGBuilder, CFG, BasicBlock, Edge, EdgeType
from .static import StringExtractor, ExtractedString, EntropyAnalyzer, SectionEntropy

# Alias for backwards compatibility
ControlFlowAnalyzer = CFGBuilder

__all__ = [
    'CFGBuilder', 'ControlFlowAnalyzer', 'CFG', 'BasicBlock', 'Edge', 'EdgeType',
    'StringExtractor', 'ExtractedString', 'EntropyAnalyzer', 'SectionEntropy',
]
