"""
CFG Construction Tests

Verifies that CFG construction:
1. Correctly identifies basic blocks
2. Creates proper edges
3. Handles control flow correctly
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reframework.disasm.decoder import X86Decoder
from reframework.disasm.instruction import FlowType


class MockBinary:
    """Mock binary for testing."""
    
    def __init__(self, code: bytes, base: int = 0x1000):
        self.code = code
        self.base = base
        self.bits = 64
    
    def is_executable_addr(self, addr: int) -> bool:
        offset = addr - self.base
        return 0 <= offset < len(self.code)
    
    def read_bytes_at_vaddr(self, addr: int, size: int) -> bytes:
        offset = addr - self.base
        if offset < 0 or offset >= len(self.code):
            return None
        return self.code[offset:offset + size]


def test_linear_block():
    """Test a simple linear block (no branches)."""
    # push rbp
    # mov rbp, rsp
    # pop rbp
    # ret
    code = bytes.fromhex("55" + "4889e5" + "5d" + "c3")
    
    binary = MockBinary(code, 0x1000)
    
    from reframework.analysis.cfg import CFGBuilder
    builder = CFGBuilder(binary)
    cfg = builder.build(0x1000)
    
    assert len(cfg.blocks) == 1, f"Expected 1 block, got {len(cfg.blocks)}"
    
    block = cfg.blocks[0x1000]
    assert len(block.instructions) == 4
    assert block.is_entry
    assert block.is_exit  # Ends with ret
    
    print("✓ Linear block test passed")


def test_conditional_branch():
    """Test conditional branch creates two successors."""
    # test eax, eax    (85 c0)
    # je +5            (74 05) -> jumps to 0x1009
    # mov eax, 1       (b8 01 00 00 00)
    # ret              (c3) at 0x1009
    code = bytes.fromhex("85c0" + "7405" + "b801000000" + "c3")
    
    binary = MockBinary(code, 0x1000)
    
    from reframework.analysis.cfg import CFGBuilder
    builder = CFGBuilder(binary)
    cfg = builder.build(0x1000)
    
    # Should have 3 blocks:
    # 1. Entry block with test + je
    # 2. Fall-through block with mov eax, 1
    # 3. Target block with ret (or merged)
    
    assert len(cfg.blocks) >= 2, f"Expected at least 2 blocks, got {len(cfg.blocks)}"
    
    entry = cfg.blocks[0x1000]
    assert len(entry.successors) == 2, f"Expected 2 successors, got {len(entry.successors)}"
    
    print("✓ Conditional branch test passed")


def test_unconditional_branch():
    """Test unconditional branch."""
    # jmp +2           (eb 02) -> jumps to 0x1004
    # nop              (90)
    # nop              (90)
    # ret              (c3) at 0x1004
    code = bytes.fromhex("eb02" + "90" + "90" + "c3")
    
    binary = MockBinary(code, 0x1000)
    
    from reframework.analysis.cfg import CFGBuilder
    builder = CFGBuilder(binary)
    cfg = builder.build(0x1000)
    
    entry = cfg.blocks[0x1000]
    assert len(entry.successors) == 1, f"Expected 1 successor, got {len(entry.successors)}"
    assert 0x1004 in entry.successors
    
    # The NOPs should not be reached (dead code)
    assert 0x1002 not in cfg.blocks, "Dead code should not be in CFG"
    
    print("✓ Unconditional branch test passed")


def run_cfg_tests():
    """Run all CFG tests."""
    print("=" * 60)
    print("CFG Construction Tests")
    print("=" * 60)
    
    test_linear_block()
    test_conditional_branch()
    test_unconditional_branch()
    
    print("\nAll CFG tests passed!")


if __name__ == '__main__':
    run_cfg_tests()
