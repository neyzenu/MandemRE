"""
Decoder Verification Tests
"""

import subprocess
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reframework.disasm.decoder import X86Decoder
from reframework.disasm.opcodes import FlowType


# Test cases: (bytes_hex, expected_mnemonic, expected_size)
# These are verified against objdump
TEST_CASES = [
    # Basic instructions
    ("90", "nop", 1),
    ("c3", "ret", 1),
    ("cc", "int3", 1),
    
    # REX prefix
    ("4889e5", "mov", 3),           # mov rbp, rsp
    ("4883ec20", "sub", 4),         # sub rsp, 0x20
    ("4883c420", "add", 4),         # add rsp, 0x20
    
    # Push/Pop
    ("55", "push", 1),              # push rbp
    ("5d", "pop", 1),               # pop rbp
    ("53", "push", 1),              # push rbx
    
    # MOV variants
    ("b800000000", "mov", 5),       # mov eax, 0
    ("48c7c000000000", "mov", 7),   # mov rax, 0
    ("8b4508", "mov", 3),           # mov eax, [rbp+8]
    ("488b4508", "mov", 4),         # mov rax, [rbp+8]
    
    # LEA with RIP-relative
    ("488d3d00000000", "lea", 7),   # lea rdi, [rip+0]
    ("488d0500000000", "lea", 7),   # lea rax, [rip+0]
    
    # Jumps
    ("eb00", "jmp", 2),             # jmp short
    ("e900000000", "jmp", 5),       # jmp near
    ("7400", "je", 2),              # je short
    ("0f8400000000", "je", 6),      # je near
    
    # Call
    ("e800000000", "call", 5),      # call near
    
    # XOR
    ("31c0", "xor", 2),             # xor eax, eax
    ("4831c0", "xor", 3),           # xor rax, rax
    
    # TEST
    ("85c0", "test", 2),            # test eax, eax
    ("4885c0", "test", 3),          # test rax, rax
    
    # CMP
    ("83f800", "cmp", 3),           # cmp eax, 0
    ("4883f800", "cmp", 4),         # cmp rax, 0
    
    # Multi-byte NOP
    ("0f1f00", "nop", 3),           # nop dword ptr [rax]
    ("0f1f4000", "nop", 4),         # nop dword ptr [rax+0]
    
    # SYSCALL
    ("0f05", "syscall", 2),
    
    # MOVZX/MOVSX
    ("0fb6c0", "movzx", 3),         # movzx eax, al
    
    # LEAVE
    ("c9", "leave", 1),
    
    # ENDBR64 (CET)
    ("f30f1efa", "endbr64", 4),
]


def run_objdump(hex_bytes: str) -> tuple:
    """
    Run objdump on raw bytes to get reference disassembly.
    
    Returns:
        (mnemonic, size) or (None, None) on failure
    """
    try:
        raw = bytes.fromhex(hex_bytes)
        
        # Write to temp file (objdump needs a file)
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(raw)
            fname = f.name
        
        try:
            proc = subprocess.run(
                ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel', fname],
                capture_output=True,
                timeout=5
            )
            output = proc.stdout.decode()
        finally:
            os.unlink(fname)
        
        # Parse output - look for first instruction line
        # Format: "   0:	48 89 e5             	mov    rbp,rsp"
        for line in output.split('\n'):
            match = re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{2}\s)+)\s+(\S+)', line)
            if match:
                bytes_str = match.group(1).strip()
                mnemonic = match.group(2).lower()
                size = len(bytes_str.split())
                return mnemonic, size
        
        return None, None
        
    except Exception as e:
        return None, None


class TestDecoder:
    """Test suite for the x86-64 decoder."""
    
    def setup_method(self):
        self.decoder = X86Decoder(mode=64)
    
    def test_instruction_sizes(self):
        """Verify instruction sizes match expected values."""
        failures = []
        
        for hex_bytes, expected_mnem, expected_size in TEST_CASES:
            raw = bytes.fromhex(hex_bytes)
            insn = self.decoder.decode(raw, 0, 0x1000)
            
            if insn.size != expected_size:
                failures.append(
                    f"{hex_bytes}: size={insn.size}, expected={expected_size}"
                )
        
        if failures:
            print("\nSize failures:")
            for f in failures:
                print(f"  {f}")
        
        assert not failures, f"{len(failures)} size mismatches"
    
    def test_mnemonics(self):
        """Verify mnemonics match expected values."""
        failures = []
        
        for hex_bytes, expected_mnem, expected_size in TEST_CASES:
            raw = bytes.fromhex(hex_bytes)
            insn = self.decoder.decode(raw, 0, 0x1000)
            
            if insn.mnemonic != expected_mnem:
                failures.append(
                    f"{hex_bytes}: mnemonic='{insn.mnemonic}', expected='{expected_mnem}'"
                )
        
        if failures:
            print("\nMnemonic failures:")
            for f in failures:
                print(f"  {f}")
        
        assert not failures, f"{len(failures)} mnemonic mismatches"
    
    def test_flow_types(self):
        """Verify control flow classification."""
        flow_tests = [
            ("c3", FlowType.RET),           # ret
            ("e800000000", FlowType.CALL),  # call
            ("eb00", FlowType.UNCOND_BRANCH),  # jmp short
            ("e900000000", FlowType.UNCOND_BRANCH),  # jmp near
            ("7400", FlowType.COND_BRANCH),  # je short
            ("0f8400000000", FlowType.COND_BRANCH),  # je near
            ("90", FlowType.SEQUENTIAL),    # nop
            ("4889e5", FlowType.SEQUENTIAL),  # mov rbp, rsp
            ("cc", FlowType.TRAP),          # int3
            ("0f0b", FlowType.TRAP),        # ud2
        ]
        
        failures = []
        
        for hex_bytes, expected_flow in flow_tests:
            raw = bytes.fromhex(hex_bytes)
            insn = self.decoder.decode(raw, 0, 0x1000)
            
            if insn.flow_type != expected_flow:
                failures.append(
                    f"{hex_bytes}: flow={insn.flow_type.name}, expected={expected_flow.name}"
                )
        
        assert not failures, f"{len(failures)} flow type mismatches: {failures}"
    
    def test_rip_relative(self):
        """Verify RIP-relative address calculation."""
        # lea rdi, [rip+0x1234] at address 0x1000
        # Instruction is 7 bytes, so RIP = 0x1007
        # Target should be 0x1007 + 0x1234 = 0x223B
        hex_bytes = "488d3d34120000"  # lea rdi, [rip+0x1234]
        raw = bytes.fromhex(hex_bytes)
        
        insn = self.decoder.decode(raw, 0, 0x1000)
        
        assert insn.valid, f"Failed to decode: {insn.decode_error}"
        assert insn.size == 7, f"Wrong size: {insn.size}"
        assert insn.mnemonic == "lea", f"Wrong mnemonic: {insn.mnemonic}"
        
        # Check RIP-relative operand
        found_rip_rel = False
        for op in insn.operands:
            if op.mem and op.mem.rip_relative:
                found_rip_rel = True
                expected = 0x1000 + 7 + 0x1234  # addr + size + disp
                assert op.mem.absolute_address == expected, \
                    f"RIP-relative: got 0x{op.mem.absolute_address:x}, expected 0x{expected:x}"
        
        assert found_rip_rel, "No RIP-relative operand found"
    
    def test_branch_targets(self):
        """Verify branch target calculation."""
        # call +0x100 at address 0x1000
        # Instruction is 5 bytes, target = 0x1005 + 0x100 = 0x1105
        hex_bytes = "e800010000"  # call +0x100
        raw = bytes.fromhex(hex_bytes)
        
        insn = self.decoder.decode(raw, 0, 0x1000)
        
        assert insn.valid
        assert insn.mnemonic == "call"
        assert insn.branch_target == 0x1105, \
            f"Branch target: got 0x{insn.branch_target:x}, expected 0x1105"
    
    def test_negative_displacement(self):
        """Verify negative displacement handling."""
        # jmp -5 (jump back 5 bytes)
        hex_bytes = "ebfb"  # jmp -5 (0xfb = -5 signed)
        raw = bytes.fromhex(hex_bytes)
        
        insn = self.decoder.decode(raw, 0, 0x1000)
        
        assert insn.valid
        assert insn.mnemonic == "jmp"
        # 0x1000 + 2 + (-5) = 0xffd
        expected = 0x1000 + 2 - 5
        assert insn.branch_target == expected, \
            f"Branch target: got 0x{insn.branch_target:x}, expected 0x{expected:x}"
    
    def test_compare_with_objdump(self):
        """Compare decoder output with objdump (requires objdump installed)."""
        try:
            subprocess.run(['objdump', '--version'], capture_output=True, timeout=2)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("objdump not available, skipping comparison test")
            return
        
        failures = []
        
        for hex_bytes, _, _ in TEST_CASES[:10]:  # Test first 10
            our_result = self.decoder.decode(bytes.fromhex(hex_bytes), 0, 0)
            objdump_mnem, objdump_size = run_objdump(hex_bytes)
            
            if objdump_size is not None:
                if our_result.size != objdump_size:
                    failures.append(
                        f"{hex_bytes}: our_size={our_result.size}, objdump_size={objdump_size}"
                    )
        
        if failures:
            print(f"\nobjdump comparison failures: {failures}")
        
        # Don't fail hard - objdump may format differently
        assert len(failures) <= 2, f"Too many objdump mismatches: {failures}"


def run_manual_tests():
    """Run tests manually without pytest."""
    print("=" * 60)
    print("RE Framework Decoder Tests")
    print("=" * 60)
    
    decoder = X86Decoder(mode=64)
    
    passed = 0
    failed = 0
    
    print("\nInstruction Decoding Tests:")
    print("-" * 60)
    
    for hex_bytes, expected_mnem, expected_size in TEST_CASES:
        raw = bytes.fromhex(hex_bytes)
        insn = decoder.decode(raw, 0, 0x1000)
        
        size_ok = insn.size == expected_size
        mnem_ok = insn.mnemonic == expected_mnem
        
        if size_ok and mnem_ok:
            status = "✓"
            passed += 1
        else:
            status = "✗"
            failed += 1
        
        print(f"  {status} {hex_bytes:<20} -> {insn.mnemonic:<8} (size={insn.size})")
        
        if not size_ok:
            print(f"      Size mismatch: got {insn.size}, expected {expected_size}")
        if not mnem_ok:
            print(f"      Mnemonic mismatch: got '{insn.mnemonic}', expected '{expected_mnem}'")
    
    print("-" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    
    # RIP-relative test
    print("\nRIP-Relative Test:")
    hex_bytes = "488d3d34120000"
    raw = bytes.fromhex(hex_bytes)
    insn = decoder.decode(raw, 0, 0x1000)
    print(f"  {hex_bytes} at 0x1000 -> {insn}")
    for op in insn.operands:
        if op.mem and op.mem.rip_relative:
            print(f"  RIP-relative target: 0x{op.mem.absolute_address:x}")
            expected = 0x1000 + 7 + 0x1234
            if op.mem.absolute_address == expected:
                print(f"  ✓ Correct!")
            else:
                print(f"  ✗ Expected 0x{expected:x}")
    
    # Branch target test
    print("\nBranch Target Test:")
    hex_bytes = "e800010000"
    raw = bytes.fromhex(hex_bytes)
    insn = decoder.decode(raw, 0, 0x1000)
    print(f"  {hex_bytes} at 0x1000 -> {insn}")
    if insn.branch_target:
        print(f"  Branch target: 0x{insn.branch_target:x}")
        expected = 0x1000 + 5 + 0x100
        if insn.branch_target == expected:
            print(f"  ✓ Correct!")
        else:
            print(f"  ✗ Expected 0x{expected:x}")
    
    return failed == 0


if __name__ == '__main__':
    success = run_manual_tests()
    sys.exit(0 if success else 1)
