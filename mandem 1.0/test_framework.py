#!/usr/bin/env python3
"""
Test script for the RE Framework.

This script tests the framework against a sample binary.
"""

import sys
import os

# Add framework to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reframework import (
    ELFParser, X86Decoder, 
    FunctionAnalyzer, ControlFlowAnalyzer,
    StringExtractor, EntropyAnalyzer,
    PluginManager, PluginContext
)
from reframework.plugins.builtin import (
    AntiDebugPlugin, NetworkIOCPlugin, 
    CredentialPlugin, ImportAnalysisPlugin
)


def test_elf_parser(filepath: str):
    """Test ELF parsing."""
    print("\n" + "=" * 60)
    print("TEST: ELF Parser")
    print("=" * 60)
    
    parser = ELFParser()
    binary = parser.parse(filepath)
    
    print(f"[+] Parsed: {binary}")
    print(f"    Entry point: 0x{binary.entry_point:x}")
    print(f"    Sections: {len(binary.sections)}")
    print(f"    Segments: {len(binary.segments)}")
    print(f"    Symbols: {len(binary.symbols)}")
    print(f"    Imports: {len(binary.imports)}")
    
    # Print some sections
    print("\n    Sections:")
    for section in binary.sections[:10]:
        print(f"      {section.name:<20} 0x{section.vaddr:016x} {section.size} bytes")
    
    return binary


def test_decoder(binary):
    """Test instruction decoder."""
    print("\n" + "=" * 60)
    print("TEST: Instruction Decoder")
    print("=" * 60)
    
    decoder = X86Decoder(mode=binary.bits)
    
    # Decode at entry point
    entry = binary.entry_point
    print(f"\n    Decoding at entry point 0x{entry:x}:")
    
    current = entry
    for i in range(10):
        data = binary.read_bytes_at_vaddr(current, 15)
        if data is None:
            break
        
        insn = decoder.decode(data, 0, current)
        if insn is None or insn.size == 0:
            break
        
        print(f"      {insn.format_with_address()}")
        current += insn.size
    
    return decoder


def test_function_analysis(binary):
    """Test function analysis."""
    print("\n" + "=" * 60)
    print("TEST: Function Analysis")
    print("=" * 60)
    
    analyzer = FunctionAnalyzer(binary)
    functions = analyzer.analyze()
    
    print(f"\n[+] Found {len(functions)} functions")
    
    # Print first 10 functions
    print("\n    Sample functions:")
    for addr in sorted(functions.keys())[:10]:
        func = functions[addr]
        print(f"      0x{addr:016x} {func.name or 'unnamed':<30} {func.size} bytes")
    
    return functions


def test_cfg(binary):
    """Test CFG construction."""
    print("\n" + "=" * 60)
    print("TEST: Control Flow Graph")
    print("=" * 60)
    
    analyzer = ControlFlowAnalyzer(binary)
    
    # Build CFG for entry point
    entry = binary.entry_point
    cfg = analyzer.build_cfg(entry, "_start")
    
    print(f"\n[+] Built CFG: {cfg}")
    print(f"    Entry: 0x{cfg.entry_address:x}")
    print(f"    Blocks: {len(cfg.blocks)}")
    print(f"    Edges: {len(cfg.edges)}")
    
    return cfg


def test_strings(binary):
    """Test string extraction."""
    print("\n" + "=" * 60)
    print("TEST: String Extraction")
    print("=" * 60)
    
    extractor = StringExtractor(binary, min_length=4)
    strings = extractor.extract_all()
    
    print(f"\n[+] Found {len(strings)} strings")
    
    # Print some interesting strings
    print("\n    Sample strings:")
    for s in strings[:15]:
        flags = []
        if s.is_url:
            flags.append('URL')
        if s.is_path:
            flags.append('PATH')
        if s.is_ip:
            flags.append('IP')
        
        flag_str = f" [{','.join(flags)}]" if flags else ""
        print(f"      0x{s.address:08x}: {s.value[:60]}{flag_str}")
    
    return strings


def test_entropy(binary):
    """Test entropy analysis."""
    print("\n" + "=" * 60)
    print("TEST: Entropy Analysis")
    print("=" * 60)
    
    analyzer = EntropyAnalyzer(binary)
    results = analyzer.analyze_sections()
    
    print("\n    Section entropy:")
    for r in results:
        status = "⚠ HIGH" if r.is_suspicious else "OK"
        print(f"      {r.name:<20} {r.entropy:.4f} {status}")
    
    is_packed, reason = analyzer.is_likely_packed()
    print(f"\n    Packed: {'Yes - ' + reason if is_packed else 'No'}")
    
    return results


def test_plugins(binary, functions, strings):
    """Test plugin system."""
    print("\n" + "=" * 60)
    print("TEST: Plugin System")
    print("=" * 60)
    
    manager = PluginManager()
    
    # Register plugins
    manager.register(AntiDebugPlugin())
    manager.register(NetworkIOCPlugin())
    manager.register(CredentialPlugin())
    manager.register(ImportAnalysisPlugin())
    
    print(f"\n[+] Registered {len(manager.plugins)} plugins")
    
    # Build context
    context = PluginContext(
        binary=binary,
        functions=functions,
        strings=strings
    )
    
    # Run all plugins
    results = manager.run_all(context)
    
    # Print results
    for result in results:
        status = "✓" if result.success else "✗"
        print(f"\n    [{status}] {result.plugin_name}: {result.summary}")
        if result.findings:
            for f in result.findings[:5]:
                print(f"        - {f.get('description', '')[:60]}")
            if len(result.findings) > 5:
                print(f"        ... and {len(result.findings) - 5} more")
    
    return results


def main():
    """Run all tests."""
    if len(sys.argv) < 2:
        # Try to find a test binary
        test_paths = [
            '/bin/ls',
            '/bin/cat',
            '/usr/bin/id',
            '/bin/echo'
        ]
        
        filepath = None
        for path in test_paths:
            if os.path.exists(path):
                filepath = path
                break
        
        if filepath is None:
            print("Usage: python test_framework.py <binary>")
            print("Or ensure /bin/ls exists for default testing")
            sys.exit(1)
    else:
        filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        sys.exit(1)
    
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║          RE Framework - Test Suite                        ║
╚═══════════════════════════════════════════════════════════╝

Testing with: {filepath}
""")
    
    try:
        # Run tests
        binary = test_elf_parser(filepath)
        decoder = test_decoder(binary)
        functions = test_function_analysis(binary)
        cfg = test_cfg(binary)
        strings = test_strings(binary)
        entropy = test_entropy(binary)
        plugins = test_plugins(binary, functions, strings)
        
        print("\n" + "=" * 60)
        print("ALL TESTS COMPLETED SUCCESSFULLY")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n[!] Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
