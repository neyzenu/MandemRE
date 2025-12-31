"""
Command Line Interface
"""

import argparse
import sys
import os
from typing import Optional, List, Dict, Any
from pathlib import Path

from ..loader.elf import ELFParser
from ..loader.binary import Binary
from ..disasm.decoder import X86Decoder
from ..disasm.opcodes import FlowType
from ..analysis.cfg import CFGBuilder
from ..analysis.static import StringExtractor, EntropyAnalyzer
from ..plugins.base import PluginManager, PluginContext
from ..utils.helpers import hexdump


class CLI:
    """Interactive command-line interface."""
    
    def __init__(self):
        self.binary: Optional[Binary] = None
        self.functions: Dict[int, Any] = {}
        self.strings: List[Any] = []
        
        self.decoder: Optional[X86Decoder] = None
        self.cfg_builder: Optional[CFGBuilder] = None
        self.plugin_manager = PluginManager()
        
        # Register all commands
        self.commands = {
            'help': self.cmd_help,
            'load': self.cmd_load,
            'info': self.cmd_info,
            'sections': self.cmd_sections,
            'segments': self.cmd_segments,
            'symbols': self.cmd_symbols,
            'imports': self.cmd_imports,
            'exports': self.cmd_exports,
            'strings': self.cmd_strings,
            'functions': self.cmd_functions,
            'disasm': self.cmd_disasm,
            'hexdump': self.cmd_hexdump,
            'cfg': self.cmd_cfg,
            'entropy': self.cmd_entropy,
            'plugins': self.cmd_plugins,
            'run': self.cmd_run_plugin,
            'quit': self.cmd_quit,
            'exit': self.cmd_quit,
        }
    
    def run_interactive(self) -> None:
        """Run interactive CLI mode."""
        print("""
╔═══════════════════════════════════════════════════════════╗
║     RE Framework v0.2.0 - Reverse Engineering Toolkit     ║
╚═══════════════════════════════════════════════════════════╝
        """)
        print("Type 'help' for available commands.\n")
        
        while True:
            try:
                prompt = "re> " if self.binary is None else f"re:{Path(self.binary.filepath).name}> "
                cmd_line = input(prompt).strip()
                
                if not cmd_line:
                    continue
                
                parts = cmd_line.split()
                cmd = parts[0].lower()
                args = parts[1:]
                
                if cmd in self.commands:
                    self.commands[cmd](args)
                else:
                    print(f"Unknown command: {cmd}")
                    print("Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\nUse 'quit' to exit.")
            except EOFError:
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def cmd_help(self, args: List[str]) -> None:
        """Display help information."""
        print("""
Available Commands:
═══════════════════════════════════════════════════════════════

File Operations:
  load <path>         Load a binary file for analysis
  info                Display binary information

Structure Analysis:
  sections            List sections
  segments            List segments
  symbols             List symbols
  imports             List imported functions
  exports             List exported functions

Code Analysis:
  strings [min_len]   Extract strings (default min_len=4)
  functions           Analyze and list functions
  disasm <addr> [n]   Disassemble at address (n instructions)
  hexdump <addr> [n]  Hex dump at address (n bytes)
  cfg <addr>          Show CFG for function at address

Security Analysis:
  entropy             Analyze section entropy (packer detection)

Plugin System:
  plugins             List available plugins
  run <plugin|all>    Run a specific plugin or all plugins

Other:
  help                Show this help
  quit/exit           Exit the program

Addresses can be specified in decimal or hex (0x prefix).
""")
    
    def cmd_load(self, args: List[str]) -> None:
        """Load a binary file."""
        if not args:
            print("Usage: load <path>")
            return
        
        filepath = args[0]
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return
        
        try:
            print(f"[*] Loading {filepath}...")
            parser = ELFParser()
            self.binary = parser.parse(filepath)
            
            self.decoder = X86Decoder(mode=self.binary.bits)
            self.cfg_builder = CFGBuilder(self.binary, self.decoder)
            self.functions = {}
            self.strings = []
            
            print(f"[+] Loaded: {self.binary}")
            print(f"    Architecture: {self.binary.arch.name}")
            print(f"    Entry point: 0x{self.binary.entry_point:x}")
            print(f"    Sections: {len(self.binary.sections)}")
            
        except Exception as e:
            print(f"[!] Failed to load: {e}")
    
    def cmd_info(self, args: List[str]) -> None:
        """Display binary information."""
        if not self._check_loaded():
            return
        
        print(f"""
Binary Information:
═══════════════════════════════════════════════════════════════
  File:          {self.binary.filepath}
  Type:          {self.binary.binary_type.name}
  Architecture:  {self.binary.arch.name}
  Bits:          {self.binary.bits}
  Entry Point:   0x{self.binary.entry_point:x}
  Sections:      {len(self.binary.sections)}
  Segments:      {len(self.binary.segments)}
  Symbols:       {len(self.binary.symbols)}
  Imports:       {len(self.binary.imports)}
  Exports:       {len(self.binary.exports)}
""")
    
    def cmd_sections(self, args: List[str]) -> None:
        """List sections."""
        if not self._check_loaded():
            return
        
        print(f"\n{'Name':<20} {'VAddr':<18} {'Size':<12} {'Type'}")
        print("=" * 70)
        
        for section in self.binary.sections:
            print(f"{section.name:<20} 0x{section.vaddr:016x} {section.size:<12} {section.type_id}")
    
    def cmd_segments(self, args: List[str]) -> None:
        """List segments."""
        if not self._check_loaded():
            return
        
        print(f"\n{'Type':<15} {'VAddr':<18} {'FileSize':<12} {'MemSize':<12} {'Flags'}")
        print("=" * 70)
        
        for seg in self.binary.segments:
            flags = []
            if seg.flags.value & 4:
                flags.append('R')
            if seg.flags.value & 2:
                flags.append('W')
            if seg.flags.value & 1:
                flags.append('X')
            flag_str = ''.join(flags) if flags else '-'
            
            print(f"{seg.name:<15} 0x{seg.vaddr:016x} {seg.file_size:<12} {seg.mem_size:<12} {flag_str}")
    
    def cmd_symbols(self, args: List[str]) -> None:
        """List symbols."""
        if not self._check_loaded():
            return
        
        print(f"\n{'Value':<18} {'Size':<8} {'Type':<8} {'Name'}")
        print("=" * 70)
        
        for sym in self.binary.symbols:
            if not sym.name:
                continue
            type_str = 'FUNC' if sym.is_function() else 'OBJ'
            print(f"0x{sym.value:016x} {sym.size:<8} {type_str:<8} {sym.name}")
    
    def cmd_imports(self, args: List[str]) -> None:
        """List imported functions."""
        if not self._check_loaded():
            return
        
        if not self.binary.imports:
            print("No imports found.")
            return
        
        print(f"\n{'PLT Address':<18} {'GOT Address':<18} {'Name'}")
        print("=" * 70)
        
        for imp in self.binary.imports:
            print(f"0x{imp.plt_address:016x} 0x{imp.got_address:016x} {imp.name}")
    
    def cmd_exports(self, args: List[str]) -> None:
        """List exported functions."""
        if not self._check_loaded():
            return
        
        if not self.binary.exports:
            print("No exports found.")
            return
        
        print(f"\n{'Address':<18} {'Size':<8} {'Name'}")
        print("=" * 60)
        
        for exp in self.binary.exports:
            print(f"0x{exp.address:016x} {exp.size:<8} {exp.name}")
    
    def cmd_strings(self, args: List[str]) -> None:
        """Extract and display strings."""
        if not self._check_loaded():
            return
        
        min_len = 4
        if args:
            try:
                min_len = int(args[0])
            except ValueError:
                pass
        
        print(f"[*] Extracting strings (min length: {min_len})...")
        
        extractor = StringExtractor(self.binary, min_length=min_len)
        self.strings = extractor.extract_all()
        
        print(f"[+] Found {len(self.strings)} strings\n")
        
        for s in self.strings[:100]:
            flags = []
            if s.is_url:
                flags.append('URL')
            if s.is_ip:
                flags.append('IP')
            if s.is_path:
                flags.append('PATH')
            
            flag_str = f" [{','.join(flags)}]" if flags else ""
            print(f"0x{s.address:08x}: {s.value[:80]}{flag_str}")
        
        if len(self.strings) > 100:
            print(f"\n... and {len(self.strings) - 100} more")
    
    def cmd_functions(self, args: List[str]) -> None:
        """List discovered functions."""
        if not self._check_loaded():
            return
        
        # Simple function discovery from symbols
        print(f"\n{'Address':<18} {'Size':<8} {'Name'}")
        print("=" * 60)
        
        count = 0
        for sym in self.binary.symbols:
            if sym.is_function() and sym.value != 0:
                print(f"0x{sym.value:016x} {sym.size:<8} {sym.name or f'sub_{sym.value:x}'}")
                count += 1
        
        print(f"\nTotal: {count} functions from symbols")
    
    def cmd_disasm(self, args: List[str]) -> None:
        """Disassemble at address."""
        if not self._check_loaded():
            return
        
        if not args:
            print("Usage: disasm <address> [count]")
            return
        
        try:
            addr = int(args[0], 0)
            count = int(args[1]) if len(args) > 1 else 20
        except ValueError:
            print("Invalid address or count")
            return
        
        print(f"\nDisassembly at 0x{addr:x}:\n")
        
        current = addr
        for _ in range(count):
            data = self.binary.read_bytes_at_vaddr(current, 15)
            if data is None:
                print(f"0x{current:08x}: <invalid address>")
                break
            
            insn = self.decoder.decode(data, 0, current)
            if not insn.valid or insn.size == 0:
                print(f"0x{current:08x}: <decode error>")
                current += 1
                continue
            
            print(insn.format_full())
            current += insn.size
            
            if insn.flow_type in (FlowType.UNCOND_BRANCH, FlowType.RET, FlowType.TRAP):
                break
    
    def cmd_hexdump(self, args: List[str]) -> None:
        """Hex dump at address."""
        if not self._check_loaded():
            return
        
        if not args:
            print("Usage: hexdump <address> [size]")
            return
        
        try:
            addr = int(args[0], 0)
            size = int(args[1]) if len(args) > 1 else 256
        except ValueError:
            print("Invalid address or size")
            return
        
        data = self.binary.read_bytes_at_vaddr(addr, size)
        if data is None:
            print("Invalid address")
            return
        
        print(f"\nHex dump at 0x{addr:x}:\n")
        print(hexdump(data, addr))
    
    def cmd_cfg(self, args: List[str]) -> None:
        """Show CFG for function."""
        if not self._check_loaded():
            return
        
        if not args:
            print("Usage: cfg <address>")
            return
        
        try:
            addr = int(args[0], 0)
        except ValueError:
            print("Invalid address")
            return
        
        print(f"[*] Building CFG for 0x{addr:x}...")
        cfg = self.cfg_builder.build(addr)
        self.cfg_builder.print_cfg(cfg)
    
    def cmd_entropy(self, args: List[str]) -> None:
        """Analyze section entropy."""
        if not self._check_loaded():
            return
        
        analyzer = EntropyAnalyzer(self.binary)
        results = analyzer.analyze_sections()
        
        print(f"\nSection Entropy Analysis:")
        print("=" * 60)
        print(f"{'Section':<20} {'Entropy':<10} {'Size':<12} {'Status'}")
        print("-" * 60)
        
        for r in results:
            status = "⚠ SUSPICIOUS" if r.is_suspicious else "OK"
            print(f"{r.name:<20} {r.entropy:<10.4f} {r.size:<12} {status}")
        
        is_packed, reason = analyzer.is_likely_packed()
        print("-" * 60)
        if is_packed:
            print(f"⚠ Binary may be packed: {reason}")
        else:
            print("✓ No packing indicators detected")
    
    def cmd_plugins(self, args: List[str]) -> None:
        """List available plugins."""
        plugins = self.plugin_manager.list_plugins()
        
        if not plugins:
            print("No plugins registered.")
            print("Plugins can be added to reframework/plugins/")
            return
        
        print(f"\nAvailable Plugins ({len(plugins)}):")
        print("=" * 60)
        
        for p in plugins:
            status = "✓" if p.enabled else "✗"
            print(f"  [{status}] {p.name:<20} v{p.version:<8} {p.description}")
    
    def cmd_run_plugin(self, args: List[str]) -> None:
        """Run a plugin."""
        if not self._check_loaded():
            return
        
        if not args:
            print("Usage: run <plugin_name> or run all")
            return
        
        # Extract strings if not done
        if not self.strings:
            extractor = StringExtractor(self.binary)
            self.strings = extractor.extract_all()
        
        context = PluginContext(
            binary=self.binary,
            functions=self.functions,
            strings=self.strings
        )
        
        if args[0].lower() == 'all':
            results = self.plugin_manager.run_all(context)
            self.plugin_manager.print_results(results)
        else:
            result = self.plugin_manager.run_plugin(args[0], context)
            if result:
                self.plugin_manager.print_results([result])
    
    def cmd_quit(self, args: List[str]) -> None:
        """Exit the program."""
        print("Goodbye!")
        sys.exit(0)
    
    def _check_loaded(self) -> bool:
        """Check if a binary is loaded."""
        if self.binary is None:
            print("No binary loaded. Use 'load <path>' first.")
            return False
        return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="RE Framework v0.2.0")
    parser.add_argument('file', nargs='?', help='Binary file to analyze')
    parser.add_argument('-d', '--disasm', type=str, help='Disassemble at address')
    parser.add_argument('-f', '--functions', action='store_true', help='List functions')
    parser.add_argument('-s', '--strings', action='store_true', help='Extract strings')
    parser.add_argument('-e', '--entropy', action='store_true', help='Analyze entropy')
    
    args = parser.parse_args()
    
    cli = CLI()
    
    if args.file:
        cli.cmd_load([args.file])
    
    if args.functions and cli.binary:
        cli.cmd_functions([])
    
    if args.strings and cli.binary:
        cli.cmd_strings([])
    
    if args.entropy and cli.binary:
        cli.cmd_entropy([])
    
    if args.disasm and cli.binary:
        cli.cmd_disasm([args.disasm])
    
    # Start interactive mode if no action specified or always
    if not any([args.functions, args.strings, args.disasm, args.entropy]):
        cli.run_interactive()


if __name__ == '__main__':
    main()
