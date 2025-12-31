# RE Framework v1.0

A pure Python reverse engineering framework for ELF/x86-64 binary analysis.

## Features

- **ELF Parser**: Complete ELF64 format parsing without external libraries
- **x86-64 Decoder**: Custom instruction decoder with MODRM, SIB, RIP-relative support
- **Control Flow Analysis**: CFG construction using recursive descent
- **Function Detection**: Symbol-based and call-target function discovery
- **Static Analysis**: String extraction, entropy analysis, packer detection
- **Plugin System**: Extensible architecture for custom analysis modules
- **Interactive CLI**: Full-featured command-line interface

## Installation

```bash
cd /home/licht/Desktop/mandem
python3 -m pip install -e .
```

Or run directly:

```bash
python3 main.py
```

## Quick Start

### Interactive Mode

```bash
python3 main.py
```

### Load and Analyze a Binary

```bash
python3 main.py /path/to/binary
```

### Command Line Options

```bash
python3 main.py binary -f          # List functions
python3 main.py binary -s          # Extract strings
python3 main.py binary -e          # Analyze entropy
python3 main.py binary -d 0x401000 # Disassemble at address
```

## CLI Commands

### File Operations
| Command | Description |
|---------|-------------|
| `load <path>` | Load a binary file for analysis |
| `info` | Display binary information |

### Structure Analysis
| Command | Description |
|---------|-------------|
| `sections` | List sections |
| `segments` | List segments (program headers) |
| `symbols` | List symbols |
| `imports` | List imported functions |
| `exports` | List exported functions |

### Code Analysis
| Command | Description |
|---------|-------------|
| `strings [min_len]` | Extract strings (default min_len=4) |
| `functions` | List discovered functions |
| `disasm <addr> [n]` | Disassemble at address (n instructions) |
| `hexdump <addr> [n]` | Hex dump at address (n bytes) |
| `cfg <addr>` | Show CFG for function at address |

### Security Analysis
| Command | Description |
|---------|-------------|
| `entropy` | Analyze section entropy (packer detection) |

### Plugin System
| Command | Description |
|---------|-------------|
| `plugins` | List available plugins |
| `run <plugin\|all>` | Run a specific plugin or all plugins |

### Other
| Command | Description |
|---------|-------------|
| `help` | Show help |
| `quit` / `exit` | Exit the program |

## Architecture

```
reframework/
├── loader/
│   ├── binary.py      # Abstract binary representation
│   └── elf.py         # ELF format parser
├── disasm/
│   ├── opcodes.py     # Opcode metadata tables
│   ├── instruction.py # Instruction representation
│   └── decoder.py     # x86-64 decoder pipeline
├── analysis/
│   ├── cfg.py         # Control flow graph builder
│   └── static.py      # String/entropy analysis
├── plugins/
│   └── base.py        # Plugin system infrastructure
├── cli/
│   └── main.py        # Command-line interface
└── utils/
    └── helpers.py     # Utility functions
```

## Decoder Pipeline

The x86-64 decoder follows a strict pipeline:

```
Prefixes → Opcode → MODRM → SIB → Displacement → Immediate
```

### Key Features

- **REX prefix handling**: Proper 64-bit register extension
- **MODRM decoding**: Full mod/reg/rm field parsing
- **SIB support**: Scale-index-base addressing
- **RIP-relative**: Correct absolute address computation

### RIP-Relative Addressing

When `mod=00` and `rm=101`, the decoder computes:
```
absolute_address = next_instruction_address + displacement
```

## Usage Examples

### Disassembly

```python
from reframework import ELFParser, X86Decoder

parser = ELFParser()
binary = parser.parse("/bin/ls")

decoder = X86Decoder(mode=64)
data = binary.read_bytes_at_vaddr(binary.entry_point, 100)

for insn in decoder.decode_block(data, binary.entry_point, max_insns=10):
    print(insn.format_full())
```

### CFG Construction

```python
from reframework import ELFParser, CFGBuilder

parser = ELFParser()
binary = parser.parse("/bin/ls")

cfg_builder = CFGBuilder(binary)
cfg = cfg_builder.build(binary.entry_point, "_start")

cfg_builder.print_cfg(cfg)
```

### String Extraction

```python
from reframework import ELFParser
from reframework.analysis import StringExtractor

parser = ELFParser()
binary = parser.parse("/bin/ls")

extractor = StringExtractor(binary, min_length=4)
strings = extractor.extract_all()

for s in strings[:20]:
    print(f"0x{s.address:x}: {s.value}")
```

### Entropy Analysis

```python
from reframework import ELFParser
from reframework.analysis import EntropyAnalyzer

parser = ELFParser()
binary = parser.parse("/bin/ls")

analyzer = EntropyAnalyzer(binary)
for section in analyzer.analyze_sections():
    print(f"{section.name}: {section.entropy:.2f}")

is_packed, reason = analyzer.is_likely_packed()
print(f"Packed: {is_packed} - {reason}")
```

## Testing

```bash
# Run decoder tests
python3 tests/test_decoder.py

# Run all tests
python3 test_all.py

# Test with a binary
python3 main.py /bin/ls -s -e
```

## Supported Features

### Binary Formats
- [x] ELF64
- [x] ELF32 (partial)
- [ ] PE (planned)
- [ ] Mach-O (planned)

### x86-64 Instructions
- [x] Basic arithmetic (ADD, SUB, XOR, etc.)
- [x] MOV variants
- [x] LEA with RIP-relative
- [x] Control flow (JMP, Jcc, CALL, RET)
- [x] Stack operations (PUSH, POP)
- [x] SYSCALL
- [x] Group instructions (shifts, bit ops)
- [x] MODRM/SIB addressing modes

### Analysis
- [x] CFG construction
- [x] Function detection (symbols)
- [x] String extraction (ASCII)
- [x] Entropy analysis
- [x] Packer detection

## Constraints

- **Pure Python**: Standard library only
- **No external disassemblers**: No Capstone, distorm, etc.
- **Educational focus**: Code is documented for learning

## License

Educational use. Learn, modify, and build upon it.

## Contributing

Contributions welcome:
- Add more instruction support
- Implement PE/Mach-O parsers
- Create analysis plugins
- Improve documentation
