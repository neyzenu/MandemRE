# Dynamic Analysis Concepts

This document explains the concepts behind dynamic analysis on Linux.
**This is for educational purposes only - for understanding how debuggers
and analysis tools work at a low level.**

## ptrace System Call

`ptrace` is the primary mechanism for process debugging on Linux.

### How ptrace Works

```
Tracer Process                    Tracee Process
     |                                  |
     |  ptrace(PTRACE_ATTACH, pid)      |
     |--------------------------------->|
     |                                  | (stops with SIGSTOP)
     |  waitpid(pid, &status, 0)        |
     |<---------------------------------|
     |                                  |
     |  ptrace(PTRACE_PEEKDATA, addr)   |
     |--------------------------------->| (read memory)
     |<---------------------------------|
     |                                  |
     |  ptrace(PTRACE_CONT, pid)        |
     |--------------------------------->| (resume execution)
     |                                  |
```

### ptrace Operations

```c
// Attach to a running process
ptrace(PTRACE_ATTACH, pid, NULL, NULL);

// Read a word from tracee's memory
long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);

// Write a word to tracee's memory  
ptrace(PTRACE_POKEDATA, pid, addr, data);

// Read tracee's registers
struct user_regs_struct regs;
ptrace(PTRACE_GETREGS, pid, NULL, &regs);

// Set tracee's registers
ptrace(PTRACE_SETREGS, pid, NULL, &regs);

// Single-step one instruction
ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);

// Continue execution
ptrace(PTRACE_CONT, pid, NULL, signal);

// Detach from tracee
ptrace(PTRACE_DETACH, pid, NULL, NULL);
```

### Setting Breakpoints

Software breakpoints work by:
1. Save the original byte at target address
2. Write INT3 (0xCC) to that address
3. When INT3 executes, tracee stops with SIGTRAP
4. Restore original byte, decrement RIP, single-step
5. Re-insert breakpoint if needed

```
Original code:    48 89 e5    mov rbp, rsp
With breakpoint:  CC 89 e5    int3; (garbage)
```

## Syscall Interception

### Using PTRACE_SYSCALL

```c
// Stop at every syscall entry/exit
ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
waitpid(pid, &status, 0);

// Check if stopped at syscall
if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
    // Get syscall number from RAX (on x86-64)
    long syscall_nr = ptrace(PTRACE_PEEKUSER, pid, 
                             8 * ORIG_RAX, NULL);
}
```

### Common Syscalls to Monitor

| Number | Name | Purpose |
|--------|------|---------|
| 0 | read | Read from file descriptor |
| 1 | write | Write to file descriptor |
| 2 | open | Open file |
| 3 | close | Close file descriptor |
| 9 | mmap | Map memory |
| 10 | mprotect | Change memory protection |
| 41 | socket | Create network socket |
| 42 | connect | Connect to remote host |
| 59 | execve | Execute program |
| 60 | exit | Exit process |
| 101 | ptrace | Debug another process |

## Anti-Debug Techniques

### 1. ptrace Self-Attach

A process can only have one tracer. Malware calls ptrace on itself:

```c
if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
    // Already being traced - exit
    exit(1);
}
```

**Detection**: Look for `ptrace(PTRACE_TRACEME)` calls.

### 2. /proc/self/status Check

```c
FILE *f = fopen("/proc/self/status", "r");
// Look for "TracerPid: 0" - non-zero means being debugged
```

### 3. Timing Checks

```c
struct timespec start, end;
clock_gettime(CLOCK_MONOTONIC, &start);
// ... sensitive code ...
clock_gettime(CLOCK_MONOTONIC, &end);
if (elapsed > threshold) {
    // Being single-stepped - exit
}
```

### 4. SIGTRAP Handler

```c
signal(SIGTRAP, handler);
raise(SIGTRAP);  // If handler not called, debugger caught it
```

### 5. Parent Process Check

```c
if (getppid() != 1 && getppid() != expected_parent) {
    // Parent is debugger
}
```

## Safe Dynamic Analysis Approaches

### 1. Use Virtual Machines

- Run malware in isolated VM
- Snapshot before analysis
- Network isolation
- Monitor at hypervisor level

### 2. Use Containers with Restrictions

```bash
# Create restricted container
docker run --rm -it \
    --network none \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    analysis_image
```

### 3. Use Specialized Tools

- **strace**: Trace syscalls without full debugging
- **ltrace**: Trace library calls  
- **perf**: Performance analysis with some tracing
- **eBPF**: Kernel-level tracing (very powerful)

### 4. Emulation

Use QEMU user-mode emulation to run binaries in controlled environment:

```bash
qemu-x86_64 -strace ./malware
```

## Conceptual Tracer Implementation

Here's pseudocode for a basic tracer (DO NOT use on untrusted binaries
without proper isolation):

```python
# CONCEPTUAL ONLY - Not for production use

import os
import signal

def trace_process(pid):
    """Conceptual tracer - educational purposes only."""
    
    # Attach to process
    # ptrace(PTRACE_ATTACH, pid, 0, 0)
    # os.waitpid(pid, 0)
    
    while True:
        # Continue until syscall
        # ptrace(PTRACE_SYSCALL, pid, 0, 0)
        # pid, status = os.waitpid(pid, 0)
        
        # Check if exited
        # if WIFEXITED(status):
        #     break
        
        # Get syscall number
        # regs = ptrace(PTRACE_GETREGS, pid)
        # syscall_nr = regs.orig_rax
        
        # Log syscall
        # print(f"Syscall: {syscall_nr}")
        
        pass
    
    # Detach
    # ptrace(PTRACE_DETACH, pid, 0, 0)
```

## Memory Layout Analysis

When analyzing a running process:

```
/proc/[pid]/maps     - Memory mappings
/proc/[pid]/mem      - Process memory (requires ptrace)
/proc/[pid]/exe      - Link to executable
/proc/[pid]/fd/      - Open file descriptors
/proc/[pid]/cmdline  - Command line arguments
/proc/[pid]/environ  - Environment variables
```

### Reading /proc/[pid]/maps

```
address           perms offset  dev   inode   pathname
7f1234560000-7f1234580000 r-xp 00000000 08:01 123456 /lib/x86_64-linux-gnu/libc.so.6
7f1234580000-7f1234780000 ---p 00020000 08:01 123456 /lib/x86_64-linux-gnu/libc.so.6
7f1234780000-7f1234784000 r--p 00020000 08:01 123456 /lib/x86_64-linux-gnu/libc.so.6
7f1234784000-7f1234786000 rw-p 00024000 08:01 123456 /lib/x86_64-linux-gnu/libc.so.6
```

## Security Considerations

1. **Never run untrusted binaries outside of isolation**
2. **Use VMs with snapshots for malware analysis**
3. **Disable networking when analyzing malware**
4. **Use dedicated analysis machines**
5. **Keep analysis environment separate from production**

## Further Reading

- Linux man pages: `man 2 ptrace`, `man 5 proc`
- "Linux Binary Analysis" by Dennis Andriesse
- GDB source code for debugger implementation details
- Linux kernel source: `kernel/ptrace.c`
