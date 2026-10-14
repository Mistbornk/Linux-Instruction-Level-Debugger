# AGENTS.md

## Project Mission

Evolve SDB from a monolithic educational Linux debugger into a small but well-designed systems debugging tool.

The project should demonstrate:

- Linux process tracing
- `ptrace`
- process state management
- software and hardware breakpoints
- x86-64 registers
- memory inspection
- ELF awareness
- disassembly
- syscall tracing
- signal handling
- debugger architecture
- modern C++ systems programming
- robust testing

Preserve the educational transparency of the implementation.

Do not turn the project into a thin wrapper around GDB or LLDB.

---

## Existing Direction

The current implementation already contains important debugger mechanisms.

Before restructuring, inspect and fully understand them.

Preserve working behavior while extracting responsibilities into clear modules.

---

## Target Architecture

A reasonable long-term architecture may resemble:

```text
include/sdb/
    debugger.hpp
    tracee.hpp
    breakpoint.hpp
    breakpoint_manager.hpp
    register_file.hpp
    memory.hpp
    disassembler.hpp
    elf_image.hpp
    syscall_tracer.hpp
    command.hpp
    command_parser.hpp

src/
    debugger.cpp
    tracee.cpp
    breakpoint.cpp
    breakpoint_manager.cpp
    register_file.cpp
    memory.cpp
    disassembler.cpp
    elf_image.cpp
    syscall_tracer.cpp
    command_parser.cpp
    main.cpp

tests/
fixtures/
docs/
```

This is a guideline.

Do not create classes that have no real responsibility.

---

## Architectural Principles

Separate:

1. CLI parsing
2. debugger state machine
3. traced-process operations
4. breakpoint management
5. memory access
6. register access
7. disassembly
8. ELF/symbol handling
9. syscall handling

Avoid having command handlers directly manipulate every global variable.

Represent process state explicitly.

Possible states include:

```text
NoProgram
Loaded
Stopped
Running
Exited
```

Transitions should be understandable and validated.

---

## ptrace Correctness

Treat `ptrace` semantics as correctness-critical.

Always consider:

- child exit
- child termination by signal
- ptrace stop
- SIGTRAP source
- syscall entry vs exit
- breakpoint traps
- single-step traps
- exec events
- signal forwarding
- PIE/ASLR

Check every relevant return value.

Do not silently ignore errors.

Use robust wrappers where appropriate.

---

## Breakpoints

Software breakpoints must correctly manage:

- original byte
- insertion of `0xCC`
- RIP adjustment after trap
- temporary restoration
- single stepping original instruction
- reinsertion
- deletion
- duplicate breakpoints
- process restart
- PIE relocation

Encapsulate this behavior.

Avoid duplicating breakpoint stepping logic across `step` and `continue`.

---

## High-Value Features

After architecture and correctness are stable, prioritize technically meaningful debugger features.

Potential features:

### 1. Attach / detach

```text
attach <pid>
detach
```

Use `PTRACE_ATTACH` or an appropriate modern alternative.

### 2. Memory commands

```text
x <address>
x/<count> <address>
write <address> <value>
```

Support safe and predictable memory access.

### 3. Register commands

```text
register read
register read rip
register write rax 123
```

### 4. Symbol-aware breakpoints

Support commands such as:

```text
break main
break function_name
```

Parse ELF symbols directly or through a suitable lightweight library.

Handle PIE relocation.

### 5. Hardware watchpoints

On x86-64 Linux, investigate debug registers DR0–DR7.

Potential CLI:

```text
watch <address>
rwatch <address>
awatch <address>
```

Do not fake hardware watchpoints using repeated polling.

### 6. Backtrace

Implement a defensible stack backtrace.

A frame-pointer based implementation is acceptable initially if limitations are clearly documented.

DWARF-based unwinding may be added later if justified.

### 7. Signal handling

Expose why the tracee stopped.

Allow meaningful signal forwarding.

### 8. Better syscall tracing

Decode syscall names and important arguments where practical.

Do not attempt to reproduce all of `strace`.

### 9. Source-level awareness

This is optional and should be attempted only after the lower-level debugger is robust.

DWARF line information may eventually support:

```text
break file.cpp:42
list
```

---

## Disassembly

Keep Capstone integration isolated.

Disassembler output should include:

- address
- raw bytes
- mnemonic
- operands

Ensure memory reads cannot accidentally walk past accessible executable regions.

Consider symbol annotations where available.

---

## ELF / PIE / ASLR

The debugger should correctly distinguish:

- ELF virtual address
- runtime address
- module load base
- PIE binaries
- non-PIE binaries

Centralize address translation.

Do not scatter `base_addr + offset` calculations throughout the codebase.

---

## Testing

Debugger testing is difficult but required.

Create small fixture programs covering:

- normal execution
- breakpoint hit
- multiple breakpoints
- loops
- function calls
- syscall
- signals
- segmentation fault
- PIE executable
- non-PIE executable
- multithreaded executable if thread support is implemented

Automate command-driven integration tests where possible.

Example concept:

```bash
sdb --batch tests/scripts/breakpoint.sdb ./fixture
```

Adding a batch/non-interactive mode is encouraged because it makes regression testing much easier.

---

## Thread Support

Do not claim multithreaded debugging unless individual Linux tasks are actually managed.

If implementing it, understand:

- thread IDs
- clone events
- waitpid behavior
- thread-local ptrace state
- breakpoints shared through process address space
- per-thread register state

Treat proper thread debugging as an advanced milestone.

---

## C++ Engineering

Use RAII where appropriate.

Possible wrappers:

```text
Tracee
Breakpoint
BreakpointManager
CapstoneHandle
ElfImage
```

Avoid wrappers that add ceremony without safety or clarity.

Prefer clear error handling.

Do not allow resource leaks for:

- file descriptors
- Capstone handles
- child processes

---

## Performance

Debugger runtime is generally dominated by kernel tracing overhead.

Do not perform meaningless micro-optimizations.

Performance work should focus on:

- avoiding redundant `/proc` parsing
- minimizing unnecessary memory reads
- caching ELF metadata
- avoiding unnecessary disassembly
- efficient breakpoint lookup

Correctness and architecture matter more than raw debugger throughput.

---

## Security and Robustness

Treat paths, PIDs, addresses, and CLI values as untrusted input.

Handle malformed commands gracefully.

Avoid undefined behavior.

Check conversions and address ranges.

---

## Documentation

README should eventually explain:

- how Linux `ptrace` debugging works
- debugger architecture
- breakpoint lifecycle
- single-step behavior
- syscall tracing
- PIE/ASLR handling
- implemented commands
- limitations

A debugger state-machine diagram is strongly encouraged.

---

## Definition of Done

A change is valuable when it improves one of:

- debugger correctness
- architectural clarity
- systems depth
- user functionality
- testability

Do not optimize for raw line count.

The final project should be something its author can confidently discuss in a Linux systems interview.

---

# CODEX MASTER PROMPT

Act as a senior Linux systems engineer building a real educational debugger.

Read AGENTS.md first.

Inspect the entire existing SDB implementation before modifying anything.

Do not throw away working ptrace logic and start over.

Your job is to evolve the current debugger into a modular, robust, portfolio-quality Linux x86-64 debugger.

Proceed autonomously.

### Phase 1 — Understand current behavior

Map every existing command and subsystem.

Specifically understand:

- process creation
- ptrace lifecycle
- process state
- breakpoint insertion
- breakpoint restoration
- RIP correction
- single stepping
- continue
- syscall tracing
- register handling
- executable-memory discovery
- Capstone disassembly
- PIE/base-address handling

Identify duplicated breakpoint/continue logic and correctness risks.

Create regression tests before making risky changes.

### Phase 2 — Break up the monolith

Refactor the single-file design into coherent modules.

At minimum investigate extracting:

- Tracee/process abstraction
- Debugger/controller
- BreakpointManager
- RegisterFile
- Memory
- Disassembler
- ELF image/address translation
- Command parser

Do not create a Java-style class hierarchy.

Use C++ abstractions only when they improve ownership, invariants, testability, or clarity.

### Phase 3 — Harden ptrace behavior

Audit every `ptrace`, `waitpid`, `/proc`, memory, and Capstone operation.

Correctly distinguish:

- exited
- signaled
- stopped
- breakpoint SIGTRAP
- single-step SIGTRAP
- syscall stop
- other signals

Eliminate duplicated trap-handling behavior.

Make the debugger state machine explicit.

### Phase 4 — Build testing infrastructure

Introduce fixture binaries and automated debugger sessions.

Strongly consider adding:

```text
--batch
--command-file
```

so debugger behavior can be regression-tested.

Test PIE and non-PIE executables.

### Phase 5 — Add meaningful features

Implement as many of the following as can be done robustly:

1. attach/detach existing processes
2. structured memory examine/write commands
3. register read/write commands
4. ELF symbol loading
5. breakpoints by symbol name
6. improved PIE/ASLR handling
7. hardware watchpoints using x86 debug registers
8. basic stack backtrace
9. useful signal reporting/forwarding
10. syscall-name decoding
11. command history or quality-of-life CLI features
12. optional multithread awareness

Prioritize systems depth over UI polish.

Do not implement fake versions of features merely to claim support.

### Phase 6 — Quality

Add:

- modern CMake build
- warnings
- sanitizers where applicable
- CI if practical
- tests
- documentation

### Phase 7 — Documentation

Rewrite README into a technical portfolio document.

Include a diagram explaining:

```text
CLI
 ↓
Debugger state machine
 ↓
Tracee / ptrace
 ├── Breakpoints
 ├── Registers
 ├── Memory
 ├── Syscalls
 └── Disassembly
```

Explain the software-breakpoint lifecycle in enough detail that a systems interviewer can ask follow-up questions.

### Engineering constraints

Never claim a debugger feature works unless there is a test or a reproducible manual demonstration.

Do not hide core functionality behind GDB.

Using libraries such as Capstone or ELF/DWARF parsing libraries is acceptable, but ptrace/process-control logic should remain ours.

Be willing to make major architectural improvements.

Keep iterating until the repository has moved substantially beyond a course-assignment implementation.
