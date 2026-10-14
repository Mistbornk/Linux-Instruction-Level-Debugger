#include "sdb/debugger.hpp"
#include "sdb/elf_image.hpp"
#include <csignal>
#include <iomanip>
#include <iostream>
#include <limits>
namespace sdb {
void Debugger::reset() noexcept {
  tracee_.terminate();
  points_.clear();
  base_ = 0;
  pending_signal_ = 0;
  syscall_number_.reset();
}
void Debugger::display() const {
  auto regs = tracee_.registers();
  try {
    disassembler_.print(memory_, points_, regs.rip);
  } catch (const std::exception &error) {
    std::cout << "** disassembly unavailable: " << error.what() << '\n';
  }
}
void Debugger::load(const std::string &path) {
  if (tracee_.pid() > 0)
    throw std::runtime_error("program already loaded");
  reset();
  ElfImage image(path);
  try {
    tracee_.launch(path);
    base_ = image.base(memory_);
    const uint64_t entry = image.entry(memory_);
    auto regs = tracee_.registers();
    if (regs.rip != entry) {
      points_.add(entry);
      Event event = tracee_.resume(Resume::Continue);
      if (event.kind != Stop::BreakpointTrap)
        throw std::runtime_error("program stopped or exited before ELF entry");
      regs = tracee_.registers();
      if (regs.rip == 0 || regs.rip - 1 != entry)
        throw std::runtime_error("unexpected trap before ELF entry");
      points_.remove(0);
      regs.rip = entry;
      tracee_.registers(regs);
      points_.clear();
    }
    std::cout << "** program '" << path << "' loaded. entry point: 0x"
              << std::hex << entry << std::dec << ".\n";
    display();
  } catch (...) {
    reset();
    throw;
  }
}
void Debugger::run(Resume mode) {
  tracee_.require_stopped();
  if (mode != Resume::Syscall)
    syscall_number_.reset();
  const uint64_t site = tracee_.registers().rip;
  const int signal = pending_signal_;
  pending_signal_ = 0;
  try {
    Event event;
    if (points_.installed(site)) {
      points_.disable(site);
      // For syscall mode, observe entry directly instead of stepping over
      // the entire syscall and silently losing its entry/exit stops.
      auto first_mode =
          mode == Resume::Syscall ? Resume::Syscall : Resume::Step;
      event = tracee_.resume(first_mode, signal);
      if (tracee_.state() == State::Stopped && event.kind != Stop::Exec)
        points_.enable(site);
      if (mode == Resume::Continue && event.kind == Stop::Step)
        event = tracee_.resume(Resume::Continue);
    } else
      event = tracee_.resume(mode, signal);
    report(event);
  } catch (...) {
    // A failed resume/reinsertion cannot leave a half-displaced breakpoint.
    reset();
    throw;
  }
}
void Debugger::report(Event event) {
  if (event.kind == Stop::Exit || event.kind == Stop::Killed) {
    if (event.kind == Stop::Exit)
      std::cout << "** the target program terminated. exit status "
                << event.exit_code << ".\n";
    else
      std::cout << "** the target program terminated by signal " << event.signal
                << ".\n";
    reset();
    return;
  }
  if (event.kind == Stop::Exec) {
    reset();
    throw std::runtime_error(
        "target executed a new image; old session closed (load again)");
  }
  auto regs = tracee_.registers();
  if (event.kind == Stop::BreakpointTrap && regs.rip &&
      points_.installed(regs.rip - 1)) {
    --regs.rip;
    tracee_.registers(regs);
    std::cout << "** hit a breakpoint at 0x" << std::hex << regs.rip << std::dec
              << ".\n";
  } else if (event.kind == Stop::Step) {
    std::cout << "** single-step stop.\n";
  } else if (event.kind == Stop::SyscallEntry) {
    syscall_number_ = event.syscall_number;
    std::cout << "** enter a syscall(" << *syscall_number_ << ") at RIP 0x"
              << std::hex << regs.rip << std::dec << ".\n";
  } else if (event.kind == Stop::SyscallExit) {
    std::cout << "** leave a syscall(";
    if (syscall_number_)
      std::cout << *syscall_number_;
    else
      std::cout << "unknown";
    std::cout << ") = " << event.result << " at RIP 0x" << std::hex << regs.rip
              << std::dec << ".\n";
    syscall_number_.reset();
  } else {
    pending_signal_ = event.signal;
    std::cout << "** stopped by signal " << event.signal
              << "; forwarded on next resume.\n";
  }
  display();
}
void Debugger::print_registers() const {
  auto regs = tracee_.registers();
  const std::pair<const char *, uint64_t> values[] = {
      {"rax", regs.rax}, {"rbx", regs.rbx}, {"rcx", regs.rcx},
      {"rdx", regs.rdx}, {"rsi", regs.rsi}, {"rdi", regs.rdi},
      {"rbp", regs.rbp}, {"rsp", regs.rsp}, {"r8", regs.r8},
      {"r9", regs.r9},   {"r10", regs.r10}, {"r11", regs.r11},
      {"r12", regs.r12}, {"r13", regs.r13}, {"r14", regs.r14},
      {"r15", regs.r15}, {"rip", regs.rip}, {"eflags", regs.eflags}};
  for (size_t i = 0; i < std::size(values); ++i) {
    std::cout << '$' << std::left << std::setw(7) << values[i].first << "0x"
              << std::right << std::hex << std::setfill('0') << std::setw(16)
              << values[i].second << std::setfill(' ') << std::dec
              << ((i + 1) % 3 ? "    " : "\n");
  }
}
bool Debugger::execute(const Command &command) {
  if (auto event = tracee_.poll_exit())
    report(*event);
  const auto &name = command.name;
  const auto &args = command.args;
  if (name.empty())
    return true;
  auto arity = [&](size_t expected) {
    if (args.size() != expected)
      throw std::runtime_error("wrong argument count for " + name);
  };
  try {
    if (name == "q") {
      arity(0);
      reset();
      return false;
    }
    if (name == "load") {
      arity(1);
      load(args[0]);
      return true;
    }
    if (name == "si" || name == "cont" || name == "syscall") {
      arity(0);
      run(name == "si"     ? Resume::Step
          : name == "cont" ? Resume::Continue
                           : Resume::Syscall);
    } else if (name == "break" || name == "breakrva") {
      arity(1);
      tracee_.require_stopped();
      uint64_t address = number(args[0]);
      if (name == "breakrva") {
        if (address > UINT64_MAX - base_)
          throw std::runtime_error("relative address overflow");
        address += base_;
      }
      points_.add(address);
      std::cout << "** set a breakpoint at 0x" << std::hex << address
                << std::dec << ".\n";
    } else if (name == "delete") {
      arity(1);
      tracee_.require_stopped();
      uint64_t id = number(args[0], 10);
      if (id > std::numeric_limits<unsigned>::max())
        throw std::runtime_error("breakpoint ID out of range");
      points_.remove(static_cast<unsigned>(id));
      std::cout << "** delete breakpoint " << id << ".\n";
    } else if (name == "patch") {
      arity(2);
      tracee_.require_stopped();
      uint64_t address = number(args[0]);
      points_.patch(address, hex_bytes(args[1]));
      std::cout << "** patch memory at 0x" << std::hex << address << std::dec
                << ".\n";
    } else if (name == "info") {
      arity(1);
      if (args[0] == "reg")
        print_registers();
      else if (args[0] == "break") {
        if (points_.all().empty())
          std::cout << "** no breakpoints.\n";
        else {
          std::cout << "Num     Address\n";
          for (const auto &[address, point] : points_.all())
            std::cout << point.id << "\t0x" << std::hex << address << std::dec
                      << '\n';
        }
      } else
        throw std::runtime_error("unknown info subcommand: " + args[0]);
    } else
      throw std::runtime_error("unknown command: " + name);
  } catch (const MemoryCorruption &) {
    reset();
    throw;
  }
  return true;
}
} // namespace sdb
