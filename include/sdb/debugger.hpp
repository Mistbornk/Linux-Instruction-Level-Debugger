#pragma once
#include "sdb/command.hpp"
#include "sdb/disassembler.hpp"
#include <optional>
namespace sdb {
class Debugger {
public:
  // for main() operation
  Debugger() : memory_(tracee_), points_(memory_) {}
  void load(const std::vector<std::string> &arguments);
  bool execute(const Command &command);
  void reset() noexcept;

private:
  void run(Resume mode);
  void report(Event event);
  void display() const;
  void print_registers() const;
  Tracee tracee_;
  Memory memory_;
  BreakpointManager points_;
  Disassembler disassembler_;
  uint64_t base_ = 0;
  int pending_signal_ = 0;
  std::optional<uint64_t> syscall_number_;
};
} // namespace sdb
