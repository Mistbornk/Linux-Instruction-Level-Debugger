#pragma once
#include "sdb/breakpoint.hpp"
#include <capstone/capstone.h>
namespace sdb {
class Disassembler {
public:
  Disassembler();
  ~Disassembler();
  Disassembler(const Disassembler &) = delete;
  Disassembler &operator=(const Disassembler &) = delete;
  void print(const Memory &memory, const BreakpointManager &points,
             uint64_t address) const;

private:
  csh handle_ = 0;
};
} // namespace sdb
