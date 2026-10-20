#pragma once
#include "sdb/memory.hpp"
#include <map>
namespace sdb {
struct Breakpoint {
  unsigned id;
  uint8_t original;
  bool installed;
};
class BreakpointManager {
public:
  explicit BreakpointManager(Memory &memory) : memory_(memory) {}
  void add(uint64_t address);
  void remove(unsigned id);
  void disable(uint64_t address);
  void enable(uint64_t address);
  bool installed(uint64_t address) const;
  void overlay(uint64_t address, std::vector<uint8_t> &bytes) const;
  void patch(uint64_t address, const std::vector<uint8_t> &bytes);
  void clear() {
    points_.clear();
    next_id_ = 0;
  }
  const std::map<uint64_t, Breakpoint> &all() const { return points_; }

private:
  Memory &memory_;
  std::map<uint64_t, Breakpoint> points_;
  unsigned next_id_ = 0;
};
} // namespace sdb
