#pragma once

#include "sdb/memory.hpp"
#include <cstdint>
#include <map>
#include <vector>

namespace sdb {
struct Breakpoint {
    uint64_t id;
    uint64_t address;
    uint8_t original_byte;
    bool installed;
    bool temporary;
};

// One authoritative address-indexed record. IDs are stable until session reset.
class BreakpointManager {
  public:
    explicit BreakpointManager(const Memory& memory) : memory_(memory) {}
    const Breakpoint& add(uint64_t address, bool temporary = false);
    void remove(uint64_t id);
    void remove_address(uint64_t address);
    void disable(uint64_t address);
    void enable(uint64_t address);
    const Breakpoint* find(uint64_t address) const;
    void patch(uint64_t address, const std::vector<uint8_t>& bytes, bool executable_only = true);
    void restore_all();
    void overlay(uint64_t address, std::vector<uint8_t>& bytes) const;
    const std::map<uint64_t, Breakpoint>& all() const { return breakpoints_; }
    // Only after exit/exec/termination: never restores bytes into another image.
    void clear() noexcept {
        breakpoints_.clear();
        next_id_ = 0;
    }

  private:
    const Memory& memory_;
    std::map<uint64_t, Breakpoint> breakpoints_;
    uint64_t next_id_ = 0;
};
} // namespace sdb
