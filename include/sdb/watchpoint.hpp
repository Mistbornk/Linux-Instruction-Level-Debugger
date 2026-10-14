#pragma once

#include "sdb/tracee.hpp"
#include <array>
#include <cstdint>
#include <map>
#include <vector>

namespace sdb {
enum class WatchAccess { Write, ReadWrite };
struct Watchpoint {
    uint64_t id;
    uint64_t address;
    unsigned length;
    WatchAccess access;
    unsigned slot;
};

// x86 DR0..DR3 are per-task; definitions are installed on every stopped task.
// Original disabled debug-register values are retained for attach/detach.
// Pre-existing enabled hardware breakpoints are rejected: coexisting owners of
// a merged #DB would require a separate signal-delivery contract.
class WatchpointManager {
  public:
    explicit WatchpointManager(Tracee& tracee) : tracee_(tracee) {}
    const Watchpoint& add(uint64_t address, unsigned length, WatchAccess access);
    void remove(uint64_t id);
    void synchronize();
    void inherit(pid_t parent, pid_t child);
    std::vector<Watchpoint> hits(pid_t tid);
    bool triggered(pid_t tid) const;
    void restore_all();
    void clear() noexcept {
        watches_.clear();
        original_.clear();
        next_id_ = 0;
    }
    const std::map<uint64_t, Watchpoint>& all() const { return watches_; }

  private:
    using Registers = std::array<uint64_t, 8>;
    Tracee& tracee_;
    std::map<uint64_t, Watchpoint> watches_;
    std::map<pid_t, Registers> original_;
    uint64_t next_id_ = 0;
    Registers snapshot(pid_t tid) const;
    void program(pid_t tid, const Registers& values);
    void apply(bool restore);
};
} // namespace sdb
