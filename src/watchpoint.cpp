#include "sdb/watchpoint.hpp"
#include "sdb/memory.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <stdexcept>

namespace sdb {
namespace {
unsigned length_encoding(unsigned length) {
    switch (length) {
    case 1:
        return 0;
    case 2:
        return 1;
    case 4:
        return 3;
    case 8:
        return 2;
    default:
        throw std::runtime_error("watchpoint length must be 1, 2, 4, or 8 bytes");
    }
}
} // namespace

WatchpointManager::Registers WatchpointManager::snapshot(pid_t tid) const {
    Registers values{};
    for (unsigned index : {0U, 1U, 2U, 3U, 6U, 7U})
        values[index] = tracee_.read_debug_register(tid, index);
    return values;
}

void WatchpointManager::program(pid_t tid, const Registers& values) {
    // Disable before changing addresses/lengths, enable only after a full setup.
    tracee_.write_debug_register(tid, 7, 0);
    for (unsigned index : {0U, 1U, 2U, 3U, 6U})
        tracee_.write_debug_register(tid, index, values[index]);
    tracee_.write_debug_register(tid, 7, values[7]);
}

void WatchpointManager::apply(bool restore) {
    tracee_.require_stopped();
    auto tids = tracee_.threads();
    std::map<pid_t, Registers> before;
    for (pid_t tid : tids) {
        const auto values = snapshot(tid);
        before.emplace(tid, values);
        original_.emplace(tid, values);
    }
    std::vector<pid_t> changed;
    try {
        for (pid_t tid : tids) {
            auto values = original_.at(tid);
            if (!restore) {
                for (const auto& [id, watch] : watches_) {
                    (void)id;
                    values[watch.slot] = watch.address;
                    const unsigned field = 16 + 4 * watch.slot;
                    values[7] &= ~((uint64_t{3} << (2 * watch.slot)) | (uint64_t{15} << field));
                    values[7] |= uint64_t{1} << (2 * watch.slot); // local enable
                    values[7] |= static_cast<uint64_t>(watch.access == WatchAccess::Write ? 1 : 3)
                                 << field;
                    values[7] |= static_cast<uint64_t>(length_encoding(watch.length))
                                 << (field + 2);
                }
                // Clear stale B0..B3, BD, BS and BT status; preserve reserved bits.
                values[6] &= ~uint64_t{0xe00f};
            }
            changed.push_back(tid); // include a partially programmed task in rollback
            program(tid, values);
        }
    } catch (...) {
        auto failure = std::current_exception();
        bool rollback_failed = false;
        for (pid_t tid : changed) {
            try {
                program(tid, before.at(tid));
            } catch (...) {
                rollback_failed = true;
            }
        }
        if (rollback_failed)
            throw MemoryCorruption("hardware debug-register rollback failed");
        std::rethrow_exception(failure);
    }
}

void WatchpointManager::synchronize() {
    if (watches_.empty())
        return;
    apply(false);
}

void WatchpointManager::inherit(pid_t parent, pid_t child) {
    if (original_.find(parent) == original_.end())
        return;
    // Linux copy_thread clears the child's ptrace_bps, although virtual DR7
    // bits may be copied. Do not create a parent's old hardware breakpoint in
    // the child when later restoring its pre-debugger state.
    auto baseline = snapshot(child);
    baseline[7] &= ~uint64_t{0xff};
    baseline[6] &= ~uint64_t{0xe00f};
    original_[child] = baseline;
}

const Watchpoint& WatchpointManager::add(uint64_t address, unsigned length, WatchAccess access) {
    length_encoding(length);
    if (address % length != 0)
        throw std::runtime_error("hardware watchpoint address must be aligned to its length");
    if (address > std::numeric_limits<uint64_t>::max() - (length - 1))
        throw std::runtime_error("watchpoint address range overflow");
    tracee_.require_stopped();
    // Hardware address validation alone accepts unmapped locations. Requiring a
    // readable range catches mistakes now; it does not poll memory while running.
    Memory(tracee_).read(address, length);
    for (const auto& [id, watch] : watches_) {
        (void)id;
        if (watch.address == address && watch.length == length && watch.access == access)
            throw std::runtime_error("watchpoint already exists");
    }
    unsigned occupied = 0;
    for (pid_t tid : tracee_.threads()) {
        const auto found = original_.find(tid);
        const auto baseline = found == original_.end() ? snapshot(tid) : found->second;
        if (baseline[7] & uint64_t{0xff})
            throw std::runtime_error("existing enabled hardware breakpoints are unsupported; "
                                     "cannot install SDB watchpoints");
        original_.emplace(tid, baseline);
    }
    for (const auto& [id, watch] : watches_) {
        (void)id;
        occupied |= 1U << watch.slot;
    }
    unsigned slot = 0;
    while (slot < 4 && (occupied & (1U << slot)))
        ++slot;
    if (slot == 4)
        throw std::runtime_error("no free hardware watchpoint slot (x86-64 has four)");
    if (next_id_ == std::numeric_limits<uint64_t>::max())
        throw std::runtime_error("watchpoint ID limit reached");
    auto it = watches_.emplace(next_id_, Watchpoint{next_id_, address, length, access, slot}).first;
    try {
        apply(false);
    } catch (...) {
        watches_.erase(it);
        throw;
    }
    ++next_id_;
    return it->second;
}

void WatchpointManager::remove(uint64_t id) {
    auto it = watches_.find(id);
    if (it == watches_.end())
        throw std::runtime_error("watchpoint does not exist");
    auto saved = watches_.extract(it);
    try {
        apply(false);
    } catch (...) {
        watches_.insert(std::move(saved));
        throw;
    }
}

bool WatchpointManager::triggered(pid_t tid) const {
    if (watches_.empty())
        return false;
    const auto status = tracee_.read_debug_register(tid, 6);
    for (const auto& [id, watch] : watches_) {
        (void)id;
        if (status & (uint64_t{1} << watch.slot))
            return true;
    }
    return false;
}

std::vector<Watchpoint> WatchpointManager::hits(pid_t tid) {
    std::vector<Watchpoint> result;
    if (watches_.empty())
        return result;
    auto status = tracee_.read_debug_register(tid, 6);
    uint64_t owned = 0;
    for (const auto& [id, watch] : watches_) {
        (void)id;
        if (status & (uint64_t{1} << watch.slot)) {
            result.push_back(watch);
            owned |= uint64_t{1} << watch.slot;
        }
    }
    if (!result.empty())
        tracee_.write_debug_register(tid, 6, status & ~owned);
    return result;
}

void WatchpointManager::restore_all() {
    if (!original_.empty())
        apply(true);
}
} // namespace sdb
