#include "sdb/breakpoint.hpp"

#include <exception>
#include <limits>
#include <stdexcept>

namespace sdb {
const Breakpoint& BreakpointManager::add(uint64_t address, bool temporary) {
    if (find(address))
        throw std::runtime_error("breakpoint already exists");
    if (!memory_.executable_end(address))
        throw std::runtime_error("breakpoint address is outside executable memory");
    auto original = memory_.read(address, 1).front();
    if (original == 0xcc)
        throw std::runtime_error("address already contains an INT3 instruction");
    if (next_id_ == std::numeric_limits<uint64_t>::max())
        throw std::runtime_error("breakpoint ID limit reached");
    // Allocate the record before changing tracee memory; roll it back on failure.
    auto it =
        breakpoints_.emplace(address, Breakpoint{next_id_, address, original, false, temporary})
            .first;
    try {
        enable(address);
    } catch (...) {
        breakpoints_.erase(it);
        throw;
    }
    if (!temporary)
        ++next_id_;
    return it->second;
}

const Breakpoint* BreakpointManager::find(uint64_t address) const {
    auto it = breakpoints_.find(address);
    return it == breakpoints_.end() ? nullptr : &it->second;
}

void BreakpointManager::disable(uint64_t address) {
    auto& bp = breakpoints_.at(address);
    if (!bp.installed)
        return;
    memory_.write(address, {bp.original_byte});
    bp.installed = false;
}

void BreakpointManager::enable(uint64_t address) {
    auto& bp = breakpoints_.at(address);
    if (bp.installed)
        return;
    memory_.write(address, {0xcc});
    bp.installed = true;
}

void BreakpointManager::remove_address(uint64_t address) {
    disable(address);
    breakpoints_.erase(address);
}

void BreakpointManager::remove(uint64_t id) {
    for (const auto& [address, bp] : breakpoints_) {
        if (!bp.temporary && bp.id == id) {
            remove_address(address);
            return;
        }
    }
    throw std::runtime_error("breakpoint " + std::to_string(id) + " does not exist");
}

void BreakpointManager::overlay(uint64_t address, std::vector<uint8_t>& bytes) const {
    for (auto it = breakpoints_.lower_bound(address); it != breakpoints_.end(); ++it) {
        auto offset = it->first - address;
        if (offset >= bytes.size())
            break;
        bytes[static_cast<size_t>(offset)] = it->second.original_byte;
    }
}

void BreakpointManager::restore_all() {
    std::vector<uint64_t> restored;
    try {
        for (const auto& [address, bp] : breakpoints_) {
            if (!bp.installed)
                continue;
            restored.push_back(address);
            disable(address);
        }
    } catch (...) {
        auto error = std::current_exception();
        for (uint64_t address : restored) {
            try {
                enable(address);
            } catch (...) {
                throw MemoryCorruption("failed to roll back breakpoint restoration");
            }
        }
        std::rethrow_exception(error);
    }
}

void BreakpointManager::patch(uint64_t address, const std::vector<uint8_t>& bytes,
                              bool executable_only) {
    if (bytes.empty() || bytes.size() - 1 > std::numeric_limits<uint64_t>::max() - address)
        throw std::runtime_error("invalid patch range");
    // Validate every covered executable VMA, allowing adjacent mappings.
    auto regions = memory_.mappings();
    for (size_t i = 0; i < bytes.size();) {
        auto current = address + i;
        bool found = false;
        for (const auto& region : regions) {
            if ((executable_only ? region.executable : region.writable) &&
                current >= region.start && current < region.end) {
                auto remaining = bytes.size() - i;
                auto available = region.end - current;
                i += static_cast<size_t>(available < remaining ? available : remaining);
                found = true;
                break;
            }
        }
        if (!found)
            throw std::runtime_error(executable_only ? "patch range is outside executable memory"
                                                     : "write range is outside writable memory");
    }
    auto physical = bytes;
    for (auto it = breakpoints_.lower_bound(address); it != breakpoints_.end(); ++it) {
        auto offset = it->first - address;
        if (offset >= bytes.size())
            break;
        if (bytes[static_cast<size_t>(offset)] == 0xcc)
            throw std::runtime_error(
                "cannot patch an active breakpoint's original instruction to INT3");
        if (it->second.installed)
            physical[static_cast<size_t>(offset)] = 0xcc;
    }
    // write() either commits, rolls back, or raises MemoryCorruption (fail closed).
    memory_.write(address, physical);
    for (auto it = breakpoints_.lower_bound(address); it != breakpoints_.end(); ++it) {
        auto offset = it->first - address;
        if (offset >= bytes.size())
            break;
        it->second.original_byte = bytes[static_cast<size_t>(offset)];
    }
}
} // namespace sdb
