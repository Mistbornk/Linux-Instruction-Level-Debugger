#pragma once

#include "sdb/tracee.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace sdb {

// Named x86-64 integer register access. Tracee remains the owner of ptrace and
// selected-task state. No shadow register cache can become stale after resume.
class RegisterFile {
  public:
    static std::uint64_t read(const Tracee& tracee, const std::string& name);
    static void write(Tracee& tracee, const std::string& name, std::uint64_t value);
    static std::vector<std::pair<std::string, std::uint64_t>> values(const Tracee& tracee);

    // Snapshot operations are also useful when inspecting a saved context.
    static std::uint64_t get(const user_regs_struct& registers, const std::string& name);
    static void set(user_regs_struct& registers, const std::string& name, std::uint64_t value);
};

} // namespace sdb
