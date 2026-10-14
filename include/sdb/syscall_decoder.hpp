#pragma once

#include "sdb/trace_event.hpp"

#include <cstdint>
#include <string>

namespace sdb {

class Memory;

// Native Linux x86-64 syscall numbers only. Unknown numbers remain explicit.
std::string syscall_name(std::uint64_t number);
// Compact descriptions without an event prefix, e.g. write(fd=1, buf=..., count=4).
// Path/payload reads are bounded and best effort; invalid pointers are reported
// as unreadable and never prevent resuming the tracee.
std::string format_syscall_entry(const TraceEvent& event, const Memory* memory = nullptr);
std::string format_syscall_exit(const TraceEvent& event);

} // namespace sdb
