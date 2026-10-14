#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <sys/types.h>

namespace sdb {

enum class EventKind {
    Exited,
    Signaled,
    Signal,
    GroupStop,
    Interrupted,
    Trap,
    SingleStep,
    SyscallEntry,
    SyscallExit,
    Exec,
    ThreadCreated,
    ThreadExited,
    // A fork/vfork or clone outside the thread group is held only for safe
    // restoration/detachment; it must never be resumed as a supported task.
    UnsupportedClone,
    PtraceEvent,
};

struct TraceEvent {
    using Kind = EventKind;
    EventKind kind = EventKind::Signal;
    pid_t tid = -1;
    pid_t new_tid = -1;
    int signal = 0;
    int exit_code = 0;
    int trap_code = 0;
    unsigned int ptrace_event = 0;
    std::optional<std::uint64_t> syscall_number;
    std::array<std::uint64_t, 6> syscall_arguments{};
    std::uint32_t syscall_architecture = 0;
    std::int64_t syscall_result = 0;

    bool terminal() const noexcept {
        return kind == EventKind::Exited || kind == EventKind::Signaled;
    }
};

} // namespace sdb
