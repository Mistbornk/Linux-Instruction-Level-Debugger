#include "sdb/syscall_decoder.hpp"
#include "sdb/memory.hpp"

#include <algorithm>
#include <asm/unistd.h>
#include <cstdint>
#include <iomanip>
#include <linux/audit.h>
#include <sstream>
#include <system_error>

namespace sdb {
namespace {

std::string hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

std::string descriptor(std::uint64_t value) {
    // Kernel syscall arguments for fd/pid use the low 32 bits, including AT_FDCWD.
    const auto bits = static_cast<std::uint32_t>(value);
    const auto signed_value = bits <= 0x7fffffffU ? static_cast<std::int64_t>(bits)
                                                  : static_cast<std::int64_t>(bits) - 0x100000000LL;
    return std::to_string(signed_value);
}

std::string quoted(const std::vector<std::uint8_t>& bytes, bool c_string, bool& terminated) {
    std::ostringstream out;
    out << '"';
    terminated = false;
    for (const auto byte : bytes) {
        if (c_string && byte == 0) {
            terminated = true;
            break;
        }
        switch (byte) {
        case '\\':
            out << "\\\\";
            break;
        case '"':
            out << "\\\"";
            break;
        case '\n':
            out << "\\n";
            break;
        case '\r':
            out << "\\r";
            break;
        case '\t':
            out << "\\t";
            break;
        default:
            if (byte >= 32 && byte < 127)
                out << static_cast<char>(byte);
            else
                out << "\\x" << std::hex << std::setfill('0') << std::setw(2)
                    << static_cast<unsigned>(byte) << std::dec;
        }
    }
    out << '"';
    return out.str();
}

std::string preview(const Memory* memory, std::uint64_t address, std::uint64_t count,
                    bool c_string) {
    if (address == 0)
        return "NULL";
    const auto prefix = hex(address);
    if (!memory || count == 0)
        return prefix;
    try {
        const auto regions = memory->mappings();
        const auto region =
            std::find_if(regions.begin(), regions.end(), [&](const Region& candidate) {
                return candidate.readable && address >= candidate.start && address < candidate.end;
            });
        if (region == regions.end())
            return prefix + " <unreadable>";
        const auto wanted = std::min<std::uint64_t>(count, c_string ? 128 : 64);
        const auto size = static_cast<std::size_t>(std::min(wanted, region->end - address));
        const auto bytes = memory->read_up_to(address, size);
        bool terminated = false;
        auto text = quoted(bytes, c_string, terminated);
        if ((c_string && !terminated) || (!c_string && bytes.size() < count))
            text += "...";
        return prefix + " " + text;
    } catch (const std::exception&) {
        return prefix + " <unreadable>";
    }
}

bool native(const TraceEvent& event) {
    // x32 shares AUDIT_ARCH_X86_64 but has a separate syscall number space.
    return event.syscall_architecture == AUDIT_ARCH_X86_64 && event.syscall_number &&
           (*event.syscall_number & 0x40000000ULL) == 0;
}

} // namespace

std::string syscall_name(std::uint64_t number) {
    switch (number) {
#define SDB_SYSCALL(name)                                                                          \
    case __NR_##name:                                                                              \
        return #name
        SDB_SYSCALL(read);
        SDB_SYSCALL(write);
        SDB_SYSCALL(open);
        SDB_SYSCALL(close);
        SDB_SYSCALL(stat);
        SDB_SYSCALL(fstat);
        SDB_SYSCALL(lstat);
        SDB_SYSCALL(poll);
        SDB_SYSCALL(lseek);
        SDB_SYSCALL(mmap);
        SDB_SYSCALL(mprotect);
        SDB_SYSCALL(munmap);
        SDB_SYSCALL(brk);
        SDB_SYSCALL(rt_sigaction);
        SDB_SYSCALL(rt_sigprocmask);
        SDB_SYSCALL(rt_sigreturn);
        SDB_SYSCALL(ioctl);
        SDB_SYSCALL(pread64);
        SDB_SYSCALL(pwrite64);
        SDB_SYSCALL(readv);
        SDB_SYSCALL(writev);
        SDB_SYSCALL(access);
        SDB_SYSCALL(pipe);
        SDB_SYSCALL(sched_yield);
        SDB_SYSCALL(mremap);
        SDB_SYSCALL(madvise);
        SDB_SYSCALL(dup);
        SDB_SYSCALL(dup2);
        SDB_SYSCALL(nanosleep);
        SDB_SYSCALL(getpid);
        SDB_SYSCALL(socket);
        SDB_SYSCALL(connect);
        SDB_SYSCALL(accept);
        SDB_SYSCALL(sendto);
        SDB_SYSCALL(recvfrom);
        SDB_SYSCALL(clone);
        SDB_SYSCALL(fork);
        SDB_SYSCALL(vfork);
        SDB_SYSCALL(execve);
        SDB_SYSCALL(exit);
        SDB_SYSCALL(wait4);
        SDB_SYSCALL(kill);
        SDB_SYSCALL(uname);
        SDB_SYSCALL(fcntl);
        SDB_SYSCALL(fsync);
        SDB_SYSCALL(getcwd);
        SDB_SYSCALL(chdir);
        SDB_SYSCALL(readlink);
        SDB_SYSCALL(getuid);
        SDB_SYSCALL(getgid);
        SDB_SYSCALL(geteuid);
        SDB_SYSCALL(getegid);
        SDB_SYSCALL(getppid);
        SDB_SYSCALL(arch_prctl);
        SDB_SYSCALL(gettid);
        SDB_SYSCALL(futex);
        SDB_SYSCALL(set_tid_address);
        SDB_SYSCALL(clock_gettime);
        SDB_SYSCALL(exit_group);
        SDB_SYSCALL(tgkill);
        SDB_SYSCALL(openat);
        SDB_SYSCALL(newfstatat);
        SDB_SYSCALL(readlinkat);
        SDB_SYSCALL(set_robust_list);
        SDB_SYSCALL(prlimit64);
        SDB_SYSCALL(getrandom);
        SDB_SYSCALL(execveat);
#ifdef __NR_rseq
        SDB_SYSCALL(rseq);
#endif
#ifdef __NR_clone3
        SDB_SYSCALL(clone3);
#endif
#undef SDB_SYSCALL
    default:
        return "syscall_" + std::to_string(number);
    }
}

std::string format_syscall_entry(const TraceEvent& event, const Memory* memory) {
    if (!event.syscall_number)
        return "unknown syscall";
    if (!native(event))
        return "unsupported syscall ABI arch=" + hex(event.syscall_architecture) +
               ", nr=" + std::to_string(*event.syscall_number);
    const auto number = *event.syscall_number;
    const auto& a = event.syscall_arguments;
    std::ostringstream out;
    out << syscall_name(number) << '(';
    switch (number) {
    case __NR_read:
    case __NR_write:
        out << "fd=" << descriptor(a[0])
            << ", buf=" << (number == __NR_write ? preview(memory, a[1], a[2], false) : hex(a[1]))
            << ", count=" << a[2];
        break;
    case __NR_open:
        out << "path=" << preview(memory, a[0], 128, true) << ", flags=" << hex(a[1])
            << ", mode=" << hex(a[2]);
        break;
    case __NR_openat:
        out << "dirfd=" << descriptor(a[0]) << ", path=" << preview(memory, a[1], 128, true)
            << ", flags=" << hex(a[2]) << ", mode=" << hex(a[3]);
        break;
    case __NR_close:
        out << "fd=" << descriptor(a[0]);
        break;
    case __NR_mmap:
        out << "addr=" << hex(a[0]) << ", length=" << a[1] << ", prot=" << hex(a[2])
            << ", flags=" << hex(a[3]) << ", fd=" << descriptor(a[4]) << ", offset=" << a[5];
        break;
    case __NR_mprotect:
        out << "addr=" << hex(a[0]) << ", length=" << a[1] << ", prot=" << hex(a[2]);
        break;
    case __NR_munmap:
        out << "addr=" << hex(a[0]) << ", length=" << a[1];
        break;
    case __NR_brk:
        out << "addr=" << hex(a[0]);
        break;
    case __NR_execve:
        out << "path=" << preview(memory, a[0], 128, true) << ", argv=" << hex(a[1])
            << ", envp=" << hex(a[2]);
        break;
    case __NR_execveat:
        out << "dirfd=" << descriptor(a[0]) << ", path=" << preview(memory, a[1], 128, true)
            << ", argv=" << hex(a[2]) << ", envp=" << hex(a[3]) << ", flags=" << hex(a[4]);
        break;
    case __NR_exit:
    case __NR_exit_group:
        out << "status=" << descriptor(a[0]);
        break;
    case __NR_futex:
        out << "uaddr=" << hex(a[0]) << ", op=" << hex(a[1]) << ", val=" << a[2]
            << ", timeout_or_val2=" << hex(a[3]) << ", uaddr2=" << hex(a[4]) << ", val3=" << a[5];
        break;
    case __NR_clone:
        out << "flags=" << hex(a[0]) << ", child_stack=" << hex(a[1])
            << ", parent_tid=" << hex(a[2]) << ", child_tid=" << hex(a[3]) << ", tls=" << hex(a[4]);
        break;
#ifdef __NR_clone3
    case __NR_clone3:
        out << "args=" << hex(a[0]) << ", size=" << a[1];
        break;
#endif
    case __NR_getpid:
    case __NR_getppid:
    case __NR_gettid:
    case __NR_getuid:
    case __NR_geteuid:
    case __NR_getgid:
    case __NR_getegid:
    case __NR_fork:
    case __NR_vfork:
    case __NR_rt_sigreturn:
    case __NR_sched_yield:
        break;
    default:
        // Do not invent argument semantics for syscalls not decoded above.
        for (std::size_t index = 0; index < a.size(); ++index) {
            if (index)
                out << ", ";
            out << "arg" << index << '=' << hex(a[index]);
        }
    }
    out << ')';
    return out.str();
}

std::string format_syscall_exit(const TraceEvent& event) {
    std::ostringstream out;
    if (native(event))
        out << syscall_name(*event.syscall_number);
    else if (event.syscall_number)
        out << "syscall_" << *event.syscall_number << " (unknown ABI)";
    else
        out << "unknown syscall";
    out << " = " << event.syscall_result;
    // These internal restart codes are observable by ptrace before the kernel
    // converts/restarts the syscall; they are not errors returned to user code.
    // Values are from Linux include/linux/errno.h (not the userspace errno API).
    const char* restart = nullptr;
    switch (event.syscall_result) {
    case -512:
        restart = "ERESTARTSYS";
        break;
    case -513:
        restart = "ERESTARTNOINTR";
        break;
    case -514:
        restart = "ERESTARTNOHAND";
        break;
    case -516:
        restart = "ERESTART_RESTARTBLOCK";
        break;
    default:
        break;
    }
    if (restart) {
        out << " (" << restart << ": kernel restart pending)";
        return out.str();
    }
    // The native kernel ABI returns -errno, not libc's -1/errno translation.
    if (event.syscall_result < 0 && event.syscall_result >= -4095) {
        const auto error = static_cast<int>(-event.syscall_result);
        out << " (errno " << error << ": " << std::generic_category().message(error) << ')';
    }
    return out.str();
}

} // namespace sdb
