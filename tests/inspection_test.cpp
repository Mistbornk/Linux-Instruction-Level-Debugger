#include "sdb/backtrace.hpp"
#include "sdb/register_file.hpp"
#include "sdb/syscall_decoder.hpp"

#include <asm/unistd.h>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <linux/audit.h>
#include <stdexcept>
#include <string>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>

extern "C" {
char sdb_inspection_path[] = "/tmp/sdb-test\n\x1b\"";
char sdb_inspection_long_path[256];
__attribute__((noinline)) void sdb_inspection_fixture() {
    std::memset(sdb_inspection_long_path, 'x', sizeof(sdb_inspection_long_path));
    __asm__ volatile("int3" : : : "memory");
    _exit(0);
}
}

namespace {

void require(bool condition, const std::string& message) {
    if (!condition)
        throw std::runtime_error(message);
}

template <typename Action> void rejects(Action action, const char* message) {
    try {
        action();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error(message);
}

bool probe_ptrace() {
    const auto child = ::fork();
    if (child == -1)
        throw std::system_error(errno, std::generic_category(), "fork probe");
    if (child == 0) {
        if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
            _exit(errno);
        _exit(0);
    }
    int status = 0;
    pid_t result;
    do {
        result = ::waitpid(child, &status, 0);
    } while (result == -1 && errno == EINTR);
    require(result == child && WIFEXITED(status), "ptrace probe failed unexpectedly");
    const auto error = WEXITSTATUS(status);
    if (error == EPERM || error == EACCES || error == ENOSYS) {
        std::cout << "SKIP: independent PTRACE_TRACEME probe: " << std::strerror(error) << '\n';
        return false;
    }
    require(error == 0, "unexpected ptrace environment error");
    return true;
}

void pure_checks() {
    user_regs_struct snapshot{};
    sdb::RegisterFile::set(snapshot, "rax", std::numeric_limits<std::uint64_t>::max());
    sdb::RegisterFile::set(snapshot, "$r15", 123);
    require(snapshot.rax == std::numeric_limits<std::uint64_t>::max() && snapshot.r15 == 123,
            "register setters wrote the wrong field");
    require(sdb::RegisterFile::get(snapshot, "$rax") == snapshot.rax &&
                sdb::RegisterFile::get(snapshot, "r15") == 123 && snapshot.rip == 0,
            "register getter or independent field failed");
    for (const auto* invalid : {"", "$", "eax", "RAX", "xmm0", "rip garbage"}) {
        rejects([&] { sdb::RegisterFile::set(snapshot, invalid, 5); },
                "accepted invalid register name");
    }

    sdb::TraceEvent event;
    event.kind = sdb::EventKind::SyscallEntry;
    event.syscall_number = __NR_openat;
    event.syscall_architecture = AUDIT_ARCH_X86_64;
    event.syscall_arguments = {0xffffff9cULL, 0x1234, 0, 0, 0, 0};
    const auto entry = sdb::format_syscall_entry(event);
    require(entry.find("openat(dirfd=-100, path=0x1234") == 0,
            "openat failed to decode low-32-bit signed directory fd");
    event.syscall_number = 999999;
    require(sdb::format_syscall_entry(event).find("syscall_999999(arg0=") == 0,
            "unknown syscall did not retain its number and raw arguments");
    event.syscall_number = 0x40000000ULL | __NR_read;
    require(sdb::format_syscall_entry(event).find("unsupported syscall ABI") == 0,
            "x32 syscall mislabeled as native x86-64");
    event.syscall_number = __NR_read;
    event.syscall_architecture = AUDIT_ARCH_I386;
    require(sdb::format_syscall_entry(event).find("unsupported syscall ABI") == 0,
            "compat syscall mislabeled as native x86-64");
    event.syscall_architecture = AUDIT_ARCH_X86_64;
    event.syscall_result = -EFAULT;
    require(sdb::format_syscall_exit(event).find("read = -14 (errno 14:") == 0,
            "negative syscall result missing kernel errno interpretation");
    event.syscall_result = -512;
    require(sdb::format_syscall_exit(event).find("ERESTARTSYS: kernel restart pending") !=
                std::string::npos,
            "kernel restart result mislabeled as userspace errno");
    event.syscall_number.reset();
    require(sdb::format_syscall_entry(event) == "unknown syscall",
            "missing syscall fabricated a name");
}

void live_checks() {
    sdb::Tracee tracee;
    const sdb::Memory memory(tracee);
    tracee.launch({"/proc/self/exe", "--fixture"});
    const auto stop = tracee.resume(sdb::ResumeMode::Continue);
    require(stop.kind == sdb::EventKind::Trap, "fixture did not reach native INT3");
    const sdb::ElfImage image("/proc/self/exe");
    const auto bias = image.load_bias(tracee.pid());
    const auto original_registers = tracee.regs();
    sdb::RegisterFile::write(tracee, "rax", 0xfedcba9876543210ULL);
    require(sdb::RegisterFile::read(tracee, "rax") == 0xfedcba9876543210ULL,
            "named register write did not reach the stopped tracee");
    require(sdb::RegisterFile::read(tracee, "rip") == original_registers.rip,
            "named write clobbered instruction pointer");
    require(sdb::RegisterFile::values(tracee).size() == 27, "register inventory incomplete");
    tracee.set_regs(original_registers);

    auto stack = sdb::collect_backtrace(tracee, memory, &image, bias);
    require(stack.frames.size() >= 2 &&
                stack.frames.front().symbol.find("sdb_inspection_fixture") == 0,
            "established frame-pointer stack or current symbol missing");
    require(sdb::collect_backtrace(tracee, memory, &image, bias, 1).frames.size() == 1,
            "backtrace exceeded requested bound");
    rejects([&] { sdb::collect_backtrace(tracee, memory, &image, bias, 0); },
            "accepted zero frames");
    rejects([&] { sdb::collect_backtrace(tracee, memory, &image, bias, 65); },
            "accepted unbounded frames");
    sdb::RegisterFile::write(tracee, "rbp", 1);
    stack = sdb::collect_backtrace(tracee, memory, &image, bias);
    require(stack.frames.size() == 1 && stack.stop_reason.find("unaligned") != std::string::npos,
            "corrupt RBP was followed");
    sdb::RegisterFile::write(tracee, "rbp", 0x7ffffffffffffff0ULL);
    stack = sdb::collect_backtrace(tracee, memory, &image, bias);
    require(stack.frames.size() == 1 && stack.stop_reason.find("mapping") != std::string::npos,
            "out-of-stack frame was read");
    tracee.set_regs(original_registers);
    const auto original_frame = memory.read(original_registers.rbp, 16);
    auto cycle = original_frame;
    std::memcpy(cycle.data(), &original_registers.rbp, sizeof(std::uint64_t));
    memory.write(original_registers.rbp, cycle);
    stack = sdb::collect_backtrace(tracee, memory, &image, bias);
    require(stack.frames.size() <= 2 && stack.stop_reason == "non-increasing frame-pointer chain",
            "cyclic frame chain was not bounded");
    memory.write(original_registers.rbp, original_frame);

    sdb::TraceEvent event;
    event.kind = sdb::EventKind::SyscallEntry;
    event.syscall_number = __NR_openat;
    event.syscall_architecture = AUDIT_ARCH_X86_64;
    event.syscall_arguments = {
        0xffffff9cULL, image.object_address("sdb_inspection_path", bias), 0, 0, 0, 0};
    const auto escaped = sdb::format_syscall_entry(event, &memory);
    require(escaped.find("/tmp/sdb-test\\n\\x1b\\\"") != std::string::npos &&
                escaped.find('\n') == std::string::npos &&
                escaped.find('\x1b') == std::string::npos,
            "tracee path injected unescaped terminal controls");
    event.syscall_arguments[1] = image.object_address("sdb_inspection_long_path", bias);
    const auto bounded = sdb::format_syscall_entry(event, &memory);
    require(bounded.size() < 240 && bounded.find("\"...") != std::string::npos,
            "path preview was not bounded and marked truncated");
    event.syscall_arguments[1] = 1;
    require(sdb::format_syscall_entry(event, &memory).find("0x1 <unreadable>") != std::string::npos,
            "invalid path pointer was not reported safely");
    event.syscall_arguments[1] = 0;
    require(sdb::format_syscall_entry(event, &memory).find("path=NULL") != std::string::npos,
            "null path pointer mishandled");
    tracee.terminate();
    rejects([&] { sdb::RegisterFile::read(tracee, "rip"); }, "register access after exit accepted");
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--fixture")
        sdb_inspection_fixture();
    try {
        pure_checks();
        if (!probe_ptrace())
            return 77;
        live_checks();
        std::cout << "inspection: named registers, frame bounds/cycle, ABI decoding, "
                     "escaped/bounded/unreadable paths passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "inspection test failure: " << error.what() << '\n';
        return 1;
    }
}
