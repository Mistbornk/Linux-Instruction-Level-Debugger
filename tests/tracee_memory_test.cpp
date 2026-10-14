#include "sdb/breakpoint.hpp"
#include "sdb/memory.hpp"
#include "sdb/tracee.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>
#include <vector>

// GNU ld wraps calls from our Memory implementation, leaving libc internals
// alone. Failures occur at the actual syscall boundary, not in a mock Memory.
namespace {
enum class Fault {
    None,
    Open,
    Read,
    ReadZero,
    ReadShort,
    Write,
    WriteZero,
    PartialWrite,
    Rollback
};
Fault fault = Fault::None;
unsigned int calls = 0;

void inject(Fault next) {
    fault = next;
    calls = 0;
}

void check(bool condition, const std::string& message) {
    if (!condition)
        throw std::runtime_error(message);
}

template <typename Exception, typename Action>
void expect_error(Action action, const char* message) {
    try {
        action();
    } catch (const Exception&) {
        return;
    }
    throw std::runtime_error(message);
}

std::size_t descriptor_count() {
    DIR* directory = ::opendir("/proc/self/fd");
    if (!directory)
        throw std::system_error(errno, std::generic_category(), "opendir");
    std::size_t count = 0;
    errno = 0;
    while (::readdir(directory))
        ++count;
    const int error = errno;
    if (::closedir(directory) == -1)
        throw std::system_error(errno, std::generic_category(), "closedir");
    if (error)
        throw std::system_error(error, std::generic_category(), "readdir");
    return count;
}

struct FixtureMemory {
    std::uint64_t address;
    std::uint64_t page_size;
};

int fixture(int report_fd) {
    const long size = ::sysconf(_SC_PAGESIZE);
    if (size <= 0)
        return 100;
    const auto page_size = static_cast<std::size_t>(size);
    void* allocation =
        ::mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (allocation == MAP_FAILED)
        return 101;
    auto* bytes = static_cast<std::uint8_t*>(allocation);
    // A real unmapped hole, rather than PROT_NONE (which /proc/mem can bypass).
    if (::munmap(bytes + page_size, page_size) == -1)
        return 102;
    // An executable mapping lets the same syscall fault tests exercise real
    // breakpoint metadata. These deliberately synthetic bytes are never run.
    if (::mprotect(bytes, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
        return 106;
    for (std::size_t i = 0; i < page_size; ++i)
        bytes[i] = static_cast<std::uint8_t>(i);
    const FixtureMemory info{reinterpret_cast<std::uintptr_t>(bytes), page_size};
    if (::write(report_fd, &info, sizeof(info)) != static_cast<ssize_t>(sizeof(info)))
        return 103;
    if (::close(report_fd) == -1)
        return 104;
    if (::raise(SIGSTOP) != 0)
        return 105;
    // Retain the mapping until the owning Tracee terminates us.
    for (;;)
        ::pause();
}

FixtureMemory launch_fixture(sdb::Tracee& tracee) {
    int report[2];
    if (::pipe(report) == -1)
        throw std::system_error(errno, std::generic_category(), "pipe");
    try {
        const auto exec = tracee.launch({"/proc/self/exe", "--fixture", std::to_string(report[1])});
        check(exec.kind == sdb::EventKind::Exec, "missing initial exec event");
        if (::close(report[1]) == -1)
            throw std::system_error(errno, std::generic_category(), "close");
        report[1] = -1;
        const auto stop = tracee.resume(sdb::ResumeMode::Continue);
        check(stop.kind == sdb::EventKind::Signal && stop.signal == SIGSTOP,
              "fixture did not stop");
        FixtureMemory info{};
        check(::read(report[0], &info, sizeof(info)) == static_cast<ssize_t>(sizeof(info)),
              "missing fixture report");
        if (::close(report[0]) == -1)
            throw std::system_error(errno, std::generic_category(), "close");
        return info;
    } catch (...) {
        ::close(report[0]);
        if (report[1] >= 0)
            ::close(report[1]);
        throw;
    }
}

bool probe_ptrace() {
    const auto pid = ::fork();
    if (pid == -1)
        throw std::system_error(errno, std::generic_category(), "fork probe");
    if (pid == 0) {
        if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
            _exit(errno);
        _exit(0);
    }
    int status = 0;
    pid_t result;
    do {
        result = ::waitpid(pid, &status, 0);
    } while (result == -1 && errno == EINTR);
    check(result == pid && WIFEXITED(status), "ptrace probe failed unexpectedly");
    const auto error = WEXITSTATUS(status);
    if (error == EPERM || error == EACCES || error == ENOSYS) {
        std::cout << "SKIP: independent PTRACE_TRACEME probe: " << std::strerror(error) << '\n';
        return false;
    }
    check(error == 0, "unexpected ptrace environment error");
    return true;
}

} // namespace

extern "C" int __real_open(const char*, int, ...);
extern "C" ssize_t __real_pread(int, void*, std::size_t, off_t);
extern "C" ssize_t __real_pwrite(int, const void*, std::size_t, off_t);

extern "C" int __wrap_open(const char* path, int flags, ...) {
    if (fault == Fault::Open && std::strncmp(path, "/proc/", 6) == 0 && std::strstr(path, "/mem")) {
        ++calls;
        errno = EACCES;
        return -1;
    }
    if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list arguments;
        va_start(arguments, flags);
        const auto mode = va_arg(arguments, mode_t);
        va_end(arguments);
        return __real_open(path, flags, mode);
    }
    return __real_open(path, flags);
}

extern "C" ssize_t __wrap_pread(int fd, void* bytes, std::size_t size, off_t offset) {
    if (fault == Fault::Read) {
        ++calls;
        errno = EIO;
        return -1;
    }
    if (fault == Fault::ReadZero) {
        ++calls;
        return 0;
    }
    if (fault == Fault::ReadShort) {
        ++calls;
        return __real_pread(fd, bytes, std::min(size, std::size_t{2}), offset);
    }
    return __real_pread(fd, bytes, size, offset);
}

extern "C" ssize_t __wrap_pwrite(int fd, const void* bytes, std::size_t size, off_t offset) {
    if (fault == Fault::Write) {
        ++calls;
        errno = EIO;
        return -1;
    }
    if (fault == Fault::WriteZero) {
        ++calls;
        return 0;
    }
    if (fault == Fault::PartialWrite || fault == Fault::Rollback) {
        ++calls;
        if (calls == 1)
            return __real_pwrite(fd, bytes, size / 2, offset);
        if (calls == 2 || fault == Fault::Rollback) {
            errno = EIO;
            return -1;
        }
    }
    return __real_pwrite(fd, bytes, size, offset);
}

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "--fixture")
        return fixture(std::stoi(argv[2]));
    if (argc == 2 && std::string(argv[1]) == "--exit")
        _exit(41);
    if (argc == 2 && std::string(argv[1]) == "--syscall-step") {
        __asm__ volatile("mov $39, %%eax\n" // getpid
                         "int3\n"
                         "syscall\n"
                         "int3\n"
                         :
                         :
                         : "rax", "rcx", "r11", "memory");
        _exit(0);
    }
    try {
        if (!probe_ptrace())
            return 77;
        const auto initial_descriptors = descriptor_count();
        {
            sdb::Tracee tracee;
            sdb::Memory memory(tracee);
            expect_error<std::logic_error>([&] { memory.read(0, 1); },
                                           "memory without tracee accepted");
            expect_error<std::logic_error>([&] { tracee.regs(); },
                                           "registers without tracee accepted");
            expect_error<std::system_error>([&] { tracee.launch({"/sdb/no-such-executable"}); },
                                            "invalid exec accepted");
            check(tracee.pid() == -1 && tracee.state() == sdb::ProcessState::NoProgram,
                  "exec failure retained process state");
            check(descriptor_count() == initial_descriptors, "launch error leaked a descriptor");

            auto info = launch_fixture(tracee);
            const std::vector<std::uint8_t> expected{0, 1, 2, 3, 4, 5, 6, 7};
            const std::vector<std::uint8_t> changed(expected.size(), 0xa5);
            check(memory.read(info.address, expected.size()) == expected, "initial memory differs");
            check(!memory.executable_end(info.address + 2 * info.page_size),
                  "data mapping reported executable");
            check(memory.executable_end(info.address) == info.address + info.page_size,
                  "executable fixture boundary incorrect");
            check(memory.executable_end(tracee.regs().rip).has_value(),
                  "code mapping not executable");

            inject(Fault::ReadShort);
            check(memory.read(info.address, expected.size()) == expected && calls == 4,
                  "short reads were not completed");
            inject(Fault::None);
            const auto boundary = info.address + info.page_size - 4;
            check(memory.read_up_to(boundary, 8) == std::vector<std::uint8_t>({252, 253, 254, 255}),
                  "partial boundary read incorrect");
            expect_error<std::system_error>([&] { memory.read(boundary, 8); },
                                            "exact boundary read accepted");
            expect_error<std::system_error>([&] { memory.write(boundary, changed); },
                                            "write with inaccessible suffix accepted");
            check(memory.read(boundary, 4) == std::vector<std::uint8_t>({252, 253, 254, 255}),
                  "snapshot failure changed accessible prefix");
            expect_error<std::out_of_range>(
                [&] { memory.write(std::numeric_limits<std::uint64_t>::max(), changed); },
                "overflowing address accepted");

            for (const auto failure :
                 {Fault::Open, Fault::Read, Fault::Write, Fault::WriteZero, Fault::PartialWrite}) {
                inject(failure);
                expect_error<std::system_error>([&] { memory.write(info.address, changed); },
                                                "injected failure succeeded");
                check(calls > 0, "fault injection was not exercised");
                if (failure == Fault::PartialWrite)
                    check(calls == 3, "partial write did not attempt rollback");
                inject(Fault::None);
                check(memory.read(info.address, expected.size()) == expected,
                      "failed write left changed bytes");
                check(descriptor_count() == initial_descriptors,
                      "failure path leaked a descriptor");
            }
            inject(Fault::ReadZero);
            expect_error<std::runtime_error>([&] { memory.read(info.address, expected.size()); },
                                             "zero-byte read succeeded");
            inject(Fault::None);

            memory.write(info.address, changed);
            check(memory.read(info.address, changed.size()) == changed, "successful write missing");
            memory.write(info.address, expected);
            for (int i = 0; i < 100; ++i) {
                check(memory.read(info.address, expected.size()) == expected,
                      "repeated read differs");
                memory.write(info.address, expected);
                check(!memory.mappings().empty(), "missing mappings");
            }
            check(descriptor_count() == initial_descriptors,
                  "repeated memory operations leaked descriptors");

            sdb::BreakpointManager breakpoints(memory);
            inject(Fault::Write);
            expect_error<std::system_error>([&] { breakpoints.add(info.address); },
                                            "failed breakpoint insertion succeeded");
            check(calls == 1, "breakpoint insertion did not reach failing write");
            inject(Fault::None);
            check(breakpoints.all().empty() &&
                      memory.read(info.address, expected.size()) == expected,
                  "failed breakpoint insertion changed metadata or memory");
            const auto breakpoint = breakpoints.add(info.address);
            check(breakpoint.id == 0 && breakpoint.original_byte == 0 && breakpoint.installed,
                  "zero original byte or failed-insertion ID invariant broken");
            auto installed_bytes = expected;
            installed_bytes.front() = 0xcc;
            check(memory.read(info.address, installed_bytes.size()) == installed_bytes,
                  "INT3 not installed");

            inject(Fault::Write);
            expect_error<std::system_error>([&] { breakpoints.remove(breakpoint.id); },
                                            "failed breakpoint removal succeeded");
            check(calls == 1, "breakpoint removal did not reach failing write");
            inject(Fault::None);
            const auto* retained = breakpoints.find(info.address);
            check(retained && retained->id == breakpoint.id && retained->original_byte == 0 &&
                      retained->installed,
                  "failed removal lost or changed breakpoint metadata");
            check(memory.read(info.address, installed_bytes.size()) == installed_bytes,
                  "failed removal changed physical breakpoint bytes");

            inject(Fault::PartialWrite);
            expect_error<std::system_error>([&] { breakpoints.patch(info.address, changed); },
                                            "partial breakpoint patch succeeded");
            check(calls == 3, "partial breakpoint patch did not roll back");
            inject(Fault::None);
            retained = breakpoints.find(info.address);
            check(retained && retained->original_byte == 0 && retained->installed,
                  "failed patch committed breakpoint original-byte metadata");
            check(memory.read(info.address, installed_bytes.size()) == installed_bytes,
                  "failed patch did not restore physical breakpoint bytes");
            auto visible = installed_bytes;
            breakpoints.overlay(info.address, visible);
            check(visible == expected, "failed patch changed debugger-visible bytes");
            breakpoints.patch(info.address, changed);
            check(breakpoints.find(info.address)->original_byte == changed.front(),
                  "successful patch did not update original byte");
            breakpoints.remove(breakpoint.id);
            check(breakpoints.all().empty() && memory.read(info.address, changed.size()) == changed,
                  "breakpoint removal did not restore successfully patched bytes");
            memory.write(info.address, expected);

            inject(Fault::Rollback);
            expect_error<sdb::MemoryCorruption>([&] { memory.write(info.address, changed); },
                                                "failed rollback did not report corruption");
            check(calls == 3, "rollback failure was not exercised");
            inject(Fault::None);
            tracee.terminate();
            check(tracee.pid() == -1, "termination retained pid");
            tracee.launch({"/proc/self/exe", "--exit"});
            const auto exit = tracee.resume(sdb::ResumeMode::Continue);
            check(exit.kind == sdb::EventKind::Exited && exit.exit_code == 41,
                  "normal child exit misclassified");
            expect_error<std::logic_error>([&] { memory.read(0, 1); },
                                           "memory access after exit accepted");

            tracee.launch({"/proc/self/exe", "--syscall-step"});
            const auto first_trap = tracee.resume(sdb::ResumeMode::Continue);
            check(first_trap.kind == sdb::EventKind::Trap && first_trap.trap_code == SI_KERNEL,
                  "native INT3 misclassified");
            const auto syscall_step = tracee.resume(sdb::ResumeMode::SingleStep);
            check(syscall_step.kind == sdb::EventKind::SingleStep,
                  "syscall single-step misclassified");
            const auto int3_step = tracee.resume(sdb::ResumeMode::SingleStep);
            check(int3_step.kind == sdb::EventKind::Trap && int3_step.trap_code == SI_KERNEL,
                  "single-stepping native INT3 swallowed application trap");
            check(tracee.resume(sdb::ResumeMode::Continue).kind == sdb::EventKind::Exited,
                  "syscall step fixture did not exit");

            launch_fixture(tracee);
            check(!tracee.poll_event(), "poll repeated an already-consumed stop");
            check(::kill(tracee.pid(), SIGKILL) == 0, "external kill failed");
            std::optional<sdb::TraceEvent> killed;
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (!(killed = tracee.poll_event())) {
                check(std::chrono::steady_clock::now() < deadline,
                      "external death not observed before deadline");
                ::usleep(1000);
            }
            check(killed->kind == sdb::EventKind::Signaled && killed->signal == SIGKILL &&
                      tracee.pid() == -1,
                  "external death did not reset tracee");
            // Destructor must also kill/reap a stopped child when no explicit
            // terminate command is issued (the debugger's EOF ownership path).
            info = launch_fixture(tracee);
            check(info.address != 0, "relaunch failed");
        }
        check(descriptor_count() == initial_descriptors, "session lifetime leaked descriptors");
        int status = 0;
        errno = 0;
        check(::waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD,
              "session lifetime left an unreaped child");
        std::cout << "PASS: tracee lifecycle, memory boundaries, breakpoint fault rollback, "
                     "descriptor ownership\n";
        return 0;
    } catch (const std::exception& error) {
        inject(Fault::None);
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
