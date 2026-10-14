#include "sdb/debugger.hpp"
#include "sdb/memory.hpp"
#include "sdb/tracee.hpp"

#include <array>
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <pthread.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>

namespace {
enum class Fault { None, SecondWatchRestore, FirstDetach, DetachPreflight, SecondDetach };
Fault fault = Fault::None;
unsigned int matching_calls = 0;
unsigned int detach_calls = 0;
unsigned int debug_write_calls = 0;
unsigned int injected_failures = 0;

alignas(8) volatile std::uint64_t watched_value = 0;

__attribute__((noinline)) void unused_breakpoint_site() {
    asm volatile("nop" ::: "memory");
}

void check(bool value, const char* message) {
    if (!value)
        throw std::runtime_error(message);
}

template <class Action> void rejected(Action action, const char* message) {
    try {
        action();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error(message);
}

void inject(Fault next) {
    fault = next;
    matching_calls = detach_calls = debug_write_calls = injected_failures = 0;
}

std::string hex_address(std::uintptr_t address) {
    std::ostringstream out;
    out << "0x" << std::hex << address;
    return out.str();
}

long peek(pid_t pid, __ptrace_request request, std::uintptr_t address) {
    errno = 0;
    const long result = ::ptrace(request, pid, reinterpret_cast<void*>(address), nullptr);
    if (result == -1 && errno != 0)
        throw std::system_error(errno, std::generic_category(), "peek detached fixture");
    return result;
}

bool probe() {
    const pid_t child = ::fork();
    check(child != -1, "fork probe failed");
    if (child == 0) {
        if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
            _exit(errno);
        _exit(0);
    }
    int status = 0;
    check(::waitpid(child, &status, 0) == child && WIFEXITED(status), "probe wait failed");
    const int error = WEXITSTATUS(status);
    if (error == EPERM || error == EACCES || error == ENOSYS) {
        std::cout << "SKIP: independent ptrace probe: " << std::strerror(error) << '\n';
        return false;
    }
    check(error == 0, "unexpected ptrace probe failure");
    return true;
}

void* idle_worker(void*) {
    for (;;)
        ::pause();
    return nullptr;
}

// A directly forked child preserves the parent's symbol addresses. All three
// tasks exist before attachment; no clone scheduling is needed by these tests.
class Child {
  public:
    Child() {
        int pipes[2];
        check(::pipe(pipes) == 0, "fixture pipe failed");
        const pid_t owner = ::getpid();
        pid_ = ::fork();
        if (pid_ == -1) {
            ::close(pipes[0]);
            ::close(pipes[1]);
            throw std::runtime_error("fixture fork failed");
        }
        if (pid_ == 0) {
            ::close(pipes[0]);
            if (::prctl(PR_SET_PDEATHSIG, SIGKILL) == -1 || ::getppid() != owner)
                _exit(90);
            pthread_t threads[2];
            for (auto& thread : threads)
                if (::pthread_create(&thread, nullptr, idle_worker, nullptr) != 0)
                    _exit(91);
            const char ready = 'r';
            if (::write(pipes[1], &ready, 1) != 1)
                _exit(92);
            ::close(pipes[1]);
            idle_worker(nullptr);
            _exit(0);
        }
        ::close(pipes[1]);
        char ready = 0;
        ssize_t size;
        do {
            size = ::read(pipes[0], &ready, 1);
        } while (size == -1 && errno == EINTR);
        ::close(pipes[0]);
        if (size != 1 || ready != 'r') {
            cleanup();
            throw std::runtime_error("thread fixture readiness failed");
        }
    }
    ~Child() { cleanup(); }
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;
    pid_t pid() const { return pid_; }

    void require_reaped() const {
        int status = 0;
        errno = 0;
        check(::waitpid(pid_, &status, WNOHANG) == -1 && errno == ECHILD,
              "failed detach did not reap the process");
    }

  private:
    pid_t pid_ = -1;
    void cleanup() noexcept {
        if (pid_ <= 0)
            return;
        int status = 0;
        pid_t result;
        do {
            result = ::waitpid(pid_, &status, WNOHANG);
        } while (result == -1 && errno == EINTR);
        // Do not signal a PID after its child has already been reaped.
        if (result == 0) {
            ::kill(pid_, SIGKILL);
            while (::waitpid(pid_, &status, 0) == -1 && errno == EINTR) {
            }
        }
        pid_ = -1;
    }
};

void restoration_failure_is_transactional(Fault failure, unsigned expected_detaches) {
    Child child;
    std::ostringstream output;
    sdb::Debugger debugger(output);
    debugger.execute("set disassemble off");
    debugger.execute("attach " + std::to_string(child.pid()));
    const auto code = reinterpret_cast<std::uintptr_t>(&unused_breakpoint_site);
    const auto data = reinterpret_cast<std::uintptr_t>(&watched_value);
    debugger.execute("break " + hex_address(code));
    debugger.execute("watch " + hex_address(data) + " 8");
    const auto dr7_offset = offsetof(user, u_debugreg) + 7 * sizeof(user::u_debugreg[0]);
    const auto dr7 = peek(child.pid(), PTRACE_PEEKUSER, dr7_offset);
    check((dr7 & 0xff) != 0, "watchpoint was not installed");

    // Restoration can fail midway, at preflight, or at the first DETACH.
    // With no released task, both software and hardware state must recover.
    inject(failure);
    rejected([&] { debugger.execute("detach"); }, "detach failure was hidden");
    check(injected_failures == 1 && detach_calls == expected_detaches,
          "restoration failure released a task or did not reach injected boundary");
    check((peek(child.pid(), PTRACE_PEEKDATA, code) & 0xff) == 0xcc,
          "detach failure left a software breakpoint disabled");
    check(peek(child.pid(), PTRACE_PEEKUSER, dr7_offset) == dr7,
          "detach failure did not roll back hardware registers");
    debugger.execute("info threads");
    debugger.execute("register read rip");
    debugger.execute("detach");
    // The external child is still alive after a successful retry.
    int status = 0;
    check(::waitpid(child.pid(), &status, WNOHANG) == 0,
          "successful detach terminated the external fixture");
}

void low_level_first_detach_preserves_all_stop() {
    Child child;
    sdb::Tracee tracee;
    tracee.attach(child.pid());
    const auto tids = tracee.threads();
    inject(Fault::FirstDetach);
    rejected([&] { tracee.detach(); }, "first detach failure was hidden");
    check(injected_failures == 1 && detach_calls == 1, "first detach was not exercised");
    check(tracee.state() == sdb::ProcessState::Stopped && tracee.all_stopped(),
          "first detach failure discarded the all-stop invariant");
    check(tracee.threads() == tids, "first detach failure forgot a task");
    for (pid_t tid : tids) {
        tracee.select_thread(tid);
        (void)tracee.regs();
    }
    tracee.detach();
    int status = 0;
    check(::waitpid(child.pid(), &status, WNOHANG) == 0,
          "first detach failure or retry killed the external process");
}

void low_level_partial_detach_invalidates_all_stop() {
    Child child;
    sdb::Tracee tracee;
    tracee.attach(child.pid());
    const auto tids = tracee.threads();
    check(tids.size() == 3 && tracee.all_stopped(), "fixture was not fully attached");
    const auto address = tracee.regs().rip;
    inject(Fault::SecondDetach);
    rejected([&] { tracee.detach(); }, "second detach failure was hidden");
    check(injected_failures == 1 && detach_calls == 2, "partial detach was not exercised");
    check(tracee.state() == sdb::ProcessState::Detaching && !tracee.stopped(),
          "partial detach retained a stopped-state claim");
    rejected([&] { tracee.resume(sdb::ResumeMode::Continue); },
             "partial detach permitted execution");
    rejected([&] { (void)tracee.regs(); }, "partial detach permitted register access");
    rejected([&] { (void)sdb::Memory(tracee).read(address, 1); },
             "partial detach permitted memory access");
    rejected([&] { tracee.select_thread(tids.back()); },
             "partial detach permitted normal task selection");
    tracee.terminate();
    child.require_reaped();
}

void existing_hardware_breakpoint_is_rejected_without_mutation() {
    Child child;
    sdb::Tracee tracee;
    tracee.attach(child.pid());
    const auto tids = tracee.threads();
    check(tids.size() == 3, "foreign-watch fixture was not fully attached");
    const pid_t peer = tids.back();
    const auto original_address = tracee.read_debug_register(peer, 0);
    const auto original_control = tracee.read_debug_register(peer, 7);
    const auto data = reinterpret_cast<std::uintptr_t>(&watched_value);
    tracee.write_debug_register(peer, 0, data);
    tracee.write_debug_register(peer, 7, 0x90001); // enabled 8-byte write watch

    constexpr std::array<unsigned int, 6> indices{0, 1, 2, 3, 6, 7};
    std::vector<std::array<std::uint64_t, indices.size()>> before;
    for (pid_t tid : tids) {
        std::array<std::uint64_t, indices.size()> values{};
        for (size_t i = 0; i < indices.size(); ++i)
            values[i] = tracee.read_debug_register(tid, indices[i]);
        before.push_back(values);
    }
    sdb::WatchpointManager watches(tracee);
    inject(Fault::None);
    rejected([&] { watches.add(data, 8, sdb::WatchAccess::Write); },
             "existing peer hardware breakpoint was accepted");
    check(debug_write_calls == 0 && watches.all().empty(),
          "foreign hardware breakpoint rejection changed state");
    for (size_t task = 0; task < tids.size(); ++task)
        for (size_t i = 0; i < indices.size(); ++i)
            check(tracee.read_debug_register(tids[task], indices[i]) == before[task][i],
                  "foreign hardware breakpoint rejection changed debug registers");

    // Never run the foreign watch or combine it with single-step in this test.
    tracee.write_debug_register(peer, 7, 0);
    tracee.write_debug_register(peer, 0, original_address);
    tracee.write_debug_register(peer, 7, original_control);
    tracee.detach();
}

void controller_partial_detach_fails_closed() {
    Child child;
    std::ostringstream output;
    sdb::Debugger debugger(output);
    debugger.execute("set disassemble off");
    debugger.execute("attach " + std::to_string(child.pid()));
    debugger.execute("break " +
                     hex_address(reinterpret_cast<std::uintptr_t>(&unused_breakpoint_site)));
    debugger.execute("watch " + hex_address(reinterpret_cast<std::uintptr_t>(&watched_value)) +
                     " 8");
    inject(Fault::SecondDetach);
    rejected([&] { debugger.execute("detach"); }, "partial controller detach was hidden");
    check(injected_failures == 1 && detach_calls == 2, "partial controller detach not exercised");
    child.require_reaped();
    rejected([&] { debugger.execute("register read rip"); },
             "controller retained a usable process after partial detach");
    debugger.load({"/bin/true"});
    debugger.execute("cont");
    check(output.str().find("exited with status 0") != std::string::npos,
          "controller was not reusable after failed detach cleanup");
}
} // namespace

// GNU ld redirects the real ptrace boundary used by sdb_core. Each selected
// operation fails only once, so rollback and cleanup use the real kernel.
extern "C" long __real_ptrace(__ptrace_request request, ...);
extern "C" long __wrap_ptrace(__ptrace_request request, ...) {
    va_list arguments;
    va_start(arguments, request);
    const pid_t pid = va_arg(arguments, pid_t);
    void* address = va_arg(arguments, void*);
    void* data = va_arg(arguments, void*);
    va_end(arguments);
    if (request == PTRACE_DETACH)
        ++detach_calls;
    if (request == PTRACE_POKEUSER)
        ++debug_write_calls;
    const bool first = fault == Fault::FirstDetach || fault == Fault::DetachPreflight;
    const bool matching =
        ((fault == Fault::FirstDetach || fault == Fault::SecondDetach) &&
         request == PTRACE_DETACH) ||
        (fault == Fault::DetachPreflight && debug_write_calls >= 21 && request == PTRACE_PEEKUSER &&
         reinterpret_cast<std::uintptr_t>(address) ==
             offsetof(user, u_debugreg) + 7 * sizeof(user::u_debugreg[0])) ||
        (fault == Fault::SecondWatchRestore && request == PTRACE_POKEUSER && data == nullptr &&
         reinterpret_cast<std::uintptr_t>(address) ==
             offsetof(user, u_debugreg) + 7 * sizeof(user::u_debugreg[0]));
    if (matching && ++matching_calls == (first ? 1U : 2U)) {
        fault = Fault::None;
        ++injected_failures;
        errno = EIO;
        return -1;
    }
    return __real_ptrace(request, pid, address, data);
}

int main() {
    try {
        if (!probe())
            return 77;
        check(::setenv("SDB_TCG_GUARD", "1", 1) == 0, "could not enable detach preflight");
        restoration_failure_is_transactional(Fault::SecondWatchRestore, 0);
        restoration_failure_is_transactional(Fault::FirstDetach, 1);
        restoration_failure_is_transactional(Fault::DetachPreflight, 0);
        low_level_first_detach_preserves_all_stop();
        existing_hardware_breakpoint_is_rejected_without_mutation();
        low_level_partial_detach_invalidates_all_stop();
        controller_partial_detach_fails_closed();
        std::cout
            << "PASS: detach preflight/first-call rollback, partial-detach state and cleanup\n";
        return 0;
    } catch (const std::exception& error) {
        fault = Fault::None;
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
