#include "sdb/memory.hpp"
#include "sdb/signal_monitor.hpp"
#include "sdb/tracee.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <iostream>
#include <iterator>
#include <map>
#include <pthread.h>
#include <sched.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace {
std::atomic<unsigned long> iterations[2];
std::atomic<unsigned int> finish{0};
struct Report {
    std::uint64_t finish_address;
};

void check(bool value, const char* message) {
    if (!value)
        throw std::runtime_error(message);
}
void* worker(void* argument) {
    auto index = reinterpret_cast<std::uintptr_t>(argument);
    while (!finish.load(std::memory_order_relaxed)) {
        if ((iterations[index].fetch_add(1, std::memory_order_relaxed) & 1023U) == 0)
            ::syscall(SYS_gettid);
    }
    return nullptr;
}
int threaded_fixture(int fd, bool stop) {
    pthread_t workers[2];
    for (std::uintptr_t i = 0; i < 2; ++i)
        if (::pthread_create(&workers[i], nullptr, worker, reinterpret_cast<void*>(i)))
            return 90;
    const Report report{reinterpret_cast<std::uintptr_t>(&finish)};
    if (::write(fd, &report, sizeof(report)) != static_cast<ssize_t>(sizeof(report)))
        return 91;
    if (::close(fd) == -1)
        return 92;
    if (stop && ::raise(SIGSTOP))
        return 93;
    for (auto thread : workers)
        if (::pthread_join(thread, nullptr))
            return 94;
    return 0;
}
void* exec_worker(void*) {
    ::execl("/bin/true", "true", nullptr);
    _exit(95);
}
void* leader_exit_worker(void*) {
    ::usleep(20000);
    ::raise(SIGUSR1);
    _exit(0);
}
void* fatal_worker(void*) {
    ::usleep(20000);
    // Test Linux group termination itself, not a sanitizer's signal handler.
    ::signal(SIGSEGV, SIG_DFL);
    ::raise(SIGSEGV);
    return nullptr;
}
int other_fixture(const std::string& mode) {
    pthread_t thread;
    const auto function = mode == "--thread-exec"    ? exec_worker
                          : mode == "--leader-fatal" ? fatal_worker
                                                     : leader_exit_worker;
    if (::pthread_create(&thread, nullptr, function, nullptr))
        return 96;
    ::pthread_exit(nullptr);
}
int cloned_child(void*) {
    return 0;
}
int process_creation_fixture(const std::string& mode) {
    std::vector<char> stack(65536);
    if (::signal(SIGUSR2, SIG_IGN) == SIG_ERR)
        return 97;
    pid_t child;
    if (mode == "--vfork")
        child = ::vfork();
    else if (mode == "--clone-process")
        child = ::clone(cloned_child, stack.data() + stack.size(), SIGUSR2, nullptr);
    else
        child = ::fork();
    if (child == -1)
        return 98;
    if (child == 0)
        _exit(0);
    int status = 0;
    pid_t result;
    do {
        result = ::waitpid(child, &status, mode == "--clone-process" ? __WCLONE : 0);
    } while (result == -1 && errno == EINTR);
    return result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 99;
}

bool probe() {
    pid_t pid = ::fork();
    check(pid != -1, "fork probe failed");
    if (pid == 0) {
        if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
            _exit(errno);
        _exit(0);
    }
    int status = 0;
    check(::waitpid(pid, &status, 0) == pid && WIFEXITED(status), "probe wait failed");
    int error = WEXITSTATUS(status);
    if (error == EPERM || error == EACCES || error == ENOSYS) {
        std::cout << "SKIP: independent ptrace probe: " << std::strerror(error) << '\n';
        return false;
    }
    check(error == 0, "unexpected probe failure");
    return true;
}

void drain(sdb::Tracee& tracee) {
    while (auto event = tracee.take_pending_event()) {
        check(event->kind == sdb::EventKind::ThreadCreated ||
                  event->kind == sdb::EventKind::ThreadExited,
              "unexpected queued fixture event");
    }
}

void run_to_exit(sdb::Tracee& tracee) {
    for (unsigned int attempts = 0; attempts < 30; ++attempts) {
        drain(tracee);
        auto event = tracee.resume(sdb::ResumeMode::Continue);
        if (event.terminal()) {
            check(event.kind == sdb::EventKind::Exited && event.exit_code == 0,
                  "fixture did not exit cleanly");
            return;
        }
        if (event.kind == sdb::EventKind::Trap || event.kind == sdb::EventKind::Signal)
            tracee.set_pending_signal(0);
    }
    throw std::runtime_error("too many fixture stops");
}

int signal_state_fixture() {
    sigset_t mask;
    struct sigaction action{};
    if (::sigprocmask(SIG_SETMASK, nullptr, &mask) == -1 ||
        ::sigaction(SIGINT, nullptr, &action) == -1)
        return 102;
    return ::sigismember(&mask, SIGTERM) == 1 && action.sa_handler == SIG_IGN ? 0 : 103;
}

void monitored_signal_state() {
    sigset_t original_mask;
    struct sigaction original_action{};
    check(::sigprocmask(SIG_SETMASK, nullptr, &original_mask) == 0 &&
              ::sigaction(SIGINT, nullptr, &original_action) == 0,
          "read original test signal state failed");
    const auto restore = [&] {
        check(::sigaction(SIGINT, &original_action, nullptr) == 0 &&
                  ::sigprocmask(SIG_SETMASK, &original_mask, nullptr) == 0,
              "restore original test signal state failed");
    };
    try {
        sigset_t mask = original_mask;
        ::sigaddset(&mask, SIGTERM);
        struct sigaction ignored{};
        ignored.sa_handler = SIG_IGN;
        ::sigemptyset(&ignored.sa_mask);
        check(::sigprocmask(SIG_SETMASK, &mask, nullptr) == 0 &&
                  ::sigaction(SIGINT, &ignored, nullptr) == 0,
              "prepare inherited signal state failed");
        {
            sdb::SignalMonitor monitor;
            check(::sigprocmask(SIG_SETMASK, nullptr, &mask) == 0 &&
                      ::sigismember(&mask, SIGTERM) == 0,
                  "debugger monitor retained a blocked termination signal");
            sdb::Tracee tracee(&monitor);
            tracee.launch({"/proc/self/exe", "--signal-state"});
            const auto rip = tracee.regs().rip;
            // A notification already queued before resume must not be lost,
            // nor may it permit a user instruction to run first.
            check(::raise(SIGINT) == 0, "queue monitor interrupt failed");
            const auto event = tracee.resume(sdb::ResumeMode::Continue);
            check(event.kind == sdb::EventKind::Interrupted && tracee.all_stopped() &&
                      tracee.regs().rip == rip && monitor.pending_signal() == SIGINT,
                  "queued interrupt resumed the tracee or lost its notification");
            monitor.acknowledge_interrupt();
            run_to_exit(tracee);
        }
        check(::sigprocmask(SIG_SETMASK, nullptr, &mask) == 0 && ::sigismember(&mask, SIGTERM) == 1,
              "monitor teardown did not restore its inherited signal mask");
        restore();
    } catch (...) {
        restore();
        throw;
    }
}

void tcg_resume_guard(sdb::Tracee& tracee) {
    const char* previous_value = ::getenv("SDB_TCG_GUARD");
    const std::optional<std::string> previous =
        previous_value ? std::optional<std::string>{previous_value} : std::nullopt;
    const auto ids = tracee.threads();
    const pid_t selected = tracee.tid();
    const pid_t watched = ids.back();
    const auto original_regs = tracee.regs(watched);
    std::map<unsigned int, std::uint64_t> original_debug;
    for (unsigned int index : {0U, 1U, 2U, 3U, 6U, 7U})
        original_debug[index] = tracee.read_debug_register(watched, index);
    const auto restore = [&] {
        tracee.write_debug_register(watched, 7, 0);
        tracee.set_regs(original_regs, watched);
        for (unsigned int index : {0U, 1U, 2U, 3U, 6U})
            tracee.write_debug_register(watched, index, original_debug.at(index));
        tracee.write_debug_register(watched, 7, original_debug.at(7));
        tracee.select_thread(selected);
        check(previous ? ::setenv("SDB_TCG_GUARD", previous->c_str(), 1) == 0
                       : ::unsetenv("SDB_TCG_GUARD") == 0,
              "restore guard environment failed");
    };
    const auto rejected = [&](auto action) {
        bool refused = false;
        try {
            action();
        } catch (const std::runtime_error& error) {
            refused =
                std::string(error.what())
                    .rfind("QEMU TCG cannot safely combine single-step and hardware watchpoints",
                           0) == 0;
        }
        check(refused, "unsafe watchpoint/single-step combination was not rejected");
        check(tracee.all_stopped(), "guard resumed a task before rejecting the command");
        check(tracee.regs(watched).rip == original_regs.rip, "guard changed watched task RIP");
    };
    try {
        check(::setenv("SDB_TCG_GUARD", "1", 1) == 0, "force guard environment failed");
        check(sdb::Tracee::tcg_watch_step_guard(), "forced-on TCG guard was not enabled");
        tracee.select_thread(watched);
        const auto reserved = original_debug.at(7) & ~std::uint64_t{0xffff00ff};
        for (unsigned int slot = 0; slot < 4; ++slot) {
            tracee.write_debug_register(watched, 7, reserved);
            tracee.write_debug_register(watched, slot, original_regs.rip);
            // Alternate write/access and local/global slots. The test never
            // executes a store with TF plus a data watchpoint, even on native CI.
            const auto access = slot % 2 == 0 ? 1U : 3U;
            const auto enabled = std::uint64_t{slot % 2 == 0 ? 1U : 2U} << (2 * slot);
            const auto control =
                reserved | enabled | (static_cast<std::uint64_t>(access) << (16 + 4 * slot));
            tracee.write_debug_register(watched, 7, control);
            rejected([&] { (void)tracee.resume(sdb::ResumeMode::SingleStep); });
            check(tracee.read_debug_register(watched, 7) == control,
                  "guard changed installed debug registers");
            tracee.require_resume_safe(sdb::ResumeMode::Continue);
            tracee.require_resume_safe(sdb::ResumeMode::Syscall);
            auto with_tf = original_regs;
            with_tf.eflags |= 0x100U;
            tracee.set_regs(with_tf, watched);
            rejected([&] { (void)tracee.resume(sdb::ResumeMode::Continue); });
            rejected([&] { (void)tracee.resume(sdb::ResumeMode::Syscall); });
            rejected([&] { tracee.detach(); });
            if (ids.size() > 1) {
                tracee.select_thread(ids.front());
                // A parked peer cannot trigger the combination during a
                // selected-task step; an all-task continue must inspect it.
                tracee.require_resume_safe(sdb::ResumeMode::SingleStep);
                tracee.require_resume_safe(sdb::ResumeMode::Continue, true);
                rejected([&] { (void)tracee.resume(sdb::ResumeMode::Continue); });
                tracee.select_thread(watched);
            }
            tracee.write_debug_register(watched, 7, reserved);
            tracee.require_resume_safe(sdb::ResumeMode::SingleStep);
            // Execute-only breakpoints are outside this narrowly established
            // TCG hazard; inspect this case without actually executing it.
            tracee.write_debug_register(watched, 7, reserved | enabled);
            tracee.require_resume_safe(sdb::ResumeMode::SingleStep);
            tracee.set_regs(original_regs, watched);
        }
        restore();
    } catch (...) {
        restore();
        throw;
    }
}

void launched_tasks() {
    int pipes[2];
    check(::pipe(pipes) == 0, "pipe failed");
    sdb::Tracee tracee;
    tracee.launch({"/proc/self/exe", "--threads", std::to_string(pipes[1])});
    check(::close(pipes[1]) == 0, "close report writer failed");
    unsigned int clones = 0;
    for (;;) {
        auto event = tracee.resume(sdb::ResumeMode::Continue);
        if (event.kind == sdb::EventKind::ThreadCreated)
            ++clones;
        else {
            check(event.kind == sdb::EventKind::Signal && event.signal == SIGSTOP,
                  "thread fixture did not stop");
            tracee.set_pending_signal(0);
            break;
        }
        drain(tracee);
    }
    check(clones == 2, "clone events were not delivered");
    check(tracee.threads().size() == 3 && tracee.all_stopped(), "thread group was not all-stopped");
    Report report{};
    check(::read(pipes[0], &report, sizeof(report)) == static_cast<ssize_t>(sizeof(report)),
          "fixture report failed");
    check(::close(pipes[0]) == 0, "close report reader failed");
    const auto tids = tracee.threads();
    const auto leader = tracee.regs(tids[0]);
    const auto peer = tracee.regs(tids[2]);
    tracee.select_thread(tids[1]);
    const auto event = tracee.resume_one(sdb::ResumeMode::SingleStep);
    check(event.kind == sdb::EventKind::SingleStep, "worker step was not classified");
    check(tracee.regs(tids[0]).rip == leader.rip && tracee.regs(tids[2]).rip == peer.rip,
          "scheduler locking ran another thread during single-step");
    auto registers = tracee.regs();
    const auto saved = registers.r15;
    registers.r15 = 0x1234;
    tracee.set_regs(registers);
    check(tracee.regs().r15 == 0x1234, "selected-task register write missing");
    check(tracee.regs(tids[0]).r15 == leader.r15, "register write changed a different task");
    registers.r15 = saved;
    tracee.set_regs(registers);
    for (pid_t tid : tids) {
        const auto dr7 = tracee.read_debug_register(tid, 7);
        tracee.write_debug_register(tid, 7, dr7);
        check(tracee.read_debug_register(tid, 7) == dr7, "debug register roundtrip failed");
    }
    tcg_resume_guard(tracee);
    // Both workers issue gettid; entry/exit pairing must belong to their own
    // TID even when INTERRUPT produces a peer syscall-exit during all-stop.
    std::map<pid_t, std::uint64_t> entries;
    std::set<pid_t> paired_workers;
    const auto observe = [&](const sdb::TraceEvent& stop) {
        if (stop.kind == sdb::EventKind::SyscallEntry && stop.syscall_number)
            entries[stop.tid] = *stop.syscall_number;
        else if (stop.kind == sdb::EventKind::SyscallExit) {
            auto entry = entries.find(stop.tid);
            if (entry != entries.end()) {
                check(stop.syscall_number && *stop.syscall_number == entry->second,
                      "syscall entry/exit pairing crossed task IDs");
                if (entry->second == SYS_gettid && stop.tid != tids[0])
                    paired_workers.insert(stop.tid);
                entries.erase(entry);
            }
        }
    };
    for (unsigned int attempts = 0; paired_workers.size() < 2 && attempts < 100; ++attempts) {
        observe(tracee.resume(sdb::ResumeMode::Syscall));
        while (auto queued = tracee.take_pending_event())
            observe(*queued);
    }
    check(paired_workers.size() == 2, "did not validate syscall pairs on both worker tasks");
    sdb::Memory memory(tracee);
    memory.write(report.finish_address, {1, 0, 0, 0});
    run_to_exit(tracee);
    check(tracee.pid() == -1 && tracee.threads().empty(), "exited tasks retained");
}

void attach_tasks() {
    int pipes[2];
    check(::pipe(pipes) == 0, "attach pipe failed");
    const pid_t owner = ::getpid();
    pid_t child = ::fork();
    check(child != -1, "attach fork failed");
    if (child == 0) {
        if (::prctl(PR_SET_PDEATHSIG, SIGKILL) == -1 || ::getppid() != owner)
            _exit(100);
        ::close(pipes[0]);
        _exit(threaded_fixture(pipes[1], false));
    }
    ::close(pipes[1]);
    try {
        Report report{};
        check(::read(pipes[0], &report, sizeof(report)) == static_cast<ssize_t>(sizeof(report)),
              "attach readiness failed");
        check(::close(pipes[0]) == 0, "attach close pipe failed");
        sdb::Tracee tracee;
        tracee.attach(child);
        check(tracee.attached() && tracee.all_stopped() && tracee.threads().size() == 3,
              "existing task attach incomplete");
        for (pid_t tid : tracee.threads())
            check(tracee.regs(tid).rip != 0, "attached task registers missing");
        sdb::Memory memory(tracee);
        memory.write(report.finish_address, {1, 0, 0, 0});
        tracee.detach();
        check(tracee.pid() == -1 && !tracee.attached() &&
                  tracee.state() == sdb::ProcessState::NoProgram,
              "detach retained task ownership or partial-detach state");
        int status = 0;
        check(::waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                  WEXITSTATUS(status) == 0,
              "detached thread group did not resume cleanly");
    } catch (...) {
        ::kill(child, SIGKILL);
        int status = 0;
        while (::waitpid(child, &status, 0) == -1 && errno == EINTR) {
        }
        throw;
    }
}

void exec_and_leader_exit() {
    for (const char* mode : {"--leader-exit", "--thread-exec", "--leader-fatal"}) {
        sdb::Tracee tracee;
        tracee.launch({"/proc/self/exe", mode});
        bool exec_seen = false;
        for (unsigned int i = 0; i < 30; ++i) {
            drain(tracee);
            const auto event = tracee.resume(sdb::ResumeMode::Continue, tracee.pending_signal());
            if (event.kind == sdb::EventKind::Exec) {
                exec_seen = true;
                check(tracee.threads().size() == 1 && tracee.pid() == tracee.tid(),
                      "nonleader exec retained stale tasks");
            }
            if (event.terminal()) {
                if (std::string(mode) == "--leader-fatal")
                    check(event.kind == sdb::EventKind::Signaled && event.signal == SIGSEGV,
                          "leader exit hid the surviving worker's fatal signal");
                else
                    check(event.kind == sdb::EventKind::Exited && event.exit_code == 0,
                          "thread exit fixture failed");
                break;
            }
            if (event.kind == sdb::EventKind::Signal && event.signal != SIGSEGV)
                tracee.set_pending_signal(0);
        }
        check(tracee.pid() == -1, "thread exit fixture hung");
        if (std::string(mode) == "--thread-exec")
            check(exec_seen, "nonleader exec event missing");
    }
}

void unsupported_process_creation() {
    for (const char* mode : {"--fork", "--vfork", "--clone-process", "--exec-then-fork"}) {
        sdb::Tracee tracee;
        tracee.launch({"/proc/self/exe", mode});
        const pid_t original = tracee.pid();
        auto event = tracee.resume(sdb::ResumeMode::Continue);
        if (std::string(mode) == "--exec-then-fork") {
            check(event.kind == sdb::EventKind::Exec, "replacement exec event missing");
            try {
                event = tracee.resume(sdb::ResumeMode::Continue);
            } catch (const std::runtime_error& error) {
                // The kernel may report either the parent creation event or
                // the foreign child's first stop first. After replacement,
                // only the former has unambiguous image provenance. Exercise
                // this sequential case without racing fork against exec.
                check(std::string(error.what())
                              .rfind("unannounced process creation after exec; session terminated",
                                     0) == 0,
                      "unexpected replacement/fork failure");
                check(tracee.pid() == -1 && tracee.threads().empty() &&
                          tracee.state() == sdb::ProcessState::Exited,
                      "ambiguous descendant survived fail-closed cleanup");
                continue;
            }
        }
        check(event.kind == sdb::EventKind::UnsupportedClone && event.new_tid > 0,
              "fork/non-thread clone was accepted as a thread");
        check(tracee.all_stopped() && tracee.threads().size() == 2,
              "unsupported descendant not held for cleanup");
        bool rejected = false;
        try {
            (void)tracee.resume(sdb::ResumeMode::Continue);
        } catch (const std::logic_error&) {
            rejected = true;
        }
        check(rejected, "unsupported descendant allowed to execute under debugger");
        // No patches in this low-level test. Controller integration separately
        // proves parent and copied child bytes are restored before detachment.
        tracee.detach();
        int status = 0;
        pid_t result;
        do {
            result = ::waitpid(original, &status, 0);
        } while (result == -1 && errno == EINTR);
        check(result == original && WIFEXITED(status) && WEXITSTATUS(status) == 0,
              "detached process-creation fixture did not finish");
    }
}

void exec_first_instruction() {
    // A tiny static ELF with a known entry avoids depending on which startup
    // instructions the host dynamic linker or compiler happens to generate.
    // xor edi,edi; mov eax,60; syscall -- exactly three user instructions.
    std::vector<std::uint8_t> bytes(4096, 0);
    const std::uint8_t code[] = {0x31, 0xff, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05};
    bytes.insert(bytes.end(), std::begin(code), std::end(code));
    Elf64_Ehdr header{};
    std::memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = ELFCLASS64;
    header.e_ident[EI_DATA] = ELFDATA2LSB;
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_type = ET_EXEC;
    header.e_machine = EM_X86_64;
    header.e_version = EV_CURRENT;
    header.e_entry = 0x401000;
    header.e_phoff = sizeof(header);
    header.e_ehsize = sizeof(header);
    header.e_phentsize = sizeof(Elf64_Phdr);
    header.e_phnum = 1;
    Elf64_Phdr segment{};
    segment.p_type = PT_LOAD;
    segment.p_flags = PF_R | PF_X;
    segment.p_vaddr = 0x400000;
    segment.p_filesz = segment.p_memsz = bytes.size();
    segment.p_align = 4096;
    std::memcpy(bytes.data(), &header, sizeof(header));
    std::memcpy(bytes.data() + sizeof(header), &segment, sizeof(segment));
    char path[] = "/tmp/sdb-step-XXXXXX";
    int fd = ::mkstemp(path);
    check(fd >= 0, "create static step fixture failed");
    try {
        std::size_t written = 0;
        while (written < bytes.size()) {
            const auto count = ::write(fd, bytes.data() + written, bytes.size() - written);
            if (count == -1 && errno == EINTR)
                continue;
            check(count > 0, "write static step fixture failed");
            written += static_cast<std::size_t>(count);
        }
        check(::fchmod(fd, 0700) == 0, "chmod static step fixture failed");
        const int closed = ::close(fd);
        fd = -1;
        check(closed == 0, "close static step fixture failed");
        sdb::Tracee tracee;
        tracee.launch({path});
        check(tracee.regs().rip == 0x401000, "static fixture entry differs");
        for (std::uint64_t expected : {0x401002ULL, 0x401007ULL}) {
            const auto stop = tracee.resume(sdb::ResumeMode::SingleStep);
            check(stop.kind == sdb::EventKind::SingleStep && tracee.regs().rip == expected,
                  "first single-step after exec did not execute exactly one instruction");
        }
        check(tracee.resume(sdb::ResumeMode::SingleStep).kind == sdb::EventKind::Exited,
              "three-instruction fixture required an extra step");
        tracee.launch({path});
        const auto syscall = tracee.resume(sdb::ResumeMode::Syscall);
        check(syscall.kind == sdb::EventKind::SyscallEntry && syscall.syscall_number == 60,
              "first syscall after exec exposed the old execve exit");
        check(tracee.resume(sdb::ResumeMode::Continue).kind == sdb::EventKind::Exited,
              "static syscall fixture did not exit");
    } catch (...) {
        if (fd >= 0)
            ::close(fd);
        ::unlink(path);
        throw;
    }
    check(::unlink(path) == 0, "remove static step fixture failed");
}
} // namespace

int main(int argc, char** argv) {
    // Self-exec fixtures use _exit to avoid running LeakSanitizer's own ptrace
    // inspection from an already traced process. The parent test still runs
    // normal sanitizer teardown and checks its own resource ownership.
    if (argc == 3 && std::string(argv[1]) == "--threads")
        _exit(threaded_fixture(std::stoi(argv[2]), true));
    if (argc == 2 && std::string(argv[1]) == "--signal-state")
        _exit(signal_state_fixture());
    if (argc == 2 &&
        (std::string(argv[1]) == "--thread-exec" || std::string(argv[1]) == "--leader-exit" ||
         std::string(argv[1]) == "--leader-fatal"))
        return other_fixture(argv[1]);
    if (argc == 2 && (std::string(argv[1]) == "--fork" || std::string(argv[1]) == "--vfork" ||
                      std::string(argv[1]) == "--clone-process"))
        _exit(process_creation_fixture(argv[1]));
    if (argc == 2 && std::string(argv[1]) == "--exec-then-fork") {
        ::execl("/proc/self/exe", "task_control_test", "--fork", nullptr);
        _exit(101);
    }
    try {
        if (!probe())
            return 77;
        exec_first_instruction();
        monitored_signal_state();
        launched_tasks();
        attach_tasks();
        exec_and_leader_exit();
        unsupported_process_creation();
        std::cout
            << "PASS: clone task tracking, all-stop, scheduler locking, per-task registers/syscall "
               "pairs, attach/detach, nonleader exec, safe fork rejection, signal restoration\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
