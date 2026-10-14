#include "sdb/tracee.hpp"
#include "sdb/signal_monitor.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cpuid.h>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <poll.h>
#include <stdexcept>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>

namespace sdb {
namespace {

[[noreturn]] void fail(const char* operation, int error = errno) {
    throw std::system_error(error, std::generic_category(), operation);
}

class FileDescriptor {
  public:
    explicit FileDescriptor(int fd) : fd_(fd) {}
    ~FileDescriptor() {
        if (fd_ >= 0 && ::close(fd_) == -1)
            std::fprintf(stderr, "sdb: close failed (errno %d)\n", errno);
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    int get() const { return fd_; }
    void close() {
        const int fd = fd_;
        fd_ = -1;
        if (fd >= 0 && ::close(fd) == -1)
            fail("close launch pipe");
    }

  private:
    int fd_;
};

long checked_ptrace(__ptrace_request request, pid_t tid, void* address, void* data,
                    const char* operation) {
    const long result = ::ptrace(request, tid, address, data);
    if (result == -1)
        fail(operation);
    return result;
}

void* ptrace_value(std::uint64_t value) {
    return reinterpret_cast<void*>(static_cast<std::uintptr_t>(value));
}

constexpr unsigned long tracing_options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC |
                                          PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT |
                                          PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;

struct LaunchError {
    int operation;
    int error;
};

// Only async-signal-safe operations between fork and exec/_exit.
[[noreturn]] void child_failure(int fd, int operation, int error) {
    const LaunchError report{operation, error};
    ssize_t written;
    do {
        written = ::write(fd, &report, sizeof(report));
    } while (written == -1 && errno == EINTR);
    _exit(written == static_cast<ssize_t>(sizeof(report)) ? 127 : 126);
}

bool stopping_signal(int signal) {
    return signal == SIGSTOP || signal == SIGTSTP || signal == SIGTTIN || signal == SIGTTOU;
}

pid_t thread_group(pid_t tid) {
    std::ifstream status("/proc/" + std::to_string(tid) + "/status");
    if (!status)
        fail("open task status", errno ? errno : ESRCH);
    std::string key;
    while (status >> key) {
        if (key == "Tgid:") {
            pid_t group = -1;
            if (status >> group && group > 0)
                return group;
            break;
        }
        status.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    throw std::runtime_error("missing thread-group ID in /proc status");
}

std::vector<pid_t> enumerate_tasks(pid_t pid) {
    const std::string path = "/proc/" + std::to_string(pid) + "/task";
    DIR* directory = ::opendir(path.c_str());
    if (!directory)
        fail("open task directory");
    std::vector<pid_t> result;
    int error = 0;
    try {
        for (;;) {
            errno = 0;
            const auto* entry = ::readdir(directory);
            if (!entry) {
                error = errno;
                break;
            }
            const std::string name = entry->d_name;
            pid_t tid = 0;
            auto parsed = std::from_chars(name.data(), name.data() + name.size(), tid);
            if (parsed.ec == std::errc{} && parsed.ptr == name.data() + name.size() && tid > 0)
                result.push_back(tid);
        }
    } catch (...) {
        if (::closedir(directory) == -1)
            std::fprintf(stderr, "sdb: closedir failed\n");
        throw;
    }
    if (::closedir(directory) == -1 && error == 0)
        error = errno;
    if (error != 0)
        fail("read task directory", error);
    std::sort(result.begin(), result.end());
    return result;
}

void validate_signal(int signal) {
    if (signal < 0 || signal >= NSIG)
        throw std::invalid_argument("invalid signal number");
}

} // namespace

Tracee::~Tracee() noexcept {
    try {
        if (state_ == ProcessState::Detaching) {
            // Released peers may already be running. Never pretend this is
            // still an all-stop session after a partial detach failure.
            terminate();
        } else if (attached_) {
            stop_all();
            if (!tasks_.empty())
                detach();
        } else
            terminate();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "sdb: tracee cleanup failed: %s\n", error.what());
    }
}

void Tracee::reset(ProcessState state) noexcept {
    pid_ = selected_ = -1;
    attached_ = false;
    unsupported_descendants_ = false;
    exec_epoch_ = 0;
    state_ = state;
    tasks_.clear();
    dying_.clear();
    resumed_.clear();
    last_wait_tid_ = -1;
    pending_.clear();
    leader_exit_.reset();
    interrupt_generation_ = signals_ ? signals_->interrupt_generation() : 0;
}

bool Tracee::all_stopped() const noexcept {
    return !tasks_.empty() && std::all_of(tasks_.begin(), tasks_.end(),
                                          [](const auto& entry) { return entry.second.stopped; });
}

void Tracee::require_stopped() const {
    if (!stopped())
        throw std::logic_error("operation requires an all-stopped program");
}

Tracee::Task& Tracee::task(pid_t tid) {
    auto it = tasks_.find(tid == 0 ? selected_ : tid);
    if (it == tasks_.end())
        throw std::invalid_argument("unknown thread ID");
    return it->second;
}
const Tracee::Task& Tracee::task(pid_t tid) const {
    auto it = tasks_.find(tid == 0 ? selected_ : tid);
    if (it == tasks_.end())
        throw std::invalid_argument("unknown thread ID");
    return it->second;
}

std::vector<pid_t> Tracee::threads() const {
    std::vector<pid_t> result;
    for (const auto& [tid, unused] : tasks_) {
        (void)unused;
        result.push_back(tid);
    }
    return result;
}

void Tracee::select_thread(pid_t tid) {
    require_stopped();
    (void)task(tid);
    selected_ = tid;
}

int Tracee::pending_signal(pid_t tid) const {
    return task(tid).signal;
}
bool Tracee::signal_delivery_stop(pid_t tid) const {
    return task(tid).delivery_stop;
}
void Tracee::set_pending_signal(int signal, pid_t tid) {
    validate_signal(signal);
    auto& selected = task(tid);
    if (signal != 0 && !selected.delivery_stop)
        throw std::logic_error("signal forwarding requires a signal-delivery stop");
    selected.signal = signal;
}

TraceEvent Tracee::launch(const std::vector<std::string>& arguments) {
    if (pid_ > 0)
        throw std::logic_error("program already loaded");
    reset(ProcessState::NoProgram);
    if (arguments.empty() || arguments.front().empty())
        throw std::invalid_argument("load requires an executable path");
    std::vector<char*> argv;
    for (const auto& argument : arguments) {
        if (argument.find('\0') != std::string::npos)
            throw std::invalid_argument("program arguments cannot contain NUL bytes");
        argv.push_back(const_cast<char*>(argument.c_str()));
    }
    argv.push_back(nullptr);
    int error_fds[2];
    if (::pipe2(error_fds, O_CLOEXEC | O_NONBLOCK) == -1)
        fail("pipe2");
    FileDescriptor reader(error_fds[0]), writer(error_fds[1]);
    int gate_fds[2];
    if (::pipe2(gate_fds, O_CLOEXEC) == -1)
        fail("pipe2 launch gate");
    FileDescriptor gate_reader(gate_fds[0]), gate_writer(gate_fds[1]);
    const pid_t child = ::fork();
    if (child == -1)
        fail("fork");
    if (child == 0) {
        if (signals_) {
            const int error = signals_->restore_in_child();
            if (error != 0)
                child_failure(writer.get(), 3, error);
        }
        if (::close(reader.get()) == -1 || ::close(gate_writer.get()) == -1)
            child_failure(writer.get(), 0, errno);
        char token = 0;
        ssize_t count;
        do {
            count = ::read(gate_reader.get(), &token, 1);
        } while (count == -1 && errno == EINTR);
        if (count != 1)
            child_failure(writer.get(), 1, count == -1 ? errno : EIO);
        if (::close(gate_reader.get()) == -1)
            child_failure(writer.get(), 0, errno);
        ::execv(argv.front(), argv.data());
        child_failure(writer.get(), 2, errno);
    }
    pid_ = selected_ = child;
    tasks_.emplace(child, Task{});
    resumed_.insert(child);
    state_ = ProcessState::Running;
    try {
        writer.close();
        gate_reader.close();
        // SEIZE preserves the fork/exec ownership model while permitting
        // PTRACE_INTERRUPT on every task, including future CLONE children.
        checked_ptrace(PTRACE_SEIZE, child, nullptr,
                       ptrace_value(tracing_options | PTRACE_O_EXITKILL), "ptrace(SEIZE child)");
        const char token = 'x';
        ssize_t count;
        do {
            count = ::write(gate_writer.get(), &token, 1);
        } while (count == -1 && errno == EINTR);
        if (count != 1)
            fail("write launch gate", count == -1 ? errno : EIO);
        gate_writer.close();
        const TraceEvent event = wait_visible();
        LaunchError report{};
        do {
            count = ::read(reader.get(), &report, sizeof(report));
        } while (count == -1 && errno == EINTR);
        if (count == static_cast<ssize_t>(sizeof(report)))
            fail(report.operation == 3   ? "restore child signal state"
                 : report.operation == 2 ? "execv"
                 : report.operation == 1 ? "read launch gate"
                                         : "close launch pipe",
                 report.error);
        if (count == -1)
            fail("read launch pipe (child has not completed exec)");
        if (count != 0)
            throw std::runtime_error("incomplete child launch error report");
        if (!stopped() || event.kind != EventKind::Exec)
            throw std::runtime_error("child did not stop at its initial exec event");
        return event;
    } catch (...) {
        terminate();
        reset(ProcessState::NoProgram);
        throw;
    }
}

TraceEvent Tracee::attach(pid_t process) {
    if (pid_ > 0)
        throw std::logic_error("program already loaded");
    if (process <= 1 || process == ::getpid())
        throw std::invalid_argument("attach requires another process PID greater than one");
    if (thread_group(process) != process)
        throw std::invalid_argument("attach requires the thread-group leader PID");
    reset(ProcessState::NoProgram);
    pid_ = selected_ = process;
    attached_ = true;
    exec_epoch_ = 1;
    state_ = ProcessState::Running;
    try {
        // Re-scan after all seized tasks stop. Unseized threads may clone while
        // the first pass runs; once every enumerated task is stopped the set is
        // stable. Kernel TRACECLONE events account for clones of seized tasks.
        for (;;) {
            bool added = false;
            for (pid_t tid : enumerate_tasks(process)) {
                if (tasks_.count(tid) || dying_.count(tid))
                    continue;
                if (::ptrace(PTRACE_SEIZE, tid, nullptr, ptrace_value(tracing_options)) == -1) {
                    if (errno == ESRCH)
                        continue; // exited between readdir and SEIZE
                    if (errno == EPERM) {
                        // A seized parent can have auto-attached this task before
                        // its clone event is consumed. Do not accept a foreign tracer.
                        std::ifstream status("/proc/" + std::to_string(tid) + "/status");
                        std::string key;
                        pid_t tracer = -1;
                        while (status >> key) {
                            if (key == "TracerPid:") {
                                status >> tracer;
                                break;
                            }
                            status.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        }
                        if (tracer != ::getpid())
                            fail("ptrace(SEIZE attach)", EPERM);
                    } else
                        fail("ptrace(SEIZE attach)");
                }
                tasks_.emplace(tid, Task{});
                added = true;
            }
            if (tasks_.empty())
                throw std::runtime_error("process exited during attach");
            stop_all();
            if (signals_ && signals_->pending_signal() != 0)
                throw std::runtime_error("attach interrupted");
            if (!added)
                break;
        }
        finish_stop();
        TraceEvent result;
        result.kind = EventKind::PtraceEvent;
        result.ptrace_event = PTRACE_EVENT_STOP;
        result.tid = selected_;
        return result;
    } catch (...) {
        // No debugger bytes have been installed yet. Preserve the external
        // process: rollback seizes instead of killing it on partial failure.
        if (!tasks_.empty()) {
            try {
                stop_all();
                detach();
            } catch (const std::exception& error) {
                std::fprintf(stderr, "sdb: attach rollback failed: %s\n", error.what());
                throw;
            }
        }
        reset(ProcessState::NoProgram);
        throw;
    }
}

void Tracee::restart(pid_t tid, ResumeMode mode, int signal) {
    auto& current = task(tid);
    const auto request = mode == ResumeMode::SingleStep ? PTRACE_SINGLESTEP
                         : mode == ResumeMode::Syscall  ? PTRACE_SYSCALL
                                                        : PTRACE_CONT;
    checked_ptrace(request, tid, nullptr, ptrace_value(static_cast<unsigned int>(signal)),
                   "ptrace(resume)");
    if (mode != ResumeMode::Syscall)
        current.syscall_number.reset();
    if (mode == ResumeMode::Continue)
        current.exec_return_rip.reset();
    current.mode = mode;
    current.stopped = false;
    current.delivery_stop = false;
    current.signal = 0;
    resumed_.insert(tid);
}

TraceEvent Tracee::resume(ResumeMode mode, int signal) {
    return resume_impl(mode, signal, mode == ResumeMode::SingleStep);
}
TraceEvent Tracee::resume_one(ResumeMode mode, int signal) {
    return resume_impl(mode, signal, true);
}

bool Tracee::tcg_watch_step_guard() noexcept {
    static const bool tcg = [] {
        unsigned int maximum = 0, ebx = 0, ecx = 0, edx = 0;
        // Hypervisor leaves are separate from the basic/extended CPUID ranges
        // checked by __get_cpuid. Read this fixed leaf directly on x86-64.
        __cpuid(0x40000000U, maximum, ebx, ecx, edx);
        (void)maximum;
        const unsigned int vendor[] = {ebx, ecx, edx};
        return std::memcmp(vendor, "TCGTCGTCGTCG", 12) == 0;
    }();
    const char* force = std::getenv("SDB_TCG_GUARD");
    // This switch can exercise the guard on native CI; it cannot turn off an
    // automatically detected restriction and risk hanging the user's VM.
    return tcg || (force && std::strcmp(force, "1") == 0);
}

void Tracee::require_resume_safe(ResumeMode mode, bool one) const {
    require_stopped();
    if (!tcg_watch_step_guard())
        return;
    const auto ids =
        one || mode == ResumeMode::SingleStep ? std::vector<pid_t>{selected_} : threads();
    for (pid_t tid : ids) {
        const auto control = read_debug_register(tid, 7);
        bool data_watch = false;
        for (unsigned int slot = 0; slot < 4; ++slot) {
            const auto enabled = (control >> (2 * slot)) & 3U;
            const auto access = (control >> (16 + 4 * slot)) & 3U;
            if (enabled && (access == 1 || access == 3)) {
                data_watch = true;
                break;
            }
        }
        if (data_watch && (mode == ResumeMode::SingleStep || (regs(tid).eflags & 0x100U))) {
            throw std::runtime_error("QEMU TCG cannot safely combine single-step and hardware "
                                     "watchpoints; delete data watchpoints before stepping or "
                                     "clear EFLAGS.TF before continuing");
        }
    }
}

TraceEvent Tracee::resume_impl(ResumeMode mode, int signal, bool one) {
    require_stopped();
    if (unsupported_descendants_)
        throw std::logic_error("fork/non-thread clone descendants must be cleaned up and detached "
                               "before further execution");
    validate_signal(signal);
    if (!pending_.empty())
        throw std::logic_error("pending task stops must be handled before resuming");
    observe_interrupt();
    if (signals_ && signals_->pending_signal() != 0) {
        TraceEvent interrupted;
        interrupted.kind = EventKind::Interrupted;
        interrupted.tid = selected_;
        return interrupted;
    }
    require_resume_safe(mode, one);
    const pid_t chosen = selected_;
    try {
        restart(chosen, mode, signal);
        state_ = ProcessState::Running;
        if (!one) {
            for (auto& [tid, current] : tasks_)
                if (tid != chosen)
                    restart(tid, mode, current.signal);
        }
        return wait_visible();
    } catch (...) {
        // A partial multi-task resume is not a stopped state. Attempt to regain
        // the all-stop invariant before returning an actionable error.
        if (pid_ > 0)
            stop_all();
        throw;
    }
}

std::optional<TraceEvent> Tracee::wait_raw(int options, bool interruptible) {
    for (;;) {
        observe_interrupt();
        if (interruptible && signals_ && signals_->pending_signal() != 0) {
            TraceEvent interrupted;
            interrupted.kind = EventKind::Interrupted;
            interrupted.tid = selected_;
            return interrupted;
        }
        int status = 0;
        const pid_t tid = ::waitpid(-1, &status, __WALL | options | (signals_ ? WNOHANG : 0));
        if (tid == -1) {
            if (errno == EINTR)
                continue;
            fail("waitpid traced tasks");
        }
        if (tid > 0) {
            last_wait_tid_ = tid;
            return consume_status(tid, status);
        }
        if (options & WNOHANG)
            return std::nullopt;
        // SIGCHLD and control signals leave a byte even when they arrive
        // between waitpid and poll. EINTR alone cannot close that race.
        pollfd notification{signals_->fd(), POLLIN, 0};
        const int ready = ::poll(&notification, 1, -1);
        if (ready == -1) {
            if (errno == EINTR)
                continue;
            fail("poll traced-task notifications");
        }
        if (notification.revents & (POLLERR | POLLHUP | POLLNVAL))
            fail("signal notification pipe unavailable", EPIPE);
        signals_->drain();
    }
}

void Tracee::observe_interrupt() {
    if (!signals_)
        return;
    const auto generation = signals_->interrupt_generation();
    if (generation == interrupt_generation_)
        return;
    interrupt_generation_ = generation;
    const pid_t debugger_group = ::getpgrp();
    for (auto& [tid, current] : tasks_) {
        const pid_t group = ::getpgid(tid);
        if (group == -1) {
            if (errno != ESRCH)
                fail("getpgid interrupted task");
        } else if (group == debugger_group)
            current.terminal_interrupt = true;
    }
}

void Tracee::finish_stop() {
    if (tasks_.empty())
        return;
    if (!all_stopped())
        throw std::logic_error("all-stop invariant not established");
    if (!tasks_.count(selected_))
        selected_ = tasks_.begin()->first;
    state_ = ProcessState::Stopped;
    resumed_.clear();
}

void Tracee::stop_all() {
    for (;;) {
        bool running = false;
        for (auto& [tid, current] : tasks_) {
            if (current.stopped)
                continue;
            running = true;
            if (!current.interrupt_sent) {
                if (::ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == -1 && errno != ESRCH)
                    fail("ptrace(INTERRUPT)");
                current.interrupt_sent = true;
            }
        }
        if (!running && (!tasks_.empty() || dying_.empty()))
            break;
        if (auto event = wait_raw(0, false))
            pending_.push_back(*event);
        if (pid_ <= 0)
            break;
    }
    finish_stop();
}

TraceEvent Tracee::wait_visible() {
    for (;;) {
        auto event = wait_raw(0);
        if (!event) {
            if (signals_ && signals_->pending_signal() != 0)
                continue;
            // An interrupt request can race a real stop and be reported only
            // on the next resume. Consume that synthetic stop transparently.
            const auto it = tasks_.find(last_wait_tid_);
            if (it != tasks_.end() && it->second.stopped && resumed_.count(last_wait_tid_)) {
                it->second.interrupt_sent = false;
                restart(last_wait_tid_, it->second.mode, 0);
            }
            continue;
        }
        if (!event->terminal()) {
            stop_all();
            // A peer may exec or the group may die while we stop the other
            // tasks. Those transitions invalidate the original task/address
            // space and supersede its earlier stop (e.g. an old INT3).
            if (!pending_.empty() &&
                (pending_.front().terminal() || pending_.front().kind == EventKind::Exec)) {
                const auto replacement = pending_.front();
                pending_.pop_front();
                return replacement;
            }
            if (tasks_.count(event->tid))
                selected_ = event->tid;
        }
        return *event;
    }
}

std::optional<TraceEvent> Tracee::take_pending_event() {
    if (pending_.empty())
        return std::nullopt;
    auto result = pending_.front();
    pending_.pop_front();
    if (tasks_.count(result.tid))
        selected_ = result.tid;
    return result;
}

std::optional<TraceEvent> Tracee::poll_event() {
    if (pid_ <= 0)
        return std::nullopt;
    // All tasks normally remain ptrace-stopped at the command prompt. Only
    // asynchronous death is expected; never consume the controller's queue.
    for (;;) {
        int status = 0;
        pid_t tid;
        do {
            // TRACEEXIT stops precede the final wait status. Once every live
            // task is exiting, complete that short reap instead of exposing a
            // stale PID with no selectable/stopped task to the next command.
            const int options = tasks_.empty() && !dying_.empty() ? __WALL : __WALL | WNOHANG;
            tid = ::waitpid(-1, &status, options);
        } while (tid == -1 && errno == EINTR);
        if (tid == 0)
            return std::nullopt;
        if (tid == -1)
            fail("waitpid while polling tracee");
        auto event = consume_status(tid, status);
        if (!event)
            continue;
        if (!event->terminal()) {
            stop_all();
            if (!pending_.empty() &&
                (pending_.front().terminal() || pending_.front().kind == EventKind::Exec)) {
                const auto replacement = pending_.front();
                pending_.pop_front();
                return replacement;
            }
        }
        return event;
    }
}

std::optional<TraceEvent> Tracee::consume_status(pid_t tid, int status) {
    observe_interrupt();
    TraceEvent event;
    event.tid = tid;
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        if (!tasks_.count(tid) && !dying_.count(tid))
            return std::nullopt;
        event.kind = WIFEXITED(status) ? EventKind::Exited : EventKind::Signaled;
        if (WIFEXITED(status))
            event.exit_code = WEXITSTATUS(status);
        else
            event.signal = WTERMSIG(status);
        if (tid == pid_)
            leader_exit_ = event;
        tasks_.erase(tid);
        dying_.erase(tid);
        if (tasks_.empty() && dying_.empty()) {
            if (leader_exit_)
                event = *leader_exit_;
            reset(ProcessState::Exited);
        } else {
            event.kind = EventKind::ThreadExited;
            if (!tasks_.count(selected_))
                selected_ = tasks_.empty() ? -1 : tasks_.begin()->first;
        }
        return event;
    }
    if (!WIFSTOPPED(status))
        throw std::runtime_error("unexpected waitpid status");
    event.signal = WSTOPSIG(status);
    event.ptrace_event = static_cast<unsigned int>(status) >> 16;
    // A CLONE child's initial event can arrive before the parent's clone event.
    auto inserted = tasks_.try_emplace(tid, Task{});
    auto& current = inserted.first->second;
    current.stopped = true;
    // INTERRUPT is fulfilled by *any* stop, including the syscall-exit stop
    // generated when it interrupts a blocked PTRACE_SYSCALL. Retaining this
    // flag would skip the next interrupt and deadlock with peers held.
    current.interrupt_sent = false;
    current.delivery_stop = false;
    current.signal = 0;
    // A newborn child's first stop can precede its parent's fork event. Mark
    // foreign address spaces now so a simultaneous parent exec cannot discard
    // an unreported descendant that still contains copied breakpoint bytes.
    if (inserted.second && tid != pid_ && thread_group(tid) != pid_) {
        unsupported_descendants_ = true;
        if (exec_epoch_ >= 2) {
            // waitpid has no cross-TID ordering guarantee. A foreign child's
            // initial stop can arrive after its cloner died during exec, so
            // no parent creation event identified which image it copied.
            // Include it in cleanup before rejecting this ambiguous case.
            terminate();
            throw std::runtime_error("unannounced process creation after exec; session terminated "
                                     "to avoid restoring stale breakpoint bytes");
        }
    }
    if (event.ptrace_event == PTRACE_EVENT_EXIT) {
        checked_ptrace(PTRACE_CONT, tid, nullptr, nullptr, "ptrace(CONT exit event)");
        tasks_.erase(tid);
        dying_.insert(tid);
        return std::nullopt;
    }
    if (event.ptrace_event == PTRACE_EVENT_EXEC) {
        if (unsupported_descendants_) {
            // The new parent image and the child's copied old image cannot
            // share one breakpoint metadata set. Do not restore old addresses
            // into the new image or release a child with stale INT3 bytes.
            terminate();
            throw std::runtime_error("exec raced unsupported process creation; session terminated");
        }
        // A nonleader exec changes its TID to the original TGID and destroys
        // every other task. Old register/syscall/breakpoint state is invalid.
        const bool terminal_interrupt = current.terminal_interrupt;
        tasks_.clear();
        Task replacement;
        replacement.stopped = true;
        replacement.terminal_interrupt = terminal_interrupt;
        user_regs_struct registers{};
        checked_ptrace(PTRACE_GETREGS, tid, nullptr, &registers, "ptrace(GETREGS exec stop)");
        replacement.exec_return_rip = registers.rip;
        tasks_.emplace(tid, replacement);
        dying_.clear();
        pending_.clear();
        leader_exit_.reset();
        selected_ = pid_ = tid;
        if (exec_epoch_ < 2)
            ++exec_epoch_;
        event.kind = EventKind::Exec;
        return event;
    }
    if (event.ptrace_event == PTRACE_EVENT_CLONE || event.ptrace_event == PTRACE_EVENT_FORK ||
        event.ptrace_event == PTRACE_EVENT_VFORK) {
        current.terminal_interrupt = false;
        unsigned long child = 0;
        checked_ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &child, "ptrace(GETEVENTMSG clone)");
        if (child == 0 || child > static_cast<unsigned long>(std::numeric_limits<pid_t>::max()))
            throw std::runtime_error("invalid clone task ID");
        event.new_tid = static_cast<pid_t>(child);
        tasks_.try_emplace(event.new_tid, Task{});
        if (event.ptrace_event == PTRACE_EVENT_CLONE && thread_group(event.new_tid) == pid_) {
            event.kind = EventKind::ThreadCreated;
        } else {
            unsupported_descendants_ = true;
            event.kind = EventKind::UnsupportedClone;
        }
        return event;
    }
    if (event.ptrace_event == PTRACE_EVENT_STOP) {
        current.interrupt_sent = false;
        if (stopping_signal(event.signal)) {
            current.terminal_interrupt = false;
            event.kind = EventKind::GroupStop;
            return event;
        }
        // Leave a marker only for a task interrupted while running. wait_visible
        // restarts it if needed; stop_all deliberately leaves every task held.
        return std::nullopt;
    }
    if (event.ptrace_event != 0) {
        current.terminal_interrupt = false;
        event.kind = EventKind::PtraceEvent;
        return event;
    }
    if (event.signal == (SIGTRAP | 0x80)) {
        // INTERRUPT of a blocked PTRACE_SYSCALL can first report its syscall
        // exit. The terminal SIGINT itself may arrive only on the next resume.
        __ptrace_syscall_info info{};
        const long available =
            checked_ptrace(PTRACE_GET_SYSCALL_INFO, tid, ptrace_value(sizeof(info)), &info,
                           "ptrace(GET_SYSCALL_INFO; requires Linux 5.3+)");
        event.syscall_architecture = info.arch;
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
            current.exec_return_rip.reset();
            constexpr auto required =
                offsetof(__ptrace_syscall_info, entry.args) + sizeof(info.entry.args);
            if (available < static_cast<long>(required))
                throw std::runtime_error("short syscall entry information");
            event.kind = EventKind::SyscallEntry;
            current.syscall_number = info.entry.nr;
            event.syscall_number = current.syscall_number;
            std::copy(std::begin(info.entry.args), std::end(info.entry.args),
                      event.syscall_arguments.begin());
        } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
            constexpr auto required =
                offsetof(__ptrace_syscall_info, exit.rval) + sizeof(info.exit.rval);
            if (available < static_cast<long>(required))
                throw std::runtime_error("short syscall exit information");
            if (current.exec_return_rip) {
                // SEIZE's EXEC event is inside execve, before its kernel
                // return. The next requested syscall is not this old exit.
                current.exec_return_rip.reset();
                current.syscall_number.reset();
                return std::nullopt;
            }
            event.kind = EventKind::SyscallExit;
            event.syscall_number = current.syscall_number;
            event.syscall_result = info.exit.rval;
            current.syscall_number.reset();
        } else
            throw std::runtime_error("kernel returned no entry/exit information at a syscall stop");
        return event;
    }
    siginfo_t info{};
    if (::ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) == -1)
        fail("ptrace(GETSIGINFO)");
    event.trap_code = info.si_code;
    observe_interrupt();
    const bool terminal_interrupt = current.terminal_interrupt;
    current.terminal_interrupt = false;
    if (terminal_interrupt && event.signal == SIGINT && info.si_code == SI_KERNEL) {
        // Correlate a terminal copy with an observed debugger interrupt and
        // shared foreground process group. Retain the token through synthetic
        // INTERRUPT stops so a delayed delivery after acknowledgement works.
        // An attached target in another terminal and kill/raise SIGINT remain
        // ordinary application signals.
        event.kind = EventKind::Interrupted;
        current.delivery_stop = false;
        current.signal = 0;
        return event;
    }
    if (current.exec_return_rip && current.mode == ResumeMode::SingleStep &&
        event.signal == SIGTRAP && info.si_code == TRAP_BRKPT) {
        user_regs_struct registers{};
        checked_ptrace(PTRACE_GETREGS, tid, nullptr, &registers, "ptrace(GETREGS exec return)");
        if (registers.rip == *current.exec_return_rip) {
            // Linux x86 reports a synthetic single-step at syscall return.
            // At the EXEC stop no user instruction has run yet; consume just
            // this unchanged-RIP TRAP_BRKPT and step the first instruction.
            // A real INT3 is SI_KERNEL and a self-loop step is TRAP_TRACE.
            current.exec_return_rip.reset();
            return std::nullopt;
        }
    }
    current.exec_return_rip.reset();
    current.delivery_stop = true;
    current.signal = event.signal;
    if (event.signal == SIGTRAP && info.si_code > 0) {
        const bool step_trap = info.si_code == TRAP_TRACE || info.si_code == TRAP_BRKPT;
        event.kind = current.mode == ResumeMode::SingleStep && step_trap ? EventKind::SingleStep
                                                                         : EventKind::Trap;
        if (event.kind == EventKind::SingleStep) {
            current.delivery_stop = false;
            current.signal = 0;
        }
    } else
        event.kind = EventKind::Signal;
    return event;
}

user_regs_struct Tracee::regs(pid_t tid) const {
    require_stopped();
    (void)task(tid);
    user_regs_struct registers{};
    checked_ptrace(PTRACE_GETREGS, tid == 0 ? selected_ : tid, nullptr, &registers,
                   "ptrace(GETREGS)");
    return registers;
}

void Tracee::set_regs(const user_regs_struct& registers, pid_t tid) {
    require_stopped();
    auto& current = task(tid);
    checked_ptrace(PTRACE_SETREGS, tid == 0 ? selected_ : tid, nullptr,
                   const_cast<user_regs_struct*>(&registers), "ptrace(SETREGS)");
    current.syscall_number.reset();
    if (current.exec_return_rip && registers.rip != *current.exec_return_rip)
        current.exec_return_rip.reset();
}

std::uint64_t Tracee::read_debug_register(pid_t tid, unsigned int index) const {
    require_stopped();
    (void)task(tid);
    if (index > 7 || index == 4 || index == 5)
        throw std::invalid_argument("invalid debug register");
    const auto offset = offsetof(user, u_debugreg) + index * sizeof(user::u_debugreg[0]);
    errno = 0;
    const long value =
        ::ptrace(PTRACE_PEEKUSER, tid == 0 ? selected_ : tid, ptrace_value(offset), nullptr);
    if (value == -1 && errno != 0)
        fail("ptrace(PEEKUSER debug register)");
    return static_cast<std::uint64_t>(value);
}

void Tracee::write_debug_register(pid_t tid, unsigned int index, std::uint64_t value) {
    require_stopped();
    (void)task(tid);
    if (index > 7 || index == 4 || index == 5)
        throw std::invalid_argument("invalid debug register");
    const auto offset = offsetof(user, u_debugreg) + index * sizeof(user::u_debugreg[0]);
    checked_ptrace(PTRACE_POKEUSER, tid == 0 ? selected_ : tid, ptrace_value(offset),
                   ptrace_value(value), "ptrace(POKEUSER debug register)");
}

void Tracee::detach(int signal) {
    require_stopped();
    validate_signal(signal);
    if (signal != 0 && !task(0).delivery_stop)
        throw std::logic_error("signal forwarding requires a signal-delivery stop");
    require_resume_safe(ResumeMode::Continue);
    // Preserve each task's own delivery stop. A synthetic INTERRUPT never
    // creates a signal to inject. Erase only successfully detached tasks so a
    // partial failure remains observable for fail-closed cleanup. Released
    // peers may run, so Detaching deliberately forbids an ordinary retry.
    const auto ids = threads();
    const pid_t chosen = selected_;
    for (pid_t tid : ids) {
        const int deliver = tid == chosen && signal != 0 ? signal : task(tid).signal;
        if (::ptrace(PTRACE_DETACH, tid, nullptr,
                     ptrace_value(static_cast<unsigned int>(deliver))) == -1) {
            if (errno != ESRCH)
                fail("ptrace(DETACH)");
            // Unlike a first EIO/EPERM, ESRCH can mean that our recorded
            // ptrace-stop is stale. Conservatively forbid ordinary rollback.
            state_ = ProcessState::Detaching;
            int status = 0;
            pid_t result;
            do {
                result = ::waitpid(tid, &status, __WALL | WNOHANG);
            } while (result == -1 && errno == EINTR);
            if (result == 0) {
                // ESRCH without an observable wait status cannot establish
                // that this task remains held. Do not allow memory rollback.
                state_ = ProcessState::Detaching;
                fail("ptrace(DETACH task not stopped)", ESRCH);
            }
            if (result == -1 && errno != ECHILD)
                fail("waitpid detached task");
            if (result > 0 && !WIFEXITED(status) && !WIFSIGNALED(status)) {
                // A racing exit/event stop is not proof of detachment. Retry
                // from the now-observed ptrace stop, retaining ownership on
                // error instead of silently leaving a traced task behind.
                state_ = ProcessState::Detaching;
                checked_ptrace(PTRACE_DETACH, tid, nullptr, nullptr, "ptrace(DETACH raced stop)");
            }
        } else {
            // Only a successful detach releases a peer. A first-call EIO or
            // EPERM leaves the all-stop invariant available for safe rollback.
            state_ = ProcessState::Detaching;
        }
        tasks_.erase(tid);
        if (selected_ == tid)
            selected_ = tasks_.empty() ? -1 : tasks_.begin()->first;
    }
    for (pid_t tid : dying_) {
        int status = 0;
        pid_t result;
        do {
            result = ::waitpid(tid, &status, __WALL);
        } while (result == -1 && errno == EINTR);
        if (result == -1 && errno != ECHILD)
            fail("waitpid exiting attached task");
    }
    reset(ProcessState::NoProgram);
}

void Tracee::terminate() {
    if (pid_ <= 0)
        return;
    if (::kill(pid_, SIGKILL) == -1 && errno != ESRCH)
        fail("kill tracee");
    // A thread-group leader can already be exiting while the surviving tasks
    // remain stopped. Signal known task IDs too; Linux delivers SIGKILL to the
    // whole group. This also prevents a reported non-thread clone escaping an
    // explicit fail-closed termination.
    for (const auto& [tid, unused] : tasks_) {
        (void)unused;
        if (::kill(tid, SIGKILL) == -1 && errno != ESRCH)
            fail("kill tracee task");
    }
    bool leader_reaped = leader_exit_.has_value();
    for (;;) {
        if (tasks_.empty() && dying_.empty() && leader_reaped) {
            reset(ProcessState::Exited);
            return;
        }
        int status = 0;
        pid_t tid;
        do {
            tid = ::waitpid(-1, &status, __WALL);
        } while (tid == -1 && errno == EINTR);
        if (tid == -1) {
            if (errno == ECHILD) {
                reset(ProcessState::Exited);
                return;
            }
            fail("waitpid while terminating tracee");
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (tid == pid_)
                leader_reaped = true;
            tasks_.erase(tid);
            dying_.erase(tid);
        } else if (WIFSTOPPED(status)) {
            if (::ptrace(PTRACE_CONT, tid, nullptr, ptrace_value(SIGKILL)) == -1 && errno != ESRCH)
                fail("ptrace(CONT) while terminating tracee");
        } else
            throw std::runtime_error("unexpected wait status while terminating tracee");
    }
}

} // namespace sdb
