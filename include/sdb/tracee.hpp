#pragma once

#include "sdb/trace_event.hpp"

#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <sys/types.h>
#include <sys/user.h>
#include <vector>

namespace sdb {

class SignalMonitor;

enum class ProcessState { NoProgram, Stopped, Running, Detaching, Exited };
enum class ResumeMode { Continue, SingleStep, Syscall };

// A single address space with individually traced Linux tasks. Every public
// stop is all-stop: no task can execute while code bytes are being changed.
class Tracee {
  public:
    explicit Tracee(SignalMonitor* signals = nullptr) : signals_(signals) {}
    ~Tracee() noexcept;
    Tracee(const Tracee&) = delete;
    Tracee& operator=(const Tracee&) = delete;

    TraceEvent launch(const std::vector<std::string>& arguments);
    TraceEvent attach(pid_t process);
    // Caller must restore its software bytes and hardware registers first.
    void detach(int signal = 0);
    TraceEvent resume(ResumeMode mode, int signal = 0);
    TraceEvent resume_one(ResumeMode mode, int signal = 0);
    // TCG has a reproducible kernel-lockup hazard when a data watchpoint and
    // x86 single-step coincide. Check before changing a software breakpoint or
    // resuming any task; ordinary hardware watchpoint continues remain valid.
    static bool tcg_watch_step_guard() noexcept;
    void require_resume_safe(ResumeMode mode, bool one = false) const;
    // Simultaneous real stops are retained. Drain and correct their breakpoint
    // RIPs before editing memory or stepping any task over a shared breakpoint.
    std::optional<TraceEvent> take_pending_event();
    std::optional<TraceEvent> poll_event();
    std::vector<pid_t> threads() const;
    void select_thread(pid_t tid);
    user_regs_struct regs(pid_t tid = 0) const;
    void set_regs(const user_regs_struct& registers, pid_t tid = 0);
    std::uint64_t read_debug_register(pid_t tid, unsigned int index) const;
    void write_debug_register(pid_t tid, unsigned int index, std::uint64_t value);
    int pending_signal(pid_t tid = 0) const;
    void set_pending_signal(int signal, pid_t tid = 0);
    bool signal_delivery_stop(pid_t tid = 0) const;
    void terminate();
    void require_stopped() const;

    pid_t pid() const noexcept { return pid_; } // thread group ID
    pid_t tid() const noexcept { return selected_; }
    bool attached() const noexcept { return attached_; }
    ProcessState state() const noexcept { return state_; }
    bool all_stopped() const noexcept;
    bool stopped() const noexcept { return state_ == ProcessState::Stopped && all_stopped(); }

  private:
    struct Task {
        bool stopped = false;
        bool interrupt_sent = false;
        bool delivery_stop = false;
        bool terminal_interrupt = false;
        int signal = 0;
        ResumeMode mode = ResumeMode::Continue;
        std::optional<std::uint64_t> syscall_number;
        std::optional<std::uint64_t> exec_return_rip;
    };
    TraceEvent resume_impl(ResumeMode mode, int signal, bool one);
    void restart(pid_t tid, ResumeMode mode, int signal);
    std::optional<TraceEvent> consume_status(pid_t tid, int status);
    std::optional<TraceEvent> wait_raw(int options, bool interruptible = true);
    TraceEvent wait_visible();
    void stop_all();
    void finish_stop();
    void observe_interrupt();
    Task& task(pid_t tid);
    const Task& task(pid_t tid) const;
    void reset(ProcessState state) noexcept;

    pid_t pid_ = -1;
    pid_t selected_ = -1;
    bool attached_ = false;
    bool unsupported_descendants_ = false;
    // Saturates at two: zero before the first image, one for the initial
    // launched/attached image, two after any later exec replacement.
    unsigned int exec_epoch_ = 0;
    ProcessState state_ = ProcessState::NoProgram;
    std::map<pid_t, Task> tasks_;
    std::set<pid_t> dying_;
    std::set<pid_t> resumed_;
    pid_t last_wait_tid_ = -1;
    std::deque<TraceEvent> pending_;
    std::optional<TraceEvent> leader_exit_;
    SignalMonitor* signals_ = nullptr;
    unsigned int interrupt_generation_ = 0;
};

} // namespace sdb
