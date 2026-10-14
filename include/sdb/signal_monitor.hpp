#pragma once

#include <array>
#include <csignal>

namespace sdb {

// One monitor belongs to the CLI process. The self-pipe wakes both command
// input and ptrace waits; all process-control work remains on the caller thread.
class SignalMonitor {
  public:
    SignalMonitor();
    ~SignalMonitor() noexcept;
    SignalMonitor(const SignalMonitor&) = delete;
    SignalMonitor& operator=(const SignalMonitor&) = delete;

    int pending_signal() const noexcept;
    unsigned int interrupt_generation() const noexcept;
    void acknowledge_interrupt();
    int fd() const noexcept { return reader_; }
    void drain();
    // Only async-signal-safe operations; called in the child before exec.
    // Return an errno value instead of throwing across the fork boundary.
    int restore_in_child() noexcept;

  private:
    static void handle(int signal) noexcept;
    static volatile sig_atomic_t writer_;
    static volatile sig_atomic_t interrupt_;
    static volatile sig_atomic_t interrupt_generation_;
    static volatile sig_atomic_t termination_;
    static constexpr std::array<int, 4> signals_{{SIGINT, SIGTERM, SIGHUP, SIGCHLD}};
    std::array<struct sigaction, signals_.size()> previous_{};
    sigset_t monitored_{};
    sigset_t original_mask_{};
    int reader_ = -1;
    int writer_fd_ = -1;
};

} // namespace sdb
