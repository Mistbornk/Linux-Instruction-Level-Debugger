#include "sdb/signal_monitor.hpp"

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <unistd.h>

namespace sdb {

volatile sig_atomic_t SignalMonitor::writer_ = -1;
volatile sig_atomic_t SignalMonitor::interrupt_ = 0;
volatile sig_atomic_t SignalMonitor::interrupt_generation_ = 0;
volatile sig_atomic_t SignalMonitor::termination_ = 0;

void SignalMonitor::handle(int signal) noexcept {
    const int saved_errno = errno;
    if (signal == SIGINT) {
        interrupt_ = 1;
        interrupt_generation_ = interrupt_generation_ == std::numeric_limits<sig_atomic_t>::max()
                                    ? 1
                                    : interrupt_generation_ + 1;
    } else if ((signal == SIGTERM || signal == SIGHUP) && termination_ == 0)
        termination_ = signal;
    const unsigned char token = 1;
    // A full pipe already has a wakeup queued. Never block in a handler.
    if (writer_ >= 0) {
        ssize_t result;
        do {
            result = ::write(static_cast<int>(writer_), &token, sizeof(token));
        } while (result == -1 && errno == EINTR);
    }
    errno = saved_errno;
}

SignalMonitor::SignalMonitor() {
    if (writer_ >= 0)
        throw std::logic_error("only one signal monitor may be active");
    ::sigemptyset(&monitored_);
    for (int signal : signals_)
        ::sigaddset(&monitored_, signal);
    if (::sigprocmask(SIG_BLOCK, &monitored_, &original_mask_) == -1)
        throw std::system_error(errno, std::generic_category(), "block debugger signals");
    size_t installed = 0;
    try {
        int descriptors[2];
        if (::pipe2(descriptors, O_NONBLOCK | O_CLOEXEC) == -1)
            throw std::system_error(errno, std::generic_category(), "create signal pipe");
        reader_ = descriptors[0];
        writer_fd_ = descriptors[1];
        interrupt_ = termination_ = 0;
        interrupt_generation_ = 0;
        writer_ = writer_fd_;
        struct sigaction action{};
        action.sa_handler = handle;
        action.sa_mask = monitored_;
        // In particular, do not use SA_NOCLDSTOP: ptrace stops wake waiters.
        action.sa_flags = 0;
        for (; installed < signals_.size(); ++installed)
            if (::sigaction(signals_[installed], &action, &previous_[installed]) == -1)
                throw std::system_error(errno, std::generic_category(), "install signal handler");
        auto running_mask = original_mask_;
        for (int signal : signals_)
            ::sigdelset(&running_mask, signal);
        if (::sigprocmask(SIG_SETMASK, &running_mask, nullptr) == -1)
            throw std::system_error(errno, std::generic_category(), "unblock debugger signals");
    } catch (...) {
        while (installed > 0) {
            --installed;
            ::sigaction(signals_[installed], &previous_[installed], nullptr);
        }
        writer_ = -1;
        if (reader_ >= 0)
            ::close(reader_);
        if (writer_fd_ >= 0)
            ::close(writer_fd_);
        ::sigprocmask(SIG_SETMASK, &original_mask_, nullptr);
        throw;
    }
}

SignalMonitor::~SignalMonitor() noexcept {
    if (::sigprocmask(SIG_BLOCK, &monitored_, nullptr) == -1)
        std::fprintf(stderr, "sdb: failed to block signals during monitor cleanup\n");
    for (size_t i = 0; i < signals_.size(); ++i)
        if (::sigaction(signals_[i], &previous_[i], nullptr) == -1)
            std::fprintf(stderr, "sdb: failed to restore signal handler\n");
    writer_ = -1;
    const int close_reader = ::close(reader_);
    const int close_writer = ::close(writer_fd_);
    if (close_reader == -1 || close_writer == -1)
        std::fprintf(stderr, "sdb: failed to close signal notification pipe\n");
    if (::sigprocmask(SIG_SETMASK, &original_mask_, nullptr) == -1)
        std::fprintf(stderr, "sdb: failed to restore signal mask\n");
}

int SignalMonitor::pending_signal() const noexcept {
    const int terminating = termination_;
    return terminating != 0 ? terminating : interrupt_ != 0 ? SIGINT : 0;
}

unsigned int SignalMonitor::interrupt_generation() const noexcept {
    return static_cast<unsigned int>(interrupt_generation_);
}

void SignalMonitor::acknowledge_interrupt() {
    sigset_t previous;
    if (::sigprocmask(SIG_BLOCK, &monitored_, &previous) == -1)
        throw std::system_error(errno, std::generic_category(), "block interrupt acknowledgement");
    interrupt_ = 0;
    if (::sigprocmask(SIG_SETMASK, &previous, nullptr) == -1)
        throw std::system_error(errno, std::generic_category(), "restore interrupt mask");
}

void SignalMonitor::drain() {
    unsigned char buffer[256];
    for (;;) {
        const auto count = ::read(reader_, buffer, sizeof(buffer));
        if (count > 0)
            continue;
        if (count == -1 && errno == EINTR)
            continue;
        if (count == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        throw std::system_error(count == 0 ? EPIPE : errno, std::generic_category(),
                                "read signal notification pipe");
    }
}

int SignalMonitor::restore_in_child() noexcept {
    if (::sigprocmask(SIG_BLOCK, &monitored_, nullptr) == -1)
        return errno;
    for (size_t i = 0; i < signals_.size(); ++i)
        if (::sigaction(signals_[i], &previous_[i], nullptr) == -1)
            return errno;
    writer_ = -1;
    if (::close(reader_) == -1)
        return errno;
    if (::close(writer_fd_) == -1)
        return errno;
    if (::sigprocmask(SIG_SETMASK, &original_mask_, nullptr) == -1)
        return errno;
    return 0;
}

} // namespace sdb
