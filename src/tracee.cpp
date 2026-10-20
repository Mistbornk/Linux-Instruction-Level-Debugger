#include "sdb/tracee.hpp"
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

namespace sdb {
namespace {
[[noreturn]] void fail(const char *operation) {
  throw std::runtime_error(std::string(operation) + ": " +
                           std::strerror(errno));
}
long checked(__ptrace_request request, pid_t pid, void *addr, void *data) {
  errno = 0;
  long result = ptrace(request, pid, addr, data);
  if (result == -1 && errno)
    fail("ptrace");
  return result;
}
int wait_status(pid_t pid) {
  int status = 0;
  pid_t result;
  do {
    result = waitpid(pid, &status, 0);
  } while (result < 0 && errno == EINTR);
  if (result < 0)
    fail("waitpid");
  return status;
}
} // namespace
Tracee::~Tracee() { terminate(); }
void Tracee::require_stopped() const {
  if (state_ != State::Stopped || pid_ <= 0)
    throw std::runtime_error("please load a stopped program first");
}
user_regs_struct Tracee::registers() const {
  require_stopped();
  user_regs_struct regs{};
  checked(PTRACE_GETREGS, pid_, nullptr, &regs);
  return regs;
}
void Tracee::registers(const user_regs_struct &regs) {
  require_stopped();
  checked(PTRACE_SETREGS, pid_, nullptr, const_cast<user_regs_struct *>(&regs));
}
void Tracee::launch(const std::vector<std::string> &arguments) {
  if (pid_ > 0)
    throw std::runtime_error("program already loaded");
  if (arguments.empty() || arguments.front().empty())
    throw std::runtime_error("load requires an executable path");
  // Prepare argv before fork so the child does not allocate before exec.
  std::vector<char *> argv;
  argv.reserve(arguments.size() + 1);
  for (const auto &argument : arguments) {
    if (argument.find('\0') != std::string::npos)
      throw std::runtime_error("program arguments cannot contain NUL bytes");
    argv.push_back(const_cast<char *>(argument.c_str()));
  }
  argv.push_back(nullptr);
  int pipefd[2];
  if (pipe2(pipefd, O_CLOEXEC) < 0)
    fail("pipe2");
  const pid_t child = fork();
  if (child < 0) {
    int saved = errno;
    close(pipefd[0]);
    close(pipefd[1]);
    errno = saved;
    fail("fork");
  }
  if (child == 0) {
    close(pipefd[0]);
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != -1)
      execv(argv.front(), argv.data());
    const int error = errno;
    const char *bytes = reinterpret_cast<const char *>(&error);
    size_t sent = 0;
    while (sent < sizeof(error)) {
      ssize_t n = write(pipefd[1], bytes + sent, sizeof(error) - sent);
      if (n < 0 && errno == EINTR)
        continue;
      if (n <= 0)
        break;
      sent += static_cast<size_t>(n);
    }
    _exit(127);
  }
  close(pipefd[1]);
  pid_ = child;
  state_ = State::Running;
  int error = 0;
  ssize_t n;
  do {
    n = read(pipefd[0], &error, sizeof(error));
  } while (n < 0 && errno == EINTR);
  const int read_error = errno;
  close(pipefd[0]);
  try {
    int status = wait_status(pid_);
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      pid_ = -1;
      state_ = State::Exited;
    } else if (WIFSTOPPED(status))
      state_ = State::Stopped;
    if (n < 0) {
      errno = read_error;
      fail("launch error pipe");
    }
    if (n > 0) {
      if (n != sizeof(error))
        throw std::runtime_error("incomplete launch error");
      throw std::runtime_error("launch: " + std::string(std::strerror(error)));
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
      throw std::runtime_error("program did not reach exec stop");
    const auto options =
        PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC;
    checked(PTRACE_SETOPTIONS, pid_, nullptr,
            reinterpret_cast<void *>(static_cast<uintptr_t>(options)));
  } catch (...) {
    terminate();
    throw;
  }
}
Event Tracee::resume(Resume mode, int signal) {
  require_stopped();
  bool syscall_step = false;
  if (mode == Resume::Step) {
    // Linux may report TRAP_BRKPT for a single-stepped SYSCALL. Do not
    // mistake an actual INT3 or a user-generated SIGTRAP for that case.
    auto regs = registers();
    errno = 0;
    long word = ptrace(PTRACE_PEEKTEXT, pid_,
                       reinterpret_cast<void *>(regs.rip), nullptr);
    if (word != -1 || errno == 0)
      syscall_step = (word & 0xffff) == 0x050f;
  }
  auto request = mode == Resume::Step       ? PTRACE_SINGLESTEP
                 : mode == Resume::Continue ? PTRACE_CONT
                                            : PTRACE_SYSCALL;
  checked(request, pid_, nullptr,
          reinterpret_cast<void *>(static_cast<intptr_t>(signal)));
  state_ = State::Running;
  try {
    return wait(mode, syscall_step);
  } catch (...) {
    terminate();
    throw;
  }
}
Event Tracee::wait(Resume mode, bool syscall_step) {
  int status = wait_status(pid_);
  if (WIFEXITED(status) || WIFSIGNALED(status)) {
    pid_ = -1;
    state_ = State::Exited;
    if (WIFEXITED(status))
      return {Stop::Exit, 0, WEXITSTATUS(status)};
    return {Stop::Killed, WTERMSIG(status)};
  }
  if (!WIFSTOPPED(status))
    throw std::runtime_error("unexpected wait status");
  state_ = State::Stopped;
  int signal = WSTOPSIG(status);
  if ((status >> 16) == PTRACE_EVENT_EXEC)
    return {Stop::Exec};
  if (signal == (SIGTRAP | 0x80)) {
    __ptrace_syscall_info info{};
    checked(PTRACE_GET_SYSCALL_INFO, pid_,
            reinterpret_cast<void *>(sizeof(info)), &info);
    if (info.op == PTRACE_SYSCALL_INFO_ENTRY)
      return {Stop::SyscallEntry, 0, 0, info.entry.nr};
    if (info.op == PTRACE_SYSCALL_INFO_EXIT)
      return {Stop::SyscallExit, 0, 0, 0, info.exit.rval};
    throw std::runtime_error("missing syscall stop information");
  }
  if (signal == SIGTRAP) {
    siginfo_t info{};
    checked(PTRACE_GETSIGINFO, pid_, nullptr, &info);
    if (info.si_code == TRAP_TRACE ||
        (mode == Resume::Step && syscall_step && info.si_code == TRAP_BRKPT))
      return {Stop::Step};
    if (info.si_code == TRAP_BRKPT || info.si_code == SI_KERNEL)
      return {Stop::BreakpointTrap, SIGTRAP};
  }
  return {Stop::Signal, signal};
}
std::optional<Event> Tracee::poll_exit() {
  if (pid_ <= 0)
    return std::nullopt;
  int status = 0;
  pid_t result;
  do {
    result = waitpid(pid_, &status, WNOHANG);
  } while (result < 0 && errno == EINTR);
  if (result == 0)
    return std::nullopt;
  if (result < 0) {
    if (errno == ECHILD) {
      pid_ = -1;
      state_ = State::Exited;
    }
    fail("waitpid reconciliation");
  }
  if (WIFEXITED(status) || WIFSIGNALED(status)) {
    pid_ = -1;
    state_ = State::Exited;
    if (WIFEXITED(status))
      return Event{Stop::Exit, 0, WEXITSTATUS(status)};
    return Event{Stop::Killed, WTERMSIG(status)};
  }
  throw std::runtime_error("unexpected unsolicited wait event");
}
void Tracee::terminate() noexcept {
  if (pid_ > 0) {
    // Never call kill(-1,...). Only the owned, unreaped child is targeted.
    if (kill(pid_, SIGKILL) < 0 && errno != ESRCH) {
      const char message[] = "sdb: failed to kill owned tracee\n";
      const auto written = write(STDERR_FILENO, message, sizeof(message) - 1);
      (void)written;
    }
    int status;
    pid_t result;
    do {
      result = waitpid(pid_, &status, 0);
    } while (result < 0 && errno == EINTR);
    if (result < 0 && errno != ECHILD) {
      const char message[] = "sdb: failed to reap owned tracee\n";
      const auto written = write(STDERR_FILENO, message, sizeof(message) - 1);
      (void)written;
    }
  }
  pid_ = -1;
  state_ = State::Empty;
}
} // namespace sdb
