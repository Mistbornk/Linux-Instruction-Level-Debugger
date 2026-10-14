#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <sys/types.h>
#include <sys/user.h>

namespace sdb {
enum class State { Empty, Stopped, Running, Exited };
enum class Resume { Step, Continue, Syscall };
enum class Stop {
  Exit,
  Killed,
  Signal,
  BreakpointTrap,
  Step,
  SyscallEntry,
  SyscallExit,
  Exec
};
struct Event {
  Stop kind;
  int signal = 0;
  int exit_code = 0;
  uint64_t syscall_number = 0;
  int64_t result = 0;
};
// Owns exactly one launched process. No attach or thread support in stage 1.
class Tracee {
public:
  ~Tracee();
  Tracee() = default;
  Tracee(const Tracee &) = delete;
  Tracee &operator=(const Tracee &) = delete;
  void launch(const std::string &path);
  Event resume(Resume mode, int signal = 0);
  void terminate() noexcept;
  std::optional<Event> poll_exit();
  void require_stopped() const;
  user_regs_struct registers() const;
  void registers(const user_regs_struct &regs);
  pid_t pid() const { return pid_; }
  State state() const { return state_; }

private:
  Event wait(Resume mode, bool syscall_step = false);
  pid_t pid_ = -1;
  State state_ = State::Empty;
};
} // namespace sdb
