#include <cerrno>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
  const pid_t child = fork();
  if (child < 0) {
    std::cerr << "FAIL: cannot fork ptrace probe\n";
    return 1;
  }
  if (child == 0) {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
      const int error = errno;
      _exit(error == EPERM || error == EACCES || error == ENOSYS ? 77 : 1);
    }
    _exit(0);
  }
  int status = 0;
  pid_t result;
  do {
    result = waitpid(child, &status, 0);
  } while (result < 0 && errno == EINTR);
  if (result < 0 || !WIFEXITED(status)) {
    std::cerr << "FAIL: cannot reap ptrace probe\n";
    return 1;
  }
  const int code = WEXITSTATUS(status);
  if (code == 77)
    std::cerr << "SKIP: ptrace(TRACEME) is unavailable; allow ptrace or use the Linux development container\n";
  else if (code != 0)
    std::cerr << "FAIL: unexpected ptrace probe error\n";
  return code;
}
