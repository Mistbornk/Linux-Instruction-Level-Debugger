#include "sdb/command_input.hpp"
#include <cerrno>
#include <fcntl.h>
#include <system_error>
#include <unistd.h>

namespace sdb {
CommandInput::CommandInput(const std::string &path) : fd_(STDIN_FILENO) {
  if (!path.empty() && path != "-") {
    fd_ = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0)
      throw std::system_error(errno, std::generic_category(),
                              "cannot open command file: " + path);
    owned_ = true;
  }
}

CommandInput::~CommandInput() {
  if (owned_ && close(fd_) < 0) {
    // Destruction must not throw, including when cleaning up another error.
    const char message[] = "sdb: failed to close command file\n";
    const auto written = write(STDERR_FILENO, message, sizeof(message) - 1);
    (void)written;
  }
}

CommandInput::Result CommandInput::read_line(std::string &line) {
  line.clear();
  for (;;) {
    char value;
    const ssize_t count = read(fd_, &value, 1);
    if (count < 0) {
      if (errno == EINTR)
        continue;
      throw std::system_error(errno, std::generic_category(),
                              "read command input");
    }
    if (count == 0)
      return line.empty() ? Result::End : Result::Line;
    if (value == '\n')
      return Result::Line;
    line.push_back(value);
  }
}
} // namespace sdb
