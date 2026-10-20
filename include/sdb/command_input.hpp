#pragma once
#include <string>

namespace sdb {
// Owns a command file, or borrows stdin when path is empty or "-".
// Reads without prefetching: a launched program may also consume stdin.
class CommandInput {
public:
  enum class Result { Line, End };

  explicit CommandInput(const std::string &path = {});
  ~CommandInput();
  CommandInput(const CommandInput &) = delete;
  CommandInput &operator=(const CommandInput &) = delete;

  Result read_line(std::string &line);

private:
  int fd_;
  bool owned_ = false;
};
} // namespace sdb
