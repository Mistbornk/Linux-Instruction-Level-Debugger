#pragma once
#include <optional>
#include <string>
#include <vector>

namespace sdb {
struct CliOptions {
  std::optional<std::string> command_file;
  std::vector<std::string> target_arguments;
  bool help = false;
};
CliOptions parse_options(const std::vector<std::string> &arguments);
} // namespace sdb
