#include "sdb/cli_options.hpp"
#include <stdexcept>

namespace sdb {
CliOptions parse_options(const std::vector<std::string> &arguments) {
  CliOptions options;
  for (size_t i = 0; i < arguments.size(); ++i) {
    const auto &argument = arguments[i];
    if (argument == "--help" || argument == "-h") {
      options.help = true;
      return options;
    }
    if (argument == "--batch" || argument == "--command-file") {
      if (options.command_file || ++i == arguments.size())
        throw std::runtime_error("supply exactly one command file after --batch");
      if (arguments[i].empty())
        throw std::runtime_error("empty command file path");
      options.command_file = arguments[i];
    } else {
      if (argument == "--")
        ++i;
      else if (!argument.empty() && argument.front() == '-')
        throw std::runtime_error("unknown option: " + argument);
      options.target_arguments.assign(arguments.begin() + i, arguments.end());
      break;
    }
  }
  return options;
}
} // namespace sdb
