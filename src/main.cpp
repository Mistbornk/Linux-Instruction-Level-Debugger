#include "sdb/cli_options.hpp"
#include "sdb/command_input.hpp"
#include "sdb/debugger.hpp"
#include <iostream>
#include <string>
#include <vector>
int main(int argc, char *argv[]) {
  try {
    const std::vector<std::string> arguments(argv + 1, argv + argc);
    const auto options = sdb::parse_options(arguments);
    if (options.help) {
      std::cout << "usage: sdb [--batch FILE | --command-file FILE] [--] "
                   "[program args...]\n"
                   "Use FILE '-' to read commands from stdin without prompts.\n"
                   "Commands: load <path> [args...], si, cont, syscall,\n"
                   "          break <hex-address>, breakrva <hex-offset>,\n"
                   "          delete <id>, patch <address> <hexbytes>,\n"
                   "          info reg, info break, q\n";
      return 0;
    }
    sdb::CommandInput commands(options.command_file.value_or(""));
    // Report stops promptly even when stdout is redirected.
    std::cout << std::unitbuf;
    sdb::Debugger debugger;
    bool failed = false;
    size_t line_number = 0;
    auto report_error = [&](const std::exception &error) {
      std::cerr << "** error: ";
      if (options.command_file && line_number)
        std::cerr << *options.command_file << ':' << line_number << ": ";
      std::cerr << error.what() << '\n';
      failed = true;
    };
    if (!options.target_arguments.empty()) {
      try {
        debugger.load(options.target_arguments);
      } catch (const std::exception &error) {
        report_error(error);
      }
    }
    std::string line;
    while (true) {
      // Preserve stage-one prompt behavior for existing pipe-driven clients.
      if (!options.command_file)
        std::cout << "(sdb) " << std::flush;

      if (commands.read_line(line) == sdb::CommandInput::Result::End)
        break;

      ++line_number;
      try {
        if (!debugger.execute(sdb::parse_command(line)))
          break;
      } catch (const std::exception &error) {
        report_error(error);
      }
    }
    // Tracee's destructor terminates/reaps its owned child on EOF too.
    return failed ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << "** error: " << error.what() << '\n';
    return 1;
  }
}
