#include "sdb/debugger.hpp"
#include <iostream>
int main(int argc, char *argv[]) {
  if (argc > 2) {
    std::cerr << "usage: sdb [program]\n";
    return 1;
  }
  try {
    sdb::Debugger debugger;
    bool failed = false;
    auto command = [&](const sdb::Command &input) {
      try {
        return debugger.execute(input);
      } catch (const std::exception &error) {
        std::cerr << "** error: " << error.what() << '\n';
        failed = true;
        return true;
      }
    };
    if (argc == 2)
      command({"load", {argv[1]}});
    std::string line;
    while (std::cout << "(sdb) " << std::flush, std::getline(std::cin, line)) {
      if (!command(sdb::parse_command(line)))
        break;
    }
    // Tracee's destructor terminates/reaps its owned child on EOF too.
    return failed ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << "** fatal: " << error.what() << '\n';
    return 1;
  }
}
