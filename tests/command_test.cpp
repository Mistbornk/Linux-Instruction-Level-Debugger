#include "sdb/cli_options.hpp"
#include "sdb/command.hpp"
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}
template <class Function> static void rejects(Function function) {
  try {
    function();
  } catch (const std::runtime_error &) {
    return;
  }
  throw std::runtime_error("invalid input was accepted");
}
int main() {
  try {
    struct Case {
      std::string text;
      std::string name;
      std::vector<std::string> args;
    };
    const std::vector<Case> cases{
        {"", "", {}},
        {" \t\r", "", {}},
        {"# comment", "", {}},
        {"info reg # comment", "info", {"reg"}},
        {R"(load "a b" 'c d' "" '')", "load", {"a b", "c d", "", ""}},
        {R"(load a\ b "c\"d" 'e\f')", "load", {"a b", "c\"d", "e\\f"}},
        {R"(load ab" c"'d' a#b '#literal' \#escaped)", "load",
         {"ab cd", "a#b", "#literal", "#escaped"}},
        {R"cmd(load '$HOME' "$(echo hi)" '*.c')cmd", "load", {"$HOME", "$(echo hi)", "*.c"}},
        {"info\tbreak\r", "info", {"break"}}};
    for (const auto &item : cases) {
      const auto parsed = sdb::parse_command(item.text);
      require(parsed.name == item.name && parsed.args == item.args,
              "command tokenization mismatch");
    }
    for (const std::string text : {"load 'unfinished", "load \"unfinished", "load x\\"})
      rejects([&] { sdb::parse_command(text); });
    rejects([] { sdb::parse_command(std::string("load x\0y", 8)); });

    const auto normal = sdb::parse_options({"program", "--batch", "literal"});
    require(!normal.command_file && normal.target_arguments ==
                std::vector<std::string>{"program", "--batch", "literal"},
            "target arguments were parsed as debugger options");
    const auto batch = sdb::parse_options({"--batch", "commands.txt", "--", "-program", ""});
    require(batch.command_file == "commands.txt" && batch.target_arguments ==
                std::vector<std::string>{"-program", ""}, "batch arguments mismatch");
    require(sdb::parse_options({"--command-file", "-"}).command_file == "-",
            "command-file alias mismatch");
    require(sdb::parse_options({"--help"}).help && sdb::parse_options({"-h"}).help,
            "help option mismatch");
    require(sdb::parse_options({"--"}).target_arguments.empty(), "bare -- mismatch");
    for (const std::vector<std::string> &args :
         std::vector<std::vector<std::string>>{{"--batch"}, {"--batch", ""},
           {"--batch", "a", "--command-file", "b"}, {"--unknown"}})
      rejects([&] { sdb::parse_options(args); });
    std::cout << "PASS: quotes, escapes, comments, empty arguments, CLI options\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
