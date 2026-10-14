#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace sdb {
struct Command {
  std::string name;
  std::vector<std::string> args;
};
Command parse_command(const std::string &line);
uint64_t number(const std::string &text, int base = 16);
std::vector<uint8_t> hex_bytes(const std::string &text);
} // namespace sdb
