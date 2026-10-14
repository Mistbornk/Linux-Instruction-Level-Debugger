#include "sdb/command.hpp"
#include <charconv>
#include <sstream>
#include <stdexcept>
namespace sdb {
Command parse_command(const std::string &line) {
  std::istringstream input(line);
  Command command;
  input >> command.name;
  std::string arg;
  while (input >> arg)
    command.args.push_back(arg);
  return command;
}
uint64_t number(const std::string &text, int base) {
  const char *begin = text.data();
  const char *end = begin + text.size();
  if (base == 16 && text.size() > 2 && text[0] == '0' &&
      (text[1] == 'x' || text[1] == 'X'))
    begin += 2;
  uint64_t result = 0;
  auto parsed = std::from_chars(begin, end, result, base);
  if (parsed.ec != std::errc{} || parsed.ptr != end || begin == end)
    throw std::runtime_error("invalid or out-of-range number: " + text);
  return result;
}
std::vector<uint8_t> hex_bytes(const std::string &text) {
  if (text.empty() || text.size() % 2 || text.size() > 2048)
    throw std::runtime_error(
        "patch requires 1..1024 bytes of hexadecimal pairs");
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < text.size(); i += 2)
    bytes.push_back(static_cast<uint8_t>(number(text.substr(i, 2))));
  return bytes;
}
} // namespace sdb
