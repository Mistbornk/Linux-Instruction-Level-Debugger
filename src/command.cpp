#include "sdb/command.hpp"
#include <cctype>
#include <charconv>
#include <iterator>
#include <stdexcept>
#include <utility>
namespace sdb {
Command parse_command(const std::string &line) {
  std::vector<std::string> words;
  std::string word;
  char quote = 0;
  bool escaped = false, started = false;
  for (char c : line) {
    if (c == '\0')
      throw std::runtime_error("commands cannot contain NUL bytes");
    if (escaped) {
      word += c;
      escaped = false;
      started = true;
    } else if (c == '\\' && quote != '\'') {
      escaped = true;
      started = true;
    } else if (quote) {
      if (c == quote)
        quote = 0;
      else
        word += c;
    } else if (c == '\'' || c == '"') {
      quote = c;
      started = true;
    } else if (c == '#' && !started) {
      break;
    } else if (std::isspace(static_cast<unsigned char>(c))) {
      if (started) {
        words.push_back(std::move(word));
        word.clear();
        started = false;
      }
    } else {
      word += c;
      started = true;
    }
  }
  if (escaped || quote)
    throw std::runtime_error("unfinished escape or quote");
  if (started)
    words.push_back(std::move(word));
  Command command;
  if (!words.empty()) {
    command.name = std::move(words.front());
    command.args.assign(std::make_move_iterator(words.begin() + 1),
                        std::make_move_iterator(words.end()));
  }
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
