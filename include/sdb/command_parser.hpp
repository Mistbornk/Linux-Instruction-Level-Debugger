#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sdb {
std::vector<std::string> parse_command(const std::string& line);
uint64_t parse_unsigned(const std::string& value, int base = 16);
std::vector<uint8_t> parse_bytes(const std::string& value);
int parse_signal(const std::string& value);
std::string signal_name(int signal);
} // namespace sdb
