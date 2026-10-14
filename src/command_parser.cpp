#include "sdb/command_parser.hpp"

#include <cctype>
#include <charconv>
#include <csignal>
#include <stdexcept>
#include <utility>

namespace sdb {
std::vector<std::string> parse_command(const std::string& line) {
    std::vector<std::string> words;
    std::string word;
    char quote = 0;
    bool escaped = false, started = false;
    for (char c : line) {
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
        } else if (c == '#' && !started)
            break;
        else if (std::isspace(static_cast<unsigned char>(c))) {
            if (started) {
                words.push_back(word);
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
        words.push_back(word);
    return words;
}

uint64_t parse_unsigned(const std::string& value, int base) {
    const char* begin = value.data();
    const char* end = begin + value.size();
    if (base == 16 && value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X'))
        begin += 2;
    uint64_t result = 0;
    auto parsed = std::from_chars(begin, end, result, base);
    if (parsed.ec != std::errc{} || parsed.ptr != end || begin == end)
        throw std::runtime_error("invalid or out-of-range number: " + value);
    return result;
}

std::vector<uint8_t> parse_bytes(const std::string& value) {
    if (value.empty() || value.size() % 2 || value.size() > 2048)
        throw std::runtime_error("patch expects 1..1024 bytes as an even-length hex string");
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < value.size(); i += 2)
        bytes.push_back(static_cast<uint8_t>(parse_unsigned(value.substr(i, 2))));
    return bytes;
}

static const std::pair<const char*, int> signals[] = {
    {"SIGHUP", SIGHUP},   {"SIGINT", SIGINT},   {"SIGQUIT", SIGQUIT}, {"SIGILL", SIGILL},
    {"SIGTRAP", SIGTRAP}, {"SIGABRT", SIGABRT}, {"SIGBUS", SIGBUS},   {"SIGFPE", SIGFPE},
    {"SIGKILL", SIGKILL}, {"SIGUSR1", SIGUSR1}, {"SIGSEGV", SIGSEGV}, {"SIGUSR2", SIGUSR2},
    {"SIGPIPE", SIGPIPE}, {"SIGALRM", SIGALRM}, {"SIGTERM", SIGTERM}, {"SIGCHLD", SIGCHLD},
    {"SIGCONT", SIGCONT}, {"SIGSTOP", SIGSTOP}, {"SIGTSTP", SIGTSTP}, {"SIGTTIN", SIGTTIN},
    {"SIGTTOU", SIGTTOU}};

int parse_signal(const std::string& value) {
    for (const auto& [name, number] : signals)
        if (value == name)
            return number;
    auto number = parse_unsigned(value, 10);
    if (number >= NSIG)
        throw std::runtime_error("signal number out of range");
    return static_cast<int>(number);
}

std::string signal_name(int signal) {
    for (const auto& [name, number] : signals)
        if (signal == number)
            return name;
    return "signal " + std::to_string(signal);
}
} // namespace sdb
