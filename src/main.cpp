#include "sdb/debugger.hpp"
#include "sdb/signal_monitor.hpp"

#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <termios.h>
#include <unistd.h>
#include <vector>

namespace {
class CommandInput {
  public:
    enum class Result { Line, End, Interrupted };
    CommandInput(const std::string& path, sdb::SignalMonitor& signals) : signals_(signals) {
        if (!path.empty() && path != "-") {
            fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd_ == -1)
                throw std::system_error(errno, std::generic_category(),
                                        "cannot open command file: " + path);
            owned_ = true;
        }
    }
    ~CommandInput() {
        if (owned_ && ::close(fd_) == -1)
            std::cerr << "** error: failed to close command file\n";
    }
    CommandInput(const CommandInput&) = delete;
    CommandInput& operator=(const CommandInput&) = delete;

    Result read_line(std::string& line) {
        line.clear();
        for (;;) {
            if (signals_.pending_signal() != 0)
                return Result::Interrupted;
            pollfd ready[]{{fd_, POLLIN, 0}, {signals_.fd(), POLLIN, 0}};
            if (::poll(ready, 2, -1) == -1) {
                if (errno == EINTR)
                    continue;
                throw std::system_error(errno, std::generic_category(), "poll command input");
            }
            if (ready[1].revents & (POLLERR | POLLHUP | POLLNVAL))
                throw std::runtime_error("signal notification pipe unavailable");
            if (ready[1].revents & POLLIN)
                signals_.drain();
            if (signals_.pending_signal() != 0)
                return Result::Interrupted;
            if (ready[0].revents & (POLLERR | POLLNVAL))
                throw std::runtime_error("command input unavailable");
            if (!(ready[0].revents & (POLLIN | POLLHUP)))
                continue;
            // Do not prefetch commands: launched programs share stdin when
            // commands also come from stdin, including interactive terminals.
            char value;
            const auto count = ::read(fd_, &value, 1);
            if (count == -1) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
                throw std::system_error(errno, std::generic_category(), "read command input");
            }
            if (count == 0)
                return line.empty() ? Result::End : Result::Line;
            if (value == '\n')
                return Result::Line;
            line.push_back(value);
        }
    }

  private:
    sdb::SignalMonitor& signals_;
    int fd_ = STDIN_FILENO;
    bool owned_ = false;
};
} // namespace

int main(int argc, char* argv[]) {
    try {
        std::string command_file;
        std::vector<std::string> arguments;
        for (int i = 1; i < argc; ++i) {
            std::string option = argv[i];
            if (option == "--help" || option == "-h") {
                std::cout
                    << "usage: sdb [--batch FILE | --command-file FILE] [--] [program args...]\n"
                    << "Use FILE '-' to read commands from stdin. Addresses are hexadecimal.\n";
                sdb::Debugger::help(std::cout);
                return 0;
            }
            if (option == "--batch" || option == "--command-file") {
                if (++i >= argc || !command_file.empty())
                    throw std::runtime_error("supply exactly one command file after --batch");
                command_file = argv[i];
                if (command_file.empty())
                    throw std::runtime_error("empty command file path");
            } else {
                if (option == "--")
                    ++i;
                else if (!option.empty() && option.front() == '-')
                    throw std::runtime_error("unknown option: " + option);
                for (; i < argc; ++i)
                    arguments.emplace_back(argv[i]);
                break;
            }
        }
        const bool interactive = command_file.empty() && isatty(STDIN_FILENO);
        sdb::SignalMonitor signals;
        CommandInput commands(command_file, signals);
        // Flush each stop promptly even when a test harness drives us over pipes.
        std::cout << std::unitbuf;
        sdb::Debugger debugger(std::cout, &signals);
        bool failed = false;
        if (!arguments.empty()) {
            try {
                debugger.load(arguments);
            } catch (const std::exception& error) {
                if (signals.pending_signal() == 0) {
                    std::cerr << "** error: " << error.what() << '\n';
                    failed = true;
                }
            }
        }
        int exit_signal = 0;
        std::string line;
        while (true) {
            const int requested = signals.pending_signal();
            if (requested != 0) {
                if (requested != SIGINT || !interactive) {
                    exit_signal = requested;
                    break;
                }
                signals.acknowledge_interrupt();
                // Discard a partially typed terminal command. This runs in
                // normal control flow, never inside the signal handler.
                if (::tcflush(STDIN_FILENO, TCIFLUSH) == -1 && errno != ENOTTY)
                    throw std::system_error(errno, std::generic_category(), "flush command line");
                std::cout << '\n';
            }
            if (interactive)
                std::cout << "(sdb) ";
            const auto result = commands.read_line(line);
            if (result == CommandInput::Result::Interrupted)
                continue;
            if (result == CommandInput::Result::End)
                break;
            if (signals.pending_signal() != 0)
                continue;
            try {
                if (!debugger.execute(line))
                    break;
            } catch (const sdb::MemoryCorruption& error) {
                debugger.terminate();
                std::cerr << "** error: session terminated after memory rollback failed: "
                          << error.what() << '\n';
                failed = true;
            } catch (const std::exception& error) {
                if (signals.pending_signal() == 0) {
                    std::cerr << "** error: " << error.what() << '\n';
                    failed = true;
                }
            }
        }
        // EOF and controlled termination share the same ownership-aware path.
        try {
            debugger.shutdown();
        } catch (const std::exception& error) {
            std::cerr << "** error: " << error.what() << '\n';
            failed = true;
        }
        const int final_request = signals.pending_signal();
        if (exit_signal == 0 && final_request != 0 && (final_request != SIGINT || !interactive))
            exit_signal = final_request;
        return exit_signal != 0 ? 128 + exit_signal : failed ? 1 : 0;
    } catch (const std::exception& error) {
        std::cerr << "** error: " << error.what() << '\n';
        return 1;
    }
}
