#pragma once

#include "sdb/breakpoint.hpp"
#include "sdb/disassembler.hpp"
#include "sdb/elf_image.hpp"
#include "sdb/tracee.hpp"
#include "sdb/watchpoint.hpp"
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace sdb {
class Debugger {
  public:
    explicit Debugger(std::ostream& out, SignalMonitor* signals = nullptr);
    ~Debugger() noexcept;
    void load(const std::vector<std::string>& arguments);
    bool execute(const std::string& command); // false means quit
    void terminate();
    void shutdown();
    static void help(std::ostream& out);

  private:
    Tracee tracee_;
    Memory memory_;
    BreakpointManager breakpoints_;
    WatchpointManager watchpoints_;
    Disassembler disassembler_;
    std::unique_ptr<ElfImage> image_;
    uint64_t bias_ = 0;
    bool automatic_disassembly_ = true;
    bool watchpoints_dirty_ = false;
    bool unsupported_clone_ = false;
    std::vector<std::string> last_arguments_;
    std::vector<std::string> history_;
    std::ostream& out_;

    void resume(ResumeMode mode, std::optional<int> signal);
    bool correct_breakpoint(const TraceEvent& event);
    void report(const TraceEvent& event);
    void report_all(const TraceEvent& event);
    void drain_pending();
    void attach(pid_t pid);
    void detach();
    void show_location();
    void print_registers();
    void reset_image() noexcept;
    bool refresh();
    bool execute_command(const std::vector<std::string>& words);
    uint64_t resolve_breakpoint(const std::string& name) const;
    uint64_t resolve_address(const std::string& name) const;
};
} // namespace sdb
