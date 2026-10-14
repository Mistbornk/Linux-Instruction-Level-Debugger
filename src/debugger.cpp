#include "sdb/debugger.hpp"
#include "sdb/backtrace.hpp"
#include "sdb/command_parser.hpp"
#include "sdb/register_file.hpp"
#include "sdb/syscall_decoder.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <exception>
#include <iomanip>
#include <limits>
#include <ostream>
#include <stdexcept>
#include <system_error>

namespace sdb {
namespace {
void arity(const std::vector<std::string>& words, size_t minimum, size_t maximum,
           const char* usage) {
    if (words.size() < minimum || words.size() > maximum)
        throw std::runtime_error(std::string("usage: ") + usage);
}

uint64_t checked_add(uint64_t a, uint64_t b) {
    if (b > std::numeric_limits<uint64_t>::max() - a)
        throw std::runtime_error("address overflow");
    return a + b;
}
} // namespace

Debugger::Debugger(std::ostream& out, SignalMonitor* signals)
    : tracee_(signals), memory_(tracee_), breakpoints_(memory_), watchpoints_(tracee_), out_(out) {}

Debugger::~Debugger() noexcept {
    try {
        shutdown();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "sdb: cleanup failed: %s\n", error.what());
        try {
            terminate();
        } catch (...) {
        }
    }
}

void Debugger::reset_image() noexcept {
    breakpoints_.clear();
    image_.reset();
    bias_ = 0;
    watchpoints_.clear();
    watchpoints_dirty_ = false;
    unsupported_clone_ = false;
}

void Debugger::terminate() {
    tracee_.terminate();
    reset_image();
}

void Debugger::shutdown() {
    if (tracee_.attached() && tracee_.stopped())
        detach();
    else
        terminate();
}

void Debugger::detach() {
    tracee_.require_stopped();
    drain_pending();
    // All threads are held, including simultaneous INT3 hits whose RIPs must
    // be corrected before restoring bytes and releasing any one task.
    std::vector<uint64_t> installed;
    for (const auto& [address, bp] : breakpoints_.all())
        if (bp.installed)
            installed.push_back(address);
    breakpoints_.restore_all();
    try {
        watchpoints_.restore_all();
    } catch (...) {
        const auto error = std::current_exception();
        try {
            for (uint64_t address : installed)
                breakpoints_.enable(address);
        } catch (...) {
            throw MemoryCorruption(
                "failed to roll back breakpoint state after detach restoration failed");
        }
        std::rethrow_exception(error);
    }
    // No code/debug-register edits are allowed once any task is detached: that
    // peer may already be executing in the shared address space.
    try {
        tracee_.detach();
    } catch (const std::exception& error) {
        if (tracee_.stopped()) {
            // No task was released, so restoring the active session is safe.
            // Keep IDs, original bytes and baseline debug registers for a retry.
            const auto failure = std::current_exception();
            try {
                for (uint64_t address : installed)
                    breakpoints_.enable(address);
                watchpoints_.synchronize();
            } catch (...) {
                throw MemoryCorruption("failed to restore debugger changes after detach failed");
            }
            std::rethrow_exception(failure);
        }
        const std::string message = error.what();
        terminate();
        throw std::runtime_error(
            "detach failed after releasing a task or losing all-stop; session terminated: " +
            message);
    }
    reset_image();
    out_ << "** detached.\n";
}

void Debugger::attach(pid_t pid) {
    refresh();
    if (tracee_.pid() > 0)
        throw std::runtime_error("program already loaded");
    reset_image();
    tracee_.attach(pid);
    try {
        image_ = std::make_unique<ElfImage>(ElfImage::from_tracee(tracee_.tid()));
        bias_ = image_->load_bias(tracee_.tid());
        out_ << "** attached to process " << pid << ".\n";
        drain_pending();
        show_location();
    } catch (...) {
        // No new bytes/registers were installed before validating the image.
        tracee_.detach();
        reset_image();
        throw;
    }
}

void Debugger::load(const std::vector<std::string>& arguments) {
    if (arguments.empty())
        throw std::runtime_error("usage: load <program> [arguments...]");
    refresh();
    if (tracee_.stopped() || tracee_.state() == ProcessState::Running)
        throw std::runtime_error("program already loaded; use q or finish execution first");
    reset_image();
    // Validate before forking; launch's error pipe distinguishes failed exec.
    auto image = std::make_unique<ElfImage>(arguments.front());
    auto argv = arguments;
    argv.front() = image->path();
    try {
        tracee_.launch(argv);
        // Read the image actually executed, including a replaced/unlinked path.
        image = std::make_unique<ElfImage>(ElfImage::from_tracee(tracee_.tid()));
        bias_ = image->load_bias(tracee_.tid());
        auto entry = image->runtime_address(image->entry(), bias_);
        image_ = std::move(image);
        if (tracee_.regs().rip != entry) {
            breakpoints_.add(entry, true);
            auto event = tracee_.resume(ResumeMode::Continue);
            if (!correct_breakpoint(event) || tracee_.regs().rip != entry)
                throw std::runtime_error("program did not reach its entry breakpoint during load");
            breakpoints_.remove_address(entry);
        }
        out_ << "** program '" << arguments.front() << "' loaded. entry point: 0x" << std::hex
             << entry << std::dec << ".\n"
             << "** tracee pid " << tracee_.pid() << ", load bias 0x" << std::hex << bias_
             << std::dec << ".\n";
        last_arguments_ = arguments;
        show_location();
    } catch (...) {
        terminate();
        throw;
    }
}

void Debugger::drain_pending() {
    const pid_t selected = tracee_.tid();
    while (auto event = tracee_.take_pending_event())
        report(*event);
    if (unsupported_clone_) {
        try {
            // A fork child copied our INT3 bytes; a vfork/CLONE_VM child may
            // share them. Both remain held. Restore every known address space
            // (repeating a byte restoration in a shared mapping is harmless).
            for (pid_t tid : tracee_.threads()) {
                tracee_.select_thread(tid);
                for (const auto& [address, bp] : breakpoints_.all())
                    memory_.write(address, {bp.original_byte});
            }
            watchpoints_.restore_all();
            tracee_.detach();
            reset_image();
        } catch (...) {
            terminate();
            throw;
        }
        throw std::runtime_error("fork/vfork or non-thread clone is unsupported; restored debugger "
                                 "changes and detached all tasks");
    }
    // Consume every DR6 hit before programming newly cloned tasks: reprogramming
    // registers clears status bits that may belong to another queued real stop.
    if (watchpoints_dirty_ && tracee_.stopped()) {
        watchpoints_.synchronize();
        watchpoints_dirty_ = false;
    }
    const auto tids = tracee_.threads();
    if (std::find(tids.begin(), tids.end(), selected) != tids.end())
        tracee_.select_thread(selected);
}

void Debugger::report_all(const TraceEvent& event) {
    report(event);
    drain_pending();
}

bool Debugger::refresh() {
    bool terminal = false;
    while (auto event = tracee_.poll_event()) {
        report_all(*event);
        terminal = terminal || event->terminal();
    }
    drain_pending();
    return terminal;
}

bool Debugger::correct_breakpoint(const TraceEvent& event) {
    if (event.kind != EventKind::Trap || event.signal != SIGTRAP ||
        (event.trap_code != TRAP_BRKPT && event.trap_code != SI_KERNEL))
        return false;
    auto regs = tracee_.regs();
    if (regs.rip == 0)
        return false;
    auto bp = breakpoints_.find(regs.rip - 1);
    if (!bp || !bp->installed)
        return false;
    --regs.rip;
    tracee_.set_regs(regs);
    tracee_.set_pending_signal(0);
    return true;
}

void Debugger::show_location() {
    if (!automatic_disassembly_ || !tracee_.stopped())
        return;
    // A fault can leave RIP outside any readable/executable VMA. Reporting the
    // stop remains valid even when there is nothing safe to disassemble.
    try {
        disassembler_.print(memory_, breakpoints_, tracee_.regs().rip, out_);
    } catch (const std::exception& error) {
        out_ << "** disassembly unavailable: " << error.what() << '\n';
    }
}

void Debugger::report(const TraceEvent& event) {
    const auto tids = tracee_.threads();
    const bool live = std::find(tids.begin(), tids.end(), event.tid) != tids.end();
    if (live)
        tracee_.select_thread(event.tid);
    switch (event.kind) {
    case EventKind::Exited:
        out_ << "** exited with status " << event.exit_code << ".\n";
        reset_image();
        return;
    case EventKind::Signaled:
        out_ << "** terminated by signal " << signal_name(event.signal) << " (" << event.signal
             << ").\n";
        reset_image();
        return;
    case EventKind::Exec:
        // exec replaced the entire address space. Never restore the old bytes.
        reset_image();
        try {
            image_ = std::make_unique<ElfImage>(ElfImage::from_tracee(tracee_.tid()));
            bias_ = image_->load_bias(tracee_.tid());
        } catch (...) {
            terminate();
            throw;
        }
        out_ << "** exec: " << image_->display_name() << "; old breakpoints cleared.\n";
        break;
    case EventKind::ThreadCreated:
        watchpoints_.inherit(event.tid, event.new_tid);
        watchpoints_dirty_ = true;
        out_ << "** thread " << event.new_tid << " created by " << event.tid << ".\n";
        break;
    case EventKind::UnsupportedClone:
        watchpoints_.inherit(event.tid, event.new_tid);
        unsupported_clone_ = true;
        break;
    case EventKind::ThreadExited:
        out_ << "** thread " << event.tid << " exited.\n";
        return;
    case EventKind::Trap:
        if (!live)
            return; // A concurrent exit can invalidate a queued stop.
        if (event.trap_code == TRAP_HWBKPT) {
            const auto hits = watchpoints_.hits(event.tid);
            if (!hits.empty()) {
                tracee_.set_pending_signal(0);
                for (const auto& watch : hits)
                    out_ << "** watchpoint " << watch.id << " hit at 0x" << std::hex
                         << watch.address << std::dec << " thread " << event.tid << " ("
                         << (watch.access == WatchAccess::Write ? "write" : "access") << ").\n";
                break;
            }
        }
        if (correct_breakpoint(event)) {
            out_ << "** hit a breakpoint at 0x" << std::hex << tracee_.regs().rip << std::dec
                 << ".\n";
            break;
        }
        // A native INT3 or other unowned SIGTRAP belongs to the application.
        [[fallthrough]];
    case EventKind::Signal:
        if (!live)
            return;
        tracee_.set_pending_signal(event.signal);
        out_ << "** stopped by signal " << signal_name(event.signal) << " (" << event.signal
             << "). Forward on resume; use cont 0 to suppress.\n";
        break;
    case EventKind::SingleStep:
        if (!live)
            return;
        // TF and a data watchpoint can share one #DB; Linux gives TRAP_TRACE
        // priority in si_code. DR6 still records the owned data breakpoint.
        if (watchpoints_.triggered(event.tid)) {
            auto combined = event;
            combined.kind = EventKind::Trap;
            combined.trap_code = TRAP_HWBKPT;
            report(combined);
            return;
        }
        out_ << "** single-step stop.\n";
        break;
    case EventKind::SyscallEntry:
        if (!live)
            return;
        out_ << "** syscall entry ";
        if (event.syscall_number)
            out_ << *event.syscall_number;
        else
            out_ << "unknown";
        out_ << " at rip 0x" << std::hex << tracee_.regs().rip << std::dec << ". "
             << format_syscall_entry(event, &memory_) << "\n";
        break;
    case EventKind::SyscallExit:
        if (!live)
            return;
        out_ << "** syscall exit ";
        if (event.syscall_number)
            out_ << *event.syscall_number;
        else
            out_ << "unknown";
        out_ << " = " << event.syscall_result << " at rip 0x" << std::hex << tracee_.regs().rip
             << std::dec << ". " << format_syscall_exit(event) << "\n";
        break;
    case EventKind::Interrupted:
        out_ << "** interrupted; all threads stopped.\n";
        break;
    case EventKind::GroupStop:
        out_ << "** group stop: " << signal_name(event.signal)
             << "; preserving job-control stops is unsupported.\n";
        break;
    case EventKind::PtraceEvent:
        out_ << "** ptrace event " << event.ptrace_event << ".\n";
        break;
    }
    show_location();
}

void Debugger::resume(ResumeMode mode, std::optional<int> requested_signal) {
    tracee_.require_stopped();
    drain_pending();
    tracee_.require_resume_safe(mode);
    const pid_t chosen = tracee_.tid();
    const int signal = requested_signal.value_or(tracee_.pending_signal());
    if (signal != 0 && !tracee_.signal_delivery_stop())
        throw std::runtime_error("signal forwarding requires a signal-delivery stop");
    tracee_.set_pending_signal(signal);

    // Shared displaced-instruction path. Peers remain stopped while a shared
    // INT3 is absent. Correct every simultaneous hit before reaching this loop.
    const auto tids =
        mode == ResumeMode::SingleStep ? std::vector<pid_t>{chosen} : tracee_.threads();
    for (pid_t tid : tids) {
        tracee_.select_thread(tid);
        const auto address = tracee_.regs().rip;
        const auto* bp = breakpoints_.find(address);
        if (!bp || !bp->installed)
            continue;
        auto step_mode = ResumeMode::SingleStep;
        // At syscall entry the opcode is already consumed. Reinsert there and
        // release peers on cont: single-stepping a blocking syscall while peers
        // are held can deadlock (for example futex wait needing a peer wake).
        if (mode != ResumeMode::SingleStep &&
            disassembler_.is_syscall(memory_, breakpoints_, address))
            step_mode = ResumeMode::Syscall;
        // Reject a known-unsafe emulated TF/watch combination while INT3 and
        // its bookkeeping are still intact. This is a recoverable CLI error.
        tracee_.require_resume_safe(step_mode, true);
        breakpoints_.disable(address);
        try {
            auto event = tracee_.resume_one(step_mode, tracee_.pending_signal());
            if (tracee_.stopped() && event.kind != EventKind::Exec)
                breakpoints_.enable(address);
            if (event.kind == EventKind::SingleStep && watchpoints_.triggered(event.tid)) {
                event.kind = EventKind::Trap;
                event.trap_code = TRAP_HWBKPT;
            }
            const bool internal_stop =
                event.kind == EventKind::SingleStep ||
                (mode == ResumeMode::Continue && step_mode == ResumeMode::Syscall &&
                 event.kind == EventKind::SyscallEntry);
            if (!internal_stop || mode == ResumeMode::SingleStep) {
                report_all(event);
                return;
            }
            drain_pending();
        } catch (...) {
            // Never let the controller resume with a silently disabled INT3.
            terminate();
            throw;
        }
    }
    tracee_.select_thread(chosen);
    report_all(tracee_.resume(mode, tracee_.pending_signal()));
}

uint64_t Debugger::resolve_breakpoint(const std::string& name) const {
    if (!image_)
        throw std::runtime_error("please load a program first");
    // All-hex strings retain the historical address syntax; other names are
    // exact ELF symbols. Prefix with @ to disambiguate e.g. @deadbeef.
    if (!name.empty() && name.front() == '@')
        return image_->symbol_address(name.substr(1), bias_);
    bool hex = !name.empty() && std::all_of(name.begin(), name.end(),
                                            [](unsigned char c) { return std::isxdigit(c) != 0; });
    if (hex || name.rfind("0x", 0) == 0 || name.rfind("0X", 0) == 0 ||
        (!name.empty() && (std::isdigit(static_cast<unsigned char>(name[0])) || name[0] == '-')))
        return parse_unsigned(name);
    return image_->symbol_address(name, bias_);
}

uint64_t Debugger::resolve_address(const std::string& name) const {
    if (!name.empty() && name.front() == '@') {
        if (!image_)
            throw std::runtime_error("please load a program first");
        return image_->object_address(name.substr(1), bias_);
    }
    return parse_unsigned(name);
}

void Debugger::print_registers() {
    size_t index = 0;
    for (const auto& [name, value] : RegisterFile::values(tracee_)) {
        out_ << '$' << name << " 0x" << std::hex << std::setw(16) << std::setfill('0') << value
             << std::setfill(' ') << std::dec << (++index % 3 ? "    " : "\n");
    }
    if (index % 3)
        out_ << '\n';
}

void Debugger::help(std::ostream& out) {
    out << "load <program> [args...]       launch and stop at ELF entry\n"
        << "break <hex-address|symbol>     install INT3 (@name forces symbol lookup)\n"
        << "breakrva <hex-offset>          breakpoint relative to mapped image base\n"
        << "delete <decimal-id>            restore byte and remove breakpoint\n"
        << "si|cont|syscall [signal|0]      resume, forwarding pending signal by default\n"
        << "info reg|break|maps|threads|watch|environment inspect debugger state\n"
        << "disasm [hex-address]           decode up to five instructions\n"
        << "patch <hex-address> <hexbytes>  replace executable bytes (max 1024)\n"
        << "attach <pid> / detach         trace/release an existing process\n"
        << "thread <tid>                  select a stopped Linux task\n"
        << "watch|awatch <address> [size]  hardware write/access watch (1/2/4/8 bytes)\n"
        << "delete watch <id>             remove a hardware watchpoint\n"
        << "x[/count] <address|@symbol>    examine 1..4096 bytes (default 16)\n"
        << "write <address|@symbol> <hexbytes> replace writable data bytes\n"
        << "register read [name]          read general-purpose registers\n"
        << "register write <name> <value>  value is decimal or 0x-prefixed hex\n"
        << "bt [max-frames]               bounded frame-pointer backtrace (1..64)\n"
        << "restart                       relaunch last owned program; clear breakpoints\n"
        << "set disassemble on|off        automatic disassembly on stops\n"
        << "history                       show up to 256 recent commands\n"
        << "help                          show commands\n"
        << "q                             clean up owned/attached process and quit\n";
}

bool Debugger::execute(const std::string& line) {
    auto words = parse_command(line);
    if (words.empty())
        return true;
    if (history_.size() == 256)
        history_.erase(history_.begin());
    history_.push_back(line);
    bool finished = refresh();
    if (finished && words.size() == 1 &&
        (words[0] == "cont" || words[0] == "si" || words[0] == "syscall"))
        return true;
    try {
        return execute_command(words);
    } catch (const std::system_error& error) {
        if (error.code().value() == ESRCH) {
            // A SIGKILL can race the nonblocking poll. Reconcile the actual wait
            // status; if it is not available yet, end the session safely.
            if (!refresh())
                terminate();
        }
        throw;
    } catch (...) {
        if (tracee_.state() == ProcessState::Exited)
            reset_image();
        throw;
    }
}

bool Debugger::execute_command(const std::vector<std::string>& words) {
    const auto& cmd = words[0];
    if (cmd == "help") {
        arity(words, 1, 1, "help");
        help(out_);
    } else if (cmd == "q" || cmd == "quit") {
        arity(words, 1, 1, "q");
        shutdown();
        return false;
    } else if (cmd == "attach") {
        arity(words, 2, 2, "attach <decimal-pid>");
        const auto pid = parse_unsigned(words[1], 10);
        if (pid > static_cast<uint64_t>(std::numeric_limits<pid_t>::max()))
            throw std::runtime_error("PID out of range");
        attach(static_cast<pid_t>(pid));
    } else if (cmd == "detach") {
        arity(words, 1, 1, "detach");
        detach();
    } else if (cmd == "restart") {
        arity(words, 1, 1, "restart");
        if (tracee_.attached())
            throw std::runtime_error("detach the attached process before restart");
        if (last_arguments_.empty())
            throw std::runtime_error("no previous program to restart");
        const auto args = last_arguments_;
        terminate();
        load(args);
    } else if (cmd == "load") {
        arity(words, 2, std::numeric_limits<size_t>::max(), "load <program> [arguments...]");
        load({words.begin() + 1, words.end()});
    } else if (cmd == "si" || cmd == "cont" || cmd == "syscall") {
        arity(words, 1, 2, "si|cont|syscall [signal-name|signal-number|0]");
        std::optional<int> signal;
        if (words.size() == 2)
            signal = parse_signal(words[1]);
        resume(cmd == "si"     ? ResumeMode::SingleStep
               : cmd == "cont" ? ResumeMode::Continue
                               : ResumeMode::Syscall,
               signal);
    } else if (cmd == "break" || cmd == "breakrva") {
        arity(words, 2, 2, "break <address|symbol> OR breakrva <offset>");
        tracee_.require_stopped();
        auto address = cmd == "break"
                           ? resolve_breakpoint(words[1])
                           : checked_add(image_->image_base(bias_), parse_unsigned(words[1]));
        if (breakpoints_.find(address)) {
            out_ << "** breakpoint already exists.\n";
            return true;
        }
        const auto& bp = breakpoints_.add(address);
        out_ << "** set a breakpoint at 0x" << std::hex << address << std::dec << ". id " << bp.id
             << ".\n";
    } else if (cmd == "delete") {
        arity(words, 2, 3, "delete <decimal-id> OR delete watch <decimal-id>");
        tracee_.require_stopped();
        if (words.size() == 3) {
            if (words[1] != "watch")
                throw std::runtime_error("usage: delete watch <decimal-id>");
            const auto id = parse_unsigned(words[2], 10);
            watchpoints_.remove(id);
            out_ << "** delete watchpoint " << id << ".\n";
            return true;
        }
        auto id = parse_unsigned(words[1], 10);
        breakpoints_.remove(id);
        out_ << "** delete breakpoint " << id << ".\n";
    } else if (cmd == "watch" || cmd == "awatch" || cmd == "rwatch") {
        arity(words, 2, 3, "watch|awatch <address|@symbol> [1|2|4|8]");
        if (cmd == "rwatch")
            throw std::runtime_error(
                "x86-64 has no read-only hardware watchpoint; use awatch for read/write access");
        const auto length = words.size() == 3 ? parse_unsigned(words[2], 10) : 1;
        if (length != 1 && length != 2 && length != 4 && length != 8)
            throw std::runtime_error("watchpoint length must be 1, 2, 4, or 8 bytes");
        const auto& watch =
            watchpoints_.add(resolve_address(words[1]), static_cast<unsigned>(length),
                             cmd == "watch" ? WatchAccess::Write : WatchAccess::ReadWrite);
        out_ << "** set watchpoint " << watch.id << " at 0x" << std::hex << watch.address
             << std::dec << " size " << watch.length << ".\n";
    } else if (cmd == "thread") {
        arity(words, 2, 2, "thread <decimal-tid>");
        const auto tid = parse_unsigned(words[1], 10);
        if (tid > static_cast<uint64_t>(std::numeric_limits<pid_t>::max()) || tid == 0)
            throw std::runtime_error("thread ID out of range");
        tracee_.select_thread(static_cast<pid_t>(tid));
        out_ << "** selected thread " << tid << ".\n";
    } else if (cmd == "x" || cmd.rfind("x/", 0) == 0) {
        arity(words, 2, 2, "x[/count] <address|@symbol>");
        const auto count = cmd == "x" ? 16 : parse_unsigned(cmd.substr(2), 10);
        if (count == 0 || count > 4096)
            throw std::runtime_error("examine count must be 1..4096");
        const auto address = resolve_address(words[1]);
        auto bytes = memory_.read(address, static_cast<size_t>(count));
        breakpoints_.overlay(address, bytes);
        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i % 16 == 0)
                out_ << "0x" << std::hex << address + i << ":";
            out_ << ' ' << std::hex << std::setw(2) << std::setfill('0') << unsigned(bytes[i]);
            if (i % 16 == 15 || i + 1 == bytes.size())
                out_ << '\n';
        }
        out_ << std::setfill(' ') << std::dec;
    } else if (cmd == "write") {
        arity(words, 3, 3, "write <address|@symbol> <hexbytes>");
        const auto address = resolve_address(words[1]);
        breakpoints_.patch(address, parse_bytes(words[2]), false);
        out_ << "** wrote memory at 0x" << std::hex << address << std::dec << ".\n";
    } else if (cmd == "register") {
        arity(words, 2, 4, "register read [name] OR register write <name> <value>");
        if (words[1] == "read") {
            arity(words, 2, 3, "register read [name]");
            if (words.size() == 2)
                print_registers();
            else {
                const auto value = RegisterFile::read(tracee_, words[2]);
                out_ << '$' << words[2] << " 0x" << std::hex << value << std::dec << '\n';
            }
        } else if (words[1] == "write") {
            arity(words, 4, 4, "register write <name> <decimal|0xhex>");
            const auto& value = words[3];
            RegisterFile::write(
                tracee_, words[2],
                parse_unsigned(value,
                               value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0 ? 16 : 10));
            out_ << "** wrote register " << words[2] << ".\n";
        } else
            throw std::runtime_error(
                "usage: register read [name] OR register write <name> <value>");
    } else if (cmd == "bt") {
        arity(words, 1, 2, "bt [max-frames]");
        const auto maximum = words.size() == 2 ? parse_unsigned(words[1], 10) : 32;
        if (maximum == 0 || maximum > 64)
            throw std::runtime_error("backtrace frame limit must be 1..64");
        const auto result =
            collect_backtrace(tracee_, memory_, image_.get(), bias_, static_cast<size_t>(maximum));
        for (size_t i = 0; i < result.frames.size(); ++i)
            out_ << '#' << i << " 0x" << std::hex << result.frames[i].address << std::dec << ' '
                 << result.frames[i].symbol << '\n';
        out_ << "** backtrace stopped: " << result.stop_reason << ".\n"
             << "** requires established frame pointers; prologue/epilogue, omitted frames, and "
                "signal frames may omit callers.\n";
    } else if (cmd == "history") {
        arity(words, 1, 1, "history");
        for (size_t i = 0; i < history_.size(); ++i)
            out_ << i + 1 << "  " << history_[i] << '\n';
    } else if (cmd == "set") {
        arity(words, 3, 3, "set disassemble on|off");
        if (words[1] != "disassemble" || (words[2] != "on" && words[2] != "off"))
            throw std::runtime_error("usage: set disassemble on|off");
        automatic_disassembly_ = words[2] == "on";
        out_ << "** automatic disassembly " << words[2] << ".\n";
    } else if (cmd == "patch") {
        arity(words, 3, 3, "patch <hex-address> <hexbytes>");
        tracee_.require_stopped();
        auto address = parse_unsigned(words[1]);
        breakpoints_.patch(address, parse_bytes(words[2]));
        out_ << "** patch memory at 0x" << std::hex << address << std::dec << ".\n";
    } else if (cmd == "disasm") {
        arity(words, 1, 2, "disasm [hex-address]");
        tracee_.require_stopped();
        auto address = words.size() == 2 ? parse_unsigned(words[1]) : tracee_.regs().rip;
        disassembler_.print(memory_, breakpoints_, address, out_);
    } else if (cmd == "info") {
        arity(words, 2, 2, "info reg|break|maps|threads|watch|environment");
        if (words[1] == "reg")
            print_registers();
        else if (words[1] == "break") {
            if (breakpoints_.all().empty())
                out_ << "** no breakpoints.\n";
            else
                out_ << "Num     Address\n";
            for (const auto& [address, bp] : breakpoints_.all())
                if (!bp.temporary)
                    out_ << bp.id << "\t0x" << std::hex << address << std::dec << '\n';
        } else if (words[1] == "environment") {
            out_ << "watchpoint single-step: "
                 << (Tracee::tcg_watch_step_guard() ? "unavailable (QEMU TCG)" : "enabled") << '\n';
        } else if (words[1] == "threads") {
            tracee_.require_stopped();
            out_ << "TID State\n";
            for (pid_t tid : tracee_.threads())
                out_ << (tid == tracee_.tid() ? "* " : "  ") << tid << " stopped\n";
        } else if (words[1] == "watch") {
            out_ << "Num Address Size Mode\n";
            for (const auto& [id, watch] : watchpoints_.all())
                out_ << id << " 0x" << std::hex << watch.address << std::dec << ' ' << watch.length
                     << ' ' << (watch.access == WatchAccess::Write ? "write" : "access") << '\n';
        } else if (words[1] == "maps") {
            for (const auto& region : memory_.mappings())
                out_ << "0x" << std::hex << region.start << "-0x" << region.end << std::dec << ' '
                     << (region.readable ? 'r' : '-') << (region.writable ? 'w' : '-')
                     << (region.executable ? 'x' : '-') << '\n';
        } else
            throw std::runtime_error("usage: info reg|break|maps|threads|watch|environment");
    } else
        throw std::runtime_error("unknown command: " + cmd);
    return true;
}
} // namespace sdb
