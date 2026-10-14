#include "sdb/register_file.hpp"

#include <algorithm>
#include <iterator>
#include <stdexcept>

namespace sdb {
namespace {

using RegisterMember = decltype(user_regs_struct::rax) user_regs_struct::*;
struct NamedRegister {
    const char* name;
    RegisterMember member;
};

constexpr NamedRegister registers[] = {{"rax", &user_regs_struct::rax},
                                       {"rbx", &user_regs_struct::rbx},
                                       {"rcx", &user_regs_struct::rcx},
                                       {"rdx", &user_regs_struct::rdx},
                                       {"rsi", &user_regs_struct::rsi},
                                       {"rdi", &user_regs_struct::rdi},
                                       {"rbp", &user_regs_struct::rbp},
                                       {"rsp", &user_regs_struct::rsp},
                                       {"r8", &user_regs_struct::r8},
                                       {"r9", &user_regs_struct::r9},
                                       {"r10", &user_regs_struct::r10},
                                       {"r11", &user_regs_struct::r11},
                                       {"r12", &user_regs_struct::r12},
                                       {"r13", &user_regs_struct::r13},
                                       {"r14", &user_regs_struct::r14},
                                       {"r15", &user_regs_struct::r15},
                                       {"rip", &user_regs_struct::rip},
                                       {"eflags", &user_regs_struct::eflags},
                                       {"orig_rax", &user_regs_struct::orig_rax},
                                       {"fs_base", &user_regs_struct::fs_base},
                                       {"gs_base", &user_regs_struct::gs_base},
                                       {"cs", &user_regs_struct::cs},
                                       {"ss", &user_regs_struct::ss},
                                       {"ds", &user_regs_struct::ds},
                                       {"es", &user_regs_struct::es},
                                       {"fs", &user_regs_struct::fs},
                                       {"gs", &user_regs_struct::gs}};

RegisterMember find(const std::string& name) {
    const std::string plain = !name.empty() && name.front() == '$' ? name.substr(1) : name;
    const auto found =
        std::find_if(std::begin(registers), std::end(registers),
                     [&](const NamedRegister& entry) { return plain == entry.name; });
    if (found == std::end(registers)) {
        throw std::invalid_argument("unknown x86-64 register: " + name +
                                    " (use full 64-bit names, e.g. rax or rip)");
    }
    return found->member;
}

} // namespace

std::uint64_t RegisterFile::get(const user_regs_struct& snapshot, const std::string& name) {
    return snapshot.*find(name);
}

void RegisterFile::set(user_regs_struct& snapshot, const std::string& name, std::uint64_t value) {
    snapshot.*find(name) = value;
}

std::uint64_t RegisterFile::read(const Tracee& tracee, const std::string& name) {
    const auto member = find(name);
    return tracee.regs().*member;
}

void RegisterFile::write(Tracee& tracee, const std::string& name, std::uint64_t value) {
    const auto member = find(name);
    auto snapshot = tracee.regs();
    snapshot.*member = value;
    tracee.set_regs(snapshot);
}

std::vector<std::pair<std::string, std::uint64_t>> RegisterFile::values(const Tracee& tracee) {
    const auto snapshot = tracee.regs();
    std::vector<std::pair<std::string, std::uint64_t>> result;
    result.reserve(std::size(registers));
    for (const auto& entry : registers)
        result.emplace_back(entry.name, snapshot.*(entry.member));
    return result;
}

} // namespace sdb
