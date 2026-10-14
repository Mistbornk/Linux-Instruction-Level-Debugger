#include "sdb/disassembler.hpp"

#include <algorithm>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace sdb {
namespace {
struct Instructions {
    cs_insn* data = nullptr;
    size_t count = 0;
    ~Instructions() {
        if (data)
            cs_free(data, count);
    }
};

std::vector<uint8_t> code_bytes(const Memory& memory, const BreakpointManager& bp, uint64_t address,
                                size_t count) {
    auto end = memory.executable_end(address);
    if (!end)
        throw std::runtime_error("address is outside executable memory");
    auto bytes =
        memory.read_up_to(address, static_cast<size_t>(std::min<uint64_t>(count, *end - address)));
    bp.overlay(address, bytes);
    return bytes;
}
} // namespace

Disassembler::Disassembler() {
    auto result = cs_open(CS_ARCH_X86, CS_MODE_64, &handle_);
    if (result != CS_ERR_OK)
        throw std::runtime_error(std::string("Capstone: ") + cs_strerror(result));
}

Disassembler::~Disassembler() {
    if (handle_)
        cs_close(&handle_);
}

void Disassembler::print(const Memory& memory, const BreakpointManager& bp, uint64_t address,
                         std::ostream& out) const {
    auto code = code_bytes(memory, bp, address, 75); // at most five 15-byte x86 instructions
    Instructions instructions;
    instructions.count =
        cs_disasm(handle_, code.data(), code.size(), address, 5, &instructions.data);
    if (!instructions.count) {
        auto error = cs_errno(handle_);
        if (error != CS_ERR_OK)
            throw std::runtime_error(std::string("Capstone: ") + cs_strerror(error));
        out << "** no complete instruction at this address.\n";
    }
    for (size_t i = 0; i < instructions.count; ++i) {
        const auto& instruction = instructions.data[i];
        std::ostringstream bytes;
        for (size_t j = 0; j < instruction.size; ++j)
            bytes << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<unsigned>(instruction.bytes[j]) << ' ';
        out << (i ? "   " : "=> ") << "0x" << std::hex << instruction.address << ": " << std::left
            << std::setw(46) << std::setfill(' ') << bytes.str() << std::setw(8)
            << instruction.mnemonic << instruction.op_str << std::right << std::dec << '\n';
    }
}

bool Disassembler::is_syscall(const Memory& memory, const BreakpointManager& bp,
                              uint64_t address) const {
    auto code = code_bytes(memory, bp, address, 15);
    Instructions instructions;
    instructions.count =
        cs_disasm(handle_, code.data(), code.size(), address, 1, &instructions.data);
    if (!instructions.count) {
        auto error = cs_errno(handle_);
        if (error != CS_ERR_OK)
            throw std::runtime_error(std::string("Capstone: ") + cs_strerror(error));
        return false;
    }
    // Native x86-64 only; compat-mode int 0x80/sysenter tracing isn't supported.
    return instructions.data[0].id == X86_INS_SYSCALL;
}
} // namespace sdb
