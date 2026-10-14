#include "sdb/disassembler.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
namespace sdb {
Disassembler::Disassembler() {
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle_) != CS_ERR_OK)
    throw std::runtime_error("cannot initialize Capstone");
}
Disassembler::~Disassembler() { cs_close(&handle_); }
void Disassembler::print(const Memory &memory, const BreakpointManager &points,
                         uint64_t address) const {
  auto code = memory.code(address, 5 * 15);
  points.overlay(address, code);
  cs_insn *instructions = nullptr;
  size_t count =
      cs_disasm(handle_, code.data(), code.size(), address, 5, &instructions);
  struct Guard {
    cs_insn *p;
    size_t n;
    ~Guard() { cs_free(p, n); }
  } guard{instructions, count};
  if (!count) {
    std::cout << "** no complete instruction available.\n";
    return;
  }
  for (size_t i = 0; i < count; ++i) {
    const auto &insn = instructions[i];
    std::ostringstream bytes;
    for (size_t j = 0; j < insn.size; ++j)
      bytes << std::hex << std::setfill('0') << std::setw(2)
            << unsigned(insn.bytes[j]) << ' ';
    std::cout << (i == 0 ? "=> " : "   ") << std::hex << insn.address << ": "
              << std::left << std::setw(45) << bytes.str() << std::setw(8)
              << insn.mnemonic << insn.op_str << std::right << std::dec << '\n';
  }
}
} // namespace sdb
