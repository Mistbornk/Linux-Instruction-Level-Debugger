#pragma once

#include "sdb/elf_image.hpp"
#include "sdb/memory.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sdb {

struct StackFrame {
    std::uint64_t address;
    std::string symbol;
};

struct BacktraceResult {
    std::vector<StackFrame> frames;
    std::string stop_reason;
};

// Walk only aligned, increasing RBP records in the readable/writable VMA
// containing RSP. Frame 0 is the current RIP; subsequent addresses are saved
// return addresses, annotated at address-1 to identify the calling function.
// Requires established frame pointers: prologue/epilogue stops, optimized frame
// omission, tail calls, alternate stacks and signal frames are not unwound.
BacktraceResult collect_backtrace(const Tracee& tracee, const Memory& memory,
                                  const ElfImage* image = nullptr, std::uint64_t bias = 0,
                                  std::size_t max_frames = 32);

} // namespace sdb
