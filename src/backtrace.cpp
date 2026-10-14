#include "sdb/backtrace.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace sdb {

BacktraceResult collect_backtrace(const Tracee& tracee, const Memory& memory, const ElfImage* image,
                                  std::uint64_t bias, std::size_t max_frames) {
    if (max_frames == 0 || max_frames > 64) {
        throw std::invalid_argument("backtrace frame count must be between 1 and 64");
    }
    const auto registers = tracee.regs();
    BacktraceResult result;
    result.frames.push_back(
        {registers.rip, image ? image->describe_address(registers.rip, bias) : std::string{}});
    const auto regions = memory.mappings();
    const auto stack = std::find_if(regions.begin(), regions.end(), [&](const Region& region) {
        return region.readable && region.writable && registers.rsp >= region.start &&
               registers.rsp < region.end;
    });
    if (stack == regions.end()) {
        result.stop_reason = "RSP is not in a readable, writable stack mapping";
        return result;
    }
    auto frame = static_cast<std::uint64_t>(registers.rbp);
    while (result.frames.size() < max_frames) {
        if (frame == 0) {
            result.stop_reason = "end of frame-pointer chain";
            return result;
        }
        if (frame % alignof(std::uint64_t) != 0 || frame < registers.rsp) {
            result.stop_reason = "unaligned frame pointer or frame below RSP";
            return result;
        }
        if (frame < stack->start || frame >= stack->end || stack->end - frame < 16) {
            result.stop_reason = "frame record leaves the current stack mapping";
            return result;
        }
        std::vector<std::uint8_t> record;
        try {
            record = memory.read(frame, 16);
        } catch (const std::exception& error) {
            result.stop_reason = std::string("unreadable frame record: ") + error.what();
            return result;
        }
        std::uint64_t next = 0, address = 0;
        std::memcpy(&next, record.data(), sizeof(next));
        std::memcpy(&address, record.data() + sizeof(next), sizeof(address));
        if (address == 0) {
            result.stop_reason = "null return address";
            return result;
        }
        const bool executable =
            std::any_of(regions.begin(), regions.end(), [&](const Region& region) {
                return region.executable && address - 1 >= region.start && address - 1 < region.end;
            });
        if (!executable) {
            result.stop_reason = "return address is outside executable mappings";
            return result;
        }
        result.frames.push_back(
            {address, image ? image->describe_address(address - 1, bias) : std::string{}});
        if (next != 0 && next <= frame) {
            result.stop_reason = "non-increasing frame-pointer chain";
            return result;
        }
        frame = next;
    }
    result.stop_reason = "frame limit reached";
    return result;
}

} // namespace sdb
