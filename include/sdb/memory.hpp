#pragma once

#include "sdb/tracee.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace sdb {

struct Region {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    bool executable = false;
    bool readable = false;
    bool writable = false;
    std::uint64_t offset = 0;
    std::string device;
    std::uint64_t inode = 0;
    std::string path;
};

// A failed rollback means the controller must terminate the session; continuing
// could execute bytes that no longer agree with its breakpoint bookkeeping.
class MemoryCorruption : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

class Memory {
  public:
    explicit Memory(const Tracee& tracee) : tracee_(tracee) {}

    std::vector<Region> mappings() const;
    std::optional<std::uint64_t> executable_end(std::uint64_t address) const;
    std::vector<std::uint8_t> read(std::uint64_t address, std::size_t size) const;
    std::vector<std::uint8_t> read_up_to(std::uint64_t address, std::size_t size) const;
    // Snapshot before mutation; on a partial write restore the written prefix.
    // Metadata may be committed only after this method returns successfully.
    void write(std::uint64_t address, const std::vector<std::uint8_t>& bytes) const;

  private:
    const Tracee& tracee_;
};

} // namespace sdb
