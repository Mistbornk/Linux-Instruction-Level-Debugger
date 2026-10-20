#pragma once
#include "sdb/tracee.hpp"
#include <stdexcept>
#include <vector>
namespace sdb {
struct Region {
  uint64_t start, end, offset, inode;
  unsigned device_major, device_minor;
  bool executable;
};
struct MemoryCorruption : std::runtime_error {
  using std::runtime_error::runtime_error;
};
class Memory {
public:
  explicit Memory(const Tracee &tracee) : tracee_(tracee) {}
  std::vector<Region> mappings() const;
  void require_executable(uint64_t address, size_t size) const;
  std::vector<uint8_t> read(uint64_t address, size_t size) const;
  std::vector<uint8_t> code(uint64_t address, size_t maximum) const;
  void write(uint64_t address, const std::vector<uint8_t> &bytes) const;

private:
  const Tracee &tracee_;
};
} // namespace sdb
