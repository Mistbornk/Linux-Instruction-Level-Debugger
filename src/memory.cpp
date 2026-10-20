#include "sdb/memory.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <sstream>
#include <unistd.h>
namespace sdb {
namespace {
struct Descriptor {
  int fd;
  Descriptor(pid_t pid, int flags)
      : fd(open(("/proc/" + std::to_string(pid) + "/mem").c_str(),
                flags | O_CLOEXEC)) {
    if (fd < 0)
      throw std::runtime_error("open memory: " +
                               std::string(std::strerror(errno)));
  }
  ~Descriptor() { close(fd); }
};
void range(uint64_t address, size_t size) {
  if (!size ||
      address > static_cast<uint64_t>(std::numeric_limits<off_t>::max()) ||
      size - 1 >
          static_cast<uint64_t>(std::numeric_limits<off_t>::max()) - address)
    throw std::runtime_error("invalid memory range");
}
void write_all(int fd, uint64_t address, const std::vector<uint8_t> &bytes) {
  size_t done = 0;
  while (done < bytes.size()) {
    ssize_t n =
        pwrite(fd, bytes.data() + done, bytes.size() - done, address + done);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      throw std::runtime_error("memory write failed");
    done += static_cast<size_t>(n);
  }
}
} // namespace
std::vector<Region> Memory::mappings() const {
  tracee_.require_stopped();
  std::ifstream file("/proc/" + std::to_string(tracee_.pid()) + "/maps");
  if (!file)
    throw std::runtime_error("cannot read process mappings");
  std::vector<Region> result;
  std::string line;
  while (std::getline(file, line)) {
    Region region{};
    char dash, colon;
    std::string perms;
    std::istringstream stream(line);
    if (!(stream >> std::hex >> region.start >> dash >> region.end >> perms >>
          region.offset >> region.device_major >> colon >>
          region.device_minor >> std::dec >> region.inode) ||
        dash != '-' || colon != ':' || region.start >= region.end ||
        perms.size() < 3)
      throw std::runtime_error("malformed process mapping");
    region.executable = perms[2] == 'x';
    result.push_back(region);
  }
  if (file.bad())
    throw std::runtime_error("process mapping read failed");
  return result;
}
void Memory::require_executable(uint64_t address, size_t size) const {
  range(address, size);
  uint64_t cursor = address;
  const uint64_t end = address + size;
  for (const auto &region : mappings()) {
    if (cursor < region.start)
      break;
    if (cursor >= region.end)
      continue;
    if (!region.executable)
      break;
    cursor = std::min(end, region.end);
    if (cursor == end)
      return;
  }
  throw std::runtime_error("the target address is outside executable memory");
}
std::vector<uint8_t> Memory::read(uint64_t address, size_t size) const {
  tracee_.require_stopped();
  range(address, size);
  Descriptor fd(tracee_.pid(), O_RDONLY);
  std::vector<uint8_t> bytes(size);
  size_t done = 0;
  while (done < size) {
    ssize_t n = pread(fd.fd, bytes.data() + done, size - done, address + done);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      throw std::runtime_error("memory read failed");
    done += static_cast<size_t>(n);
  }
  return bytes;
}
std::vector<uint8_t> Memory::code(uint64_t address, size_t maximum) const {
  for (const auto &region : mappings()) {
    if (region.executable && address >= region.start && address < region.end)
      return read(address, std::min<uint64_t>(maximum, region.end - address));
  }
  throw std::runtime_error("the target address is outside executable memory");
}
void Memory::write(uint64_t address, const std::vector<uint8_t> &bytes) const {
  auto original = read(address, bytes.size());
  Descriptor fd(tracee_.pid(), O_RDWR);
  try {
    write_all(fd.fd, address, bytes);
  } catch (...) {
    try {
      write_all(fd.fd, address, original);
    } catch (...) {
      throw MemoryCorruption("memory rollback failed; session must terminate");
    }
    throw;
  }
}
} // namespace sdb
