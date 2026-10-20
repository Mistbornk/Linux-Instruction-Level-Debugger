#include "sdb/breakpoint.hpp"
#include <limits>
namespace sdb {
void BreakpointManager::add(uint64_t address) {
  memory_.require_executable(address, 1);
  if (points_.count(address))
    throw std::runtime_error("breakpoint already exists");
  if (next_id_ == std::numeric_limits<unsigned>::max())
    throw std::runtime_error("breakpoint IDs exhausted");
  uint8_t original = memory_.read(address, 1)[0];
  if (original == 0xcc)
    throw std::runtime_error("cannot replace a native INT3");
  // Allocate metadata before mutation, but publish only after successful write.
  auto item =
      points_.emplace(address, Breakpoint{next_id_, original, false}).first;
  try {
    memory_.write(address, {0xcc});
  } catch (...) {
    points_.erase(item);
    throw;
  }
  item->second.installed = true;
  ++next_id_;
}
bool BreakpointManager::installed(uint64_t address) const {
  auto it = points_.find(address);
  return it != points_.end() && it->second.installed;
}
void BreakpointManager::disable(uint64_t address) {
  auto &point = points_.at(address);
  if (point.installed) {
    memory_.write(address, {point.original});
    point.installed = false;
  }
}
void BreakpointManager::enable(uint64_t address) {
  auto &point = points_.at(address);
  if (!point.installed) {
    memory_.write(address, {0xcc});
    point.installed = true;
  }
}
void BreakpointManager::remove(unsigned id) {
  for (auto it = points_.begin(); it != points_.end(); ++it) {
    if (it->second.id != id)
      continue;
    disable(it->first);
    points_.erase(it);
    return;
  }
  throw std::runtime_error("breakpoint does not exist");
}
void BreakpointManager::overlay(uint64_t address,
                                std::vector<uint8_t> &bytes) const {
  for (const auto &[site, point] : points_) {
    if (site >= address && site - address < bytes.size())
      bytes[site - address] = point.original;
  }
}
void BreakpointManager::patch(uint64_t address,
                              const std::vector<uint8_t> &bytes) {
  memory_.require_executable(address, bytes.size());
  auto physical = bytes;
  for (const auto &[site, point] : points_) {
    if (site < address || site - address >= bytes.size())
      continue;
    if (bytes[site - address] == 0xcc)
      throw std::runtime_error(
          "cannot patch a breakpoint's original byte to INT3");
    if (point.installed)
      physical[site - address] = 0xcc;
  }
  memory_.write(address, physical);
  // Commit original-byte metadata only after the entire write succeeds.
  for (auto &[site, point] : points_) {
    if (site >= address && site - address < bytes.size())
      point.original = bytes[site - address];
  }
}
} // namespace sdb
