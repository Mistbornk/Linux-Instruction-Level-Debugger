#pragma once
#include "sdb/memory.hpp"
#include <elf.h>
#include <string>
namespace sdb {
// Only entry-point relocation in this stage: deliberately no symbol lookup.
class ElfImage {
public:
  explicit ElfImage(const std::string &path);
  uint64_t entry(const Memory &memory) const;
  uint64_t base(const Memory &memory) const;

private:
  uint64_t bias(const Memory &memory) const;
  Elf64_Ehdr header_{};
  std::vector<Elf64_Phdr> segments_;
  uint64_t inode_ = 0, first_page_ = 0, page_size_ = 0;
  unsigned major_ = 0, minor_ = 0;
};
} // namespace sdb
