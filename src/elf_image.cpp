#include "sdb/elf_image.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
namespace sdb {
namespace {
uint64_t add(uint64_t a, uint64_t b) {
  if (b > UINT64_MAX - a)
    throw std::runtime_error("ELF address overflow");
  return a + b;
}
} // namespace
ElfImage::ElfImage(const std::string &path) {
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    throw std::runtime_error("cannot open ELF file");
  struct Guard {
    int fd;
    ~Guard() { close(fd); }
  } guard{fd};
  struct stat stat{};
  if (fstat(fd, &stat) < 0 || !S_ISREG(stat.st_mode) ||
      stat.st_size < static_cast<off_t>(sizeof(header_)))
    throw std::runtime_error("not a regular ELF file");
  auto read_at = [&](void *buffer, size_t size, uint64_t offset) {
    if (offset > static_cast<uint64_t>(stat.st_size) ||
        size > static_cast<uint64_t>(stat.st_size) - offset)
      throw std::runtime_error("truncated ELF file");
    size_t done = 0;
    while (done < size) {
      ssize_t n = pread(fd, static_cast<char *>(buffer) + done, size - done,
                        offset + done);
      if (n < 0 && errno == EINTR)
        continue;
      if (n <= 0)
        throw std::runtime_error("ELF read failed");
      done += static_cast<size_t>(n);
    }
  };
  read_at(&header_, sizeof(header_), 0);
  if (std::memcmp(header_.e_ident, ELFMAG, SELFMAG) ||
      header_.e_ident[EI_CLASS] != ELFCLASS64 ||
      header_.e_ident[EI_DATA] != ELFDATA2LSB ||
      header_.e_ident[EI_VERSION] != EV_CURRENT ||
      header_.e_version != EV_CURRENT || header_.e_machine != EM_X86_64 ||
      (header_.e_type != ET_EXEC && header_.e_type != ET_DYN) ||
      header_.e_ehsize != sizeof(header_) ||
      header_.e_phentsize != sizeof(Elf64_Phdr) || !header_.e_phnum ||
      header_.e_phnum == PN_XNUM)
    throw std::runtime_error(
        "unsupported or malformed ELF64 x86-64 executable");
  long page = sysconf(_SC_PAGESIZE);
  if (page <= 0)
    throw std::runtime_error("cannot determine page size");
  page_size_ = static_cast<uint64_t>(page);
  std::vector<Elf64_Phdr> headers(header_.e_phnum);
  read_at(headers.data(), headers.size() * sizeof(Elf64_Phdr), header_.e_phoff);
  first_page_ = UINT64_MAX;
  bool entry_is_code = false;
  for (const auto &segment : headers) {
    if (segment.p_type != PT_LOAD)
      continue;
    if (segment.p_filesz > segment.p_memsz ||
        segment.p_offset > static_cast<uint64_t>(stat.st_size) ||
        segment.p_filesz >
            static_cast<uint64_t>(stat.st_size) - segment.p_offset ||
        segment.p_vaddr % page_size_ != segment.p_offset % page_size_)
      throw std::runtime_error("invalid ELF load segment");
    uint64_t end = add(segment.p_vaddr, segment.p_memsz);
    if ((segment.p_flags & PF_X) && header_.e_entry >= segment.p_vaddr &&
        header_.e_entry < end)
      entry_is_code = true;
    first_page_ =
        std::min(first_page_, segment.p_vaddr - segment.p_vaddr % page_size_);
    segments_.push_back(segment);
  }
  if (!entry_is_code)
    throw std::runtime_error("ELF entry is outside executable segments");
  inode_ = stat.st_ino;
  major_ = major(stat.st_dev);
  minor_ = minor(stat.st_dev);
}
uint64_t ElfImage::bias(const Memory &memory) const {
  const auto maps = memory.mappings();
  // Match file identity and executable PT_LOAD file pages, not path substrings.
  for (const auto &segment : segments_) {
    if (!(segment.p_flags & PF_X) || !segment.p_filesz)
      continue;
    uint64_t offset = segment.p_offset - segment.p_offset % page_size_;
    uint64_t address = segment.p_vaddr - segment.p_vaddr % page_size_;
    for (const auto &region : maps) {
      if (!region.executable || region.inode != inode_ ||
          region.device_major != major_ || region.device_minor != minor_ ||
          region.offset != offset || region.start < address)
        continue;
      uint64_t result = region.start - address;
      if (header_.e_type == ET_EXEC && result != 0)
        throw std::runtime_error("unexpected ET_EXEC load bias");
      return result;
    }
  }
  throw std::runtime_error("cannot match executable ELF load segment");
}
uint64_t ElfImage::entry(const Memory &memory) const {
  return add(bias(memory), header_.e_entry);
}
uint64_t ElfImage::base(const Memory &memory) const {
  return add(bias(memory), first_page_);
}
} // namespace sdb
