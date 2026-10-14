#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <sys/types.h>
#include <vector>

namespace sdb {

// Metadata for the main executable. ELF virtual addresses and runtime addresses
// stay separate: runtime = ELF virtual address + the process's load bias.
class ElfImage {
  public:
    explicit ElfImage(const std::string& path);
    // Open the procfs magic link itself, even if the executable was unlinked,
    // replaced at its pathname, or created through memfd_create/fexecve.
    static ElfImage from_tracee(pid_t tid);

    // The source used for opening metadata, not necessarily a launchable path.
    const std::string& path() const noexcept { return path_; }
    const std::string& display_name() const noexcept { return display_name_; }
    std::uint64_t entry() const noexcept { return entry_; }
    bool is_pie() const noexcept { return pie_; }
    bool has_static_symbols() const noexcept { return has_static_symbols_; }

    std::uint64_t load_bias(pid_t pid) const;
    std::uint64_t runtime_address(std::uint64_t elf_va, std::uint64_t bias) const;
    std::uint64_t symbol_address(const std::string& name, std::uint64_t bias) const;
    // Defined non-TLS data symbols, for memory inspection and watchpoints.
    std::uint64_t object_address(const std::string& name, std::uint64_t bias) const;
    // Function symbol + hexadecimal offset, or empty when no containing
    // function is known. A zero-size assembly symbol matches only its address.
    std::string describe_address(std::uint64_t runtime, std::uint64_t bias) const;
    // Legacy breakrva offsets are relative to the lowest mapped PT_LOAD page,
    // including for ET_EXEC, whose load bias is zero but image base is not.
    std::uint64_t image_base(std::uint64_t bias) const;

  private:
    enum class SourceKind { FilePath, TraceeExecutable };
    ElfImage(const std::string& path, SourceKind source);

    struct Segment {
        std::uint64_t offset;
        std::uint64_t address;
        std::uint64_t file_size;
        std::uint64_t memory_size;
        std::uint32_t flags;
    };
    struct Symbol {
        std::uint64_t value;
        std::uint64_t size;
        bool executable;
        bool object;
    };

    bool executable_address(std::uint64_t address) const noexcept;
    std::uint64_t resolve_symbol(const std::string& name, std::uint64_t bias, bool object) const;

    std::string path_;
    std::string display_name_;
    std::uint64_t entry_ = 0;
    std::uint64_t page_size_ = 0;
    std::uint64_t image_base_ = 0;
    std::uint64_t inode_ = 0;
    unsigned int device_major_ = 0;
    unsigned int device_minor_ = 0;
    bool pie_ = false;
    bool has_static_symbols_ = false;
    std::vector<Segment> segments_;
    std::map<std::string, std::vector<Symbol>> symbols_;
};

} // namespace sdb
