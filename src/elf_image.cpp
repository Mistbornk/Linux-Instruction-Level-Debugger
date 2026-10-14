#include "sdb/elf_image.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace sdb {
namespace {

[[noreturn]] void invalid(const std::string& detail) {
    throw std::runtime_error("invalid or unsupported ELF: " + detail);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::runtime_error("ELF address or size overflow");
    }
    return left + right;
}

bool power_of_two(std::uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

// pread avoids struct pointer casts into untrusted buffers. Every read is bounded
// by the fstat size and checked again for a short read (including file changes).
class ElfFile {
  public:
    explicit ElfFile(const std::string& path) {
        // A user-supplied FIFO must not block before fstat can reject it.
        // O_NONBLOCK has no effect on reads from a regular executable file.
        fd_ = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd_ == -1) {
            throw std::runtime_error("open ELF: " + std::string(std::strerror(errno)));
        }
        if (fstat(fd_, &stat_) == -1) {
            const int error = errno;
            close_descriptor();
            throw std::runtime_error("stat ELF: " + std::string(std::strerror(error)));
        }
        if (!S_ISREG(stat_.st_mode) || stat_.st_size < 0) {
            close_descriptor();
            throw std::runtime_error("ELF path must name a regular file");
        }
        size_ = static_cast<std::uint64_t>(stat_.st_size);
    }
    ~ElfFile() { close_descriptor(); }
    ElfFile(const ElfFile&) = delete;
    ElfFile& operator=(const ElfFile&) = delete;

    const struct stat& metadata() const noexcept { return stat_; }

    void range(std::uint64_t offset, std::uint64_t size) const {
        if (offset > size_ || size > size_ - offset) {
            invalid("file range is out of bounds");
        }
    }

    void table(std::uint64_t offset, std::uint64_t count, std::uint64_t stride) const {
        if (stride == 0 || offset > size_ || count > (size_ - offset) / stride) {
            invalid("header table is out of bounds");
        }
    }

    template <typename T> T object(std::uint64_t offset) const {
        T value{};
        read(offset, &value, sizeof(value));
        return value;
    }

    std::vector<char> bytes(std::uint64_t offset, std::uint64_t size) const {
        range(offset, size);
        if (size > std::numeric_limits<std::size_t>::max()) {
            invalid("string table is too large");
        }
        std::vector<char> data(static_cast<std::size_t>(size));
        read(offset, data.data(), data.size());
        return data;
    }

  private:
    void close_descriptor() const noexcept {
        // Linux releases the descriptor even if close reports EINTR: do not
        // retry, which could close an unrelated reused descriptor.
        if (close(fd_) == -1) {
            std::fprintf(stderr, "sdb: close ELF failed (errno %d)\n", errno);
        }
    }

    void read(std::uint64_t offset, void* buffer, std::size_t size) const {
        range(offset, size);
        auto* output = static_cast<char*>(buffer);
        std::size_t done = 0;
        while (done != size) {
            const auto chunk = std::min(
                size - done, static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
            const ssize_t count =
                pread(fd_, output + done, chunk, static_cast<off_t>(offset + done));
            if (count == -1 && errno == EINTR) {
                continue;
            }
            if (count == -1) {
                throw std::runtime_error("read ELF: " + std::string(std::strerror(errno)));
            }
            if (count == 0) {
                invalid("truncated file while reading");
            }
            done += static_cast<std::size_t>(count);
        }
    }

    int fd_ = -1;
    struct stat stat_{};
    std::uint64_t size_ = 0;
};

std::string string_at(const std::vector<char>& strings, std::uint32_t index) {
    if (index >= strings.size()) {
        invalid("symbol name index is out of bounds");
    }
    const char* start = strings.data() + index;
    const auto* end = static_cast<const char*>(std::memchr(start, '\0', strings.size() - index));
    if (end == nullptr) {
        invalid("unterminated symbol name");
    }
    return std::string(start, end);
}

std::uint64_t number(const std::string& text, int base) {
    std::uint64_t value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (text.empty() || result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::runtime_error("malformed /proc maps number");
    }
    return value;
}

struct Mapping {
    std::uint64_t start;
    std::uint64_t end;
    std::uint64_t offset;
};

} // namespace

ElfImage::ElfImage(const std::string& path) : ElfImage(path, SourceKind::FilePath) {}

ElfImage ElfImage::from_tracee(pid_t tid) {
    if (tid <= 0)
        throw std::invalid_argument("cannot read executable image for an invalid TID");
    return ElfImage("/proc/" + std::to_string(tid) + "/exe", SourceKind::TraceeExecutable);
}

ElfImage::ElfImage(const std::string& path, SourceKind source) {
    if (path.find('\0') != std::string::npos) {
        throw std::runtime_error("executable path cannot contain NUL bytes");
    }
    if (source == SourceKind::FilePath) {
        std::unique_ptr<char, decltype(&std::free)> canonical(realpath(path.c_str(), nullptr),
                                                              &std::free);
        if (!canonical) {
            throw std::runtime_error("resolve executable path: " +
                                     std::string(std::strerror(errno)));
        }
        path_ = canonical.get();
    } else {
        path_ = path;
    }
    // Both identity and bytes come from this one open descriptor. A procfs
    // link's display target may no longer exist and must never be reopened.
    ElfFile file(path_);
    display_name_ = path_;
    if (source == SourceKind::TraceeExecutable) {
        std::error_code error;
        const auto label = std::filesystem::read_symlink(path_, error);
        if (!error)
            display_name_ = label.string();
    }
    inode_ = static_cast<std::uint64_t>(file.metadata().st_ino);
    device_major_ = major(file.metadata().st_dev);
    device_minor_ = minor(file.metadata().st_dev);
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || !power_of_two(static_cast<std::uint64_t>(page_size))) {
        throw std::runtime_error("cannot determine Linux page size");
    }
    page_size_ = static_cast<std::uint64_t>(page_size);

    const auto header = file.object<Elf64_Ehdr>(0);
    if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) {
        invalid("bad ELF magic");
    }
    if (header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_machine != EM_X86_64 || header.e_ident[EI_VERSION] != EV_CURRENT ||
        header.e_version != EV_CURRENT || header.e_ehsize != sizeof(Elf64_Ehdr)) {
        invalid("expected ELF64 little-endian x86-64 version 1");
    }
    if (header.e_type != ET_EXEC && header.e_type != ET_DYN) {
        invalid("expected ET_EXEC or ET_DYN");
    }
    pie_ = header.e_type == ET_DYN;
    entry_ = header.e_entry;

    std::uint64_t section_count = header.e_shnum;
    std::uint64_t program_count = header.e_phnum;
    std::uint64_t name_section = header.e_shstrndx;
    if (header.e_shoff == 0) {
        if (section_count != 0 || name_section != SHN_UNDEF || program_count == PN_XNUM) {
            invalid("missing section header table");
        }
    } else {
        if (header.e_shentsize != sizeof(Elf64_Shdr)) {
            invalid("unexpected section header size");
        }
        const auto first = file.object<Elf64_Shdr>(header.e_shoff);
        if (first.sh_type != SHT_NULL) {
            invalid("section zero must be SHT_NULL");
        }
        if (section_count == 0)
            section_count = first.sh_size;
        if (program_count == PN_XNUM)
            program_count = first.sh_info;
        if (name_section == SHN_XINDEX)
            name_section = first.sh_link;
        if (section_count == 0)
            invalid("empty section header table");
        file.table(header.e_shoff, section_count, sizeof(Elf64_Shdr));
    }
    if (program_count == 0 || header.e_phentsize != sizeof(Elf64_Phdr) || header.e_phoff == 0) {
        invalid("missing or unsupported program header table");
    }
    file.table(header.e_phoff, program_count, sizeof(Elf64_Phdr));
    image_base_ = std::numeric_limits<std::uint64_t>::max();
    for (std::uint64_t i = 0; i < program_count; ++i) {
        const auto program = file.object<Elf64_Phdr>(header.e_phoff + i * sizeof(Elf64_Phdr));
        if (program.p_type != PT_LOAD)
            continue;
        file.range(program.p_offset, program.p_filesz);
        checked_add(program.p_vaddr, program.p_memsz);
        if (program.p_filesz > program.p_memsz ||
            program.p_vaddr % page_size_ != program.p_offset % page_size_ ||
            (program.p_align > 1 &&
             (!power_of_two(program.p_align) ||
              program.p_vaddr % program.p_align != program.p_offset % program.p_align))) {
            invalid("invalid PT_LOAD size or alignment");
        }
        if (program.p_memsz == 0)
            continue;
        segments_.push_back({program.p_offset, program.p_vaddr, program.p_filesz, program.p_memsz,
                             program.p_flags});
        image_base_ = std::min(image_base_, program.p_vaddr - program.p_vaddr % page_size_);
    }
    if (segments_.empty() || !executable_address(entry_)) {
        invalid("entry point is not in an executable PT_LOAD segment");
    }

    std::vector<Elf64_Shdr> sections;
    for (std::uint64_t i = 0; i < section_count; ++i) {
        const auto section = file.object<Elf64_Shdr>(header.e_shoff + i * sizeof(Elf64_Shdr));
        if (section.sh_type != SHT_NULL && section.sh_type != SHT_NOBITS) {
            file.range(section.sh_offset, section.sh_size);
        }
        if (section.sh_type != SHT_NULL) {
            checked_add(section.sh_addr, section.sh_size);
            if (section.sh_addralign > 1 && !power_of_two(section.sh_addralign)) {
                invalid("invalid section alignment");
            }
        }
        sections.push_back(section);
    }
    if (name_section != SHN_UNDEF &&
        (name_section >= sections.size() || sections[name_section].sh_type != SHT_STRTAB)) {
        invalid("invalid section name string table");
    }

    for (std::size_t table_index = 0; table_index < sections.size(); ++table_index) {
        const auto& table = sections[table_index];
        if (table.sh_type != SHT_SYMTAB && table.sh_type != SHT_DYNSYM)
            continue;
        has_static_symbols_ = has_static_symbols_ || table.sh_type == SHT_SYMTAB;
        if (table.sh_entsize != sizeof(Elf64_Sym) || table.sh_size % sizeof(Elf64_Sym) != 0 ||
            table.sh_link >= sections.size() || sections[table.sh_link].sh_type != SHT_STRTAB) {
            invalid("invalid symbol table or linked string table");
        }
        const auto& string_section = sections[table.sh_link];
        const auto strings = file.bytes(string_section.sh_offset, string_section.sh_size);
        const auto symbol_count = table.sh_size / sizeof(Elf64_Sym);
        std::optional<Elf64_Shdr> extended_indexes;
        for (const auto& section : sections) {
            if (section.sh_type == SHT_SYMTAB_SHNDX && section.sh_link == table_index) {
                if (extended_indexes || section.sh_entsize != sizeof(Elf32_Word) ||
                    section.sh_size / sizeof(Elf32_Word) != symbol_count ||
                    section.sh_size % sizeof(Elf32_Word) != 0) {
                    invalid("invalid extended symbol index table");
                }
                extended_indexes = section;
            }
        }
        for (std::uint64_t i = 0; i < symbol_count; ++i) {
            const auto symbol = file.object<Elf64_Sym>(table.sh_offset + i * sizeof(Elf64_Sym));
            const auto name = string_at(strings, symbol.st_name);
            if (name.empty())
                continue;
            std::uint64_t section_index = symbol.st_shndx;
            bool ordinary_section = section_index < SHN_LORESERVE && section_index != SHN_UNDEF;
            if (section_index == SHN_XINDEX) {
                if (!extended_indexes)
                    invalid("missing extended symbol index table");
                section_index =
                    file.object<Elf32_Word>(extended_indexes->sh_offset + i * sizeof(Elf32_Word));
                ordinary_section = section_index != SHN_UNDEF;
            }
            if (ordinary_section && section_index >= sections.size()) {
                invalid("symbol section index is out of bounds");
            }
            const auto type = ELF64_ST_TYPE(symbol.st_info);
            const bool code_type = type == STT_FUNC || type == STT_NOTYPE;
            const bool allocated_section =
                ordinary_section && (sections[section_index].sh_flags & SHF_ALLOC) != 0 &&
                symbol.st_value >= sections[section_index].sh_addr &&
                symbol.st_value - sections[section_index].sh_addr < sections[section_index].sh_size;
            const bool code_section =
                allocated_section && (sections[section_index].sh_flags & SHF_EXECINSTR) != 0;
            const bool data_type = type == STT_OBJECT || type == STT_NOTYPE;
            const bool data_section = allocated_section && (sections[section_index].sh_flags &
                                                            (SHF_EXECINSTR | SHF_TLS)) == 0;
            const bool loaded =
                std::any_of(segments_.begin(), segments_.end(), [&](const Segment& segment) {
                    return symbol.st_value >= segment.address &&
                           symbol.st_value - segment.address < segment.memory_size;
                });
            // Bounds also keep annotations from claiming an address in another
            // section when untrusted symbol metadata invents an oversized range.
            const auto available = allocated_section
                                       ? sections[section_index].sh_size -
                                             (symbol.st_value - sections[section_index].sh_addr)
                                       : 0;
            const auto symbol_size = std::min(symbol.st_size, available);
            // Undefined, TLS, IFUNC resolvers, absolute values and data symbols
            // are not code addresses suitable for this debugger's break command.
            symbols_[name].push_back(
                {symbol.st_value, symbol_size,
                 code_type && code_section && executable_address(symbol.st_value),
                 data_type && data_section && loaded});
        }
    }
}

bool ElfImage::executable_address(std::uint64_t address) const noexcept {
    return std::any_of(segments_.begin(), segments_.end(), [address](const Segment& segment) {
        return (segment.flags & PF_X) != 0 && address >= segment.address &&
               address - segment.address < segment.memory_size;
    });
}

std::uint64_t ElfImage::load_bias(pid_t pid) const {
    if (pid <= 0)
        throw std::runtime_error("cannot resolve load bias for an invalid PID");
    std::ifstream input("/proc/" + std::to_string(pid) + "/maps");
    if (!input)
        throw std::runtime_error("cannot open tracee /proc maps");
    std::vector<Mapping> mappings;
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string addresses, permissions, offset, device, inode;
        if (!(fields >> addresses >> permissions >> offset >> device >> inode)) {
            throw std::runtime_error("malformed /proc maps entry");
        }
        const auto dash = addresses.find('-');
        const auto colon = device.find(':');
        if (dash == std::string::npos || colon == std::string::npos) {
            throw std::runtime_error("malformed /proc maps address or device");
        }
        const auto start = number(addresses.substr(0, dash), 16);
        const auto end = number(addresses.substr(dash + 1), 16);
        const auto file_offset = number(offset, 16);
        const auto map_major = number(device.substr(0, colon), 16);
        const auto map_minor = number(device.substr(colon + 1), 16);
        const auto map_inode = number(inode, 10);
        if (start >= end)
            throw std::runtime_error("invalid /proc maps address range");
        // Identity avoids substring matches, whitespace/path escapes, symlinks,
        // and the " (deleted)" suffix in procfs pathnames.
        if (map_inode == inode_ && map_major == device_major_ && map_minor == device_minor_) {
            mappings.push_back({start, end, file_offset});
        }
    }
    if (input.bad())
        throw std::runtime_error("failed reading tracee /proc maps");

    const auto first = std::find_if(segments_.begin(), segments_.end(),
                                    [](const Segment& segment) { return segment.file_size != 0; });
    if (first == segments_.end())
        throw std::runtime_error("ELF has no file-backed PT_LOAD segment");
    const auto first_offset = first->offset - first->offset % page_size_;
    const auto first_address = first->address - first->address % page_size_;
    std::set<std::uint64_t> candidates;
    for (const auto& mapping : mappings) {
        if (first_offset < mapping.offset ||
            first_offset - mapping.offset >= mapping.end - mapping.start)
            continue;
        const auto runtime_page = checked_add(mapping.start, first_offset - mapping.offset);
        if (runtime_page < first_address)
            continue;
        const auto bias = runtime_page - first_address;
        if (!pie_ && bias != 0)
            continue;
        bool all_segments_match = true;
        for (const auto& segment : segments_) {
            if (segment.file_size == 0)
                continue;
            const auto page_address = segment.address - segment.address % page_size_;
            const auto page_offset = segment.offset - segment.offset % page_size_;
            const auto runtime = checked_add(page_address, bias);
            const bool matched =
                std::any_of(mappings.begin(), mappings.end(), [&](const Mapping& candidate) {
                    return runtime >= candidate.start && runtime < candidate.end &&
                           page_offset >= candidate.offset &&
                           runtime - candidate.start == page_offset - candidate.offset;
                });
            if (!matched) {
                all_segments_match = false;
                break;
            }
        }
        if (all_segments_match)
            candidates.insert(bias);
    }
    if (candidates.empty())
        throw std::runtime_error("cannot match executable PT_LOAD segments to tracee mappings");
    if (candidates.size() != 1)
        throw std::runtime_error("ambiguous executable load bias");
    return *candidates.begin();
}

std::uint64_t ElfImage::runtime_address(std::uint64_t elf_va, std::uint64_t bias) const {
    if (!pie_ && bias != 0)
        throw std::runtime_error("ET_EXEC requires zero load bias");
    return checked_add(elf_va, bias);
}

std::uint64_t ElfImage::image_base(std::uint64_t bias) const {
    return runtime_address(image_base_, bias);
}

std::uint64_t ElfImage::symbol_address(const std::string& name, std::uint64_t bias) const {
    return resolve_symbol(name, bias, false);
}

std::uint64_t ElfImage::object_address(const std::string& name, std::uint64_t bias) const {
    return resolve_symbol(name, bias, true);
}

std::uint64_t ElfImage::resolve_symbol(const std::string& name, std::uint64_t bias,
                                       bool object) const {
    const auto found = symbols_.find(name);
    if (found == symbols_.end()) {
        throw std::runtime_error(
            "symbol '" + name + "' not found" +
            (has_static_symbols_ ? "" : " (no .symtab; executable may be stripped)"));
    }
    std::set<std::uint64_t> addresses;
    for (const auto& symbol : found->second) {
        if (object ? symbol.object : symbol.executable)
            addresses.insert(symbol.value);
    }
    if (addresses.empty()) {
        throw std::runtime_error("symbol '" + name + "' is not a defined " +
                                 (object ? "data symbol" : "executable code symbol") +
                                 " (TLS/IFUNC unsupported)");
    }
    if (addresses.size() != 1) {
        throw std::runtime_error("symbol '" + name + "' is ambiguous; use an explicit address");
    }
    return runtime_address(*addresses.begin(), bias);
}

std::string ElfImage::describe_address(std::uint64_t runtime, std::uint64_t bias) const {
    if ((!pie_ && bias != 0) || runtime < bias)
        return {};
    const auto address = runtime - bias;
    if (!executable_address(address))
        return {};
    const Symbol* best = nullptr;
    const std::string* name = nullptr;
    for (const auto& [candidate, definitions] : symbols_) {
        for (const auto& symbol : definitions) {
            if (!symbol.executable || address < symbol.value)
                continue;
            const auto offset = address - symbol.value;
            if (offset != 0 && (symbol.size == 0 || offset >= symbol.size))
                continue;
            if (!best || symbol.value > best->value ||
                (symbol.value == best->value && candidate.size() < name->size())) {
                best = &symbol;
                name = &candidate;
            }
        }
    }
    if (!best)
        return {};
    std::ostringstream description;
    description << *name;
    if (address != best->value)
        description << "+0x" << std::hex << address - best->value;
    return description.str();
}

} // namespace sdb
