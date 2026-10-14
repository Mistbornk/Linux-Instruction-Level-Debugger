#include "sdb/elf_image.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <link.h>
#include <stdexcept>
#include <string>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

// Real symbols in this test executable let us cross-check the parser against
// actual runtime addresses, independently of ptrace and debugger output.
extern "C" {
int sdb_elf_test_data = 42;
thread_local int sdb_elf_test_tls = 7;
__attribute__((noinline)) int sdb_elf_test_function(int value) {
    return value + 1;
}
using ProbeFunction = int (*)(int);
ProbeFunction sdb_elf_test_resolver() {
    return sdb_elf_test_function;
}
int sdb_elf_test_ifunc(int) __attribute__((ifunc("sdb_elf_test_resolver")));
}

namespace {
void require(bool condition, const std::string& message) {
    if (!condition)
        throw std::runtime_error(message);
}

template <typename Function> void require_rejected(Function action, const std::string& message) {
    bool rejected = false;
    try {
        action();
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    require(rejected, message);
}

template <typename T> T object_at(const std::vector<char>& bytes, std::size_t offset) {
    require(offset <= bytes.size() && sizeof(T) <= bytes.size() - offset,
            "invalid test fixture offset");
    T result;
    std::memcpy(&result, bytes.data() + offset, sizeof(T));
    return result;
}

template <typename T> void replace(std::vector<char>& bytes, std::size_t offset, const T& value) {
    require(offset <= bytes.size() && sizeof(T) <= bytes.size() - offset,
            "invalid mutation offset");
    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

struct TemporaryDirectory {
    std::filesystem::path path;
    TemporaryDirectory() {
        char pattern[] = "/tmp/sdb-elf-unit-XXXXXX";
        const auto* created = mkdtemp(pattern);
        if (!created)
            throw std::runtime_error("mkdtemp failed");
        path = created;
    }
    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
};

void write_file(const std::filesystem::path& path, const std::vector<char>& bytes) {
    std::ofstream stream(path, std::ios::binary);
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    stream.close();
    require(!stream.fail(), "cannot write malformed ELF fixture");
}

int main_image_bias(dl_phdr_info* info, std::size_t, void* result) {
    if (!info->dlpi_name || info->dlpi_name[0] == '\0') {
        *static_cast<std::uint64_t*>(result) = info->dlpi_addr;
        return 1;
    }
    return 0;
}
} // namespace

int main() {
    try {
        const sdb::ElfImage image("/proc/self/exe");
        const auto bias = image.load_bias(getpid());
        std::uint64_t loader_bias = std::numeric_limits<std::uint64_t>::max();
        require(dl_iterate_phdr(main_image_bias, &loader_bias) != 0,
                "main image absent from loader metadata");
        require(bias == loader_bias, "load bias disagrees with the dynamic loader");
        require(image.runtime_address(image.entry(), bias) == getauxval(AT_ENTRY),
                "entry point disagrees with kernel AT_ENTRY");
        require(image.symbol_address("sdb_elf_test_function", bias) ==
                    reinterpret_cast<std::uintptr_t>(&sdb_elf_test_function),
                "resolved code symbol disagrees with its actual address");
        require(image.object_address("sdb_elf_test_data", bias) ==
                    reinterpret_cast<std::uintptr_t>(&sdb_elf_test_data),
                "resolved data symbol disagrees with its actual address");
        const auto live_image = sdb::ElfImage::from_tracee(getpid());
        const auto live_bias = live_image.load_bias(getpid());
        require(live_image.path() == "/proc/" + std::to_string(getpid()) + "/exe",
                "tracee image did not retain the direct procfs source");
        require(live_image.display_name() == image.path() && image.display_name() == image.path(),
                "ordinary executable display name changed");
        require(live_bias == loader_bias &&
                    live_image.runtime_address(live_image.entry(), live_bias) ==
                        getauxval(AT_ENTRY),
                "direct tracee image disagrees with loader bias or AT_ENTRY");
        require(live_image.symbol_address("sdb_elf_test_function", live_bias) ==
                        reinterpret_cast<std::uintptr_t>(&sdb_elf_test_function) &&
                    live_image.object_address("sdb_elf_test_data", live_bias) ==
                        reinterpret_cast<std::uintptr_t>(&sdb_elf_test_data),
                "direct tracee image resolved the wrong code or data address");
        for (const pid_t invalid_tid : {pid_t{0}, pid_t{-1}}) {
            bool rejected = false;
            try {
                (void)sdb::ElfImage::from_tracee(invalid_tid);
            } catch (const std::invalid_argument&) {
                rejected = true;
            }
            require(rejected, "tracee image accepted a nonpositive TID");
        }
        const auto function_address = reinterpret_cast<std::uintptr_t>(&sdb_elf_test_function);
        require(image.describe_address(function_address, bias) == "sdb_elf_test_function",
                "function annotation failed");
        require(image.describe_address(function_address + 1, bias) == "sdb_elf_test_function+0x1",
                "function offset annotation failed");
        require(image.describe_address(reinterpret_cast<std::uintptr_t>(&sdb_elf_test_data), bias)
                    .empty(),
                "data address received a misleading code annotation");
        require(image.describe_address(1, bias).empty(), "unknown address received a symbol");
        for (const auto* symbol :
             {"sdb_elf_test_function", "sdb_elf_test_tls", "sdb_elf_test_ifunc", "getpid",
              "sdb_symbol_that_does_not_exist"}) {
            require_rejected([&] { image.object_address(symbol, bias); },
                             std::string("accepted unsupported object symbol: ") + symbol);
        }
        require(image.has_static_symbols(), "self-test executable unexpectedly stripped");
        for (const auto* symbol : {"sdb_elf_test_data", "sdb_elf_test_tls", "sdb_elf_test_ifunc",
                                   "getpid", "sdb_symbol_that_does_not_exist"}) {
            require_rejected([&] { image.symbol_address(symbol, bias); },
                             std::string("accepted unsupported symbol: ") + symbol);
        }
        require_rejected(
            [&] { image.runtime_address(std::numeric_limits<std::uint64_t>::max(), 1); },
            "accepted address overflow or a nonzero ET_EXEC bias");
        require_rejected([&] { image.load_bias(-1); }, "accepted invalid PID");

        std::ifstream input(image.path(), std::ios::binary);
        require(input.good(), "cannot open self executable");
        const std::vector<char> original{std::istreambuf_iterator<char>(input), {}};
        const auto original_header = object_at<Elf64_Ehdr>(original, 0);
        require(image.is_pie() == (original_header.e_type == ET_DYN), "incorrect ELF type");
        std::uint64_t lowest_address = std::numeric_limits<std::uint64_t>::max();
        const long native_page_size = sysconf(_SC_PAGESIZE);
        require(native_page_size > 0, "invalid page size");
        const auto page_size = static_cast<std::uint64_t>(native_page_size);
        std::size_t first_load = 0;
        for (std::size_t i = 0; i < original_header.e_phnum; ++i) {
            const auto offset = original_header.e_phoff + i * sizeof(Elf64_Phdr);
            const auto program = object_at<Elf64_Phdr>(original, offset);
            if (program.p_type == PT_LOAD) {
                if (!first_load)
                    first_load = offset;
                lowest_address =
                    std::min(lowest_address, program.p_vaddr - program.p_vaddr % page_size);
            }
        }
        require(first_load != 0, "fixture has no PT_LOAD");
        require(image.image_base(bias) == lowest_address + loader_bias,
                "wrong breakrva image base");
        if (!image.is_pie())
            require(bias == 0, "ET_EXEC unexpectedly relocated");

        TemporaryDirectory temporary;
        const auto alias = temporary.path / "executable-link";
        std::filesystem::create_symlink(image.path(), alias);
        const auto relative_alias = alias.lexically_relative(std::filesystem::current_path());
        require(!relative_alias.empty() && relative_alias.is_relative(),
                "could not construct relative executable alias");
        const sdb::ElfImage aliased(relative_alias.string());
        require(aliased.path() == image.path() && aliased.display_name() == image.path() &&
                    aliased.load_bias(getpid()) == bias,
                "relative symlink changed canonical file-path loading or image identity");
        require_rejected([&] { sdb::ElfImage invalid(image.path() + std::string("\0ignored", 8)); },
                         "accepted path containing a NUL byte");
        const auto fifo = temporary.path / "named-pipe";
        require(mkfifo(fifo.c_str(), 0600) == 0, "cannot create FIFO fixture");
        require_rejected([&] { sdb::ElfImage invalid(fifo.string()); },
                         "accepted non-regular ELF file");
        require_rejected([&] { sdb::ElfImage invalid(temporary.path.string()); },
                         "accepted directory as ELF");
        std::size_t rejected_count = 0;
        auto malformed = [&](const std::string& name, const std::vector<char>& data) {
            const auto path = temporary.path / name;
            write_file(path, data);
            require_rejected([&] { sdb::ElfImage invalid(path.string()); },
                             "accepted malformed ELF: " + name);
            ++rejected_count;
        };
        malformed("empty", {});
        malformed("text", {'n', 'o', 't', ' ', 'E', 'L', 'F'});
        malformed("truncated",
                  std::vector<char>(original.begin(), original.begin() + sizeof(Elf64_Ehdr)));
        const auto maximum = std::numeric_limits<std::uint64_t>::max();
        for (int variant = 0; variant < 11; ++variant) {
            auto bytes = original;
            auto header = original_header;
            switch (variant) {
            case 0:
                header.e_ident[EI_MAG0] = 0;
                break;
            case 1:
                header.e_ident[EI_CLASS] = ELFCLASS32;
                break;
            case 2:
                header.e_ident[EI_DATA] = ELFDATA2MSB;
                break;
            case 3:
                header.e_machine = EM_AARCH64;
                break;
            case 4:
                header.e_version = 0;
                break;
            case 5:
                header.e_type = ET_REL;
                break;
            case 6:
                header.e_phoff = maximum;
                break;
            case 7:
                header.e_shoff = maximum;
                break;
            case 8:
                header.e_entry = maximum;
                break;
            case 9:
                header.e_phentsize = 1;
                break;
            case 10:
                header.e_shentsize = 1;
                break;
            }
            replace(bytes, 0, header);
            malformed("header-" + std::to_string(variant), bytes);
        }
        for (int variant = 0; variant < 3; ++variant) {
            auto bytes = original;
            auto program = object_at<Elf64_Phdr>(bytes, first_load);
            if (variant == 0)
                program.p_filesz = maximum;
            if (variant == 1) {
                program.p_memsz = maximum;
                program.p_vaddr = page_size;
            }
            if (variant == 2)
                program.p_align = 3;
            replace(bytes, first_load, program);
            malformed("segment-" + std::to_string(variant), bytes);
        }
        for (std::size_t i = 0; i < original_header.e_shnum; ++i) {
            const auto offset = original_header.e_shoff + i * sizeof(Elf64_Shdr);
            const auto table = object_at<Elf64_Shdr>(original, offset);
            if (table.sh_type != SHT_SYMTAB)
                continue;
            for (int variant = 0; variant < 3; ++variant) {
                auto bytes = original;
                auto broken = table;
                if (variant == 0)
                    broken.sh_link = std::numeric_limits<std::uint32_t>::max();
                if (variant == 1)
                    broken.sh_entsize = 1;
                replace(bytes, offset, broken);
                if (variant == 2) {
                    auto symbol = object_at<Elf64_Sym>(original, table.sh_offset);
                    symbol.st_name = std::numeric_limits<std::uint32_t>::max();
                    replace(bytes, table.sh_offset, symbol);
                }
                malformed("symbol-table-" + std::to_string(variant), bytes);
            }
            break;
        }
        // ELF can be loaded without section headers; symbols then have a useful
        // stripped/absent-table diagnostic instead of a fabricated resolution.
        auto sectionless = original;
        auto header = original_header;
        header.e_shoff = 0;
        header.e_shnum = 0;
        header.e_shstrndx = SHN_UNDEF;
        replace(sectionless, 0, header);
        const auto sectionless_path = temporary.path / "sectionless";
        write_file(sectionless_path, sectionless);
        sdb::ElfImage without_sections(sectionless_path.string());
        require(!without_sections.has_static_symbols(), "sectionless image has fabricated symbols");
        require_rejected([&] { without_sections.symbol_address("sdb_elf_test_function", 0); },
                         "sectionless image resolved a missing symbol");

        std::cout << (image.is_pie() ? "PIE" : "ET_EXEC")
                  << ": file/procfs identity, loader bias, AT_ENTRY, function/data addresses, "
                     "annotations, symbol rejection, "
                  << rejected_count << " malformed files, sectionless ELF passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ELF test failure: " << error.what() << '\n';
        return 1;
    }
}
