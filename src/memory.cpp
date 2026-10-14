#include "sdb/memory.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <sstream>
#include <system_error>
#include <unistd.h>

namespace sdb {
namespace {

class FileDescriptor {
  public:
    FileDescriptor(const Tracee& tracee, int flags) {
        const auto path = "/proc/" + std::to_string(tracee.tid()) + "/mem";
        fd_ = ::open(path.c_str(), flags | O_CLOEXEC);
        if (fd_ == -1)
            throw std::system_error(errno, std::generic_category(), "open " + path);
    }
    ~FileDescriptor() {
        if (::close(fd_) == -1)
            std::fprintf(stderr, "sdb: close memory failed (errno %d)\n", errno);
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    int get() const { return fd_; }

  private:
    int fd_ = -1;
};

void validate_range(std::uint64_t address, std::size_t size) {
    const auto maximum = static_cast<std::uint64_t>(std::numeric_limits<off_t>::max());
    if (address > maximum || (size != 0 && size - 1 > maximum - address)) {
        throw std::out_of_range("memory range exceeds the supported /proc memory offsets");
    }
}

std::size_t chunk_size(std::size_t remaining) {
    return std::min(remaining, static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
}

std::string location(const char* operation, std::uint64_t address) {
    std::ostringstream message;
    message << operation << " memory at 0x" << std::hex << address;
    return message.str();
}

std::vector<std::uint8_t> read_bytes(int fd, std::uint64_t address, std::size_t size,
                                     bool partial) {
    std::vector<std::uint8_t> bytes(size);
    std::size_t done = 0;
    while (done < size) {
        const auto count = ::pread(fd, bytes.data() + done, chunk_size(size - done),
                                   static_cast<off_t>(address + done));
        if (count == -1) {
            if (errno == EINTR)
                continue;
            if (partial && done > 0 && (errno == EIO || errno == EFAULT))
                break;
            throw std::system_error(errno, std::generic_category(),
                                    location("read", address + done));
        }
        if (count == 0) {
            if (partial && done > 0)
                break;
            throw std::runtime_error(location("short read of", address + done));
        }
        done += static_cast<std::size_t>(count);
    }
    bytes.resize(done);
    return bytes;
}

std::uint64_t parse_integer(const std::string& value, int base) {
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result, base);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
        throw std::runtime_error("malformed integer in /proc maps");
    }
    return result;
}

} // namespace

std::vector<Region> Memory::mappings() const {
    tracee_.require_stopped();
    const auto path = "/proc/" + std::to_string(tracee_.tid()) + "/maps";
    std::ifstream stream(path);
    if (!stream)
        throw std::system_error(errno ? errno : EIO, std::generic_category(), "open " + path);
    std::vector<Region> regions;
    std::string line;
    while (std::getline(stream, line)) {
        std::istringstream fields(line);
        std::string range, permissions, offset, inode;
        Region region;
        if (!(fields >> range >> permissions >> offset >> region.device >> inode)) {
            throw std::runtime_error("malformed /proc maps line");
        }
        const auto separator = range.find('-');
        if (separator == std::string::npos || permissions.size() != 4) {
            throw std::runtime_error("malformed /proc maps range or permissions");
        }
        region.start = parse_integer(range.substr(0, separator), 16);
        region.end = parse_integer(range.substr(separator + 1), 16);
        if (region.start >= region.end)
            throw std::runtime_error("invalid /proc maps range");
        region.offset = parse_integer(offset, 16);
        region.inode = parse_integer(inode, 10);
        region.readable = permissions[0] == 'r';
        region.writable = permissions[1] == 'w';
        region.executable = permissions[2] == 'x';
        std::getline(fields, region.path);
        const auto first = region.path.find_first_not_of(" \t");
        region.path = first == std::string::npos ? std::string{} : region.path.substr(first);
        regions.push_back(std::move(region));
    }
    if (stream.bad())
        throw std::runtime_error("failed while reading " + path);
    return regions;
}

std::optional<std::uint64_t> Memory::executable_end(std::uint64_t address) const {
    for (const auto& region : mappings()) {
        if (region.executable && address >= region.start && address < region.end)
            return region.end;
    }
    return std::nullopt;
}

std::vector<std::uint8_t> Memory::read(std::uint64_t address, std::size_t size) const {
    tracee_.require_stopped();
    validate_range(address, size);
    if (size == 0)
        return {};
    const FileDescriptor fd(tracee_, O_RDONLY);
    return read_bytes(fd.get(), address, size, false);
}

std::vector<std::uint8_t> Memory::read_up_to(std::uint64_t address, std::size_t size) const {
    tracee_.require_stopped();
    validate_range(address, size);
    if (size == 0)
        return {};
    const FileDescriptor fd(tracee_, O_RDONLY);
    return read_bytes(fd.get(), address, size, true);
}

void Memory::write(std::uint64_t address, const std::vector<std::uint8_t>& bytes) const {
    tracee_.require_stopped();
    validate_range(address, bytes.size());
    if (bytes.empty())
        return;
    const FileDescriptor fd(tracee_, O_RDWR);
    const auto original = read_bytes(fd.get(), address, bytes.size(), false);
    std::size_t done = 0;
    int error = 0;
    while (done < bytes.size()) {
        const auto count = ::pwrite(fd.get(), bytes.data() + done, chunk_size(bytes.size() - done),
                                    static_cast<off_t>(address + done));
        if (count == -1 && errno == EINTR)
            continue;
        if (count <= 0) {
            error = count == -1 ? errno : EIO;
            break;
        }
        done += static_cast<std::size_t>(count);
    }
    if (error == 0)
        return;

    std::size_t restored = 0;
    while (restored < done) {
        const auto count =
            ::pwrite(fd.get(), original.data() + restored, chunk_size(done - restored),
                     static_cast<off_t>(address + restored));
        if (count == -1 && errno == EINTR)
            continue;
        if (count <= 0) {
            const int rollback_error = count == -1 ? errno : EIO;
            throw MemoryCorruption(location("failed to roll back", address + restored) + ": " +
                                   std::generic_category().message(rollback_error));
        }
        restored += static_cast<std::size_t>(count);
    }
    throw std::system_error(error, std::generic_category(),
                            location("write (rolled back)", address + done));
}

} // namespace sdb
