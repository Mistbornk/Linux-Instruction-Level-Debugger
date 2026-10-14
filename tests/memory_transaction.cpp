#include "sdb/breakpoint.hpp"
#include "sdb/elf_image.hpp"
#include <cerrno>
#include <iostream>
#include <unistd.h>

// Inject failures into the real procfs write boundary, not a mock debugger.
static int mode = 0;
static int calls = 0;
extern "C" ssize_t __real_pwrite(int, const void *, size_t, off_t);
extern "C" ssize_t __wrap_pwrite(int fd, const void *data, size_t size,
                                 off_t offset) {
  ++calls;
  if (mode == 3 || (mode == 1 && calls == 2) || (mode == 2 && calls == 1)) {
    errno = EIO;
    return -1;
  }
  if (mode == 1 && calls == 1 && size > 1)
    return __real_pwrite(fd, data, 1, offset);
  return __real_pwrite(fd, data, size, offset);
}
static void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  try {
    sdb::Tracee tracee;
    sdb::ElfImage image(argv[1]);
    tracee.launch(argv[1]);
    sdb::Memory memory(tracee);
    sdb::BreakpointManager points(memory);
    auto site = image.entry(memory);
    auto original = memory.read(site, 5);
    mode = 2;
    calls = 0;
    bool failed = false;
    try {
      points.add(site);
    } catch (const std::runtime_error &) {
      failed = true;
    }
    mode = 0;
    require(failed && points.all().empty(),
            "failed insertion published metadata");
    require(memory.read(site, 5) == original, "failed insertion altered bytes");
    points.add(site + 2);
    auto physical = memory.read(site, 5);
    auto changed = original;
    changed[0] = 0x90;
    changed[2] = 0x91;
    mode = 1;
    calls = 0;
    failed = false;
    try {
      points.patch(site, changed);
    } catch (const std::runtime_error &) {
      failed = true;
    }
    mode = 0;
    require(failed && memory.read(site, 5) == physical,
            "partial write was not rolled back");
    require(points.all().at(site + 2).original == original[2],
            "failed patch changed original byte");
    points.remove(0);
    require(memory.read(site, 5) == original,
            "delete did not restore original code");
    mode = 3;
    calls = 0;
    failed = false;
    try {
      memory.write(site, changed);
    } catch (const sdb::MemoryCorruption &) {
      failed = true;
    }
    mode = 0;
    require(failed, "rollback failure not distinguished");
    std::cout << "PASS: insertion failure, partial-write rollback, metadata "
                 "consistency, rollback failure\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
