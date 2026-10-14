#include <capstone/capstone.h>
#include <cstdlib> // for realpath
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits.h> // for PATH_MAX
#include <sstream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <map>
#include <vector>

pid_t child_pid = -1;
std::string prog_path;
bool loaded = false;
uint64_t base_addr = 0;
int status;

std::map<uint64_t, uint8_t> break_points;
std::map<int, uint64_t> id_map;
int next_bp_id = 0;

struct ExecRegion {
  uint64_t start;
  uint64_t end;
};
std::vector<ExecRegion> exec_regions;

enum {
  SI,
  CONT,
  SYSCALL
};

void prompt() { std::cout << "(sdb) "; }

bool is_instruction_boundary(uint64_t addr) {
  constexpr size_t MAX_INST_SIZE = 15;
  char code[MAX_INST_SIZE];

  std::stringstream mem_path;
  mem_path << "/proc/" << child_pid << "/mem";
  int fd = open(mem_path.str().c_str(), O_RDONLY);
  pread(fd, code, MAX_INST_SIZE, addr);

  csh handle;
  cs_insn *insn;
  size_t count;

  cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
  count = cs_disasm(handle, (uint8_t *)code, MAX_INST_SIZE, addr, 1, &insn);

  bool valid = (count > 0 && insn[0].address == addr);

  cs_free(insn, count);
  cs_close(&handle);

  return valid;
}


void collect_exec_regions(pid_t pid) {
  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(maps, line)) {
    std::istringstream iss(line);
    std::string addr_range, perms;
    iss >> addr_range >> perms;

    if (perms.find("r-xp") == std::string::npos)
      continue;

    size_t dash = addr_range.find('-');
    uint64_t start = std::stoull(addr_range.substr(0, dash), 0l, 16);
    uint64_t end = std::stoull(addr_range.substr(dash + 1), 0l, 16);

    exec_regions.push_back({start, end});
  }
}

bool in_exec_region(uint64_t rip) {
  for (auto &region : exec_regions) {
    if (rip >= region.start && rip < region.end)
      return true;
  }
  return false;
}

void print_instruction(const cs_insn &insn) {
  // [address]: [raw machine bytes]         [mnemonic] [operands]
  printf("      %06lx: ", insn.address);

  std::ostringstream bytes_str;
  for (size_t j = 0; j < insn.size; j++) {
    bytes_str << std::hex << std::setfill('0') << std::setw(2) << (int)insn.bytes[j] << ' ';
  }
  std::string raw = bytes_str.str();

  // 對齊 mnemonic：將 raw byte 填到固定寬度欄位（例如 32）
  printf("%-32s%-7s %s\n", raw.c_str(), insn.mnemonic, insn.op_str);
}


void end_process() {
  kill(child_pid, SIGKILL);
  waitpid(child_pid, 0l, 0);
  loaded = false;
  child_pid = -1;
  base_addr = 0;
  next_bp_id = 0;
  break_points.clear();
  exec_regions.clear();
}

void wait_until_rip(pid_t pid, uint64_t target_rip) {
  // store original byte
  uint8_t original_byte;
  std::stringstream mem_path;
  mem_path << "/proc/" << pid << "/mem";
  int fd = open(mem_path.str().c_str(), O_RDWR);
  pread(fd, &original_byte, 1, target_rip);

  // set int3 breakpoint
  uint8_t int3 = 0xCC;
  pwrite(fd, &int3, 1, target_rip);
  close(fd);

  // cont to breakpoint
  ptrace(PTRACE_CONT, pid, 0l, 0l);
  waitpid(pid, &status, 0);

  // restore rip and original instuction
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, child_pid, 0l, &regs);
  regs.rip -= 1;
  ptrace(PTRACE_SETREGS, child_pid, 0l, &regs);

  // 恢復原 byte
  fd = open(mem_path.str().c_str(), O_RDWR);
  pwrite(fd, &original_byte, 1, target_rip);
  close(fd);
}

// find PT_DYNAMIC
bool is_dynamic_linked(const std::string &path) {
  std::ifstream elf(path, std::ios::binary);
  //elf.seekg(0x20); // e_phoff (program header offset)
  //uint64_t phoff;
  //elf.read(reinterpret_cast<char *>(&phoff), sizeof(phoff));

  //elf.seekg(0x36); // e_phnum (program header entries count))
  //uint16_t phnum;
  //elf.read(reinterpret_cast<char *>(&phnum), sizeof(phnum));

  //for (int i = 0; i < phnum; ++i) {
  //  elf.seekg(phoff + i * 56); // sizeof(Elf64_Phdr)
  //  uint32_t p_type;
  //  elf.read(reinterpret_cast<char *>(&p_type), sizeof(p_type));
  //  if (p_type == 2 /* PT_DYNAMIC */)
  //    return true;
  //}
  //return false;

  /*
    typedef struct {
        uint32_t   p_type;    // 4 bytes: Segment type
        uint32_t   p_flags;   // 4 bytes: Segment flags
        uint64_t   p_offset;  // 8 bytes: Offset in file
        uint64_t   p_vaddr;   // 8 bytes: Virtual address in memory
        uint64_t   p_paddr;   // 8 bytes: Physical address (rarely used)
        uint64_t   p_filesz;  // 8 bytes: Size of segment in file
        uint64_t   p_memsz;   // 8 bytes: Size of segment in memory
        uint64_t   p_align;   // 8 bytes: Alignment
    } Elf64_Phdr;
  */

   elf.seekg(0x10);  // e_type 在 0x10 處（2 bytes）
   uint16_t e_type;
   elf.read(reinterpret_cast<char*>(&e_type), sizeof(e_type));
   return (e_type == 3);  // 3 = ET_DYN (PIE)
}

void disassemble(pid_t pid, uint64_t rip) {
  constexpr size_t CODE_SIZE = 64;
  char code[CODE_SIZE];

  // read /proc/[pid]/mem
  std::stringstream mem_path;
  mem_path << "/proc/" << pid << "/mem";
  int fd = open(mem_path.str().c_str(), O_RDONLY);
  if (fd < 0) {
    perror("open mem");
    return;
  }
  // pread(fd, buf, size, offset)
  ssize_t nread = pread(fd, code, CODE_SIZE, rip);
  if (nread <= 0) {
    std::cerr << "** warning: failed to read memory at 0x" << std::hex << rip
              << std::dec << "\n";
    close(fd);
    return;
  }
  close(fd);

  for (auto& [addr, orig] : break_points) {
    if (addr >= rip && addr < rip + CODE_SIZE) {
      code[addr - rip] = orig; // 將 0xCC 還原為原 byte
    }
  }

  csh handle;
  cs_insn *insn;
  size_t count;

  cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
  count = cs_disasm(handle, (uint8_t *)code, CODE_SIZE, rip, 5,
                    &insn); // for 5 intsruction

  if (count > 0) {
      bool out_of_range = false;
      for (size_t i = 0; i < count; i++) {
          if (!in_exec_region(insn[i].address)) {
              std::cout << "** the address is out of the range of the executable region.\n";
              out_of_range = true;
              break;
          }

          if (insn[i].address == rip)
              std::cout << "=> ";
          else
              std::cout << "   ";
          print_instruction(insn[i]);
      }

      if (count < 5 && !out_of_range) {
          std::cout << "** the address is out of the range of the executable region.\n";
          out_of_range = true;
      }
  }

  cs_close(&handle);
}

void load_program(const std::string &path) {
  if (loaded) {
    std::cerr << "** program already loaded\n";
    return;
  }

  pid_t pid = fork(); // child process
  if (pid == 0) {
    // ptrace (request, pid, addr, data)
    // will be trace
    ptrace(PTRACE_TRACEME, pid, 0l, 0l);
    // int execl(const char *path, const char *arg0 (name), ..., NULL);
    execl(path.c_str(), path.c_str(), 0l); // jump to exec loaded file
    perror("exec");
    exit(1);
  }
  // wait for child sigtrap
  waitpid(pid, &status, 0);
  ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACESYSGOOD);

  child_pid = pid;
  prog_path = path;
  loaded = true;

  // Update executable regions
  exec_regions.clear();
  collect_exec_regions(child_pid);

  // 讀出 entry point offset 和 判斷 PIE
  bool is_dynamic = is_dynamic_linked(path);
  uint64_t entry_offset;
  {
    std::ifstream elf(path, std::ios::binary);
    // 讀取 e_entry
    elf.seekg(0x18); // 在 0x18
    elf.read(reinterpret_cast<char *>(&entry_offset), sizeof(entry_offset));
  }

  // 找出 binary 的 base address（從 /proc/[pid]/maps）
  {
    char real_path[PATH_MAX];
    realpath(path.c_str(), real_path);
    std::string abs_path = real_path;

    std::ifstream maps("/proc/" + std::to_string(child_pid) + "/maps");
    std::string line;

    while (std::getline(maps, line)) {
      if (line.find("r-xp") != std::string::npos &&
          line.find(abs_path) != std::string::npos) {
        // std::cerr << line << "\n";
        std::stringstream ss(line);
        std::string addr_range, perms, offset_hex;
        ss >> addr_range >> perms >> offset_hex;

        size_t dash_idx = addr_range.find('-');
        uint64_t start_addr = std::stoull(addr_range.substr(0, dash_idx), 0l, 16); // std::stoull(str, pos, base)
        uint64_t file_offset = std::stoull(offset_hex, 0l, 16);

        base_addr = start_addr - file_offset;
        break;
      }
    }
  }

  uint64_t rip;
  if (is_dynamic) {
     rip = base_addr + entry_offset;
  }else {
     rip = entry_offset;
  }

  // 等到 entry point
  wait_until_rip(child_pid, rip);

  std::cout << "** program '" << path << "' loaded. entry point: 0x" << std::hex
            << rip << ".\n";
  disassemble(child_pid, rip);
}

uint8_t put_bp(uint64_t addr) {
  uint8_t orig;
  std::stringstream mem_path;
  mem_path << "/proc/" << child_pid << "/mem";
  int fd = open(mem_path.str().c_str(), O_RDWR);
  if (fd < 0) {
    std::cout << "** failed to open memory path.\n";
    close(fd);
    return 0;
  }
  if (pread(fd, &orig, 1, addr) != 1) {
    std::cerr << "** the target address is not valid.\n";
    close(fd);
    return 0;
  }
  uint8_t int3 = 0xCC;
  pwrite(fd, &int3, 1, addr);
  close(fd);
  return orig;
}

void take_bp(uint64_t addr, uint8_t orig) {
  std::stringstream mem_path;
  mem_path << "/proc/" << child_pid << "/mem";
  int fd = open(mem_path.str().c_str(), O_RDWR);
  pwrite(fd, &orig, 1, addr);
  close(fd);
}

void run_si() {
  if (!loaded) {
    std::cout << "** please load a program first.\n";
    return;
  }

  // restore breakpoint
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, child_pid, 0l, &regs);
  
  auto it{break_points.find(regs.rip)};
  if (it != break_points.end()) take_bp(regs.rip, it->second);

  // exec sigle instruction and stop
  ptrace(PTRACE_SINGLESTEP, child_pid, 0L, 0l);
  waitpid(child_pid, &status, 0);

  if (WIFEXITED(status)) {   
      std::cout << "** the target program terminated.\n";
      end_process(); // add this to clean up
  }

  if (it != break_points.end()) put_bp(regs.rip);
  ptrace(PTRACE_GETREGS, child_pid, 0l, &regs);

  if (break_points.count(regs.rip)) {
    std::cout << "** hit a breakpoint at 0x" << std::hex << regs.rip << ".\n";
  }

  // Update executable regions
  exec_regions.clear();
  collect_exec_regions(child_pid);

  disassemble(child_pid, regs.rip);
}

void run_cont_syscall(const int& type) {
  if (!loaded) {
    std::cout << "** please load a program first.\n";
    return;
  }

  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, child_pid, 0l, &regs);  
  auto it{break_points.find(regs.rip)};

  if (it != break_points.end()) {
    take_bp(regs.rip, it->second);

    ptrace(PTRACE_SINGLESTEP, child_pid, 0l, 0l);
    waitpid(child_pid, &status, 0);
    
    if (WIFEXITED(status)) {
      std::cout << "** the target program terminated.\n";
      end_process();
      return;
    }
    put_bp(regs.rip);
  }

  // exec until end or trap
  ptrace((type == CONT) ? PTRACE_CONT : PTRACE_SYSCALL, child_pid, 0l, 0l);
  waitpid(child_pid, &status, 0);
  if (WIFEXITED(status)) {
    std::cout << "** the target program terminated.\n";
    end_process();
    return;
  }

  ptrace(PTRACE_GETREGS, child_pid, 0l, &regs);

  // Update executable regions
  exec_regions.clear();
  collect_exec_regions(child_pid);

  if (break_points.count(regs.rip - 1)) {
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, child_pid, 0l, &regs);

    std::cout << "** hit a breakpoint at 0x" << std::hex << regs.rip << ".\n";
    disassemble(child_pid, regs.rip);
  } else {
    struct __ptrace_syscall_info info;
    memset(&info, 0, sizeof(info));

    long ret = ptrace(PTRACE_GET_SYSCALL_INFO, child_pid, sizeof(info), &info);
    if (ret < 0) {
      perror("ptrace(GET_SYSCALL_INFO)");
      return;
    }

    static int sc_nr; // syscall number
    // sc_nr = info.entry.nr;
    // cout << "** a syscall(" << dec << sc_nr << hex << ") at " << (regs.rip - 2) << "." << endl;

    if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
      sc_nr = info.entry.nr;
      std::cout << "** enter a syscall(" << std::dec << sc_nr << std::hex << ") at 0x" << std::hex << (regs.rip - 2) << ".\n";
    } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
      std::cout << "** leave a syscall(" << std::dec << sc_nr << std::hex << ") = ";
      std::cout << std::dec << info.exit.rval << std::hex << " at 0x" << std::hex << (regs.rip - 2) << ".\n";
    }

    disassemble(child_pid, regs.rip - 2);
  }
}

void set_break(std::string &arg, bool is_offset) {
  if (!loaded) {
    std::cout << "** please load a program first.\n";
    return;
  }

  uint64_t addr = (is_offset) ? base_addr + std::stoull(arg, 0l, 16) : std::stoull(arg, 0l, 16);
  if (break_points.count(addr)) {
    std::cout << "** breakpoint already exists.\n";
    return;
  }

  if (!is_instruction_boundary(addr)) {
    std::cout << "** invalid breakpoint: not at instruction boundary.\n";
    return;
  }

  if (!in_exec_region(addr)) {
    std::cout << "** the target address is not valid.\n";
    return;
  }

  uint8_t orig = put_bp(addr);
  if (!orig && errno != 0) return;

  break_points[addr] = orig;
  id_map[next_bp_id] = addr;
  std::cout << "** set a breakpoint at 0x" << std::hex << addr << ".\n";
  next_bp_id++;
}

void info_break() {
  if (id_map.empty()) {
    std::cout << "** no breakpoints.\n";
    return;
  }
  std::cout << "Num     Address\n";
  for (const auto &[id, addr] : id_map) {
    std::cout << id << "\t" << "0x" << std::hex << addr << std::dec << "\n";
  }
}

void info_reg() {
  if (!loaded) {
    std::cout << "** please load a program first.\n";
    return;
  }
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, child_pid, 0l, &regs);

#define PRINT3(a, b, c)                                                        \
  printf("%-4s 0x%016llx    %-4s 0x%016llx    %-4s 0x%016llx\n", "$" #a,       \
         (unsigned long long)regs.a, "$" #b, (unsigned long long)regs.b,       \
         "$" #c, (unsigned long long)regs.c);

  PRINT3(rax, rbx, rcx);
  PRINT3(rdx, rsi, rdi);
  PRINT3(rbp, rsp, r8);
  PRINT3(r9, r10, r11);
  PRINT3(r12, r13, r14);
  PRINT3(r15, rip, eflags);

#undef PRINT3
}

void delete_break(std::string& id) {
  int num{std::stoi(id)};
  auto it{id_map.find(num)};

  if (it == id_map.end()) {
    std::cout << "** breakpoint "<< num << " does not exist.\n";
    return;
  }

  uint64_t addr{it->second};
  auto bp_it{break_points.find(addr)};
  if (bp_it != break_points.end()) {
    take_bp(addr, bp_it->second);
    id_map.erase(it);
    break_points.erase(bp_it);
    std::cout << "** delete breakpoint "<< num <<".\n";
  } else {
    std::cout << "id is not in breakpoint map\n";
  }
}

void patch_memory(std::string addr_str, std::string hex_str) {
  if (!loaded) {
    std::cout << "** please load a program first.\n";
    return;
  }
  if (hex_str.length() % 2 != 0 || hex_str.length() > 2048) {
    std::cout << "** invalid hex string length.\n";
    return;
  }

  uint64_t addr{std::stoull(addr_str, 0l, 16)};
  size_t len{hex_str.length() / 2};

  // validate address range by each byte
  for (size_t i = 0; i < len; ++i) {
      if (!in_exec_region(addr + i)) {
          std::cout << "** the target address is not valid.\n";
          return;
      }
  }

  std::vector<uint8_t> bytes(len);
  for (size_t i = 0; i < len; ++i) {
    std::string byte_str = hex_str.substr(i * 2, 2);
    bytes[i] = static_cast<uint8_t>(std::stoul(byte_str, 0l, 16));
  }

  std::stringstream mem_path;
  mem_path << "/proc/" << child_pid << "/mem";
  int fd = open(mem_path.str().c_str(), O_RDWR);
  if (fd < 0) {
    std::cout << "** failed to open memory path.\n";
    return;
  }

  for (size_t i = 0; i < len; ++i) {
    auto it = break_points.find(addr + i);
    if (it != break_points.end()) {
      it->second = bytes[i];  // patch original byte
      bytes[i] = 0xCC;         // keep int3 in memory
    }
  }

  pwrite(fd, bytes.data(), len, addr);
  close(fd);
  std::cout << "** patch memory at 0x" << std::hex << addr << ".\n";

}

int main(int argc, char *argv[]) {
  if (argc == 2) {
    std::string path = argv[1];
    load_program(path);
  }

  std::string line;
  while (true) {
    prompt();
    if (!std::getline(std::cin, line))
      break;

    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;

    if (cmd == "load") {
      std::string path;
      iss >> path;
      load_program(path);
    } else if (cmd == "si") {
      run_si();
    } else if (cmd == "cont") {
      run_cont_syscall(CONT);
    } else if (cmd == "syscall") {
      run_cont_syscall(SYSCALL);
    } else if (cmd == "break") {
      std::string addr;
      iss >> addr;
      set_break(addr, false);
    } else if (cmd == "breakrva") {
      std::string offset;
      iss >> offset;
      set_break(offset, true);
    } else if (cmd == "info") {
      std::string type;
      iss >> type;
      if (type == "break") {
        info_break();
      } else if (type == "reg") {
        info_reg();
      } else { 
        std::cout << "** unknown command: " << cmd << "\n";
      }
    } else if (cmd == "delete") {
      std::string id;
      iss >> id;
      delete_break(id);
    } else if (cmd == "patch") {
      std::string addr_str, hex_str;
      iss >> addr_str >> hex_str;
      patch_memory(addr_str, hex_str);
    } else if (cmd == "q") {
      if (loaded) {
        end_process();
      }
      return 0;
    } else {
      std::cout << "** unknown command: " << cmd << "\n";
    }
  }
  return 0;
}
