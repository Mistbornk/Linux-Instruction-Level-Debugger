# SDB — 面試導向的嚴格程式碼審查與改進計畫

> **實作進度入口：** 本文保留原始審查與規劃內容；目前實作、需求對照及驗證界線請見
> [docs/improvement-status.md](docs/improvement-status.md) 與 [docs/testing.md](docs/testing.md)。

> **審查日期：2026-10-13**  
> **目標職缺：C++ Software Engineer、Linux Systems Software、System Software / 軟韌體相關工程師**  
> **原始專案：** [Mistbornk/SDB](https://github.com/Mistbornk/SDB)  
> **審查範圍：** 公開 `main` 分支的 [`sdb.cpp`](https://github.com/Mistbornk/SDB/blob/main/sdb.cpp)、[`Makefile`](https://github.com/Mistbornk/SDB/blob/main/Makefile)、[`.gitignore`](https://github.com/Mistbornk/SDB/blob/main/.gitignore) 與 repo 結構。
>
> **驗證界線：** 本報告是依公開原始碼做的 **static code review**。嘗試在審查環境 clone repository 時遇到 DNS／網路限制，**未完成實際編譯、執行、sanitizer 或 ptrace 整合測試**。因此下文將區分「可直接由原始碼確認的缺陷」、「高風險情境」及「建議用測試驗證的事項」，不把推論寫成已重現的 bug。

---

## 0. 最終結論：有 systems 技術核心，但現階段不能當作成熟的履歷主打專案

**目前定位：有實作深度的 Linux debugger 雛形／課程型作品，還不是可靠、可測試、可展示的工程作品。**

這個專案的價值不在程式碼行數，而在它確實接觸到 Linux debugger 的底層機制：`fork` / `exec`、`ptrace`、`waitpid`、x86-64 `INT3` breakpoint、RIP 修正、register 存取、`PTRACE_SYSCALL`、Capstone 反組譯，以及 `/proc/<pid>/mem` 記憶體修改。這些比單純 CRUD 專案更有 **Linux / OS / C++ systems** 辨識度。

但若面試官真的讀 code，當下最容易扣分的不是「你沒做 hardware watchpoint」，而是：

1. tracee 正常結束、收到 signal 或發生 ptrace error 時，狀態是否還正確？
2. breakpoint 的原始 byte、`0xCC`、RIP 與 debugger 內部索引是否始終一致？
3. `waitpid` 回來的 stop reason 是否有正確分類？
4. 程式執行與記憶體操作是否有 error checking、resource lifetime 管理？
5. 你如何證明以上機制在 PIE / non-PIE、異常結束與反覆 breakpoint 命中時都正確？

**優先方向：Correctness → Tests → Architecture → 一項有技術深度的功能 → Documentation。**

### 面試標準差距表

| 面向 | 目前公開程式碼 | 嚴格面試標準下的缺口 | 優先度 |
|---|---|---|---|
| Systems 核心 | 已有 ptrace、INT3、單步、syscall tracing、Capstone、patch | 應能完整解釋 lifecycle 與 trap 原理 | 保留強項 |
| 正確性 | 多條錯誤、signal、exit 路徑未完整處理 | 不得繼續存取已結束 tracee；stop reason 正確 | **P0** |
| Breakpoint | 兩套相似的暫停／恢復邏輯，狀態分散 | 一致性、可恢復、重複命中、可測試 | **P0** |
| 測試 | 未見 test／fixture／CI | 可重現的 ptrace 整合測試與 regression | **P0** |
| 架構 | 單一 `sdb.cpp`、大量 global state | 能說明明確的責任、生命週期與邊界 | **P1** |
| ELF / PIE | 直接讀固定 ELF header offset，搭配 `/proc/maps` 推算 base | 正確定義 ET_DYN / ET_EXEC / load bias | **P1** |
| 功能完整性 | 指令地址 breakpoint、沒有符號名稱／attach | 一項深挖功能，推薦 `break main` | **P1** |
| 可重現性 | 簡短 Makefile、沒有依賴安裝說明 | Linux x86-64 環境、測試指令、CI | **P1** |
| 履歷呈現 | Repo 首頁缺 README、架構、範例、測試證據 | 1 分鐘 demo、架構圖、技術挑戰 | **P1** |
| Performance | 無 benchmark | debugger 不必追求任意 speedup | **P2** |

---

## 1. 目前已經做出的功能：哪些應保留

以下是 **程式碼中確實看得到** 的功能，不代表已通過各種邊界情境驗證。

| 指令／函式 | 目前功能 | 值得展示的底層概念 |
|---|---|---|
| `load` / `load_program()` | `fork`、`PTRACE_TRACEME`、`execl`、等待初始 stop，試圖停到 entry point | tracer / tracee lifecycle、`exec` trap |
| `break`、`breakrva`、`delete` | 在指定位址寫入 `0xCC` 並管理 original byte | x86 software breakpoint、code patching |
| `si` | `PTRACE_SINGLESTEP` | instruction-level execution |
| `cont` | `PTRACE_CONT` | continue、trap handling |
| `syscall` | `PTRACE_SYSCALL` + `PTRACE_GET_SYSCALL_INFO` | syscall entry / exit stop |
| `info reg` | `PTRACE_GETREGS` | CPU register context |
| `disassemble()` | Capstone 反組譯、覆蓋顯示 breakpoint 原始 byte | x86-64 machine code 與 debugger 視圖 |
| `patch` | 寫入 tracee memory，嘗試與 breakpoint 保持一致 | memory modification / debugger state consistency |

**值得稱讚的一點：** `patch_memory()` 有注意到「被 `0xCC` 覆蓋的 breakpoint byte 不該直接被 patch 掉」，也就是它開始思考 *debugger-visible bytes* 與 *tracee memory bytes* 的區別。這個設計值得保留，但目前錯誤處理與一致性仍不足。

**建議保留範圍：** 先明確宣告支援 **Linux x86-64、單一 tracee／單一執行緒的 debugger**。不必在第一階段支援所有平台或假裝已經是 GDB 替代品。

---

## 2. P0 — 必修的正確性問題（新功能之前完成）

> 判定原則：會影響基本 debugger 正確性、tracee lifecycle、記憶體狀態或可重現驗證；**P0 不是說這些問題已全部在真機上重現**。

### SDB-001 — `run_si()` 在 tracee 結束後沒有停止後續操作

**位置：** [`sdb.cpp`](https://github.com/Mistbornk/SDB/blob/main/sdb.cpp) → `run_si()`、`end_process()`。

程式邏輯大致如下：

```cpp
if (WIFEXITED(status)) {
    end_process();
}
if (it != break_points.end()) put_bp(regs.rip);
ptrace(PTRACE_GETREGS, child_pid, 0l, &regs);
```

**為什麼是明確缺陷：** `end_process()` 已清除 `break_points` 並把 `child_pid` 改為 `-1`。其後仍繼續使用舊的 breakpoint iterator、存取 child registers、更新映射及 disassemble。此路徑含已失效 iterator 的使用風險，以及對無效 PID 的後續操作。

**修法：**

- `waitpid` 結果統一轉成 typed `TraceEvent`；`Exited` / `Signaled` 立即終止本次命令處理。
- 區分「tracee 已自然結束」與「使用者要求終止」：自然結束只要 reap / reset，不應再次 kill / wait。
- 所有 read-register、write-memory、disassemble API 必須要求有效且 stopped 的 tracee。

**驗收：** `si` 執行到程式結束，不 crash、不對 `pid=-1` 發 ptrace、不再顯示假的暫停資訊；之後能正常 `load` 新程式。

### SDB-002 — 缺少完整的 `waitpid` / signal / trap 分類

**位置：** `run_si()`、`run_cont_syscall()`、`wait_until_rip()`、`load_program()`。

程式主要檢查 `WIFEXITED(status)`，卻沒有全面處理：

- `waitpid()` 返回 `-1`（例如 `EINTR` / `ECHILD`）
- `WIFSIGNALED(status)`（tracee 被 signal 終止）
- `WIFSTOPPED(status)` + `WSTOPSIG(status)`
- ordinary `SIGTRAP`、breakpoint trap、single-step trap
- `SIGTRAP | 0x80` 的 syscall stop（已設 `PTRACE_O_TRACESYSGOOD`，但沒有充分利用）
- 使用者程式收到 `SIGSEGV`、`SIGILL`、`SIGUSR1` 時的處理與 signal forwarding

`run_cont_syscall()` 在非 breakpoint 的分支直接要求 `PTRACE_GET_SYSCALL_INFO`，但該次 stop **不一定是 syscall stop**；`cont` 也可能因 signal / trap 停下。`wait_until_rip()` 則是在 wait 後幾乎無條件做 `RIP -= 1`，必須先確認確實命中所設的臨時 INT3。

**修法：**

```text
waitpid(status)
    ├─ error
    ├─ Exited(exit_code)
    ├─ Signaled(signal)
    └─ Stopped
        ├─ SoftwareBreakpoint(address)
        ├─ SingleStep
        ├─ SyscallEntry / SyscallExit
        ├─ SignalDeliveryStop(signal)
        └─ PtraceEvent / UnknownStop
```

實作時搭配 `WIF*`、`WSTOPSIG`、`PTRACE_GETSIGINFO`、目前 resume mode、已安裝的 breakpoint 與必要的 ptrace event 資訊，**不要只靠 `RIP - 1` 推斷任何 `SIGTRAP` 都是自己設的 breakpoint**。

**驗收：** 每種 stop reason 有明確類型、輸出與測試；`SIGSEGV` 不被錯誤印成 syscall；指定要傳遞的 signal 可以正確送回 tracee。

Linux 參考：[ptrace(2) manual](https://man7.org/linux/man-pages/man2/ptrace.2.html)。

### SDB-003 — Breakpoint API 以 `uint8_t` 同時表示「原始 byte」和「錯誤」

**位置：** `put_bp()`、`set_break()`、`take_bp()`。

目前 `put_bp()` 失敗時 `return 0`，成功時也可能合法地讀到原始 byte `0x00`，而 `set_break()` 嘗試用下式判斷：

```cpp
uint8_t orig = put_bp(addr);
if (!orig && errno != 0) return;
```

**問題：** `0x00` 是合法的 machine-code byte，不能當失敗 sentinel；`errno` 也沒有在呼叫前清零，可能保留前一次系統呼叫的錯誤。此外，`pwrite()` 成功與否沒有檢查，失敗時仍可能把 breakpoint 登錄進 map。

**修法：**

- `put_bp` / `take_bp` 回傳明確的 `Result` / `std::optional` / `std::expected`（若採 C++23）或具體錯誤碼。
- 成功讀取原始 byte 及成功寫入 `INT3`，才可更新 debugger map。
- 寫入失敗須保持或回復原狀；breakpoint 移除失敗不能無條件清除內部紀錄。
- 以 `Breakpoint {id, address, original_byte, installed}` 統一儲存，不要讓兩張 map 成為兩套互相衝突的真相。

**驗收：** 可在原始 byte 為 `0x00` 的位址設 breakpoint；模擬 `open` / `pread` / `pwrite` 失敗時，內部狀態不與 tracee memory 脫鉤。

### SDB-004 — Breakpoint 的重複命中、單步、重新插入沒有共同的狀態機

**位置：** `run_si()`、`run_cont_syscall()`、`wait_until_rip()`。

現有程式在三個地方各自處理「移除 INT3 → 修正或取得 RIP → single-step → 插回 INT3」。雖然有部分共用 `put_bp` / `take_bp`，但控制流程並未真正統一。若 temporary breakpoint、普通 breakpoint、signal stop 或 step error 交錯，容易產生：

- breakpoint 沒有插回
- original byte 被誤覆蓋
- RIP 修正錯誤
- patch 後的 original byte 不一致
- tracee 結束時仍嘗試 restore breakpoint

**修法：** `BreakpointManager` 管理生命週期；所有 `continue` / `single-step` 都透過共用的 resume / step-over-breakpoint 函式。程式必須有 `installed` / `temporarily_disabled` 等可驗證不變條件。entry-point 的臨時 breakpoint 不應另寫一套不受管理的 patch 流程。

**驗收：** 同一個 breakpoint 被迴圈命中至少 10 次，輸出位置與 hit 次數正確；同位址單步再繼續、兩個 breakpoint 交錯與 patch-over-breakpoint 都正確。

### SDB-005 — 啟動程序及 ELF 載入流程對失敗情況不安全

**位置：** `load_program()`、`wait_until_rip()`、`is_dynamic_linked()`。

目前有幾個獨立風險：

- 不檢查 `fork()`、`PTRACE_TRACEME`、`waitpid()`、`PTRACE_SETOPTIONS` 的返回值。
- `execl()` 失敗後 child 離開，但 parent 仍可能把該 PID 標記為 `loaded`。
- 直接讀 ELF header 固定 offset，沒有驗證檔案大小、ELF magic、`EI_CLASS`、endianness、machine type、完整讀取量。
- `realpath(path.c_str(), real_path)` 失敗時，後續仍以 `real_path` 建構字串。
- `wait_until_rip()` 不確認真的在指定 entry breakpoint 停下，便假設要將 `RIP` 減一。

**修法：**

1. 先驗證檔案類型與 ELF metadata；給非 ELF、錯誤路徑可理解的錯誤。
2. 讓 parent 透過正確的 wait status 或 child error-reporting pipe 得知 exec 成功／失敗。
3. 將 `load` 視為具有成功／失敗狀態轉移的 transaction，失敗時完整 rollback。
4. 只有在確認 trap 來源是 entry breakpoint 時才修 RIP 並復原 byte。

**驗收：** 無效路徑、非 ELF、空檔案、無執行權限、child 很快結束時，都能保持 debugger 可繼續使用；不出現 stale PID / 假的 `loaded=true`。

### SDB-006 — 缺少自動化整合測試，無法證明底層機制正確

**位置：** repo 整體。

目前公開根目錄只有 `sdb.cpp`、`Makefile`、`.gitignore`；未見 `tests/`、fixture、GitHub Actions、README。對一般練習程式可以接受，對 **debugger side project** 不足。

**修法：** 在進行大規模 refactor 之前，先做最小的 automated integration test harness，最好加入 `--batch` / `--command-file`，讓測試能把 SDB 指令餵給 CLI 並檢查輸出／tracee 行為，而不是靠人工操作與肉眼觀察。

**驗收：** 具備下方第 5 節列出的核心測試矩陣，CI 可自動執行；如果 runner 不允許 ptrace，必須明確標示 skipped，不能把未執行測試呈現為通過。

---

## 3. P1 — 應補齊的穩健性與工程品質

| ID | 具體發現 | 問題與建議 | 可驗收結果 |
|---|---|---|---|
| SDB-007 | `is_instruction_boundary()` | 從任意位址讓 Capstone 成功解出一條指令，**不等於**證明它是原程式的合法 instruction boundary；x86 指令是可變長度。更嚴重的是忽略 `open/pread/cs_open` 失敗，且此函式沒有 `close(fd)`。應先修 resource/error，再重新定義為「可讀／可解碼候選位置」，別誇稱具備可靠指令邊界驗證。 | 非法記憶體位址不讀未初始化 buffer；大量 `break` 操作不洩漏 FD；文件誠實描述能力限制 |
| SDB-008 | `disassemble()` | `pread()` 只檢查 `nread <= 0`，但後續一律把 **64 bytes** 交給 `cs_disasm`，短讀時可能含未初始化 bytes；`cs_disasm` 產生的 `insn` 沒有看到對應的 `cs_free`，也未完整檢查 `cs_open`。 | 只反組譯實際讀到的 bytes；`cs_free` / `cs_close` 成對、壓測後無持續洩漏 |
| SDB-009 | `end_process()` | 自然結束後還呼叫 `kill()` 與 `waitpid()`；狀態清理未清 `id_map`；正常 EOF 離開 `main` 時未走 `q` cleanup。拆分 `terminate()`、`detach()`、`reset_state()`、`reap()`。 | 退出、重新載入、EOF/正常 q 都無 stale state；不向無效 PID 發 signal |
| SDB-010 | `patch_memory()` | 未確認 `pwrite()` 有完整寫入，卻先改動 `break_points` 內的原始 byte；若 write failed / partial write，內部狀態可能與記憶體不同。輸入 `stoul` 例外也未攔截。 | patch 失敗不會宣告成功； breakpoint overlay 與 patch 回復一致 |
| SDB-011 | CLI parser | `break`、`breakrva`、`delete`、`patch` 使用 `stoull/stoi/stoul`，對缺參數、非數字或越界資料可能丟出未捕捉例外，直接結束 debugger。 | 錯誤輸入只印 usage / error，CLI 可繼續互動 |
| SDB-012 | `collect_exec_regions()` | 只比對 `r-xp`，對其他 executable mappings 沒有明確策略；讀 `/proc/<pid>/maps` 與 ELF image 配對需要更穩健的映射模型。 | 能顯示與驗證實際 executable VMA；遇到其他 mapping perms 時行為明確 |
| SDB-013 | `is_dynamic_linked()` | 讀的是 `e_type == ET_DYN`，這是 **ELF 類型**，不是「是否 dynamic linked」；函式名稱與註解會誤導。`base_addr = mapping_start - file_offset` 也依賴常見 segment 配置，應依 `PT_LOAD` 與 runtime mapping 取得 load bias。 | PIE 與 non-PIE entry、符號位址正確，且以 `readelf` / `proc/maps` 交叉驗證 |
| SDB-014 | `run_cont_syscall()` | `static int sc_nr` 持續保存跨 session 值；syscall stop 沒有完整分類；假定 `regs.rip - 2` 是 syscall 指令位址只適用特定已知場景。 | entry/exit 可配對；signal stop 不印成 syscall；位址描述不超出實作證據 |
| SDB-015 | resource management | 多處手動 `open` / `close`、`cs_open` / `cs_close`、child lifecycle，缺少錯誤安全的資源管理。 | RAII FD / Capstone wrappers 與 error propagation；sanitizer / leak tests 過關 |
| SDB-016 | `.gitignore`、build | `.gitignore` 只有 `.DS_Store`；Makefile 可編譯，但沒有依賴說明、測試 target、release/debug/sanitizer 選項。 | 新環境可按 README 安裝 `libcapstone`、build、test；不誤提交 build artifacts |
| SDB-017 | 可用性 | `execl()` 不轉發目標程式參數；沒有 CLI `help`、script/batch mode、明確停止原因輸出或 restart flow。 | `sdb -- ./program arg1 arg2`、`help`、batch test、可理解的停止資訊 |

### 兩個容易被面試官抓到的細節

**（1）判斷「指令邊界」不是 `cs_disasm(addr, 1 instruction)` 就能解決。** 在 x86-64 中，從一個指令的第二個 byte 開始，有時仍可以解出另一條合法指令。若要嚴格驗證，需要可信的反組譯起始點與控制流程分析；對一般 debugger，接受使用者提供的 code address，並在文件說明限制，也比提供有誤導性的 `is_instruction_boundary()` 好。

**（2）ELF 的 `ET_DYN` 與「有使用動態連結」不是同一件事。** PIE executable 常是 ET_DYN；一個 dynamically-linked non-PIE executable 也可以是 ET_EXEC。這是很好的 Linux/ELF 面試追問題目。

---

## 4. P1 — 架構重整：重構成有意義的幾個元件即可

不建議把原本單檔硬拆成十幾個空殼 class。先針對「擁有資源」「維護不變條件」「分類事件」的責任抽模組：

```text
sdb/
├── CMakeLists.txt
├── README.md
├── LICENSE                 # 依實際授權意願選擇
├── include/sdb/
│   ├── tracee.hpp         # pid, lifecycle, ptrace wrappers
│   ├── trace_event.hpp    # waitpid/ptrace stop classification
│   ├── breakpoint.hpp     # INT3 lifecycle, original byte
│   ├── memory.hpp         # process memory access
│   ├── elf_image.hpp      # ELF + module load bias + symbols
│   └── debugger.hpp       # coordinator / public commands
├── src/
│   ├── main.cpp
│   ├── command_parser.cpp
│   ├── tracee.cpp
│   ├── breakpoint.cpp
│   ├── memory.cpp
│   ├── elf_image.cpp
│   ├── disassembler.cpp
│   └── debugger.cpp
├── tests/
│   ├── fixtures/
│   └── scripts/
├── docs/
│   ├── architecture.md
│   ├── breakpoint-lifecycle.md
│   └── testing.md
└── .github/workflows/ci.yml
```

### 必須守住的抽象邊界

- **Tracee / ProcessSession：** 擁有 PID 與 lifecycle；不能在 `Exited` 狀態呼叫 register/memory API。
- **TraceEvent：** 將 `waitpid` / ptrace events 分類為 typed event；不讓 CLI 自己解析 raw status。
- **BreakpointManager：** 唯一管理 breakpoint ID、位址、original byte、是否安裝及 step-over 流程；包含 entry temporary breakpoint。
- **ProcessMemory：** 唯一實作受控的 memory read/write 與錯誤傳遞；避免散落的 `/proc/<pid>/mem` 路徑和 FD。
- **ElfImage / SymbolResolver：** 管理 ET_EXEC/ET_DYN、load bias、symbol RVA/VA/runtime address；不在 command handler 裡猜地址。
- **CLI：** 僅做參數解析與輸出；不直接調 `PTRACE_SETREGS`。

### 需要明文紀錄的 invariants

1. Tracee 只有在 stopped 且 PID 有效時，才能讀寫 regs/memory。
2. 每個啟用中的 software breakpoint 有且只有一筆 ID/address/original byte 紀錄。
3. Breakpoint `installed=true` 時，目標位址記憶體是 `0xCC`；停用／step-over 時應可還原正確的 original byte。
4. `Exited` / `Signaled` event 後不再讀 tracee 的 regs/memory。
5. `load` 失敗必須留下 `Unloaded` 狀態，不能半初始化。
6. `delete`、`patch`、`step-over` 失敗必須顯示錯誤，並明確維持／回復可證明的一致狀態。

---

## 5. P0/P1 — 必須加入的測試矩陣

先完成一個最小的 `--batch` 模式，避免腳本依賴互動 prompt。測試要查 **實際 program 行為**，而不是只 grep `** hit a breakpoint` 字串。

| 測試類別 | 具體案例 | 期待結果 | 等級 |
|---|---|---|---|
| launch | 正常 ELF、PIE executable | 成功停在正確 entry point | P0 |
| launch failure | 不存在路徑／不可執行檔／非 ELF | 不 crash、不假裝 loaded | P0 |
| termination | tracee 正常 `exit(0)` | 合法 reset，沒有額外 ptrace | P0 |
| termination | signal termination | 正確列出 signal 與 lifecycle | P0 |
| `si` | 從指令執行到 tracee exit | 不再使用已清理 PID/iterator | P0 |
| stop reason | `SIGSEGV`、`SIGILL`、`SIGUSR1` | 不與 breakpoint/syscall 混淆 | P0 |
| breakpoint | 原始位址 byte 是 `0x00` | 能設置、命中、刪除與還原 | P0 |
| breakpoint | 相同位址重複 `break` | 不產生兩筆或重覆改寫 | P0 |
| breakpoint | 同一 breakpoint 在迴圈中命中十次 | 每次 RIP 與原指令皆正確 | P0 |
| breakpoint | 同時設置兩個 breakpoint | 命中順序／ID／restore 正確 | P0 |
| step over | 命中 breakpoint 後 `si` → `cont` | 執行原指令一次、重新安裝 INT3 | P0 |
| patch | patch 與 breakpoint 同一位址 | 刪除 breakpoint 後保留新 byte | P0 |
| patch failure | 無效位址、短寫、無效 hex | 不更新錯誤的 internal state | P0 |
| parser | 空參數、非法 hex、過大整數 | 印 error，CLI 持續運作 | P1 |
| ELF | `-no-pie` vs `-fPIE -pie` | runtime address 與 `readelf` / maps 一致 | P1 |
| disassembly | executable mapping 邊界附近 | 不讀未初始化資料、不越界 | P1 |
| resources | 連續 disassemble / set breakpoint 多次 | FD 數與 heap allocations 無持續增長 | P1 |
| lifecycle | 程式結束 → 新 `load` | 不殘留舊 breakpoint ID、base、PID | P1 |
| syscall | 連續 syscall entry/exit | pair 正確；signal stop 不混入 | P1 |
| attach / detach | 有實作才測 | detach 後 tracee 正常運作、無 `0xCC` 遺留 | P1（功能完成時） |

**測試 fixture 建議：** `exit_zero.c`、`loop.c`、`signals.c`、`syscalls.c`、`pie_target.c`、`nonpie_target.c`、`invalid_elf.bin`、`patch_target.S`。使用 tiny C/assembly fixtures 能讓 RIP / machine-byte 預期更精確。

**CI 建議：** `ubuntu` Linux x86-64、安裝 Capstone / CMake / C++ compiler，先 build → unit tests → ptrace integration tests。部分 runner 的 ptrace 權限／seccomp 可能阻擋特定測試，必須記錄 environment 限制，不要把 skipped 說成 passed。Attach 類測試可能比「trace 自己 fork 的 child」更容易受 kernel policy 影響。

---

## 6. 新功能應該加什麼？依面試投資報酬排序

### 第一推薦：ELF symbol-aware breakpoints（`break main`）

**原因：** 這個功能可以把現有的 `ptrace`、breakpoint、ELF parser、PIE load bias 連成完整技術敘事，而且面試 demo 易懂。

預期互動：

```text
sdb -- ./tests/fixtures/target
(sdb) break main
(sdb) info break
(sdb) cont
** breakpoint hit: main ...
(sdb) info reg
(sdb) si
```

最低要求：

- 讀取 ELF `.symtab` / `.dynsym`，區分符號不存在與 stripped binary。
- 正確計算 **runtime address = ELF symbol value + load bias**（對 ET_EXEC / ET_DYN 分別處理；不要盲目一律加 base）。
- 在 ASLR 開啟下驗證 PIE 每次 runtime 地址可能不同，且皆能命中 `main`。
- `break main`、`break <address>` 並存；文件清楚界定支援範圍。

**不要一開始就做 DWARF source-line debugger。** `break file.cpp:42` 的 parsing、line table、address-to-line、inline functions、unwinding 會顯著擴大 scope。

### 第二推薦：Attach / detach

- `attach <pid>`：整合 `PTRACE_ATTACH` 或 `PTRACE_SEIZE`；注意 stop 手續、權限及 Yama `ptrace_scope`。
- `detach`：先還原所有 software breakpoint 與必要 process state，再 `PTRACE_DETACH`；tracee 必須能正常繼續。
- **注意：** 目前使用 `fork + PTRACE_TRACEME` 的模型相對單純；attach 是新的 lifecycle 分支，應在 stop-event、breakpoint correctness 完成後才加。

### 第三推薦：Hardware watchpoints（進階加分）

- 使用 x86-64 DR0–DR7 偵測資料存取。
- 清楚處理 debug register 數量、長度／對齊、read/write 模式及 trap type。
- 要有真正的 fixture 驗證；**不可把反覆輪詢記憶體稱作 hardware watchpoint**。

### 第四推薦：簡化 backtrace（進階加分）

- 可先實作對 `-fno-omit-frame-pointer` fixture 的 frame-pointer stack walking。
- 要檢查 stack address 的讀取安全與 frame chain termination。
- 文件清楚註明不支援 FPO、tail calls、某些 optimized binary／exception frame；完整 DWARF unwinding 屬另一個大專題。

### 暫時不建議優先做

- **多執行緒 debugger：** ptrace 是 per-thread，需管理 TID、clone events、每個 thread 的 stop status 與 breakpoint 恢復競態，整體複雜度大增。
- **CUDA / OpenMP / 平行化：** debugger 的核心難點是事件與狀態正確性，強行平行化不會自然帶來履歷價值。
- **任意「效能提升 X%」：** 若瓶頸主要在 ptrace context switch，微優化 std::map 無說服力。
- **複製 GDB 的所有指令：** 功能廣度會搶走時間，卻不一定改善你最需要的正確性證據。

---

## 7. 實作順序：建議拆成 6 個可審查的 PR / Codex milestones

### M0 — Baseline 與再現性（先做）

- [ ] 新增 README（目前功能清單、Linux x86-64、Capstone 依賴、build / run）
- [ ] 建立 CMake 或完善現有 Makefile（不用為了 CMake 而重構）
- [ ] 加入小型 C/asm fixtures、batch mode 與至少 5 個 smoke/regression tests
- [ ] 記錄現有已知缺陷與可重現步驟；不把 static suspicion 說成已重現

**DoD：** 新 checkout 可照文件完成 build；CI/本機能自動測基本 `load`/`break`/`cont`/`si`/`exit`。

### M1 — Tracee state / wait-event 正確性（最高優先）

- [ ] 改用 `TraceEvent` 分類 `waitpid` outcome
- [ ] 正確處理 `WIFSTOPPED`、`WIFEXITED`、`WIFSIGNALED`、ptrace/syscall trap
- [ ] `run_si()` 在 exit 後立即 return，清除 dangling iterator / invalid PID 使用
- [ ] 統一正常結束、terminate、detach、reset 的狀態轉移
- [ ] 處理 child `exec` failure / invalid executable

**DoD：** 退出與 signals 測試通過；不再把 signal-stop 當 syscall。

### M2 — Breakpoint / Memory 正確性

- [ ] Breakpoint map 改為單一權威資料結構
- [ ] 明確 error-aware read/write API，移除 `0` sentinel / stale errno 判斷
- [ ] 一條共用 `step_over_breakpoint()` 流程
- [ ] entry temporary breakpoint 也走同一管理器
- [ ] 修好 patch 原始 byte 與失敗 rollback
- [ ] 解決 FD / Capstone resource leak、partial read / write

**DoD：** 重複 hit、delete、patch、短讀、錯誤寫入、資源壓測通過。

### M3 — 封裝與可維護性

- [ ] 抽離 Tracee、TraceEvent、BreakpointManager、Memory、Disassembler、CLI
- [ ] 移除 `child_pid` / `loaded` / `status` 等可避免的全域共享狀態
- [ ] `-Wall -Wextra -Wpedantic` 等檢查（依工具鏈逐步開啟）
- [ ] sanitizer、clang-format（風格一致即可，非重點）
- [ ] 文件新增狀態機／breakpoint lifecycle 圖

**DoD：** CLI 不直接接觸 ptrace；系統功能可由 integration tests 驗證。

### M4 — 一項真正的深入新功能

- [ ] ELF header / PT_LOAD parser 與 load-bias model
- [ ] `.symtab` / `.dynsym` 解析
- [ ] `break main` 或 `break <symbol>`
- [ ] PIE / non-PIE / ASLR 自動驗證

**DoD：** 連續數次執行 PIE，`break main` 都能停在正確函式位置；對 stripped binary 給合理錯誤。

### M5 — 面試與履歷交付

- [ ] GitHub Actions：build + unit/integration tests（依實際 ptrace 權限註記）
- [ ] README：features / limitations / architecture / command examples / demo
- [ ] `docs/breakpoint-lifecycle.md` 說明 INT3、trap、RIP-1、restore、step、reinsert
- [ ] `docs/engineering-decisions.md` 說明選擇 `/proc/pid/mem` vs `PTRACE_PEEK/POKE`、PIE 解析、resource ownership
- [ ] 60–90 秒 demo：load → break symbol → cont → info reg → si → graceful exit
- [ ] 用實際數據補測試案例數、CI 結果、記憶體／FD leak 檢查結果

**DoD：** 陌生工程師讀完 README 可重現 demo，面試官能從設計文件追問核心問題。

---

## 8. README 必備內容（面試官／HR 第一眼會看到）

建議標題：**SDB — Linux x86-64 Debugger in C++**。

README 至少包含以下章節：

1. **Overview**：限定 Linux x86-64，說明是為學習 Linux tracing 與 debugger internals 實作。
2. **Features**：將「已實作並驗證」與「Planned / Experimental」分開。
3. **Architecture**：CLI → Debugger → Tracee + BreakpointManager + Memory + ELF + Disassembler。
4. **How It Works**：用圖說 `INT3` breakpoint lifecycle。
5. **Build & Run**：Linux distro、compiler、Capstone version/套件、command。
6. **Demo**：shell commands + 預期輸出；若使用 screenshot / GIF，必須與實際程式一致。
7. **Testing**：test commands、fixture 類型、CI constraints、已驗證平台。
8. **Engineering Challenges**：signal-stop 分類、PIE load bias、breakpoint state consistency、partial memory read/write。
9. **Limitations**：單執行緒、Linux x86-64、符號支援限制、受 ptrace 權限政策影響。
10. **Development / Attribution**：如源自課程或參考教學，清楚標示原始背景與後續獨立擴充內容。

**不要**只放「Implemented a Linux debugger with ptrace」。README 要證明你懂得 *why/how/limitations*。

---

## 9. 面試官可能直接追問的 10 題

以下每題都值得能搭配你自己的 code/測試解釋：

1. **Software breakpoint 為什麼是 `0xCC`？** x86 `INT3` 的行為與 RIP 為什麼要回退 1 byte？
2. **如何避免 breakpoint hit 後陷入無限迴圈？** 說明 original byte restore → single-step → reinsert 的時序。
3. **`SIGTRAP` 一定是 breakpoint 嗎？** 如何區分 software breakpoint、single-step、syscall stop 和其他 trap？
4. **`PTRACE_TRACEME` 和 `PTRACE_ATTACH` 有何不同？** 權限、停止與 detach lifecycle。
5. **`waitpid()` 的 `WIFEXITED`、`WIFSIGNALED`、`WIFSTOPPED` 分別表示什麼？** 失敗時怎麼辦？
6. **PIE / ASLR 怎麼影響 breakpoint 位址？** `ET_DYN`、ELF symbol value 與 runtime load bias 的關係。
7. **Capstone 能證明指令邊界嗎？** 為什麼從任意 byte 解出指令不代表原始指令流從那裡開始？
8. **你如何保證 patch 與 breakpoint 不互相破壞？** original byte 與目標 memory 哪一個是 authoritative？
9. **使用 `/proc/<pid>/mem` 有哪些限制？** 要如何處理開檔失敗、partial reads/writes、target exit？
10. **你如何驗證 debugger 的正確性？** 具體拿出 fixtures、stop-event tests、PIE/non-PIE、FD leak check、CI，而不是只說「我手動試過」。

**履歷加分在於回答深度與測試證據，而不是指令數量。**

---

## 10. 履歷怎麼寫（只能寫完成後真正具備的成果）

### 現階段建議定位

**SDB — Educational Linux Debugger (C++17, ptrace, Capstone)**

如果 P0/P1 尚未修好，不建議把它包裝成 production-grade debugger；可作為 technical coursework / personal systems project，著重已完成的 Linux tracing 與 breakpoint mechanisms。

### 完成 M0–M5 後可參考的英文履歷敘述（須依實際成果調整）

> **Linux x86-64 Debugger | C++17, ptrace, Capstone**  
> - Built a Linux x86-64 debugger supporting software breakpoints, single-step execution, register inspection, disassembly, and syscall tracing using `ptrace`.  
> - Refactored tracee lifecycle and breakpoint management into explicit stateful components, with automated integration tests covering signals, process termination, and repeated breakpoint hits.  
> - Implemented ELF symbol resolution and PIE/ASLR-aware function breakpoints; validated behavior using reproducible Linux test fixtures.

**重要：** 後兩個 bullet 是「完成後才可使用」的候選文案；目前公開 repo 尚無足夠證據支持它們。若取得可驗證結果，可以再加測試數量、支援平台或實際測得指標。

---

## 11. 交付驗收總清單（可以直接當 Codex issue checklist）

### P0：沒做完不建議當履歷主專案

- [ ] `run_si()`、`cont`、`syscall` 不會在 tracee exit 後操作失效的 PID / iterator
- [ ] `waitpid` / `SIGTRAP` / syscall / signal stop 有明確且經測試的分類
- [ ] `load` 對 invalid path、exec failure、非 ELF 有正確恢復機制
- [ ] breakpoint 原始 byte、INT3 插入／移除、RIP、patch 狀態一致
- [ ] memory / ptrace / Capstone 重要 API 都有回傳值與資源管理
- [ ] 最基本自動化 integration tests 已能重複執行

### P1：做完才有強的 systems portfolio 呈現

- [ ] 全域狀態已封裝，CLI / tracee / breakpoint / memory / ELF 責任分離
- [ ] PIE/ASLR entry & runtime address 有可重現測試
- [ ] 有一項代表性深入功能：首選 `break <symbol>`
- [ ] `README.md` 有 setup、commands、架構、demo、限制
- [ ] CI 正確執行並記錄 pass / skip 結果
- [ ] 具備清楚 attribution、LICENSE 選擇與不含 build artifacts 的 repo

### P2：有餘裕再加

- [ ] attach / detach
- [ ] hardware watchpoint 或受限條件下的 backtrace
- [ ] syscall names / args decoding
- [ ] thread-aware debugging（不是單純啟用 std::thread）
- [ ] 可測量且確實有價值的 syscall / disassembler overhead 分析

---

## 12. 最後的工程取捨

若專案目的是 **C++ / Linux Systems 面試**，我建議把最終 scope 收斂成：

> **一個對 Linux x86-64 單一 tracee 可靠運作、具有 software breakpoint、single-step、register inspection、syscall tracing、Capstone disassembly、PIE-aware ELF symbol breakpoint，並有完整 regression tests 的小型 debugger。**

這樣比「支援 30 種指令但 exit/signal 會出錯」更有說服力。**不要優先追求平行化或空泛的效能優化**；這個專案最適合展示的是 **OS primitives、狀態機、resource ownership、low-level correctness、debugging methodology、test engineering**。

### 原始參考

- [GitHub repository](https://github.com/Mistbornk/SDB)
- [sdb.cpp](https://github.com/Mistbornk/SDB/blob/main/sdb.cpp)
- [Makefile](https://github.com/Mistbornk/SDB/blob/main/Makefile)
- [Linux `ptrace(2)` manual](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [Linux `/proc/<pid>/maps` manual](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)

*本報告只針對 2026-10-13 審查時可讀取到的公開 main 程式碼；未驗證未公開分支、尚未推送的修改或實際執行結果。*
