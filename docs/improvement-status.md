# SDB_improve.md 需求對照

`SDB_improve.md` 保留原始審查背景；本文件將實作位置、驗證與能力界線分開記錄。
執行結果以 [testing.md](testing.md) 的最新驗證為準，不把測試檔存在等同測試通過。

面試前 hardening 包含 debugger 訊號處理、零釋放 detach rollback、實際 executable inode
解析與可重播 demo。來源 commit `37c1e96` 已通過本機 Debug、Release、ASan/UBSan 各
11 組 CTest，以及[原生 GitHub Actions 四組工作](https://github.com/Mistbornk/SDB/actions/runs/38536434814)。
本機每組執行 68 個 Python 方法、另有 1 個 TCG skip；原生每組 69 個方法全部執行，
兩種環境均通過兩段 interview demo。完整來源雜湊與紀錄見 [testing.md](testing.md)。

原生 CI 曾抓到延遲 terminal SIGINT 重複停止；新增 mask fixture 後，又重現跨 breakpoint
與單步時遺失 correlation 的問題。最終修正保留 correlation 至 SIGINT 交付並重新檢查
process group；兩次修改前的失敗證據與最終通過紀錄均保留。

## P0 / P1：SDB-001 至 SDB-017

| 項目 | 實作 | 驗證 |
|---|---|---|
| 001：exit 後失效 PID / iterator | typed terminal events、清理 session、跨 resume 保留值而非 iterator | 單步到 exit、斷點 step 遇 exit、reload |
| 002：wait / trap / signal 分類 | Tracee 集中分類；逐 task pending signal；exec/terminal 優先於過期 peer stops | SIGSEGV/SIGILL/SIGUSR1、原生 INT3、syscall、step、thread lifecycle |
| 003：原 byte 0 與錯誤 | original_byte 不作 error sentinel；所有系統呼叫 checked | zero-byte breakpoint；open/pread/pwrite fault injection |
| 004：共同斷點狀態機 | Debugger 共用 displaced-instruction path，all-stop peers | 10 次 loop hit、兩個斷點、step/cont、12 次共享 thread hit |
| 005：安全載入 | ELF 驗證、gated fork/SEIZE/exec、CLOEXEC error pipe；exec 後開啟實際 `/proc/TID/exe` | 無效路徑、非 ELF、空檔、不可執行、失敗後再次 load；unlinked/replaced/memfd image |
| 006：整合測試 | batch mode、C/assembly fixtures、Python command sessions | `integration.py`、`extensions.py`、CTest、CI script |
| 007：候選地址與 FD leak | executable VMA 驗證、RAII FD；不宣稱 instruction-boundary proof | 無效位址、150 次 breakpoint/disasm/delete 與 FD 數比較 |
| 008：Capstone 短讀與資源 | 實際 byte count、VMA 邊界、cs_free/cs_close | executable page 邊界、ASan/LSan |
| 009：清理與重新載入 | owned terminate/reap、borrowed detach、q/EOF 與受控 TERM/HUP/INT；零釋放失敗回復 | EOF、controlled signal cleanup、external tracee SIGKILL/reload、detach fault injection |
| 010：patch 一致性 | 完整 snapshot、短寫 rollback、成功後更新 metadata | patch-over-breakpoint、partial write、rollback failure |
| 011：錯誤輸入 | from_chars、arity、數值界限、quote/escape parser | malformed/overflow/缺參數後 CLI 繼續操作 |
| 012：映射權限 | 解析全部 mappings，以 x/w flags 分別驗證 patch/write | maps、executable boundary、non-writable write 拒絕 |
| 013：ELF / PIE | ELF64 x86-64 header/PT_LOAD、同一 FD 的 bytes/dev/inode、集中 load bias | PIE/non-PIE、nm/readelf/proc、dl_iterate_phdr/AT_ENTRY；pathname replacement 與 memfd |
| 014：syscall 配對 | 每 TID 的 GET_SYSCALL_INFO、切換模式清除過期 pair | 多 worker 配對、signal 插入、reload、breakpoint 上 syscall |
| 015：resource ownership | RAII FD/Capstone/Tracee；mutation rollback | fault injection、FD stress、ASan/UBSan/LSan |
| 016：build / artifacts | CMake、Make、warnings、sanitizers、clang-format、gitignore | Debug/Release/sanitizer、format check、Make test |
| 017：CLI 可用性 | target argv、help、batch、restart、history、停止原因、interactive Ctrl-C | argv/quoted path、batch stdin/file、restart PIE relocation、PTY interrupt 與回到 prompt |

## M0–M5 交付位置

- M0：原版 `01aeec7` 的六組 baseline 與 `tests/baseline.py`；README build/run；fixtures 與 batch。
- M1：`tracee.hpp/.cpp`、`trace_event.hpp`、task lifecycle tests。
- M2：`breakpoint.cpp`、`memory.cpp`、共用 step-over、fault injection tests。
- M3：`include/sdb` / `src` 模組、CMake warnings/sanitizers、`.clang-format`、架構與 lifecycle 圖。
- M4：`elf_image.cpp`、`.symtab/.dynsym`、`break main`、PIE/non-PIE runtime cross-check。
- M5：`.github/workflows/ci.yml`、共用 `scripts/ci.sh`、README、設計文件、`tests/scripts/demo.sdb`、實測紀錄。
- 面試交付：公開 Ubuntu 24.04 Dockerfile、`docs/interview-demo.md` 與同一組 batch scripts 的自動驗收。

原生 CI 的 Debug、Release、ASan/UBSan 與公開 Ubuntu 24.04 Docker Release 四組已通過，
保存 logs、JUnit 與 pass/fail/skip 摘要。公開 image 工作從 Dockerfile 與 checkout 建置，
不依賴個人的 `up25_image`；原生結果來自上述實際 CI run，與本機 TCG 證據分別記錄。

## P2 與 AGENTS.md 的進階要求

| 功能 | 實作與可重现驗證 | 界線 |
|---|---|---|
| Attach / detach | SEIZE 全部 tasks，還原 INT3/DR；零釋放錯誤回復可重試、partial release 失敗終止 | 需既有 kernel ptrace 權限；SIGKILL/crash 無法保證恢復外部程序的 INT3 |
| 硬體 watchpoints | DR0–DR3/DR6/DR7、實際 store/access traps、四槽與長度、clone 傳播；TCG 保護可恢復，native 合併 trap 已於 CI 執行 | `watch` 寫入、`awatch` 讀寫；x86 無純 read-only。QEMU TCG 禁止資料 watchpoint 與 single-step／EFLAGS.TF 同時執行 |
| Backtrace | 有界 RBP chain、函式符號+offset、壞 chain 測試 | frame pointer/prologue/epilogue/signal frames 限制；不是 DWARF |
| Syscall names/args | 常用 native x86-64 names/args、bounded escaped previews、未知 ABI/number 明示 | 非完整 strace；未知 pointer 不阻止繼續執行 |
| 真正 task-aware debugging | 每 TID 的暫存器、signals/syscall pairs、clone/exit、選擇 task、all-stop、共享斷點 | 單一程序；fork/vfork/non-thread clone 只做安全清理與 detach，不 follow |
| Memory / register commands | `x[/count]`、`write`、`register read/write`、PIE data symbols | memory bytes 用 hex string；整數 registers，無 SIMD/FPU |
| CLI 品質 | restart、history、auto-disassembly toggle、target argv、batch、受控 Ctrl-C/TERM/HUP | session history 上限 256；沒有 readline、shell expansion 或完整 job control |
| Performance | `scripts/benchmark.py`、相同 200-syscall fixture、7 輪原始資料與 median | 量測含 tracing/格式化/VM 成本，不捏造單一 Capstone speedup |
| License / attribution | 作者授權選擇 MIT；`LICENSE`、README 背景與參考來源 | Capstone 仍是外部相依套件 |

原計畫明列 optional 的 source-level DWARF、共享函式庫符號解析與完整 GDB 相容命令不在這次承諾範圍。
所有可宣稱的功能與限制以 README、測試及上述文件交叉對照。

`info environment` 會顯示 TCG 的 watchpoint/single-step 限制。本機測試將 native 合併
TF/watchpoint 案例明確列為 scenario skip，同時實測保護機制會保留 RIP、INT3 與 all-stop
狀態，移除 watchpoint／清除 TF 後可繼續。GitHub 的原生 x86 runner 另外使用
`SDB_REQUIRE_NATIVE_WATCHSTEP=1`，已在上述四組工作實際執行合併 trap 案例且沒有 skip；
本機保護測試與原生執行證據分開保存。詳細依據見 [task-debugging.md](task-debugging.md)。
