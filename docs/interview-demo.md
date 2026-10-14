# 面試演示：追查被運費覆寫的訂單金額

這個三至五分鐘案例呈現 SDB 如何診斷實際記憶體寫入。訂單金額應保持 100，運費應為 7；
錯誤版本把運費寫到金額欄位。兩個 pointer 都指向有效、對齊的 `uint64_t`，所以不會因
segmentation fault 自動指出問題。硬體 write watchpoint 用來找出是哪條指令寫錯位置。

以下是可重播命令；2026-10-14 已於本機與原生 CI 驗證，保存的
[完整 transcript](validation/2026-10-14-hardening/interview-demo.log) 包含錯誤與修正兩次執行。
重播時 runtime address 可能不同，harness 會檢查當次實際結果。

## 準備

在已建置 SDB 的 Linux x86-64 環境執行。公開 Dockerfile 與 Colima 的差異見
[README](../README.md#開發環境)。以 Make 的 `./sdb` 為例；CMake build 可替換 executable 路徑。

```sh
cc -std=c11 -Wall -Wextra -O0 -g -fno-omit-frame-pointer \
  -fno-optimize-sibling-calls -fPIE -pie tests/fixtures/interview_order.c -o /tmp/sdb-order
```

fixture 使用 PIE，位址每次可能不同，因此所有設定與記憶體查詢都透過 ELF symbols。
`-O0`、frame pointer 與禁止 sibling-call optimization 讓四層呼叫鏈容易重現。
這些條件是目前 RBP backtrace 的適用範圍，不代表 DWARF 或任意最佳化程式的完整 unwind。

## 1. 重現症狀（約 30 秒）

```sh
/tmp/sdb-order bug
```

預期印出 `INVOICE_TOTAL=7 SHIPPING_FEE=0`，target 退出碼為 3。此時可先說明：
運費被寫到了錯的欄位；需要找到寫入位置，而非只在結束前觀察最後數值。

## 2. 找出寫入與呼叫者（約兩分鐘）

```sh
./sdb -- /tmp/sdb-order bug
```

依序輸入以下命令；它們也保存在 [interview-bug.sdb](../tests/scripts/interview-bug.sdb)。

```text
set disassemble off
info environment
x/8 @invoice_total
x/8 @shipping_fee
watch @invoice_total 8
cont
bt 8
x/8 @invoice_total
x/8 @shipping_fee
delete watch 0
cont
q
```

觀察與說明：

- 初始金額 bytes 是 `64 00 00 00 00 00 00 00`；小端序的 `0x64` 就是十進位 100。
- `watchpoint 0 hit` 表示 DR0–DR3 的硬體 write watchpoint 已捕捉寫入。這類 trap 發生在
  寫入指令完成後，停止時金額已是 `07 00 00 00 00 00 00 00`。
- `bt` 前四層依序為 `store_fee`、`record_shipping`、`process_order`、`main`，各自帶 runtime
  address 與 symbol offset。`store_fee` 當前 RIP 位於其 frame 已建立的函式本體。
- 運費仍是 0；回頭看 [fixture](../tests/fixtures/interview_order.c) 的 `record_shipping`，
  問題是傳入 `&invoice_total`，正確目的位址應是 `&shipping_fee`。
- 繼續後 target 明確以 status 3 結束。SDB 本身的命令都成功，所以 debugger exit code 為 0；
  harness 會分別檢查這兩個結果。

這段演示沒有 software breakpoint，也沒有 `si`；DR7 啟用時只使用 `cont`。
因此不會要求 QEMU TCG 執行不安全的 single-step/watchpoint 組合。

## 3. 驗證修正（約一分鐘）

fixture 的 `fixed` 模式選擇正確目的位址；函式與呼叫鏈維持相同。執行：

```sh
./sdb --batch tests/scripts/interview-fixed.sdb -- /tmp/sdb-order fixed
```

此 script 同時監看 `invoice_total`（ID 0）與 `shipping_fee`（ID 1）。預期只命中
watchpoint 1；停止時金額仍為 100、運費為 7。移除 watchpoints 並繼續後，target 輸出
`INVOICE_TOTAL=100 SHIPPING_FEE=7`，並以 status 0 結束。

## 自動驗收與講解重點

```sh
python3 tests/interview_demo.py ./sdb --show-output
```

harness 會在暫存目錄建置同一個 PIE fixture，先檢查未追蹤的錯誤與修正版本，再使用上述
兩份 batch scripts 驗證 watchpoint ID、呼叫鏈、四次記憶體觀察、target 輸出與退出碼。
`--show-output` 印出當次已驗證的 transcript；不帶此選項適合 CTest。只有獨立 ptrace 環境
probe 不可用時回傳 77；錯誤結果、逾時或 sanitizer diagnostic 都會失敗。

面試時應能從此案例往下解釋：

- software breakpoint 的 `INT3`、RIP−1、原 byte 恢復與 reinsertion，為何不同於本例的
  hardware data breakpoint。
- 硬體四槽、長度與對齊限制，以及為何 watchpoint trap 的 RIP 已經越過寫入指令。
- ELF virtual address 加 load bias 如何成為 PIE runtime address。
- RBP chain 的驗證邊界：遞增、對齊、stack mapping、frame 上限；遇到最佳化或 signal frame
  時不能承諾完整呼叫鏈。
- 這次演示證明的是實際寫入被捕捉與修正後的觀察結果；多執行緒共享 INT3、信號與 detach
  回復流程有各自的整合測試，見 [testing.md](testing.md)。
