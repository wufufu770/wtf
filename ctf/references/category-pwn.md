---
verified: "2026-10-15 | 本地复跑：gcc 13（Linux 容器）编译 x86-64 PIE ELF 实测，见条目1复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "CTF-wiki（pwn 章节）、0rangec3t/Black-cat 五段式范式、M2 实测复跑（2026-10-15）"
changelog:
  - "[2026-10-15] 初始空壳，等待首个回流条目"
  - "[2026-10-15] v0.2：条目模板升级为五段式假设条目 + 机器可校验裁决词（REFLIGHT 回流协议，见 ../../shared/REFLIGHT.md）"
  - "[2026-10-15] v0.3：M2 填充 4 条（verified 1 / inconclusive 1 / hypothesis 2）"
  - "[2026-10-16] v0.4：「升级」字段边化——跳转目标改 [[条目名]] 图边引用（REFLIGHT §3）"
---

# 题型：Pwn

> 读取时机：附件为 ELF/内核镜像等二进制利用题（栈/堆/ROP/格式化字符串条目主库）

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态：verified=最近一次复现日期+环境；source=条目主要出处；changelog 追加一行/次，不删除历史。
4. **失败样本优先回流**：refuted 条目必须附 FAIL 复跑记录、失败原因与"下一步转哪个新假设"，失败样本优先级高于成功经验。
5. verified/refuted/inconclusive 条目必须附复跑记录表（格式见 ../../shared/REFLIGHT.md §4）；未经复跑的条目状态只允许 hypothesis。
6. 工具具体用法归 ../../shared/tools/ 对应文件，此处不重复（去重原则）；五段式的「验证步骤」只保留最小可执行命令骨架。
7. 本文件超过 100 行时，在本节下方补 TOC 目录。

## 条目区（TOC）

1. [格式化字符串 %p 泄露栈数据](#格式化字符串-p-泄露栈数据)（verified）
2. [栈溢出偏移定位（cyclic 模式）](#栈溢出偏移定位cyclic-模式)（hypothesis）
3. [ret2libc 两段式利用](#ret2libc-两段式利用)（hypothesis）
4. [内核 pwn（qemu + rootfs）](#内核-pwnqemu--rootfs)（inconclusive）

### 格式化字符串 %p 泄露栈数据
- **假设**：程序把用户输入直接作为 printf 第一参数（`printf(user_input)`）→ 输入 `%p %p %p...` 可逐个泄露栈上数据（返回地址/canary/栈指针），第 6 个 `%p` 起越过 printf 自身寄存器参数进入调用者栈帧。
- **验证步骤**：
  ```bash
  ./vuln "%p %p %p %p %p %p %p %p"   # 无参数注入环境时直接命令行试
  # 命中字符串型线索时改 %s，定位偏移后用 %N$s / %N$n 精确读写
  ```
  本机实测（2026-10-15，自编译 64 位 PIE）：8 连 `%p` 输出中第 2 个为栈上明文片段（`0x78305f5952414e41` = 小端 "ANAR0x"），第 8 个命中全局字符串起始（`0x435f544552434553` = "SECRET_C"）。
- **判定标准**：PASS = 输出中出现栈地址/预期泄露值；FAIL = 程序过滤了 `%` 字符或用 `printf("%s", input)` 固定格式。
- **裁决词**：PASS
- **来源**：M2 实测复跑（evidence T7）；CTF-wiki 格式化字符串漏洞
- **升级**：定位到可写 GOT 的偏移后转 `%n` 任意写（新假设，待回流建条目）；配合 [[gdb + GEF/pwndbg 插件]] 确认偏移。
- **关键差异**：x86-64 前 5 个 `%p` 落在寄存器参数（RSI/RDX/RCX/R8/R9），要从第 6 个开始数栈——按 32 位经验从 `%1$p` 数会偏。

### 复跑记录（verified / refuted / inconclusive 必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 本地 gcc 自编译 ELF（x86-64 PIE） | `./t7_fmt "%p %p %p %p %p %p %p %p"` | PASS | evidence/T7-fmtstr | 第 8 参数命中 "SECRET_C" 小端明文 |

### 栈溢出偏移定位（cyclic 模式）
- **假设**：输入超长导致 segfault 且无栈保护回显 → 用 De Bruijn 序列（pwntools `cyclic`）填充后读 crash 时 RIP/RSP 指向的 4/8 字节，反查即得返回地址偏移。
- **验证步骤**：1) `cyclic 200` 作为输入跑程序至 crash；2) dmesg/调试器取 RIP 值；3) `cyclic -l <RIP值>` 得偏移。
- **判定标准**：PASS = 反查得到稳定偏移且用 `b'A'*偏移 + b'BBBB'` 复跑 RIP=0x4242424242424242；FAIL = 偏移不稳定（考虑alloca/vla 动态栈）。
- **裁决词**：待复跑
- **来源**：CTF-wiki 栈溢出；pwntools cyclic 文档
- （可选）**关键差异**：无 pwntools 环境可手写 De Bruijn 生成脚本替代，勿用纯 'A' 填充（无法反查偏移）。

### ret2libc 两段式利用
- **假设**：NX 开启但无 PIE 且 libc 版本已知/可下载 → 第一次溢出泄露 puts@got 解析值，用 `libc_base = leak - libc.symbols['puts']` 算基址，第二次溢出调 `system("/bin/sh")`。
- **验证步骤**：1) ROPgadget 找 `pop rdi; ret`；2) payload1 = 填充 + pop_rdi + puts_got + puts@plt + main；3) 接收 6 字节地址算 base；4) payload2 = 填充 + ret(对齐) + pop_rdi + binsh + system。
- **判定标准**：PASS = 拿到 shell（`id` 回显 uid）；FAIL = base 计算错（检查低 12 位页内偏移应与目标 libc 一致）。
- **裁决词**：待复跑
- **来源**：CTF-wiki ret2libc
- （可选）**关键差异**：64 位 Ubuntu 18.04+ 记得栈对齐（多垫一个 `ret`），否则 `system` 内 movaps 崩——报错不在 payload 长度。

### 内核 pwn（qemu + rootfs）
- **假设**：附件为 `bzImage + rootfs.cpio + start.sh` 的内核题 → 需本地 qemu 起内核调试（`-s` 开 gdb stub），攻击面通常在 LKM 驱动的 ioctl（UAF/越界/竞态）。
- **验证步骤**：1) `file` 确认 rootfs 格式后 cpio 解包看 init 与驱动；2) qemu 按 start.sh 启动 + gdb 远程调试；3) 对驱动逆向定位 ioctl 命令字与结构体。
- **判定标准**：PASS = qemu 内提权至 root（读 flag 文件成功）；FAIL = 驱动漏洞点判断错误。
- **裁决词**：INCONCLUSIVE
- **来源**：CTF-wiki kernel pwn
- （inconclusive 缺口清单）本机无 qemu-system、无 gdb、无内核题样本附件；无法复跑。下次遇到内核题附件时按上述步骤补验证。

### 复跑记录（verified / refuted / inconclusive 必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 无内核环境（本机缺 qemu/gdb） | 未执行 | INCONCLUSIVE | - | 缺口：qemu-system-x86_64 + gdb + bzImage/rootfs 样本 |
