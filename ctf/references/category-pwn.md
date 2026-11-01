---
verified: "2026-10-15 | 本地复跑：gcc 13（Linux 容器）编译 x86-64 PIE ELF 实测，见条目1复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "CTF-wiki（pwn 章节）、0rangec3t/Black-cat 五段式范式、M2 实测复跑（2026-10-15）"
changelog:
  - "[2026-11-02] v0.7：蒸馏 P4 批次并入 6 条（binary_exploitation 主标 + 隐写批次路由 1（FSB 栈泄露），hypothesis 待复跑；07 审阅 + 08 修正批已归零）｜源：ctf-corpus/distill/by-category/pwn/p4-20261030.md + candidates.jsonl（P4 批次报告 06、审阅报告 07、修正简报 08）"
  - "[2026-10-30] v0.6：蒸馏 P3 批次并入 6 条（中段困难档·薄域优先，hypothesis 待复跑）｜源：ctf-corpus/distill/by-category/pwn/p3-20261029.md + candidates.jsonl（P3 批次报告 02） + 修正批同步（46 修正批涉已入库条目，pilot/04-修正简报）（本文件 9 处）"
  - "[2026-10-29] v0.5：蒸馏 P1+P2 批次并入 15 条（hypothesis 待复跑，REFLIGHT §1 二手知识纪律）｜源：ctf-corpus/distill 候选池（candidates.jsonl）+ distill/pilot/01-蒸馏批次报告-P2-20261029.md"
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
5. [自定义浮点 stack guard 固定常量回填 + ret2stack shellcode](#自定义浮点-stack-guard-固定常量回填-ret2stack-shellcode)（hypothesis）
6. [「勿信补丁」修复覆盖面验证纪律](#勿信补丁修复覆盖面验证纪律)（hypothesis）
7. [泄露旧源码 ≠ 现役二进制](#泄露旧源码-现役二进制)（hypothesis）
8. [栈溢出活跃元数据零填充与循环计数收敛](#栈溢出活跃元数据零填充与循环计数收敛)（hypothesis）
9. [rand() 未播种的服务端门禁（SSL 回显可预测）](#rand-未播种的服务端门禁ssl-回显可预测)（hypothesis）
10. [只读文件系统的 nc 代理流式投递](#只读文件系统的-nc-代理流式投递)（hypothesis）
11. [unlink 利用（P→P-0x18 自写指针 + GOT 覆写）](#unlink-利用pp-0x18-自写指针-got-覆写)（hypothesis）
12. [glibc rand() 状态恢复（z3 约束求解 31 状态字）](#glibc-rand-状态恢复z3-约束求解-31-状态字)（hypothesis）
13. [PIE 部分覆盖（页内低位改写跳转 + 固定地址跳板）](#pie-部分覆盖页内低位改写跳转-固定地址跳板)（hypothesis）
14. [VM 寄存器索引截断越界（16-bit 无符号折返 + seccomp 打父进程）](#vm-寄存器索引截断越界16-bit-无符号折返-seccomp-打父进程)（hypothesis）
15. [自研分配器 1 字节 footer 覆盖（块链伪造 + GOT 覆写）](#自研分配器-1-字节-footer-覆盖块链伪造-got-覆写)（hypothesis）
16. [整数溢出尺寸 + realloc 一致性检查逃逸（失败样本）](#整数溢出尺寸-realloc-一致性检查逃逸失败样本)（hypothesis）
17. [栈溢出 GOT 改写 + 全局字符串作参（Unix socket 报送）](#栈溢出-got-改写-全局字符串作参unix-socket-报送)（hypothesis）
18. [\0 截断对抗 ROP（pop4ret 跳板 + dynELF 补 libc）](#0-截断对抗-roppop4ret-跳板-dynelf-补-libc)（hypothesis）
19. [相邻变量覆写改认证标志（authenticated 旁路）](#相邻变量覆写改认证标志authenticated-旁路)（hypothesis）
20. [假 cookie 猜想排除 + off-by-one 造 unlink（printf 泄漏走偏）](#假-cookie-猜想排除-off-by-one-造-unlinkprintf-泄漏走偏)（hypothesis）
21. [top chunk 随机化 + calloc 清零下的 unsorted bin 泄漏（error 路径触发 malloc_hook）](#top-chunk-随机化-calloc-清零下的-unsorted-bin-泄漏error-路径触发-malloc_hook)（hypothesis）
22. [off-by-null 溢出打 BSS 指针数组（money 连续添加 + 索引无校验）](#off-by-null-溢出打-bss-指针数组money-连续添加-索引无校验)（hypothesis）
23. [stdout FILE 结构改写打 tcache（write_base 定点 + 部分覆写改 size）](#stdout-file-结构改写打-tcachewrite_base-定点-部分覆写改-size)（hypothesis）
24. [括号语言深度语义推理（absorb/combine 形式文法自动化）](#括号语言深度语义推理absorbcombine-形式文法自动化)（hypothesis）
25. [SUID 相对设备路径 + IOCTL 失败信息泄露（dev/console 缺斜杠）](#suid-相对设备路径-ioctl-失败信息泄露devconsole-缺斜杠)（hypothesis）
26. [32 位 FSB 逐偏移 %p 链读栈上 flag（无写原语纯泄露）](#32-位-fsb-逐偏移-p-链读栈上-flag无写原语纯泄露)（hypothesis）
27. [内核堆 off-by-one 劫持 freelist + modprobe_path 提权（SMEP/SMAP 全开）](#内核堆-off-by-one-劫持-freelist--modprobe_path-提权smepsmap-全开)（hypothesis）
28. [ELF 段清零对抗（.data/.rodata 清零 + .text 清零两条路）](#elf-段清零对抗datarodata-清零--text-清零两条路)（hypothesis）
29. [引用计数双删 UAF（brief 扩容重用 + GOT 泄露 + formatter 劫持）](#引用计数双删-uafbrief-扩容重用--got-泄露--formatter-劫持)（hypothesis）
30. [KVM 虚拟机管理程序逃逸（guest 内核漏洞 → host 堆利用）](#kvm-虚拟机管理程序逃逸guest-内核漏洞--host-堆利用)（hypothesis）
31. [VM 字节码引擎逃逸（swap2_stack 栈指针越界改写）](#vm-字节码引擎逃逸swap2_stack-栈指针越界改写)（hypothesis）

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

### 自定义浮点 stack guard 固定常量回填 + ret2stack shellcode
- **分层**：简单档·可复现强
- **假设**：checksec 报「No canary found」但程序自造 stack guard（以浮点数存储）⇒ guard 是二进制内**固定常量**而非每次随机 → 溢出时按原字节回填即绕过；NX disabled + 程序主动打印缓冲区地址 ⇒ shellcode 落栈、ret 指向 buf 的直接 ret2stack。
- **验证步骤**：1) `checksec`（确认 NX/PIE/canary 三项）；2) IDA 定位自造 guard 的 8 字节浮点常量（如 0x405015 5547 5a31 a5 系，按小端记录）；3) payload = shellcode.ljust(buf_size,'a') + guard 原字节 + padding + buf_addr 小端；4) nc 交互后 `cat flag`。
- **判定标准**：PASS = 回填 guard 后程序正常走到 ret 并执行 shellcode；FAIL = guard 每次随机（真 canary 语义）→ 转泄漏型（格式化字符串等）。
- **裁决词**：待复跑
- **来源**：CSAW 2015 precision（pwn 100p，272 solves）｜p4｜raw/github-repos/p4/2015_csaw_e_precision.md（完整 socket exploit 与 guard 字节 'a5315a4755155040' 在 WP；checksec 输出随附）
- **陷阱备注**：「自造 canary」≠ canary——先看常量是否运行期固定，固定则只是回填题。

### 「勿信补丁」修复覆盖面验证纪律
- **分层**：超级难档·失败样本/陷阱
- **回流优先级：refuted 候选**——「厂商修复 commit/公告 = 漏洞已消除」假设被 WP 证伪：Valve 第一版 fix 只修了第一处 `Get()` 调用、被报告的第二处（真正的报告点）未覆盖；待复跑转正。
- **假设**：已修复版本上仍可能利用——修复常只覆盖公告引用的调用点之一；以**二进制 diff 验证每个危险触点**（fix 前后两版函数对比 + 交叉引用列出全部同类调用）为准，不信 commit message 与新闻口径。
- **验证步骤**：1) 取 fix 前后两版二进制；2) 定位补丁函数（bindiff/符号差）；3) xref 列出全部同类危险调用（如全部 `Get(buf, len)` 点）；4) 逐点验证未覆盖处可否仍触发。
- **判定标准**：PASS = 找到至少一个未修复调用点并稳定触发；FAIL = 全部触点已覆盖（真修完 → 转新漏洞挖掘）。
- **裁决词**：待复跑
- **来源**：Real World CTF 2018 Quals P90 Rush B｜perfect blue（未在赛内解出，赛后两天完成利用）｜raw/github-repos/perfectblue/2018_realworldctf_x_p90-rush-b.md（结论段 "never trust a fix. Always verify it actually fixes the bug!"）

### 泄露旧源码 ≠ 现役二进制
- **分层**：超级难档·失败样本/陷阱
- **回流优先级：refuted 候选**——「公开泄露的旧源码（2007 年 CS:GO leak）可直接定位现役漏洞点」假设被 WP 证伪：补丁只落二进制、源码与线上脱节，队耗时主要损耗于此；待复跑转正。
- **假设**：利用现役二进制时以逆向为准、泄露源码只作命名/结构参考：先对关键函数做「源码 vs 反编译」diff，**差异处（补丁痕迹）优先审计**——补丁修复常不完整，正好引出相邻未修点。
- **验证步骤**：1) 逆目标函数；2) 与泄露源码同名函数 diff；3) 差异处判修复语义；4) 沿差异点找同类未修调用。
- **判定标准**：PASS = 在源码-二进制差异处找到可达漏洞；FAIL = 源码与二进制完全对齐（可直接读源码省时）。
- **裁决词**：待复跑
- **来源**：Real World CTF 2018 Quals P90 Rush B｜perfect blue｜raw/github-repos/perfectblue/2018_realworldctf_x_p90-rush-b.md（"We could have saved a lot of time by just opening the binary up in IDA"——比赛环境没带 IDA 转而信泄露源码是直接损失原因）

### 栈溢出活跃元数据零填充与循环计数收敛
- **分层**：超级难档·失败样本/陷阱
- **假设**：溢出会覆盖**仍在使用**的栈上元数据（结构体字段/文件长度/循环计数）时，0x41 填充破坏运行语义导致先崩在劫持点之前 → 改**零填充**（NULL 引用解引用少、循环边界归零）；循环以「文件数」计数的（`nCentralDirectoryEntries_Total`），把计数收敛到 2、在第 2 次迭代触发溢出后立刻满足退出条件 → 溢出即函数尾部即控制流劫持点。
- **验证步骤**：1) 引用追踪定位溢出后仍被读取的栈槽；2) payload 对应区段置 0 / 还原原值；3) 循环计数字段调至最小迭代数；4) 前置检查（如 fileLen 上限）用尾部零填充绕过；5) ret 前保留必要指针，ROP 接管。
- **判定标准**：PASS = 程序语义保持稳定到达 EIP 控制点；FAIL = 崩溃在劫持前 → 回读崩溃点栈槽继续修正（迭代收敛）。
- **裁决词**：待复跑
- **来源**：Real World CTF 2018 Quals P90 Rush B｜perfect blue｜raw/github-repos/perfectblue/2018_realworldctf_x_p90-rush-b.md（"a lot of metadata on the stack that is still being used"→零填充；"nCentralDirectoryEntries_Total holds the number of files"→ 置 2 即溢出+退出循环）
- **陷阱备注**：0x41414141 填充是默认习惯，活跃元数据场景它是崩溃源——先问「这块栈后面还被谁读」。

### rand() 未播种的服务端门禁（SSL 回显可预测）
- **分层**：超级难档·失败样本/陷阱
- **回流优先级：refuted 候选**——「SSL 服务须攻击 TLS 层（MITM/密钥恢复）」假设被 WP 拆穿：handler 门禁 = `rand()` 未播种的回显匹配，连上回填即过；待复跑转正。
- **假设**：SSL 门禁题先审 handler 业务逻辑再碰密码学层：Ghidra 反编译 `main/init/handler`，识别 `rand()`/`time()` 类未播种熵源 → 门禁可预测（连接即回显"随机"数，原样回填即得旗）。
- **验证步骤**：1) 反编译定位 handler 主体；2) 查 `rand()` 调用前有无 `srand(time(NULL))`（WP 反编译注释 "this value is NOT seeded!"）；3) 连接读回显 → atoi 后回填 → 收旗。
- **判定标准**：PASS = 回显匹配即得旗；FAIL = rand 已播种 → 转攻 SSL 实现/协议层。
- **裁决词**：待复跑
- **来源**：Dragon CTF 2020 babyshell（242p，38 solved）｜p4｜raw/github-repos/p4/2020_dragonctf_x_babyshell.md（非预期解：作者预期 shellcode 题，解者走 SSL 门禁）

### 只读文件系统的 nc 代理流式投递
- **分层**：超级难档·失败样本/陷阱（环境纠错链样本）
- **假设**：靶机 rootfs 只读（`mount -o remount,ro /`）+ 工具贫瘠（无 openssl、nc 无 PATH symlink 但 `/bin/busybox nc` 可用）时，本地工具栈经 **nc 管道代理**进靶机：服务端起 `(while true; do base64 -d; done) | /bin/busybox nc 127.0.0.1 4433`，本地 pwntools 双 socket 对接转发。
- **验证步骤**：1) `stty -echo` 关回显（否则回显污染流）；2) base64 分块流式传（规避 nc stdin 关闭时机问题）；3) 特殊字节损坏（如 `\x10` 变 `\x16`）用 `| xxd -c1` 修正；4) 本地端同步解 base64 写目标 socket。
- **判定标准**：PASS = 代理完成完整 TLS 会话并收旗；FAIL = 字节流损坏 → 三查（回显污染 → -echo；stdin 提前关闭 → while-read 循环；坏字节 → 换 \xNN 转义）。
- **裁决词**：待复跑
- **来源**：Dragon CTF 2020 babyshell｜p4｜raw/github-repos/p4/2020_dragonctf_x_babyshell.md（"Part 2: The struggle" problems #1/#2/#3 逐条纠错记录——p4 明言 "skipping here loooong hours spent on debugging"）——**典型多步失败-修正链，失败样本密度最高的正文段之一**

### unlink 利用（P→P-0x18 自写指针 + GOT 覆写）
- **分层**：困难档·经典原语
- **假设**：存在可控堆指针数组（全局 `box[i]` 指向堆块）且可溢出伪造 chunk 头 → 造 `FD=P-0x18、BK=P-0x10`（P 为指针数组自身地址）→ 触发 free 合并时 unlink 检查 `FD->BK==P && BK->FD==P` 自洽 → unlink 后 `P` 处指针被改写为 `P-0x18` → 经该指针二次写入达成对指针数组/GOT 的任意写（atoi→system + 传 `/bin/sh`）。
- **验证步骤**：1) 定位指向堆的全局指针 P；2) 溢出写假 chunk（prev_size/size=F 地/”fd=P-0x18, bk=P-0x10"）；3) 触发向后合并（改下一块 prev_inuse=0）；4) unlink 自洽校验过 → `box[i]` 读回；5) 二级写覆盖 GOT。
- **判定标准**：PASS = unlink 自洽通过且 GOT 覆写后拿到 shell；FAIL = libc 2.26+（safe-unlinking 检查差异）→ 转 [[栈溢出偏移定位（cyclic 模式）]] 之外的 off-by-null / tcache 路线。
- **裁决词**：待复跑
- **来源**：kxctf 2017 Puzzle 4（pwn）｜六星战队（sixstars）｜raw/github-repos/sixstars/2017_kxctf_h_solve.md（完整 exp 与 unlink 布局在 WP；本地同版 libc 可重放）
- **陷阱备注**：题设 PIE——需先经随机数预测（见下条）拿 .bss 段堆指针地址，unlink 的 P 才能算出。

### glibc rand() 状态恢复（z3 约束求解 31 状态字）
- **分层**：困难档·状态恢复
- **假设**：服务端用 `glibc rand()`（无播种偏差）且「猜错给出当前随机数」回显 → r[i] = Σ state[j]·输出（31 个 32 位状态字、等价线性递推）→ 采 ≥93 个连续输出建 z3 线性约束 → 解出全部状态并预测下一输出（以及 seed 地址类派生泄露）。
- **验证步骤**：1) 采集错误回显序列（≥93）；2) 按 glibc TYPE_3 递推建立 SMT 约束；3) solver 解状态；4) 预测下一次输出对拍；5) 用预测换 seed/.bss 地址。
- **判定标准**：PASS = 预测值与实际逐次一致并换得地址泄露；FAIL = 输出不足 93 → 继续采集；版本差异（musl/旧版 libc）→ 重推递推式。
- **裁决词**：待复跑
- **来源**：kxctf 2017 Puzzle 4（pwn）｜六星战队（sixstars）｜raw/github-repos/sixstars/2017_kxctf_h_solve.md（z3 脚本骨架在 WP；本地 C 程序可完整复现）
- **关联**：知识锚 = 上条 unlink（同一题双阶段）；与 [[格式化字符串 %p 泄露栈数据]] 同属「先泄露再利用」族——区别在泄露源是伪随机输出流。

### PIE 部分覆盖（页内低位改写跳转 + 固定地址跳板）
- **分层**：困难档·概率利用
- **假设**：溢出长度被截断到恰好能改返回地址低 2 字节（无完整地址泄露时）→ 页对齐使高 12 位不变 → 覆盖后落点在 ±1 页内：①目标函数与被覆盖返回点同段近邻 → 直接低 2 字节跳目标（成功率 1/1，若同 64 KiB 窗口则 1/16）；②需稳定 gadget 落点 → 跳 `0xffffffffff600000`（vsyscall 入口，内核映射固定且可执行）作 ret 跳板。
- **验证步骤**：1) 测溢出可用字节数（返回地址偏移后余量）；2) 计算目标/落点同页差；3) 覆写低 2 字节（小端）；4) 多次运行统计命中率；5) vsyscall 入口选 `0xffffffffff600000`（入口而非 +9 的指令中段）。
- **判定标准**：PASS = 概率命中拿到 shell/旗；FAIL = 窗口不含目标 → 需先泄露（%p/puts）再全量覆写；vsyscall 被模拟层禁止（`vsyscall=none`）→ 转其他固定映射。
- **裁决词**：待复跑
- **来源**：hack.lu 2015 hackme｜sixstars 仓库（wp2 行）｜raw/github-repos/sixstars/2015_hack-lu_h_writeup.md（源码+概率分析在 WP；本地同参数 gcc 可复现）；姊妹证据：SunshineCTF 2019 Return_To_Mania（welcome 地址 printf 泄露 + 低 2 字节跳 mania，同页内差 0x90）｜Dvd848（S1 扩容源）
- **陷阱备注**：部分覆盖本质是用「放弃高位」换「免泄露」——两案例分别走 1/16 概率与固定跳板两条补偿路径。

### VM 寄存器索引截断越界（16-bit 无符号折返 + seccomp 打父进程）
- **分层**：困难档·复合链
- **假设**：自研 VM 的栈/内存以「寄存器值作索引」且寄存器宽 16 bit → 索引按 half-word 计可达 VM 栈外（0x68/2、0xa8/2 等偏移）→ 越界读泄露 PIE/libc、越界写改 main 返回地址；子进程 seccomp=STRICT（仅 exit/sigreturn/read/write）拿不了 shell → 攻击面转父进程：父进程从共享内存按「前 2 字节尺寸」memcpy → 控制尺寸/内容使父进程溢出（ROP 链无限长）。
- **验证步骤**：1) 定位 VM 栈基址与寄存器宽；2) readstack/write 越界偏移试算（泄露 PIE@0x68、libc@0xa8）；3) 改子进程返回走 sigreturn ROP；4) 构造共享内存 2 字节尺寸 + ROP 内容；5) 父进程 memcpy 触发。
- **判定标准**：PASS = 父进程接管 shell；FAIL = 尺寸边界被截断（0x40 一类对齐检查）→ 换 0x90 等非 2 次幂尺寸（WP 实测卡点）。
- **裁决词**：待复跑
- **来源**：MidnightSun CTF 2019 Quals hfs-vm2（pwn 660p，14 solved）｜perfect blue（战队）｜raw/github-repos/perfectblue/2019_midnightsun-ctf-quals_h_hfs-vm2.md（VM 指令语义与两段 exp 在 WP；需自建父子进程同构）
- **陷阱备注**：WP 记录卡点——memcpy 尺寸 0x40 反复失败、0x90 成功：非对齐尺寸的边界行为要用实测而不是猜（典型「环境细节反直觉」失败样本）。

### 自研分配器 1 字节 footer 覆盖（块链伪造 + GOT 覆写）
- **分层**：困难档·结构对抗
- **假设**：自研内存管理器块头/尾各 8 字节（`size|used` 位）且分配存在 1 字节越界（覆盖本块 footer 低字节）→ 反向遍历（coalesce）用 footer 算前块指针 → 篡 footer 低字节 = 伪造前块大小 → 合并时指针错位产出「前后重叠块」→ 双指针引用同一数据 → 覆写 Wisdom 对象函数指针/GOT（strcmp→system + /bin/sh）。
- **验证步骤**：1) 读 mm.c 确认 header/footer 语义与双向遍历点；2) 构造 1 字节覆盖值（size 低位+used bit）；3) 触发 free 使 coalesce 吃到伪造 footer；4) 用重叠块写函数指针；5) 调 strcmp('...')→system('/bin/sh')。
- **判定标准**：PASS = 拿 shell；FAIL = footer 校验（size 一致性/对齐）拦下 → 转正向遍历面的溢出。
- **裁决词**：待复跑
- **来源**：TUCTF 2017 Temple（pwn 500p，49 solved）｜perfect blue (战队)｜raw/github-repos/perfectblue/2017_tuctf_h_temple-500.md（mm.c 与利用序列在 WP；本地可全重放）

### 整数溢出尺寸 + realloc 一致性检查逃逸（失败样本）
- **分层**：困难档·失败样本/陷阱（**refuted 优先回流**）
- **假设**：32 位下 `65535×65536` 乘法溢出使请求尺寸回绕 → 覆盖堆内容可控（假 chunk + 指针改写）；但 realloc 路径上 libc 检查「当前 chunk 尺寸合法性」与「分配状态一致性」→ 传统 unlink/假 chunk 路径被卡（WP 作者卡死未出，赛后复盘 flappy pig 队走「realloc 失败返回大地址写」绕开全部检查）。
- **验证步骤**：1) 复现整数溢出改写点；2) 假 chunk + unlink 尝试并记录被拦检查清单；3) 复测「realloc 失败→返回极小地址/大地址」路径的可用写原语；4) GOT 改写收尾。
- **判定标准**：PASS = 复现「unlink 被检查拦截」与「失败路径成写原语」双记录；FAIL = 环境 libc 无该检查差异 → 记录版本对照。
- **裁决词**：待复跑
- **来源**：ISG 2015 dict（pwn）｜六星战队（sixstars）｜raw/github-repos/sixstars/2015_isg_h_writeup.md（含完整失败路径与赛后他人解法对照；卡点段为高价值失败样本）
- **陷阱备注**：本条知识主体是「检查清单」——malloc/realloc 的 size/used 一致性检查在堆已乱时几乎必然触发，别硬冲 unlink；先枚举「失败返回值能否当写原语用」。

### 栈溢出 GOT 改写 + 全局字符串作参（Unix socket 报送）
- **分层**：困难档·经典原语
- **假设**：Unix domain socket 服务读入定长字段可溢出而二进制无 libc 可泄 ⇒ 覆写 `system@GOT`（atoi/system 族改写点）并以程序内已有全局字符串（`/bin/sh` 同型）作参数——ret 布局为 [padding(含 '\xff'×20 保前 16 字节无 \0)][system@GOT][nops][binsh_addr]，经 socket 发 payload length + payload 两段协议投递，起 shell 后回连取 /tmp/shopkey。
- **验证步骤**：1) 定 LEN_TO_RET 与 GOT 地址；2) 构造不含前置 \0 的填充（\xff 兜底）；3) l32 序列化地址；4) socket 发 l32(len)+payload；5) nc -l 收文件。
- **判定标准**：PASS = 回连收到旗文件；FAIL = ASLR/PIE → 转部分覆写或泄漏原语。
- **裁决词**：待复跑
- **来源**：GeekGame 360 信息安全大赛 2015 80（pwn）｜六星战队（中国）｜raw/github-repos/sixstars/2015_geekgame-360_h_writeup.md（完整 exp 与本地复现条件在 WP；本地 32 位环境可重放）
- **关联**：与 [[栈溢出偏移定位（cyclic 模式）]] 的进阶位——定位后本题增量在「无 libc 场景用现成 GOT 目标 + 全局字符串」与「Unix socket 双段协议」投递。
- **陷阱备注**：Q1 归位说明——按栈溢出实类归 pwn（选材线记 misc 合集归类）。

### \0 截断对抗 ROP（pop4ret 跳板 + dynELF 补 libc）
- **分层**：困难档·经典原语
- **假设**：64 位 read→copy 溢出但 copy 遇 `\0` 截断而 ROP 链地址必含 \0 ⇒ 用无 \0 的前 16 字节覆盖到返回地址改写为 pop4ret（一次 pop 四个寄存器跳过不可控区），把真正的链放在「截断点之后已被读入的缓冲」里；无 libc ⇒ dynELF 以泄漏函数逐页扫 ELF 头建 mini-got，再回填 system。
- **验证步骤**：1) cyclic 定偏移；2) 前 16B 纯可打印覆盖 + pop4ret 地址（无 \0 的程序内 gadget）；3) 截断点后放置完整 ROP；4) dynELF 泄漏/写回两段式。
- **判定标准**：PASS = 链执行拿到 shell；FAIL = gadget 含 \0 → 换地址半字节对齐的 pop 变体。
- **裁决词**：待复跑
- **来源**：RCTF 2015 welpwn（PWN 200）｜六星战队（中国）｜raw/github-repos/sixstars/2015_rctf_h_writeup.md（思路要点在 WP；现代环境建议 ret2csu 化重放）
- **关联**：[[ret2libc 两段式利用]] 的无 libc 前置版——dynELF 是「泄漏→建表→回填」三段式的时间换空间。
- **陷阱备注**：Q1 归位说明——按栈溢出实类归 pwn（选材线记 ai/RCTF 合集归类）。

### 相邻变量覆写改认证标志（authenticated 旁路）
- **分层**：困难档·单点
- **假设**：`username[USERNAME_LEN]` 却按 `read(PASSWORD_LEN)` 读入（长度错配溢出）而 PIE/Full RELRO 封死地址型利用 ⇒ 目标转为栈上紧邻的 `authenticated` 标志变量——溢出量精确覆盖其低位非零 → print_flag 路径放行。
- **验证步骤**：1) checksec 确认防护矩阵；2) 反汇编量 username 与 authenticated 相对偏移；3) read 定长填充至该偏移并写非零；4) 触发登录流程收旗。
- **判定标准**：PASS = 认证旁路出旗；FAIL = 变量间有 canary/粘合 → 换栈上其他控制标志。
- **裁决词**：待复跑
- **来源**：Technion Ducky Debug Duck 2021 Flag_Server（pwn 100p）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2021_flag-server-md_h_flag-server.md（偏移与 payload 在 WP；本地同构秒级重放）
- **关联**：与 [[栈溢出活跃元数据零填充与循环计数收敛]] 互补——该条讲「为何会漏填」，本条讲「高防护下最优目标从地址退化为数据标志」。

### 假 cookie 猜想排除 + off-by-one 造 unlink（printf 泄漏走偏）
- **分层**：困难·多段链
- **假设**：Gamebox 登录声称随机 cookie 防伪造，但程序自己用 printf 打印了 cookie（可逐条取出对应会话），随机化是假防线；真正漏洞在读取名称时的 off-by-one：可覆写下一 chunk 的 size 字段，与 P2 unlink 经典原语衔接实现任意写。
- **验证步骤**：1) 读程序流程确认 cookie 由固定文件读出（24B/条）而 printf 直接输出；2) 定位 off-by-one 写点（长度输入差一）；3) 构造 chunk 布局使 size 覆盖进可控 chunk；4) unlink 改 GOT/函数指针收官。
- **判定标准**：PASS = 链路全通拿到 shell/flag；FAIL = 在猜 cookie 上耗时（假随机陷阱）或 off-by-one 覆盖成非法 size 触发 abort。
- **裁决词**：待复跑
- **来源**：强网杯 2018 Gamebox｜六星战队（中国）｜raw/github-repos/sixstars/2018_qiangwangbei_h_qiangwangbei.md（EXP 脚本与 unlink 布局全量在 WP）
- **关联**：与 [[unlink 利用（P→P-0x18 自写指针 + GOT 覆写）]] 同核心原语；假防线甄别与 [[rand() 未播种的服务端门禁（SSL 回显可预测）]] 共享「先证伪再利用」纪律。

### top chunk 随机化 + calloc 清零下的 unsorted bin 泄漏（error 路径触发 malloc_hook）
- **分层**：困难·多段链
- **假设**：babyheap 反常规三件套：初始 top chunk 地址随机化（防 House of Orange 类）+ calloc 申请（清零已用内存，泄不了残留）+ off-by-one 改 size 伪造 chunk 走 unlink；libc 泄漏改走「切分 unsorted bin 把 arena 指针写进可打印 chunk」；最终因可用 gadget 不足，转用触发堆分配 error——libc error 信息函数内部调用 strdup→malloc，间接跳 malloc_hook 上 gadget。
- **验证步骤**：1) off-by-one 改下一 chunk size 成大块；2) free 造 unsorted bin，申请分割使 main_arena 指针落入可读 chunk 并输出；3) fastbin fd 指向 malloc_hook 附近伪造（对齐 0x7f 检查）；4) 主动触发堆 error 走 strdup 分配路径。
- **判定标准**：PASS = arena 地址可读且 error 路径成功触发 gadget；FAIL = 直接 malloc 触发（gadget 不可用）或 calloc 清零后仍想拿残留指针。
- **裁决词**：待复跑
- **来源**：RCTF 2018 babyheap｜六星战队（中国）｜raw/github-repos/sixstars/2018_rctf_h_rctf2018.md（三阶段思路全量在 WP）
- **关联**：与 [[unlink 利用（P→P-0x18 自写指针 + GOT 覆写）]] 共享 unlink 原语；unsorted bin 泄漏与 [[stdout FILE 结构改写打 tcache（write_base 定点 + 部分覆写改 size）]] 互为 2.23/2.27 两代 libc 泄漏路线；error 路径触发与 [[相邻变量覆写改认证标志（authenticated 旁路）]]共享「绕过前置条件换触发面」思路。

### off-by-null 溢出打 BSS 指针数组（money 连续添加 + 索引无校验）
- **分层**：困难·多段链
- **假设**：shoppingcart 的 edit 存在单 \x00 溢出且索引无边界检查：连续 add money 二十次把 BSS 上指针数组推满，令相邻堆指针以 \x00 截位，实现「指针整体改小」；再借索引负数/超界读与 edit 配合，得到任意地址读写，最终改写 hook/返回地址。
- **验证步骤**：1) 反汇编确认 edit 写入无长度校验、索引仅 32 位截断；2) 连续 add 20 次排布 BSS 指针；3) edit 触发 off-by-null 覆盖目标指针低字节；4) 用受控指针完成 GOT/hook 改写。
- **判定标准**：PASS = 任意读写成立并拿到 shell；FAIL = 只用单字节截断当字节溢出用（不成链）或索引检查误判（edit 有 recvuntil 特征可复用内容）。
- **裁决词**：待复跑
- **来源**：护网杯 2018 shoppingcart｜六星战队（中国）｜raw/github-repos/sixstars/2018_huwangbei_h_readme.md（完整 EXP 在 WP）
- **关联**：与 [[自研分配器 1 字节 footer 覆盖（块链伪造 + GOT 覆写）]] 同属一字节溢出原语族；BSS 指针数组目标与 [[相邻变量覆写改认证标志（authenticated 旁路）]]相邻。

### stdout FILE 结构改写打 tcache（write_base 定点 + 部分覆写改 size）
- **分层**：困难·多段链
- **假设**：three 限申请 3 个堆块且 glibc 2.27 tcache 在位、double free 恰好够不到：改打 stdout 结构体——先利用其对齐残差泄漏栈/ELF 地址，再把 stdout 的 write_base 指向 notes 数组附近，利用 stdout 缓冲区写入对 notes[0] 低字节部分覆盖（改小）；被改小的 notes[0] 再去改 notes[1] 指向堆 size，free 后进不了 0x50 tcache，重获任意分配权。
- **验证步骤**：1) 布局 3 chunk 使 stdout 可被覆写（flags/write_base 字段序列）；2) 泄漏栈与 ELF 基址（write 输出本身）；3) write_base 定点 notes 附近做 1-2 字节覆盖；4) 借 notes[0]→notes[1] size 篡改绕 tcache 入口；5) 任意分配改 hook/返回地址。
- **判定标准**：PASS = 三 chunk 约束下完成泄漏+改写+执行；FAIL = 硬套 unsorted bin attack（2.27 的 error msg 不调 _IO_flush_all，行不通——WP 明示踩坑）。
- **裁决词**：待复跑
- **来源**：BCTF 2016 three｜六星战队（中国）｜raw/github-repos/sixstars/2018_bctf_h_readme.md（完整 EXP 与 stdout 字段操作在 WP）
- **关联**：与 [[相邻变量覆写改认证标志（authenticated 旁路）]] 同题族约束解题；「走 stdout」非常规 IO 通道与 [[无头视频流分辨率搜索（RGB 字节流重排 + 尾帧取证）]] 共享直觉；2.27/2.23 两代对照见 [[top chunk 随机化 + calloc 清零下的 unsorted bin 泄漏（error 路径触发 malloc_hook）]]。

### 括号语言深度语义推理（absorb/combine 形式文法自动化）
- **分层**：困难·单点
- **假设**：script-me 给出 8 条加法规则实例：单目对 ()() 与嵌套 () 相加结果由双方「最大嵌套深度」与顺序决定——右吸收/左吸收/结合吸收的统一规律 = 深度大者包住深度小者、深度相等则并列；由此可写求解器把任意题面表达式按文法归约，交互答题机自动通关。
- **验证步骤**：1) 归纳规则：deep(a)+shallow(b) ⇒ b 嵌入 a 外层（absorb 方向由操作数序决定）；2) 写 parser 求两侧深度与结构；3) 按规则生成结果串；4) 脚本接 socket 自动答题至取旗。
- **判定标准**：PASS = 全部题目答对自动取旗；FAIL = 把 absorb 理解为字符串拼接（忽略深度层级导致错序）。
- **裁决词**：待复跑
- **来源**：picoCTF 2018 script me｜Dvd848 (S1扩容)｜raw/github-repos/Dvd848/2018_script-me-md_h_script-me.md（规则实例与解题脚本在 WP）
- **关联**：与 [[brainfuck VM 执行轨迹跟踪（解码即抹零）]] 共享「形式语言规则归纳」方法论；自动化答题与 [[LLM 约束解码 + UCT 树搜索恢复审查文本]] 同属「规则发现后脚本收官」。

### SUID 相对设备路径 + IOCTL 失败信息泄露（dev/console 缺斜杠）
- **分层**：困难·多段链
- **假设**：holey_beep 为 SUID root 的 PC speaker 程序（Google CTF 真实漏洞复现链）：它打开 dev/console（缺前导斜杠的相对路径）——在自控目录建 dev/console 符号链接指向任意 root 文件；随后对链接目标做 IOCTL 失败，进入错误处理打印目标文件 0x3ff 字节内容，即可读出 root-only 文件（/secret_cake_recipe）。
- **验证步骤**：1) 确认 SUID 位与打开路径字符串（dev/console 相对）；2) 在工作目录构造 dev/console 链接指向目标 root 文件；3) 运行 holey_beep 令 IOCTL 失败进 debug 输出分支；4) 收集 0x3ff 泄露内容拼出 flag。
- **判定标准**：PASS = 泄露内容含 CTF{...}；FAIL = 去 patch 二进制找 ROP（真实考点是路径+IOCTL 双缺陷，非内存破坏）。
- **裁决词**：待复跑
- **来源**：Google CTF 2018 Holey Beep（Beginner Quest 链）｜Dvd848 (S1扩容)｜raw/github-repos/Dvd848/2018_holey-beep-md_h_holey-beep.md（完整复现步骤在 WP）
- **关联**：与 [[管理接口路径穿越自体提取（/proc/self/exe 落盘）]] 同属「路径处理缺陷反读特权文件」；错误路径副作用与 [[top chunk 随机化 + calloc 清零下的 unsorted bin 泄漏（error 路径触发 malloc_hook）]] 共享「error 分支当触发面」思路；SUID 生态与 [[钓鱼 DFIR 报告链（邮件→msc→VBScript 解混淆→白 EXE 黑 DLL→RAT）]] 的白加黑手法呼应。

### 32 位 FSB 逐偏移 %p 链读栈上 flag（无写原语纯泄露）
- **分层**：困难·单点
- **假设**：32 位非 PIE ELF 若把 flag 读进 vuln 栈帧局部变量且存在 printf(user_input)，则无需 GOT 改写/ROP：gdb 断点定位 flag 缓冲区栈地址相对 printf 首参的 4 字节槽位（本例第 36 槽），用 %36$p→%37$p… 逐次连接读 4 字节小端拼 ASCII——纯读型 FSB 的最短路径。
- **验证步骤**：1) Ghidra 确认 readflag 写入 local_4c、printf(local_cc) 为 FSB 点；2) gdb 断 printf 前 x/64wx $esp 找 flag 特征双字（0x67616c66="flag"）；3) 数槽位偏移 i；4) pwntools 循环 %<i>$p 发包、int(data,16) 转 p32 拼接；5) 遇 '}' 截断。
- **判定标准**：PASS = 拼出语义完整 flag；FAIL = 栈 ASLR/远端偏移漂移（本地对照重数槽位）或 flag 含 0x00 截断（%s 单发替代）。
- **裁决词**：待复跑
- **来源**：OSCTF 2024 Leaky Pipes｜よっちん（yocchin のブログ）｜raw/team-blogs/yocchin/2024_osctf_leaky-pipes.md
- **关联**：与 pwn 库 FSB 写原语条目构成读写对照（本条纯泄露免 GOT）；gdb 数槽位法与 [[NTLMv2 响应手工拆解（字段级 hash 形态）]] 的"字段级手工拆解"方法论互通。
- **熵控预检**：Q1 无重名；Q3 强（gdb 栈图与 pwntools 脚本全在 WP）；Q4 边 2 条。


### 内核堆 off-by-one 劫持 freelist + modprobe_path 提权（SMEP/SMAP 全开）
- **分层**：困难·多段链
- **假设**：qemu 内核题（+smep,+smap，kaslr 未开）中设备驱动的 edit 例程若多拷 1 字节（malloc_size+1），可溢出改写下一空闲块的 freelist 指针 LSB；内核堆 freelist 弱校验（无 trailing metadata）使指针可指向 channel_info 块内，达成 chunk overlap→控制 data 指针→设备 edit/read 即任意读写→改 modprobe_path 字符串，触发未知格式文件执行提权脚本拿 /root/flag——无需 ret2usr。
- **验证步骤**：1) 逆向 ioctl 四命令（alloc/free/edit/read）与 channel_info{ id, data, malloc_size }；2) 布置 victim channel + 空闲块使 overflow 落在 freelist 指针；3) 改 LSB 使 next 指向 channel_info 前部；4) 两次 alloc 拿回 overlap 块，写 data 指针；5) read 泄露内核基址校验，edit 覆写 modprobe_path；6) 触发无效格式文件执行拷贝脚本。
- **判定标准**：PASS = /root/flag 可读；FAIL = freelist 校验版本差异（换 tty_struct/seq_operations 目标）或 kaslr 开启（先泄露基址）。
- **裁决词**：待复跑
- **来源**：MidnightSun CTF 2019 Quals HFSIPC (558p/18 solved)｜Dvd848 (S1扩容)｜raw/github-repos/perfectblue/2019_midnightsun-ctf-quals_h_hfsipc.md
- **关联**：与 pwn 库用户态堆条目构成堆利用分级（用户态 tcache vs 内核 freelist）；modprobe_path 提权与库内 ret2usr 条目构成"SMAP/SMEP 对抗"双路径。
- **熵控预检**：Q1 无重名（库内无内核堆条目）；Q3 中（结构与思路全在 WP，exp 未全附）；Q4 边 2 条。


### ELF 段清零对抗（.data/.rodata 清零 + .text 清零两条路）
- **分层**：困难·多段链
- **假设**：判题器清零指定段后仍要求输出 Hello, world!：清 .data/.rodata 时字符串常量归零，改为栈上逐字符 putchar（局部 char 不入文件段）；清 .text 时全部指令归零，出路是让代码落在非 .text 节——用 __attribute__((constructor))（进 .init_array，加载器构造期执行）或把函数显式放自定义 section，objcopy 只清 .text 时代码幸存——考察段语义与加载期执行面。
- **验证步骤**：1) readelf -S 对照正常编译产物定位段；2) 第一问：char c='H'; putchar(c)…栈变量+常数；3) 第二问：constructor 函数写 hello（链接进 .init_array）或 #pragma code_seg 自定义段；4) gcc -O -m32 编译提交判题。
- **判定标准**：PASS = 判题器输出 Hello, world!；FAIL = -O 优化把栈变量折叠回常量（用 volatile 抑制）或 constructor 被 LTO 内联（加 noinline）。
- **裁决词**：待复跑
- **来源**：中国科学技术大学 Hackergame 2021 Amnesia（轻度失忆 150 + 记忆清除 200）｜Peter Gu（regymm）｜raw/github-repos/hackergame2021/2021_hackergame_h_amnesia.md
- **关联**：段语义与 [[BMP 头跳过 + 8 字节组 LSB 流提取（zsteg/StegSolve 全盲区）]]（本批）的容器结构意识同源（ELF vs BMP）；"加载期执行面"（init_array）与 pwn 库 hook 类条目（__malloc_hook 等）互证。
- **熵控预检**：Q1 无重名；Q3 强（两问解法+编译器版本细节在 WP）；Q4 边 2 条。

### 引用计数双删 UAF（brief 扩容重用 + GOT 泄露 + formatter 劫持）
- **分层**：困难·多段链
- **假设**：图书管理器的"最畅销"列表持有悬垂引用时，同 book 连删两次（引用计数缺陷）进入 UAF 态；先加短 brief 的书再扩容 brief 使 malloc 重用 victim chunk，List 输出即读伪造 brief 指针（指向 .got 表项泄露 libc），再改 brief 指针+formatter 函数指针（指向 system）二次 List 触发 system("/bin/sh")——无 free hook 时代的 UAF 标准三段。
- **验证步骤**：1) Add book（短 brief）+ Add best-seller；2) 删 best-seller 两次（Double Remove）；3) 扩容 brief 重用 chunk 覆盖 brief 指针为 GOT 地址；4) List 泄露 libc 基址；5) 二次伪造 brief="/bin/sh" 与 formatter=system；6) List 拿 shell。
- **判定标准**：PASS = shell 可交互；FAIL = 扩容不落 victim chunk（调 brief 长度匹配 size class）或无 formatter（找 printf 类函数指针）。
- **裁决词**：待复跑
- **来源**：WhiteHat Grand Prix 2018 Quals pwn02 (130p/37 solved)｜Writeup 仓（exploit.py 附件）｜raw/github-repos/p4/2018_whitehat_h_pwn02.md
- **关联**：与 [[内核堆 off-by-one 劫持 freelist + modprobe_path 提权（SMEP/SMAP 全开）]]（本批）构成堆漏洞分层（用户态 UAF vs 内核 off-by-one）；"输出型函数指针劫持"思路与库内格式化输出条目互通。
- **熵控预检**：Q1 无重名；Q3 中（五步流程在 WP，exp 全文在附件链接）；Q4 边 2 条。

### KVM 虚拟机管理程序逃逸（guest 内核漏洞 → host 堆利用）
- **分层**：超级难·流程
- **假设**：以 /dev/kvm 为后端的微型 hypervisor 题，host 通过 VCPU 共享页执行 guest 发来的 alloc/update/free 请求；内核侧（guest 固件，mmap 加载 0x18e0 偏移数据）的 update 例程缺边界检查（页内偏移可越界改写相邻结构），先在 guest 内伪造请求让 host 的 alloc 拿到带 hook 的 chunk，最终在 host 侧复现 malloc/free 利用链拿 RCE——"嵌套漏洞面"（guest 漏洞作为 host 利用原语）。
- **验证步骤**：1) 静态分析 VCPU 循环与三对内核/host 函数；2) 逆向 guest 固件（0x18e0 blob）找 update 越界；3) 构造 guest 请求序列控制 host malloc 内容；4) host 侧 hook/函数指针劫持；5) 触发 exit 路径拿 shell 读 flag。
- **判定标准**：PASS = host 进程执行任意命令；FAIL = host 校验了请求序号（找 TOCTOU 窗口）。
- **裁决词**：待复跑
- **来源**：RealWorldCTF 2018 Quals Kid VM｜VoidMercy（github WP 仓）｜raw/github-repos/perfectblue/2018_realworldctf_x_kid-vm.md
- **关联**：与 [[VM 字节码引擎逃逸（swap2_stack 栈指针越界改写）]]（本批 faustctf 路由条）构成"解释器/虚拟化逃逸"双样本（KVM 型 vs 字节码型）；嵌套攻击面与 [[内核堆 off-by-one 劫持 freelist + modprobe_path 提权（SMEP/SMAP 全开）]]（本批）分层互补。
- **熵控预检**：Q1 无重名；Q3 中（结构分析在 WP，完整 exp 未附）；Q4 边 2 条。


### VM 字节码引擎逃逸（swap2_stack 栈指针越界改写）
- **分层**：超级难·多段链
- **假设**：自研栈式字节码 VM（0x20 opcodes，指针以 1<<63 打标签防混淆）若 swap2_stack 只校验"≥1 个元素"而不查"≥2"，单元素栈上 swap 会把栈顶与紧邻的 _sp（栈指针本体）交换——攻击者由此获得任意栈指针控制，配合 alloc_buf/fgets 等 opcode 构造 ROP 链逃逸；先 push 一个值再 swap 即改 _sp 指向 code 区执行注入指令。
- **验证步骤**：1) 逆向 vm_context{_ip,_sp,stack,code,flags}；2) 定位 swap2_stack 的边界检查缺陷；3) 构造单元素 swap 序列改 _sp；4) 用字符串 opcode 组合（concat/atoi/strcmp）读写越界内存；5) ROP/注入取 shell。
- **判定标准**：PASS = VM 外命令执行；FAIL = 指针标签校验（用 push_mem 造合法标签值）。
- **裁决词**：待复跑
- **来源**：Faust CTF 2021 Veighty Machinery（超级难）｜Writeup 仓｜raw/github-repos/perfectblue/2021_faustctf_x_veighty-machinery.md
- **关联**：与 [[KVM 虚拟机管理程序逃逸（guest 内核漏洞 → host 堆利用）]]（本批）构成逃逸双样本（字节码型 vs hypervisor 型）；opcode 审计清单（边界检查/标签校验/指针算术）可复用至所有解释器审计。
- **熵控预检**：Q1 无重名；Q3 中（结构与思路在 WP，完整 bytecode 未附）；Q4 边 2 条。
