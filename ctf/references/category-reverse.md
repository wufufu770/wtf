---
verified: "2026-10-15 | 本地复跑：Python 3.12.13 / strings(GNU binutils) / gcc 13（Linux 容器），见条目1复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "CTF-wiki（reverse 章节）、mukul975/Anthropic-Cybersecurity-Skills（结构化条目范式）、M2 实测复跑（2026-10-15）"
changelog:
  - "[2026-10-29] v0.5：蒸馏 P1+P2 批次并入 16 条（hypothesis 待复跑，REFLIGHT §1 二手知识纪律）｜源：ctf-corpus/distill 候选池（candidates.jsonl）+ distill/pilot/01-蒸馏批次报告-P2-20261029.md"
  - "[2026-10-15] 初始空壳，等待首个回流条目"
  - "[2026-10-15] v0.2：条目模板升级为五段式假设条目 + 机器可校验裁决词（REFLIGHT 回流协议，见 ../../shared/REFLIGHT.md）"
  - "[2026-10-15] v0.3：M2 填充 4 条（verified 2 / inconclusive 1 / hypothesis 1）"
  - "[2026-10-16] v0.4：「升级」字段边化——跳转目标改 [[条目名]] 图边引用（REFLIGHT §3）"
---

# 题型：Reverse

> 读取时机：二进制/APK 校验逻辑、反编译、混淆、自修改代码条目主库

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态：verified=最近一次复现日期+环境；source=条目主要出处；changelog 追加一行/次，不删除历史。
4. **失败样本优先回流**：refuted 条目必须附 FAIL 复跑记录、失败原因与"下一步转哪个新假设"，失败样本优先级高于成功经验。
5. verified/refuted/inconclusive 条目必须附复跑记录表（格式见 ../../shared/REFLIGHT.md §4）；未经复跑的条目状态只允许 hypothesis。
6. 工具具体用法归 ../../shared/tools/ 对应文件，此处不重复（去重原则）；五段式的「验证步骤」只保留最小可执行命令骨架。
7. 本文件超过 100 行时，在本节下方补 TOC 目录。

## 条目区（TOC）

1. [strings 明文侦察（含输出截断坑）](#strings-明文侦察含输出截断坑)（verified）
2. [pyc 魔数定位 Python 版本](#pyc-魔数定位-python-版本)（verified）
3. [UPX 壳识别](#upx-壳识别)（inconclusive）
4. [反编译工具链优先级](#反编译工具链优先级)（hypothesis）
5. [Windows 逆向前置条件 patch（参数校验 + PEB 反调试 #DE）](#windows-逆向前置条件-patch参数校验-peb-反调试-de)（hypothesis）
6. [逆向问答链：strcmp 常量答案 → 常量变换 → RC4 资源口令](#逆向问答链strcmp-常量答案-常量变换-rc4-资源口令)（hypothesis）
7. [call $+5 PIC 反混淆（patch + 模拟器解密）](#call-5-pic-反混淆patch-模拟器解密)（hypothesis）
8. [Heaven's Gate 32↔64 段切换（far ret 换 CS）](#heavens-gate-3264-段切换far-ret-换-cs)（hypothesis）
9. [编译期 CFG 深度乘积水印提取（小素数编码）](#编译期-cfg-深度乘积水印提取小素数编码)（hypothesis）
10. [逐位代数链逆推（flag 各位独立的朴素爆破）](#逐位代数链逆推flag-各位独立的朴素爆破)（hypothesis）
11. [PyInstaller 解包 + 主循环重写（时间反演取旗）](#pyinstaller-解包-主循环重写时间反演取旗)（hypothesis）
12. [多级指针间接寻址混淆（结构体化 + 半字节拼旗）](#多级指针间接寻址混淆结构体化-半字节拼旗)（hypothesis）
13. [pyobfuscate 混淆还原（lambda 派发 + 自定义表 base64）](#pyobfuscate-混淆还原lambda-派发-自定义表-base64)（hypothesis）
14. [brainfuck VM 执行轨迹跟踪（解码即抹零）](#brainfuck-vm-执行轨迹跟踪解码即抹零)（hypothesis）
15. [SVG 原理图转网表 + 32 位 SAT 求逆（硬件逆向）](#svg-原理图转网表-32-位-sat-求逆硬件逆向)（hypothesis）
16. [esoteric 语言反编译 + OEIS 数学同构（whitespace）](#esoteric-语言反编译-oeis-数学同构whitespace)（hypothesis）
17. [位打包校验函数逆推（Pascal digit→QWord 变换）](#位打包校验函数逆推pascal-digitqword-变换)（hypothesis）
18. [8051 固件 EEPROM 导出 + 位级 patch（anl 立即数清零）](#8051-固件-eeprom-导出-位级-patchanl-立即数清零)（hypothesis）
19. [EFI 字节码 VM 逆向 + z3 求解（EBC 运行时）](#efi-字节码-vm-逆向-z3-求解ebc-运行时)（hypothesis）
20. [多进程互斥校验逆向 + AES 轮密钥恢复（3-process lock）](#多进程互斥校验逆向-aes-轮密钥恢复3-process-lock)（hypothesis）

### strings 明文侦察（含输出截断坑）
- **假设**：未加壳二进制的校验逻辑/flag 往往以明文字符串（提示语、比较目标、格式串）存在于 .rodata → `strings -n 6 <bin> | grep` 关键词是最快的第一轮侦察。
- **验证步骤**：
  ```bash
  strings -n 6 t7_fmt | grep "SECRET"     # 命中内嵌标记即确认
  file t7_fmt                              # 先确认 ELF/壳状态，加壳的 strings 命中率骤降
  ```
  本机实测（2026-10-15，自编译 ELF）：`strings -n 6` 命中内嵌标记 `SECRET_CH`——注意：字面量原为 `SECRET_CANARY_0x1337`，输出**被相邻字节合并/截断**，只命中前缀。
- **判定标准**：PASS = grep 命中预期关键词（含部分命中）；FAIL = 零命中（先查是否加壳/明文是否运行时解密生成）。
- **裁决词**：PASS
- **来源**：M2 实测复跑（evidence T6）；GNU binutils strings 手册
- **升级**：零命中转 [[file + strings 零依赖侦察]] 排查壳（[[UPX 壳识别]]），再上 [[反编译工具链优先级]]。
- **关键差异**：strings 输出可能因相邻字符合并/截断——命中关键词即算成功，勿期待 flag 原样完整出现；`-n` 阈值过低会噪声爆炸，6 起步。

### 复跑记录（verified / refuted / inconclusive 必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 本地 gcc 自编译 ELF | `strings -n 6 t7_fmt \| grep SECRET` | PASS | evidence/T6-strings | 命中 `SECRET_CH`（原字面量被截断合并）——输出不保证完整字面量 |

### pyc 魔数定位 Python 版本
- **假设**：附件为 .pyc/.pyo 或解包 PyInstaller 后得到 pyc → 前 4 字节魔数可反查编译器 Python 版本，版本不匹配则 uncompyle6/decompyle3 反编译必然失败（先对齐版本再反编译）。
- **验证步骤**：
  ```bash
  python3 -c "print(open('<chall>.pyc','rb').read(4).hex())"
  # 对照：本机 python3 -c "import importlib.util;print(importlib.util.MAGIC_NUMBER.hex())"
  ```
  本机实测（2026-10-15）：Python 3.12.13 编译产物魔数 `cb0d0d0a`，与 `importlib.util.MAGIC_NUMBER` 反查一致。
- **判定标准**：PASS = 魔数与本机 MAGIC_NUMBER 一致（可直接反编译）或查表定位到具体版本；FAIL = 魔数无法匹配任何已知版本（考虑魔数被篡改的反调试套路）。
- **裁决词**：PASS
- **来源**：M2 实测复跑（evidence T8）；CTF-wiki Python 逆向；CPython importlib 源码 MAGIC_NUMBER
- **升级**：版本确定后转 [[反编译工具链优先级]]（3.9 前 uncompyle6、3.9+ pycdc/pycdas；PyInstaller 先 pyinstxtractor）。

### 复跑记录（verified / refuted / inconclusive 必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 本地 Python 3.12.13 | `py_compile` + 读前 4 字节 | PASS | evidence/T8-pycmagic | 3.12 → `cb0d0d0a`，与 importlib.util.MAGIC_NUMBER 一致 |

### UPX 壳识别
- **假设**：二进制体积异常小、strings 零命中、节名异常（UPX0/UPX1）→ UPX 壳，`upx -d` 直接脱壳后转常规反编译流程。
- **验证步骤**：1) `file <bin>` 看是否直接标注 UPX；2) 二进制内搜 `UPX!` 魔数（4 处左右）；3) `upx -d -o unpacked <bin>`。
- **判定标准**：PASS = 脱壳后 strings/反编译恢复信息量；FAIL = 非 UPX 壳（转 VMProtect/自实现壳分析）。
- **裁决词**：INCONCLUSIVE
- **来源**：CTF-wiki 脱壳；UPX 官方文档
- （inconclusive 缺口清单）本机无 upx 工具、无加壳样本；仅思路。下次遇壳样本时补齐 `UPX!` 魔数定位与 `-d` 脱壳复跑。

### 反编译工具链优先级
- **假设**：ELF 反编译效果 Ghidra（免费/批量）≈ IDA（交互最优）＞ objdump -d（纯汇编兜底）→ 按此顺序投入时间，先看 main/校验函数而非全量阅读。
- **验证步骤**：1) `readelf -h` 确认架构与入口；2) Ghidra headless 导出反编译 C；3) 定位字符串交叉引用直达校验函数。
- **判定标准**：PASS = 拿到与题面行为一致的校验伪代码；FAIL = 反编译结果与运行行为矛盾（存在自修改/SMC/反调试，转动态调试）。
- **裁决词**：待复跑
- **来源**：CTF-wiki 逆向工具链；x-glacier/kali-pentest 四层工具文档体系（场景化组织）
- （可选）**关键差异**：模型盲区——静态结果与动态行为矛盾时信动态；先交叉引用字符串比通读函数快一个量级。

### Windows 逆向前置条件 patch（参数校验 + PEB 反调试 #DE）
- **分层**：简单档·可复现强
- **假设**：Windows CTF 逆向题常设**启动前置**（命令行参数校验 + PEB 反调试检查触发除零 #DE）→ 不 patch 掉全部检查，题面交互流程不展开；参数校验常要求特定参数串（如 `TM`）。
- **验证步骤**：1) 逆 main/WinMain 找 argc/argv 校验；2) 搜 PEB 访问（`fs:[30h]`、BeingDebugged/NtGlobalFlag）与 #DE 触发路径；3) NOP/反转检查分支；4) 带参数在调试器下重跑进入交互。
- **判定标准**：PASS = patch 后进入题面问答交互；FAIL = 仍有隐匿检查（多层反调试）→ 转静态解（定位比较常量直推答案）。
- **裁决词**：待复跑
- **来源**：TrendMicro CTF 2019 Quals RE-100 GuessWhat.exe｜p4｜raw/github-repos/p4/2019_trendmicro-quals_e_re-100.md（"Binary must be executed with at least one argument TM" + "PEB-based anti-debugger checks leading to #DE exception"）

### 逆向问答链：strcmp 常量答案 → 常量变换 → RC4 资源口令
- **分层**：简单档·可复现强
- **假设**：问答式逆向题的**正确答案 = 二进制内 strcmp 比较常量**；后续密钥 = 某常量串经变换子程序的产物；末环口令/附件藏于 PE 资源（ZIP resource）——三环串联，逐环提取。
- **验证步骤**：1) base64 解交互提示（`V2hhdCBkbyB5b3Uga25vdyBhYm91dCBjaXBoZXJzPwo=` → "What do you know about ciphers?"，答案常量 `rc4`）；2) 定 strcmp 比较常量即该环答案；3) 跟常量变换函数（如 `9g>csumcsu` → `0x7fffffff`）算出下一环密钥；4) 用密钥 RC4 解密服务回显（`&N0wu4rEgeTTinGth3re!`）；5) 密钥解 PE 内 ZIP resource 得 img.jpg 进下一题型环。
- **判定标准**：PASS = 三环串通（答案 → 密钥 → 资源口令）；FAIL = 某环不匹配 → 对该环常量做 xref 引用追踪找缺失变换步。
- **裁决词**：待复跑
- **来源**：同上 RE-100（末段旗 `NGWNZ{AAQJ_AFBZ}` 为 ROT-6 → `TMCTF{GGWP_GLHF}`）｜p4｜raw/github-repos/p4/2019_trendmicro-quals_e_re-100.md
- **陷阱备注**：解出最终密文后旗仍可能**不是明文**（ROT 变体）——终检先试凯撒家族再报失败。

### call $+5 PIC 反混淆（patch + 模拟器解密）
- **分层**：超级难档·失败样本/陷阱
- **回流优先级：refuted 候选**——「IDA 自动反编译可直接读」假设被 `call $+5 / pop reg` 型 PIC trampoline 证伪：函数边界与交叉引用被打乱；待复跑转正。
- **假设**：PIC 反混淆（`call $+5; pop reg` 取当前地址）型样本分两步：① **patch 恢复 xrefs**——把 call/pop 组合改写为等价 `mov reg, imm`（地址常量直接写入），函数边界即恢复；② **解密例程交给 CPU 模拟器**（如 uEmu 插件）——入口下断、模拟执行到返回，dump 解密后缓冲，比动态调试稳且不依赖环境。
- **验证步骤**：1) 搜 `call $+5`（E8 00 00 00 00）模式批量定位；2) patch 成 mov 等价序列恢复引用；3) 解密函数入口断点 + emulator 单步到 ret；4) dump 输出（如解密后的 cnc 域名串）；5) 全样本套用后配合 `nmap -Pn` 等验证基础设施连通性（可并入取证侧）。
- **判定标准**：PASS = 反编译可读 + 模拟器跑通解密；FAIL = 混淆含反模拟手段（自修改/时间检查）→ 转全 Unicorn 脚本化模拟。
- **裁决词**：待复跑
- **来源**：Google CTF 2018 apt42 Part1（恶意样本逆向）｜p4｜raw/github-repos/p4/2018_google-ctf_x_apt42-part1.md（uEmu 模拟解出 cnc 地址 + 端口）

### Heaven's Gate 32↔64 段切换（far ret 换 CS）
- **分层**：超级难档·失败样本/陷阱
- **假设**：32 位进程内嵌 64 位代码段（WoW64 Heaven's Gate：far return/jmp 切 CS 选择子 0x23↔0x33）→ 反汇编器按 32 位解 64 位段会看到错位乱码；以 call gate/far ret 定位模式切换点，**分段设置 32/64 位反汇编** + IDAPython 按 gate 划分代码段，重复模式批量脚本化（z3 解约束恢复输入）。
- **验证步骤**：1) 搜 far ret/jmp（`retf`、call far、段选择子 0x33/0x23）定位切换点；2) 切换点后区段改按 64 位反汇编（IDA seg 属性或独立反汇编器）；3) 重复 64 位块用 python 解析反汇编文本批量注释；4) 约束求解（z3 BitVec 逐字节）恢复满足校验的输入串。
- **判定标准**：PASS = 双模式分段后逻辑可读、z3 出输入；FAIL = 段切换运行时动态决定 → 转动态 trace 分段。
- **裁决词**：待复跑
- **来源**：HITCON 2022 meow-way（aiml 类目）｜perfect blue｜raw/github-repos/perfectblue/2022_hitcon_x_meow-way.md（"return to 64 bits heavens gate nonsense... very classic trick in windows reversing"）
- **陷阱备注**：题面给人「AI/模型」外观（aiml 分层）时，先验「要逆向模型」常错——本题核心是 Windows 双模式逆向。

### 编译期 CFG 深度乘积水印提取（小素数编码）
- **分层**：困难档·复合链
- **假设**：软件水印不以附加数据而以 IR 级代码变换嵌入——CFG 基本块被赋予 DFS 遍历深度值并折算为小素数乘积 ⇒ 逆向侧重建 CFG、对基本块按（改造过的）DFS 赋深度、以目标素数乘积匹配即可定位水印块，逐级分解提取比特串。
- **验证步骤**：1) 反汇编重建函数 CFG；2) 按出题人变体 DFS 赋深度（注意一个 BB 可被赋多深度以小素数乘入）；3) 素因子分解对齐目标乘积；4) 拼比特、恢复 shuffle（复用 std::shuffle 或 ctypes 调 C++ 实现保证 RNG 一致）。
- **判定标准**：PASS = 还原水印串/SHA3 一致；FAIL = 深度赋值不收敛 → 检查遍历变体（后序/重复入栈）。
- **裁决词**：待复跑
- **来源**：Hackergame 2023 旧日之痕（binary 300/350p）｜emc2314｜raw/github-repos/hackergame2023/2023_hackergame_h_cn-7e261a.md（原理与深度赋值法在 WP；sdcc/IDA 均可复现）
- **关联**：Q1 边界——与 [[逆向问答链：strcmp 常量答案 → 常量变换 → RC4 资源口令]] 同为「校验逻辑提取」但对象是自嵌水印（无外部口令）。
- **陷阱备注**：水印若被「对比两份二进制」攻击会失效，本题设计点即抗差分——提取必须走 CFG 语义而非字节对比。

### 逐位代数链逆推（flag 各位独立的朴素爆破）
- **分层**：困难档·单点
- **假设**：混淆器把校验展开成 per-byte 常量代数链（xor/add 交替）且输出按位独立 ⇒ 无需符号执行/angr，逐位 256 枚举反查即可整段恢复。
- **验证步骤**：1) IDA 定位每字节链函数；2) Python 复写代数式；3) 对每位 0-255 枚举比对目标值；4) 拼串。
- **判定标准**：PASS = 全 32 位唯一命中；FAIL = 存在跨位耦合 → 找耦合位（进位/移位）改两两联合枚举。
- **裁决词**：待复跑
- **来源**：XNUCA 2016 babyfuscator｜六星战队（中国）｜raw/github-repos/sixstars/2016_xnuca_h_babyfuscator.md（完整交互式求解过程在 WP）
- **关联**：反例条——[[STG-K01 高级外观先做减法——代数化简优先于重武器]] 的操作面证据：看起来要 angr 的题先看能不能拆成逐位独立。

### PyInstaller 解包 + 主循环重写（时间反演取旗）
- **分层**：困难档·复合链
- **假设**：PyInstaller exe 可 pyinstxtractor 解出入口 pyc ⇒ 不必完全读懂程序——重写主循环、直接 import 原 pyc 的函数与全局对象，把粒子速度取反（并降速）即可回放到 0 时刻之前的状态，目测截屏收旗。
- **验证步骤**：1) pyinstxtractor 解包，Ctrl-C 调用栈定位入口 pyc；2) monkey patch pygame.quit 防退出；3) import 原模块后对 Pointlist 逐粒子 vx/vy 取反 ×0.1；4) 跑自写循环至旗形显现。
- **判定标准**：PASS = 反演画面出现可读旗；FAIL = 模块级副作用（import 即全速跑完）→ patch FPS/时钟再重放。
- **裁决词**：待复跑
- **来源**：Hackergame 2021 Micro World｜USTC-Hackergame（官方+选手）｜raw/github-repos/hackergame2021/2021_hackergame_h_micro-world-md.md（重写循环代码全量在 WP，wine+py3 本地可重放）
- **关联**：同「模拟程序重写」族 [[逆向问答链：strcmp 常量答案 → 常量变换 → RC4 资源口令]] 的动态派——静态读不懂就接管主循环。

### 多级指针间接寻址混淆（结构体化 + 半字节拼旗）
- **分层**：困难档·单点
- **假设**：校验函数以 `*(*(**(a1+4)+8)+i)` 型多级指针藏数据源、且 XOR 后叠加索引加减 ⇒ IDA 手工建结构体定型指针链，读出两段 15B 密文与两条明文串，逐位反推半字节（高 4 位/低 4 位各一串）拼成可见 flag。
- **验证步骤**：1) IDA 结构体视图展开 a1 偏移链；2) dump dest1/dest2 与 xor1/xor2；3) `(dest±i)^plain` 分高低半字节；4) `h*16+l` 重组。
- **判定标准**：PASS = 输出可读串；FAIL = 出现不可见字符 → 反转索引加减方向（反汇编翻译可能颠倒）再试。
- **裁决词**：待复跑
- **来源**：XNUCA 2016 indirect｜六星战队（中国）｜raw/github-repos/sixstars/2016_xnuca_h_indirect.md（指针链与复原脚本在 WP）
- **陷阱备注**：本条留「翻译反向」教训：OD/IDA 对 ± 的翻译与真实语义相悖时，先小样本试两个方向再全量。

### pyobfuscate 混淆还原（lambda 派发 + 自定义表 base64）
- **分层**：困难档·复合链
- **假设**：pyobfuscate 生成的 lambda/__g 派发树可以机械还原（专用反混淆工具/手动 eval 顶层）⇒ 还原后露出 encode 逻辑 = 查自定义 table 的 +1 移位 base64 变体；输出仅 6 位可见 ⇒ 手动补第 7 位 index ≥64 的映射（table[+64] 查表）拼全旗。
- **验证步骤**：1) lambda-deobfuscator/pyobfuscate-deobf 还原主逻辑；2) 提取 table 与 encode 变换；3) 对密文逐字符查表逆移位；4) 手补 64+ 位映射字符。
- **判定标准**：PASS = 拼出可读旗；FAIL = 表非标准序 → 先 diff 标准 base64 表对齐。
- **裁决词**：待复跑
- **来源**：XDCTF 2015 300（sixstars）｜六星战队（中国）｜raw/github-repos/sixstars/2015_xdctf_h_writeup_p4.md（原始混淆源码与还原后代码对照在 WP）
- **关联**：Q1 边界——混淆层归 reverse、编码层邻 [[编码套娃链识别与解链]]（那条管链式识别，本条管 Python 混淆对抗）。

### brainfuck VM 执行轨迹跟踪（解码即抹零）
- **分层**：困难档·单点
- **假设**：BF 代码远长于纯 echo（`[,.]`）⇒ 怀疑其在内存上解码 flag 后再清零 ⇒ 给解释器加 hook 打印每步内存快照，轨迹中即出现中间明文。
- **验证步骤**：1) IDA 确认 VM 指令派发表；2) 输入魔串触发隐藏 BF 载荷；3) 记录每条指令后 tape 状态；4) diff 相邻快照定位写入段。
- **判定标准**：PASS = 轨迹中出现 flag 段；FAIL = 抹零前有多轮变形 → 对 tape 做逐轮差分叠加。
- **裁决词**：待复跑
- **来源**：ASIS CTF 2018 Quals Echo（reverse 80p）｜perfect blue（战队）｜raw/github-repos/perfectblue/2018_asis-ctf-quals_h_echo.md（VM 派发与轨迹图在 WP）
- **关联**：同「VM 动态跟踪」族 [[AVX2 轮函数对称逆推（无密钥加密器）]] 的表亲——一个逆轮函数、一个顺跑留痕。

### SVG 原理图转网表 + 32 位 SAT 求逆（硬件逆向）
- **分层**：困难档·复合链
- **假设**：题给电路原理图为 SVG 矢量 ⇒ 用 lxml 拉出全部 line2d 路径与 text 标签、按端点邻近关系连接「谁喂谁」成组合逻辑网表 ⇒ 对 32 个输入变量建 SAT 约束（Override=1），z3 求解唯一解即旗。
- **验证步骤**：1) parse_svg.py 提取线段/标签；2) 端点吸附建边（注意 decoy 门与冗余线）；3) 网表转 z3 表达式；4) solve 取 I00..I31。
- **判定标准**：PASS = 唯一 SAT 解为可读旗；FAIL = 多解/UNSAT → 检查转写漏边（诱饵线未剔除）。
- **裁决词**：待复跑
- **来源**：CSS CTF 2026 Return of Nexus Silicon Snare（hardware 250p）｜hax1ng｜raw/github-repos/hax1ng/css-ctf-2026-return-of-nexus/hardware/silicon-snare/README.md（parse_svg 与求解脚本全量在 WP）
- **关联**：Q1 边界——硬件外观但方法本质是「图提取 + 约束求解」，与 [[PPC 脚本题约束建模]] 共用求解器纪律。

### esoteric 语言反编译 + OEIS 数学同构（whitespace）
- **分层**：困难档·复合链
- **假设**：whitespace 程序暴力跑不出大参数结果 ⇒ 反编译成 asm 指令序列读懂算法（求 highly abundant number 之类）→ 与 OEIS 数列同构查得目标值，交给数学引擎（wolfram/除数和）一步出结果。
- **验证步骤**：1) whitespace→伪汇编转换器（或手撸解析）；2) 动态小样本归纳计算模式；3) OEIS 检索匹配数列；4) 按 10^12 参数查表/计算得值。
- **判定标准**：PASS = 输出与远程校验一致；FAIL = 数列偏一（用错起点）→ 用程序小样本输出对 OEIS 前几项校准。
- **裁决词**：待复跑
- **来源**：Tokyo Westerns/MMA CTF 2016 Whiteout Mathematics（rev+ppc 200p）｜p4 (波兰战队)｜raw/github-repos/p4/2016_tokyo-mma_h_whiteout-mathematics.md（流程描述与 OEIS 链接在 WP）
- **关联**：[[STG-K01 高级外观先做减法——代数化简优先于重武器]] 的标准案例——先问「程序在算什么数学对象」再选武器。

### 位打包校验函数逆推（Pascal digit→QWord 变换）
- **分层**：困难档·单点
- **假设**：16 位十进制码以 nibble 打包进 QWord、经 xor 常数 + RolQWord + 分组掩码校验 ⇒ 变换可写为逐位可逆函数——对掩码特征（0x111…/0x222… 等 nibble 掩码）逐层剥离，直接逆推或对 16 位做逐位爆破。
- **验证步骤**：1) 读出 xor 常数与 Rol 位数；2) 反 Rol + 反 xor；3) 对四组 nibble 掩码分别判 0/1 → 位图重组；4) 输出 16 位码。
- **判定标准**：PASS = CheckKeyPadCode(res)=True；FAIL = rol 方向反 → 两个方向试跑。
- **裁决词**：待复跑
- **来源**：Google CTF 2021 15-Unknown - Outside Secret Base（re）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2021_15-unknown-outside-secret-base-md_h_15-unknown-outside-secret-base.md（Pascal 源码与求解脚本在 WP）
- **关联**：同「校验函数求逆」族 [[逐位代数链逆推（flag 各位独立的朴素爆破）]]——packing 与代数链只是外衣，逆推策略同源。

### 8051 固件 EEPROM 导出 + 位级 patch（anl 立即数清零）
- **分层**：困难档·复合链
- **假设**：emu8051 环境下固件可经 I2C 0x24 端口整页读写（端口校验只查「单字符」不查「是数字」⇒ 用 ' \x54' 字符直访 0x24）⇒ dump 全部固件页 → sdcc 重编译 firmware.c 对照 .rst 定位 rand 函数 → 在「只能 1→0 擦写、限 9 比特」约束内把 `anl _init_rand,#0x07` 的立即数 7 改 0（3 bits）消除随机扰动 → 读 0-0x23 端口轮速转 ASCII 得旗。
- **验证步骤**：1) `r \x54 i` 逐页读 EEPROM 拼固件；2) sdcc 编译比对偏移；3) 按位写回 0（payload 置 1 位即擦写位）；4) 复位后读 0x00-0x23 端口拼旗。
- **判定标准**：PASS = 轮速 ASCII 成旗；FAIL = 写位超限 → 换 NOP（0x00）等价改法。
- **裁决词**：待复跑
- **来源**：Hackergame 2022 RoboGame 轮子（binary 300p）｜USTC-Hackergame（官方+选手，cabasky）｜raw/github-repos/hackergame2022/2022_hackergame_h_robogame.md（固件/指令偏移/exp 在 WP 与附件）
- **关联**：[[STG-P02 泄露源码≠现役二进制——逆向为准，源码只作参考]] 的镜像案例——本题源码与固件同源但以 .rst 对照加速定位；位约束（只准 1→0）是物理特性先验。
- **陷阱备注**：Q1 归位说明——选材线记 misc 系合集归类，按 8051 固件逆向实类归 reverse。

### EFI 字节码 VM 逆向 + z3 求解（EBC 运行时）
- **分层**：困难档·复合链
- **假设**：EFI Byte Code（EBC）虚拟机程序实现校验逻辑而手读低效 ⇒ 逆 EBC VM 指令（SIM 表 + 栈语义）转成 SSA/逻辑表达式 → z3 以已知旗前缀（TWCTF{…}）+ 逐字符约束求解剩余字节 → VM 求值器逐条核验。
- **验证步骤**：1) EBC_disassembler 定指令流；2) 依 EBC spec 把 STACK/REL 语义翻成 z3 表达式；3) 加旗格式约束求解；4) 逐条回放 VM 验证。
- **判定标准**：PASS = 模型唯一且过 VM；FAIL = 约束不定 → 追加可打印约束/已知分段。
- **裁决词**：待复跑
- **来源**：TWCTF 2016 ebc（reversing 111p/52 解）｜p4 (波兰战队)｜raw/github-repos/p4/2016_twctf_h_ebc.md（VM 求值器与 z3 约束脚本在 WP 附件；本地可重放）
- **关联**：[[brainfuck VM 执行轨迹跟踪（解码即抹零）]] 的静态对偶——动态 trace vs 符号求解殊途同归；Q1 归位说明——按 VM 逆向实类归 reverse（选材线记 encoding 合集归类）。

### 多进程互斥校验逆向 + AES 轮密钥恢复（3-process lock）
- **分层**：困难档·复合链
- **假设**：密码校验拆进 3 个持互斥锁进程（锁字段 0/2/4/6 循环）⇒ 从第一个进程的校验函数逆出 key 前半，AES 为魔改轮（部分轮密钥已知）⇒ 由 key schedule 逆向恢复完整轮密钥 → 解密后半校验 → 组合出正确密码取旗。
- **验证步骤**：1) 交叉引用定位 3 进程入口与锁交互；2) 逐进程 F5 恢复校验逻辑；3) 逆 key schedule 补全轮密钥；4) 解密得剩余约束并求解。
- **判定标准**：PASS = 组合密码过三进程校验出旗；FAIL = 锁顺序假设错 → 按竞态日志重定顺序。
- **裁决词**：待复跑
- **来源**：MeePwn CTF 2018 Quals xss (re 233p/27 解)｜p4 (波兰战队)｜raw/github-repos/p4/2018_meepwn_h_xss.md（三进程分析与 AES 轮密钥恢复脚本在 WP；本地 wine/IDA 可重放）
- **关联**：与 [[魔改 AES 常量指纹识别（表全换场景裸写实现）]] 同「魔改 AES 逆推」族——关键差异 = 该条换表、本条截轮，恢复点分别在 S 盒与 key schedule。
- **陷阱备注**：Q1 归位说明——按校验逆向实类归 reverse（选材线记 encoding 合集归类）；题名 xss 有误导性（实为 re）。
