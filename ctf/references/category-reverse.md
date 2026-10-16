---
verified: "2026-10-15 | 本地复跑：Python 3.12.13 / strings(GNU binutils) / gcc 13（Linux 容器），见条目1复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "CTF-wiki（reverse 章节）、mukul975/Anthropic-Cybersecurity-Skills（结构化条目范式）、M2 实测复跑（2026-10-15）"
changelog:
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
