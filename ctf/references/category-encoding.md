---
verified: "2026-10-30 | 回流复跑轮（接手 A）：5 条全裁决——3 PASS / 2 INCONCLUSIVE（端到端素材缺口留痕）；本机 Python3.12，见各条复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "ctf-corpus 蒸馏层 P1+P2 批次（distill/by-category/encoding），原始 WP 见 ctf-corpus/raw/ 与 meta/register.jsonl"
changelog:
  - "[2026-10-30] 回流复跑轮：5 条全裁决（Noita/Vigenère/Bacon 三条 v3 求解器全 PASS——B 初版求解器缺陷已按 raw 原文重写修复，A 接手轮亲复跑全复现；gslab note/Astrolabe 二条数学核心部分复算成立但端到端素材缺失 → INCONCLUSIVE）；证据归档 shared/wtf-reflight-evidence-20261030/"
  - "[2026-10-29] v0.5 新库：蒸馏 P1+P2 批次建库并入 5 条（hypothesis 待复跑，REFLIGHT §1 二手知识纪律）｜11→10 库映射见 ctf-wp 采集规划 §4.4"
---

# 题型：编码分析

> 读取时机：非标准编码/自定义字母表、多层编码套娃、esoteric 语言类题面（本条目主库）

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态；changelog 每次结构变更一行留痕（append-only）。
4. 「升级」字段跳转目标用双中括号图边引用，必须命中全库某个 ### 级条目标题（第 4 检；字面示例只准放 frontmatter）。
5. 未经复跑的条目状态只允许 hypothesis（REFLIGHT §1 二手知识纪律）。

## 条目区（TOC）
1. [自定义字母表 base64（内存 dump 定位表）](#自定义字母表-base64内存-dump-定位表)（inconclusive）
2. [游戏 glyph 密码破译（Noita 眼睛符文 + 维基对照）](#游戏-glyph-密码破译noita-眼睛符文-维基对照)（verified）
3. [16 字符字母表 Vigenère（b16 前置 + 逐位独立密钥爆破）](#16-字符字母表-vigenèreb16-前置-逐位独立密钥爆破)（verified）
4. [排版 Bacon 密码（斜体/正体交替 5bit）](#排版-bacon-密码斜体正体交替-5bit)（verified）
5. [自改写字节码 VM 谐振编程（三层变换 + 精确周期预算）](#自改写字节码-vm-谐振编程三层变换-精确周期预算)（inconclusive）

### 自定义字母表 base64（内存 dump 定位表）
- **分层**：困难档·单点
- **假设**：明文流以非标准 64 字符表编码（`OPWvYny#Nopz0$HI…`）⇒ 在内存/静态数据区搜索与输出字符集吻合的 64 长度表 → 按表重建 index→6bit 映射 → 标准解码；常量特征串（0123-4567-89ab-cdef 循环）可先验定位目标区域。
- **验证步骤**：1) 字符集频率分析确认 64 符号域；2) dump 中 grep 表串；3) 以表序重解码；4) 末位 padding 依 76 长度补等号。
- **判定标准**：PASS = 解码得可读明文/旗；FAIL = 表为变序/含重复符 → 先去重校验再映射。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：① 端到端「解码得旗」不可复算——WP 未记录编码密文串与旗本体（corpus raw 仅有解法叙述）；② 缺原始二进制（gslab 2017 附件站下线），内存 dump 定位法无法活体重走。已复算子项（全部成立）：表 64 符号去重校验（65 长含 '=' padding、表体 64 符号无重复）、编解码 roundtrip 自洽（61 字节探针）、XOR 置乱表重构可逆（x^(x>>4) derangement）、z3 六元方程组解代入 eq1/eq2 全 True。
- **来源**：gslab 2017 note（misc）｜六星战队（中国）｜raw/github-repos/sixstars/2017_gslab_h_note.md（编解码函数与自定义表全量在 WP）
- **关联**：与 [[编码套娃链识别与解链]] 互补——套娃条管「层识别」、本条管「字母表面替换」；Q1 归位说明：按编码实质归 encoding（选材线记 misc 合集归类）。
- **陷阱备注**：变体表常与魔数常量相邻出现（`0123-4567-89ab-cdef` 循环是本题定位锚）。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 本机 Python3.12 | r45-gslab-astrolabe-partial.py（表校验/roundtrip/XOR 置乱重构/z3 解代入） | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/r45-gslab-astrolabe-partial.log | A 接手轮亲复跑全复现；补齐密文串或原二进制后可续跑升级 PASS |
### 游戏 glyph 密码破译（Noita 眼睛符文 + 维基对照）
- **分层**：困难档·复合链
- **假设**：两图所引符号是游戏 Noita 的眼睛字母文字（社区已破解）⇒ 检索 wiki/社区解码资料建立 glyph→字符映射 → 解出首段提示（编码方式说明）+ 次段编码正文 → 按提示做二次转换得旗。
- **验证步骤**：1) 识图确认 Noita 眼睛符文；2) 对照 noita wiki Eye Messages 映射；3) 按首段指示的编码（如 7 数结构/7 进制）转换；4) 校验旗格式。
- **判定标准**：PASS = 二次转换后旗格式成立；FAIL = 映射歧义（镜像/旋转形）→ 用高频字校准。
- **裁决词**：PASS
- **来源**：Hacky Easter 2024 Eyes Reading（misc medium）｜ngroegli｜raw/github-repos/ngroegli/hacky-easter-2024/Level5-Cinque/EyesReading/README.md（社区资料链接与解码输出在 WP）
- **关联**：[[替换密码·旗即密钥（密钥表重建）]] 的游戏文字版——密钥表来源从 oracle 换成社区知识库。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 本机 Python3.12（按 raw 原文重写的 v2/v3 求解器） | r3-noita-solver-v3.py（独立重建映射 c=0/t=1/r=2/d=3/l=4 + int 列表复算） | PASS | shared/wtf-reflight-evidence-20261030/r3-noita-v3.log | 独立复算 int 数 146 与 WP 记录全等；复算明文含旗 he2024{eYe5_$7ill_keep_a_5ecreT}；A 接手轮亲复跑全复现（B 初版映射表不全 KeyError 已修复） |
### 16 字符字母表 Vigenère（b16 前置 + 逐位独立密钥爆破）
- **分层**：困难档·单点
- **假设**：明文先 b16（字节→两个 4bit 半字节→16 字符表字符）再与未知密钥循环异或/移位 ⇒ 同密钥位对应的密文字符集合不受其他位影响 → 对每个密钥字符独立枚举 16 种候选，以「解出半字节对拼回可打印 ASCII」过滤。
- **验证步骤**：1) 密文按 16 字符域校验；2) 逐密钥位枚举 16 值；3) 半字节拼装 + hex 可读性过滤；4) 拼 picoCTF{} 校验。
- **判定标准**：PASS = 唯一密钥使全部位可解码；FAIL = 多候选 → 用 MD5 形态旗校验。
- **裁决词**：PASS
- **来源**：picoCTF 2021 New Vignere（crypto 300p）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2021_new-vignere-md_h_new-vignere.md（b16 解码与爆破代码在 WP）
- **关联**：关键差异 = 与 [[编码套娃链识别与解链]] 同「双层结构」但外层是循环密钥而非逐层编码——独立可枚举性来自密钥循环结构。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 本机 Python3.12（按 raw 原文重写的 v2/v3 求解器） | r1-vignere-solver-v3.py（good_letters 逐位 16 值枚举 + 全 hex 可解码过滤） | PASS | shared/wtf-reflight-evidence-20261030/r1-vignere-v3.log | 全解集唯一：key_len=9 key=bgabajepk → picoCTF{94bf01ad4b8a63425c32c02ba4c9632f}，与 WP ground truth 全等；A 接手轮亲复跑全复现（B 初版语法错已修复） |
### 排版 Bacon 密码（斜体/正体交替 5bit）
- **分层**：困难档·单点
- **假设**：正文以字体属性（斜体 vs 正体）作为二进制信道，5 字符一组按 Bacon 码表转字母 ⇒ 提取段落中每词的字符样式序列 → a/b 二值化 → 5bit 分组查表 → 去除填充（X）得旗。
- **验证步骤**：1) 解析 HTML/富文本样式标注；2) 按字符生成 a/b 序列；3) 5bit 查表；4) 尾部 X 填充规则（AAAAA/BBBBB→X）校验。
- **判定标准**：PASS = 解码串成旗；FAIL = 样式解析遗漏空格/标点 → 以原文长度整除 5 复核。
- **裁决词**：PASS
- **来源**：Hackvent 2019 Day 06 Bacon and Eggs｜shiltemann（CI team）｜raw/github-repos/shiltemann/2019_hackvent_h_day-06-bacon-and-eggs.md（样式序列与解码输出在 WP）
- **关联**：与 [[文本空白字符隐写（空格/制表符二进制）]] 同「排版属性信道」族——关键差异 = 本条用字体样式、该条用空白字符，提取器不同但 5bit 分组同构。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 本机 Python3.12（按 raw 原文重写的 v2/v3 求解器） | r2-bacon-solver-v3.py（样式流 a/b 二值化 + 5bit 查表 + 配置枚举） | PASS | shared/wtf-reflight-evidence-20261030/r2-bacon-v3.log | 路线 A/B 双载体三种配置均收敛同一旗 HV19{BACONCIPHERISSIMPLEBUTCOOL}（载体长 827/WP 块 823 差异为样式口径，旗不受影响）；A 接手轮亲复跑全复现 |
### 自改写字节码 VM 谐振编程（三层变换 + 精确周期预算）
- **分层**：困难档·复合链
- **假设**：自改写 VM 上须一次性命中三层「谐振」校验（置换门、耦合递推、椭圆曲线点）且总执行周期严格落窗（112 cycles）⇒ 离线预计算三段的正确输入组合（含 SAT/暴力可行部分），再以紧凑操作码编码 + 无操作垫圈把尾指令精确落在窗口内。
- **验证步骤**：1) 读 VM ISA 确定指令周期表与自改写规则；2) 三层变换分别求满足输入；3) 组装程序并计算周期；4) pad no-op 至 112 周期；5) 上载执行验证谐振。
- **判定标准**：PASS = 三环同时谐振且周期命中；FAIL = 周期超窗 → 换更短编码路径（复用指令/自改写折叠）。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：① 缺 ouroboros.7z 题目附件（corpus raw 仅 WP 文本），VM ISA/指令周期表与自改写规则无法活体重走；② 环 2 耦合递推与环 3 椭圆曲线点的精确形式 WP 未给出方程原式，形式探测未命中 ≥3/4 环。已复算子项（成立）：环 1 置换门 F(pre)==post 逐寄存器 True（claim (37101,35947,43627,40060)）；周期窗算术 4 loads+98 no-op+10 final=112 落窗（112–128）；曲线 y²=x³+17x+43 (mod 65521) 上给定四元组内部无点对（如实记录，与「点在曲线上」原文表述存在口径差——待附件复核）。
- **来源**：CSS CTF 2026 Return of Nexus The Astrolabe Overwrite（misc 250p/162 解）｜hax1ng｜raw/github-repos/hax1ng_css-ctf-2026-return-of-nexus/misc/the-astrolobe-overwrite/README.md（预计算与编码策略在 WP）
- **关联**：[[多源碎片雕刻与权威哈希仲裁（NXFR 记录）]] 同赛事姊妹题——「精确预算」纪律互证（那条是 hash 仲裁、本条是周期窗）。
- **陷阱备注**：静重部分（椭圆曲线）离线算，活重部分（beacon 同步+编码）保持轻量——「离线算重的、在线跑轻的」。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 本机 Python3.12 | r5-astrolabe-probe2.py + r45-gslab-astrolabe-partial.py（数学核心部分复算） | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/r45-gslab-astrolabe-partial.log | A 接手轮亲复跑全复现；附件 ouroboros.7z 入库后可续跑端到端 |
