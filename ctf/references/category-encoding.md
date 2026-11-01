---
verified: "2026-10-30 | 回流复跑轮（接手 A）：5 条全裁决——3 PASS / 2 INCONCLUSIVE（端到端素材缺口留痕）；本机 Python3.12，见各条复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "ctf-corpus 蒸馏层 P1+P2 批次（distill/by-category/encoding），原始 WP 见 ctf-corpus/raw/ 与 meta/register.jsonl"
changelog:
  - "[2026-11-02] v0.7：蒸馏 P4 批次并入 3 条（encoding_analysis 主标，hypothesis 待复跑；07 审阅 + 08 修正批已归零）｜源：ctf-corpus/distill/by-category/encoding/p4-20261030.md + candidates.jsonl（P4 批次报告 06、审阅报告 07、修正简报 08）"
  - "[2026-10-30] v0.6：蒸馏 P3 批次并入 5 条（中段困难档·薄域优先，hypothesis 待复跑）｜源：ctf-corpus/distill/by-category/encoding/p3-20261029.md + candidates.jsonl（P3 批次报告 02）"
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
6. [3-gram 间距定钥长 + base64 结构 oracle 逐位破 Vigenère](#3-gram-间距定钥长-base64-结构-oracle-逐位破-vigenère)（hypothesis）
7. [JSON 洋葱 op 指令驱动递归剥层（map/gzip/b64/xor/rev）](#json-洋葱-op-指令驱动递归剥层mapgzipb64xorrev)（hypothesis）
8. [摩斯无分隔符回溯分割（字典约束穷举）](#摩斯无分隔符回溯分割字典约束穷举)（hypothesis）
9. [PyPI 版本考古 + 七层编码链（b32→b64→gzip→binary→binary→hex→b85）](#pypi-版本考古-七层编码链b32b64gzipbinarybinaryhexb85)（hypothesis）
10. [PE 头三处修复救活废件（Machine/OEP/段名 UPX0-1）](#pe-头三处修复救活废件machineoep段名-upx0-1)（hypothesis）
11. [行星符号数字替换 + TAPIR 密码表解码（东德斯塔西遗留）](#行星符号数字替换--tapir-密码表解码东德斯塔西遗留)（hypothesis）
12. [交互题数值答案的 ASCII 侧信道编码（最短路→字符→base64）](#交互题数值答案的-ascii-侧信道编码最短路字符base64)（hypothesis）
13. [摩尔斯电码 + base36 组合信道（0-9A-Z 字母表识别）](#摩尔斯电码--base36-组合信道0-9a-z-字母表识别)（hypothesis）

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

### 3-gram 间距定钥长 + base64 结构 oracle 逐位破 Vigenère
- **分层**：困难·单点
- **假设**：MMACTF vigenere 为重复密钥古典替换：重复 3-gram 出现间距的 GCD 给出密钥长 12；每列单表替换可用「字符平移后整段须为合法 base64 明文」作硬约束 oracle——每列 256 个平移量中合法者唯一，逐列锁定，再按已知明文头（XLF/I8HU/shA6 前缀逐步）拼出全钥。
- **验证步骤**：1) 统计重复 3-gram 间距取 GCD ⇒ 12；2) 逐列平移试解，以「该列解字符全部落在 base64 字母表 + 解块可 decode 且可打印」过滤候选；3) 部分密钥（XLF 等）回填相邻列用明文连续性约束推进；4) 全钥解出整串。
- **判定标准**：PASS = 全钥 12 字符解密整段为合法 base64+明文链；FAIL = 用英文空格频谱法（本题字符集非 ASCII 英文文本，空格假设失灵）。
- **裁决词**：待复跑
- **来源**：MMACTF 2016 Vigenère｜六星战队（中国）｜raw/github-repos/sixstars/2016_mmactf_h_vigenere.md（间距统计与逐位爆破代码全量在 WP）
- **关联**：与 [[16 字符字母表 Vigenère（b16 前置 + 逐位独立密钥爆破）]] 同题族升级版（多了 base64 oracle）；与 [[自定义字母表 Base64 变体（IDA 加密函数逆向回推）]] 共享「结构可解性当过滤器」直觉。

### JSON 洋葱 op 指令驱动递归剥层（map/gzip/b64/xor/rev）
- **分层**：困难·多段链
- **假设**：jsonion.json 是 1.5MB 自描述洋葱：最外层 JSON 数组元素带 op 字段声明下一层变换（map=字符映射表 mapFrom→mapTo、gzip、b64、nul、xor=重复掩码异或、rev=反转）；写递归 process() 按指令逐层剥开约 9 层，终点 op=flag。
- **验证步骤**：1) json.loads 读首层取 op；2) 按分派表执行 map（str.maketrans）/gzip.decompress(b64decode)/xor（掩码循环扩展）/rev；3) 递归直至 op==flag 打印；4) 各层字节数日志佐证收敛。
- **判定标准**：PASS = 递归全程无异常且终点取到 flag；FAIL = 手工逐层（gzip 后二进制无 op 提示易迷路）或 map 表不一一对应抛 KeyError。
- **裁决词**：待复跑
- **来源**：HackVent 2017 Dec 9 JSONion｜Shiltemann (Galaxians)｜raw/github-repos/shiltemann/2017_hackvent_h_readme.md（递归解洋葱代码全量在 WP）
- **关联**：与 [[补条建议：编码套娃链识别与解链——链头数字标记密码类型]] 同族「自描述编码链」；gzip 层与 [[ZFS 删除队列与快照恢复（lz4 压缩剥层）]] 共享压缩剥层手法。

### 摩斯无分隔符回溯分割（字典约束穷举）
- **分层**：困难·单点
- **假设**：crypto100 只给连续点划流（无字符/单词分隔）：摩斯树非前缀唯一，分割歧义须靠字典约束——从串首开始回溯，每步取 1-4 位的摩斯码必须命中字母/数字表，单词边界再以目标词表过滤，最终唯一解为口令。（方法论重构注记：原题初版实际不可解——组织者 gist 解码器+数字字典产生约 2000 万 md5 候选未收敛，11 小时后承认出错并换发带空格分隔版本；本条将该方法重构为可收敛的字典约束回溯。）
- **验证步骤**：1) 建摩斯码表与反查字典；2) 回溯搜索所有合法字母分割；3) 对每个分割结果做词表匹配打分；4) 唯一高分解即口令（验证其满足题面语义）。
- **判定标准**：PASS = 对带分隔符版本直接解码验证口令；对无分隔符版本验证候选规模量级（海量即符合原文记录，不以收敛为判据）；FAIL = 贪心取最长码（前缀歧义直接错位）或误以「无分隔版应收敛」自责方法。
- **裁决词**：待复跑
- **来源**：DCTF Finals 2015 crypto100｜p4 (波兰战队)｜raw/github-repos/p4/2015_dctffinals_h_crypto100.md（原版解法尝试与换题记录在 WP，修改代码未贴）
- **关联**：与 [[时间倒放摩尔斯（整段倒放·符号序反转）]] 同域无分隔变体；回溯分割与 [[迷宫染色 QR 修复（非白即黑 + 邻接反色）]] 共享「约束空间剪枝搜索」。

### PyPI 版本考古 + 七层编码链（b32→b64→gzip→binary→binary→hex→b85）
- **分层**：困难·多段链
- **假设**：spentalkux 玩具包是编码链载体：最新版只有全息废话，图片提示 look back into the past——PyPI 历史版本 0.9 才是真身；其 base64 源解开后给出 7 层链（base32→base64→gzip→binary→binary→hex→base85），每层产物形态可嗅探逐层解。
- **验证步骤**：1) pip download spentalkux==0.9 或 PyPI 页取旧版；2) base64 解码得 go_away_msgs 与密文；3) 按层嗅探（b32 字母表/64 头/魔数 1f8b/01 串/0x 串/b85 字母表）逐层解；4) 末端得 flag。
- **判定标准**：PASS = 七层全自动脚本解出 flag；FAIL = 停在新版源码找逻辑（新版本是红鲱鱼，无解链）。
- **裁决词**：待复跑
- **来源**：AwesomeCTF 2020 Spentalkux｜Adrien Poirrier (Q C)｜raw/github-repos/apoirrier/2020_awesomectf_h_spentalkux.md（全链解码脚本在 WP）
- **关联**：与 [[补条建议：编码套娃链识别与解链——链头数字标记密码类型]] 同族（本条靠形态嗅探而非链头标记）；版本考古与 [[git 历史考古取旗（log 提交信息 / blame 作者 / 丢失提交找回）]] 共享「历史版本当真身」直觉。

### PE 头三处修复救活废件（Machine/OEP/段名 UPX0-1）
- **分层**：困难·单点
- **假设**：rev04.exe 被人为损坏头部打不开（DOS/PE 头本身完好）：① Machine 位深不符（32 位代码编成 PE64，UPX 3.08 壳特征佐证 32 位）；② Entrypoint/OEP 错误；③ UPX0/UPX1 段名被改（壳识别失败）。三处补正后正常加载脱壳分析。
- **验证步骤**：1) 按代码特征与 UPX 3.08 壳特征定 32 位、改 Machine；2) 按 UPX stub 特征恢复 Entrypoint/OEP；3) 段名改回 UPX0/UPX1；4) upx -d 脱壳后 IDA 分析还原算法。
- **判定标准**：PASS = 三处修复后可执行/可脱壳；FAIL = 漏修 OEP 或段名（单修 Machine 依旧拒载/脱壳失败）。
- **裁决词**：待复跑
- **来源**：WhiteHat GrandPrix 2018 rev04｜perfect blue (战队)｜raw/github-repos/perfectblue/2018_whitehat-grandprix_h_rev04.md（三处损坏点与 UPX 3.08 佐证在 WP）
- **关联**：与 [[OLE/Word97 头修复 + foremost 嵌套提取]] 同族「容器头修复前置」；脱壳后分析与 [[密码算法大礼包识别（常量指纹 + F5 恢复 + SM4 收官）]] 的常量指纹法互补。

### 行星符号数字替换 + TAPIR 密码表解码（东德斯塔西遗留）
- **分层**：困难·多段链
- **假设**：天文符号流（♆♀♇⊕）若为 1930-2006 九行星符号，按行星序号（☿1..♇9）替换得 5 位十进制组；每 5 位组按首位行号+后 4 位列号查 TAPIR 密码表（东德斯塔西真实用表，0=Zwischenraum 空格）即出德文/英文明文——历史密码档案的"符号→数字→查表"三跳。
- **验证步骤**：1) 建 planet→num 映射（☿♀⊕♂♃♄♅♆♇ = 1-9）；2) 符号流替换成数字串；3) 按 5 位切片（首位=行，后 4 位=列）；4) 查 TAPIR 表（WP 附全表）逐字翻译；5) 拼读 flag。
- **判定标准**：PASS = 解出可读英文；FAIL = 行列切位（5 位组内换位）或表版本差异（对照 wiki TAPIR 原表）。
- **裁决词**：待复跑
- **来源**：InternetWache CTF 2016 Crypto 50 Crypto-Pirat｜Writeup 仓（IceCTF 官方格式）｜raw/github-repos/hackthissite/2016_internetwache-ctf_h_crypto50.md
- **关联**：历史密码（TAPIR/恩尼格玛族）与库内古典密码条目互补（本条增量＝符号集+真实档案表）；提示词解读（"9 planets 1930-2006"）是谜面侦察通用功。
- **熵控预检**：Q1 无重名；Q3 强（映射表+TAPIR 全表在 WP）；Q4 边 1 条。

### 交互题数值答案的 ASCII 侧信道编码（最短路→字符→base64）
- **分层**：困难·多段链
- **假设**：100 关交互算法题（7x7 网格最短路和）若每关答案恰落在 32-126 可见 ASCII 域，逐关答案 chr() 拼接即是 base64 串，解码得 flag——出题人把"答案格式"本身当作编码载体，服务端 Congratz 提示后别急着退出，回看全部数值。
- **验证步骤**：1) DFS 三方向递归求最小路径和（剪枝 val+mx>best）；2) 100 关自动化循环收全部答案；3) 答案逐个 chr 拼串；4) base64 -d 解码。
- **判定标准**：PASS = 拼串是合法 base64 且解码可读；FAIL = 答案域超 ASCII（检查网格数值范围）或有关卡超时（换 Dijkstra）。
- **裁决词**：待复跑
- **来源**：Codegate CTF 2019 Preliminary algo_auth (Easy algorithm)｜kaibro｜raw/github-repos/balsn/slices/20190126-codegatectf/algo_auth.md
- **关联**："答案即编码"范式与 [[DTMF 双音多频拨号音译码 + 十进制流多跳解码]]（本批 forensics）同为多跳编码族；交互自动化与 [[ReCaptcha 并发窗口绕过（token 复用 + 字典喷洒）]]（本批 web）的会话管理互通。
- **熵控预检**：Q1 无重名；Q3 强（DFS 代码全在 WP）；Q4 边 1 条。

### 摩尔斯电码 + base36 组合信道（0-9A-Z 字母表识别）
- **分层**：超级难·单点
- **假设**：socket 服务下发点划流，摩尔斯解码后得到 0-9A-Z 混排长串（既非 b64 又非 b32）时，字母表恰 36 个提示 base36；解码得明文问题（What is SHA256(grapefruit1234)?），答案按同格式（明文→base36→摩尔斯）回传——双向自定义信道协议的完整闭环。
- **验证步骤**：1) 收流按点划/间隔切分查摩尔斯表；2) 识别 0-9A-Z 字母表→base36 int(s,36) 解码；3) 解出问题计算答案（hashlib）；4) 逆过程编码回发；5) 收 flag。
- **判定标准**：PASS = 服务端返回 flag；FAIL = 摩尔斯分隔符歧义（单空格字母/三空格词）或 base36 大小写敏感（统一大写）。
- **裁决词**：待复跑
- **来源**：PlaidCTF 2016 morset (Misc 50p/86 solved)｜p4 (波兰战队)｜raw/github-repos/p4/2016_plaid-ctf_x_morset.md
- **关联**：摩尔斯与 [[PT2262 无线信号波形译码（脉冲宽度三元映射）]]、[[Flash dump MKV 双音轨 + 2000Hz 正弦波摩尔斯 + base32 落图]]（本批）构成摩尔斯三载体（点划文本/波形/音轨）；"字母表基数识别"是编码分析域通用启发式（2/8/16/32/36/58/64/85 速查）。
- **熵控预检**：Q1 无重名；Q3 中（思路+样例在 WP，doit.py 未内联）；Q4 边 2 条。
