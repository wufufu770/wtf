# PORTABILITY.md — 跨 Agent 通用性说明（wtf / ctf，v0.7）

> 本仓库是 SKILL-DUO 项目 ctf skill 的独立发行版。硬约束不变：**skill 不得绑定任何单一运行时**。任何支持 SKILL.md 约定（Anthropic Agent Skills 规范 / agentskills.io 事实标准）的 Agent 都应能直接加载。

## 1. 已遵守的通用规范

| 约束项 | 本仓库做法 |
|---|---|
| frontmatter | 仅 `name` + `description` 两个公开通用字段；name ≤64 字符、小写连字符、与目录名一致；description ≤1024 字符（v0.5 实测 964 字符，见 §4）。**不使用** `allowed-tools`、`metadata` 等非通用或平台专有字段 |
| 专有语法 | 全库禁用：特定 Agent 的工具调用格式、`{{...}}` 模板变量、平台专有 hook/拦截指令、`<EXTREMELY-IMPORTANT>` 类社区私有标签。所有指令用通用祈使句书写 |
| 引用方式 | references 全部纯 markdown，相对路径 + 正斜杠，**引用只许一层深**（SKILL.md → reference，不嵌套）；>100 行的引用文件头部加 TOC |
| 无人类向文件 | skill 目录（ctf/）内不放 README/CHANGELOG/INSTALLATION（PORTABILITY.md、README.md 与 tests/ 置于 skill 目录之外，不参与加载） |
| 行数经济 | SKILL.md 正文 78 行（≤150；v0.5 题型路由表 6→10 行 + 策略层行 + 策略跳转规则后仍达标），只做索引+触发+回流，技术细节全部外置 |

## 2. 兼容边界（如实声明，不掩盖）

1. **shared/ 已复制入库（形态 B：复制 + 重新同步）**：本仓库为独立发行版，SKILL-DUO 源项目的共享层（`shared/REFLIGHT.md` 与 `shared/tools/`）已**复制**进本仓库，`ctf/SKILL.md` 以 `../shared/...` 相对路径引用。装载形态：
   - **形态 A（推荐，目录树完整）**：克隆整个仓库后以目录树为单位注册/加载，相对路径直接生效；
   - **形态 B（单目录装载的降级）**：将 `ctf/` 单独拷入仅支持单 skill 目录的运行时前，需把 `shared/` 内容并入 `ctf/` 内并修正引用路径，使 skill 变为自包含副本。
   **同步义务**：复制意味着去重失效——本仓库 `shared/` 与姊妹仓库 [wpt](https://github.com/wufufu770/wpt) 的 `shared/` 保持同源，**任一侧对 `shared/` 的修改必须重新同步到另一侧**（`diff -r` 校验零差异），否则共享层漂移。此义务已在两仓库 README 与 `shared/tools/INDEX.md` 维护规则中注明。
2. **references 的 frontmatter**：SKILL.md 规范只约束 SKILL.md 本身；references 头部的 verified/status/source/changelog 是本项目的**知识管理约定**（YAML 子集，多数 markdown 渲染器可解析，不参与触发机制），任何 Agent 忽略它也不影响加载。状态为五态（hypothesis/verifying/verified/refuted/inconclusive），裁决词 PASS/FAIL/INCONCLUSIVE 为纯文本标准词，任何 Agent 均可静态校验，无平台依赖。
3. **触发依赖 description**：触发逻辑全部写在 description 字段内，未假设任何运行时的确定性路由能力；可用 tests/trigger-regression.md 的 20 条用例做触发回归（其中 C-01~C-05 正向用例与 §B 全部负例适用于本仓库；P 系用例属姊妹仓库 pentest skill，保留在清单中便于双仓库统一对照）。
4. **REFLIGHT 协议的通用性**：回流协议（shared/REFLIGHT.md）为纯 markdown 约定——状态机五态、裁决词三态、复跑记录为普通 markdown 表格。它不调用任何平台能力，单 Agent 亦可独立执行（自己写条目、自己复跑、自己推进状态）；多 Agent 场景下可作为跨 Agent 的共享知识库纪律。v0.3 实战闭环 7 条（6 PASS + 1 FAIL）全部本机可复现，复跑证据见各题型文件复跑记录表。

## 3. 验证方式

- 加载验证：目标 Agent 装载后，用 tests/trigger-regression.md 的适用用例跑触发回归（每条 3 次取多数）。
- 结构验证：name=目录名、description 长度、SKILL.md 行数、引用一层深，四项可用脚本静态检查。
- 回流质量验证：tests/reflight-static-check.py 做静态校验——裁决词正则 `^(PASS|FAIL|INCONCLUSIVE)$` + 状态词枚举 + 复跑表存在性 + 图边引用存在性（v0.4 第 4 检：[[条目名]] 必须命中全库条目标题）。

## 4. 实测指标（v0.7，2026-11-02 更新）

- ctf/SKILL.md：78 行（≤150 达标；v0.5 题型路由表 10 行 + 策略层行 + 策略跳转规则后仍达标）；description 964 字符（≤1024 达标）。
- ctf 十题型知识库：五段式条目 368 条（web 46 / crypto 50 / forensics 108 / reverse 33 / pwn 31 / mobile 16 / recon 50 / misc 10 / encoding 13 / aiml 11；其中 134 条 v0.5 蒸馏 P1+P2 并入 + 110 条 v0.6 蒸馏 P3 并入 + 100 条 v0.7 蒸馏 P4 并入（07 审阅 + 08 修正批 28 项归零后入库），均自 hypothesis/待复跑起步；库内硬裁决 44 / 待复跑 344）。
- 策略层（v0.5 首建）：references/strategy-{cross,pwn,crypto,forensics,recon,web}.md 六域策略页 16 条 + 机读 strategy.jsonl（镜像自 ctf-corpus 策略库，源库六检 6/6）——本仓镜像口径维持 v0.5 十六条；ctf-corpus 策略源库已增至 21 条（P3/P4 轮新 seed），整体镜像统一留待下轮策略层发行，本轮仅回填池侧双向互指。
- v0.7 变更面：ctf/references/ 九份 category-*.md（P4 批次 100 条并入；misc 无 P4 条目未动）、ctf/SKILL.md（路由计数 v0.7）、README.md 与本文件同步 v0.7 指标——shared/ 与 tests/ 未动，与 SKILL-DUO 源及 wpt 仓库保持字节同源（`diff -r` 零差异）。入库口径：仅并入候选池条目区正文（含熵控预检行随条目 verbatim 入库），池侧选材留痕/处置表等审计段原地保留不入库。
- v0.6 变更面（存档）：ctf/references/ 十份 category-*.md（P3 批次 110 条并入 + 已入库条目修正批同步 33 项 + recon 重复标题清理 6 处）。
- 跨 Agent 通用性硬约束逐项复核：frontmatter 双字段、无专有语法、一层深引用、无人类向文件——均未回退。
- v0.6 指标存档：条目总数 268（硬裁决 44 / 待复跑 244）、图边 318 / 节点 304；v0.5.1 指标存档：条目总数 158 不变、硬裁决 44 / 待复跑 134，图边 96 / 节点 194；v0.5 指标：五段式条目 158 条，ctf/SKILL.md 78 行，description 964 字符。
