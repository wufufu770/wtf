---
verified: "[协议文件：2026-10-15 制定]"
status: verified
source: "调研结论②：transilienceai/communitytools「基准失败→写 skill→复跑」范式（15 轮迭代 +10.6pp，回流关键输入是失败样本）+ Black-cat verdict 三态机检 + ACS 条目门槛（模板校验+PR 审查）；SKILL-DUO v0.2"
changelog:
  - "[2026-10-15] 新增：REFLIGHT 回流协议 v1（状态机 + 机器可校验裁决词表 + 复跑记录格式 + 回流门槛）"
  - "[2026-10-15] M2 实战检验：ctf 六题型库填充 24 条，7 条完成 hypothesis→verifying→verified/refuted 复跑闭环（6 PASS + 1 FAIL），静态校验脚本 tests/reflight-static-check.py 落地并通过"
---

# REFLIGHT —— 知识回流协议（pentest / ctf 双 skill 共用）

> 定位：两个 skill「收尾回流条款」的唯一协议源。回流闭环 = 实战/基准 → 失败与成功样本 → 五段式条目写入 references → 复跑验证 → 状态机推进。
> 回流的最小单元是**带触发条件与可观测验证判据的技术条目**，不是叙事文档（transilienceai 教训：叙事 skill 让模型失焦，条目化才提分）。

## 1. 条目状态机

```
hypothesis（假设，默认态，≈旧 draft）
   │  开始执行条目「验证步骤」
   ▼
verifying（验证中：至少一条复跑记录在案，尚无最终裁决）
   │  复跑产出裁决词
   ├─ PASS ─────────→ verified（验证通过：须 ≥1 条 PASS 复跑记录）
   ├─ FAIL ─────────→ refuted（证伪：须附 FAIL 记录 + 失败原因，失败样本留存价值最高）
   └─ INCONCLUSIVE → inconclusive（证据不足挂起：须写明缺口——缺环境/缺靶场/判据不可观测）
```

- 状态只能沿箭头推进；verified 之后被新证据推翻 → 回退 refuted，changelog 追加一行说明，**不删除原文**（与 changelog 同纪律）。
- 旧词映射（兼容已回流历史条目）：draft ≡ hypothesis；deprecated ≡ refuted。
- 未经复跑的条目只允许停在 hypothesis；verifying 是过程态，收尾时不允许以 verifying 结束——要么有裁决词，要么标 inconclusive。

## 2. 机器可校验裁决词表

条目「裁决词」字段只允许以下标准词（正则 `^(PASS|FAIL|INCONCLUSIVE)$`，可被脚本/CI 直接 grep 校验）：

| 裁决词 | 判定语义 | CTF 语境示例 | Pentest 语境示例 |
|---|---|---|---|
| **PASS** | 条目「判定标准」全部成立 | payload 打出 flag{...}（拿到 flag 恒为 PASS 的充分条件） | 非破坏性 PoC 复现成功且留有工件 |
| **FAIL** | 判定标准明确不成立 | 该思路证伪 | 漏洞不可利用 / 前提不成立 |
| **INCONCLUSIVE** | 无法观测或环境不支持 | 靶场环境与题面差异过大 | 需生产数据或二次授权才能验证 |

- 不允许出现"应该差不多""大概率可行"类模糊裁决；判据必须**外部可复现**（工件、靶机 solve log、命令输出），不信模型自述（验证外部化原则）。
- pentest 特例：PoC 必须非破坏性跑通才算 PASS，破坏性验证须 RoE 显式允许。

## 3. 五段式假设条目模板（写入各 references/ 的唯一格式）

```markdown
### <条目名：一技术一条目>
- **假设**：<现象/信号触发的待验证判断>
- **验证步骤**：<可直接执行的命令管道/操作序列，低自由写法（精确命令，不自改参数）>
- **判定标准**：<什么算 PASS / 什么算 FAIL，必须是可观测判据>
- **裁决词**：PASS | FAIL | INCONCLUSIVE（当前态）
- **来源**：<URL / 仓库 / 实战记录标识>
- （可选）**升级**：<PASS 后拿到什么、跳转哪条链；FAIL 后转哪个新假设>
- （可选）**关键差异**：<模型盲区/易错点——把"为什么想不到"显式写成知识>

### 复跑记录（verified / refuted / inconclusive 必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | <YYYY-MM-DD> | <发行版/工具版本/靶场> | <cmd> | <PASS> | <evidence/...> | |
```

## 4. 复跑记录格式要求

1. **状态与记录匹配**：verified ≥1 条 PASS 记录；refuted ≥1 条 FAIL 记录 + 失败原因；inconclusive 必须写明缺口清单。
2. 复跑记录为文件内 **append-only 追加表**，不删除、不回改历史行（与 frontmatter changelog 同纪律）。
3. 工件路径按 `pentest/references/scope-authorization.md` §2 的输出路径分级存放（reports/ evidence/ loot/）。
4. 同一条目跨环境复跑结论冲突时：以最新记录为准推进状态，冲突环境写入备注，不删除旧行。

## 5. 回流触发物与写入门槛

| 触发物 | 依据 | 处置 |
|---|---|---|
| 基准/实战**失败样本** | transilienceai：回流关键输入是失败样本而非成功经验（15 轮 +10.6pp） | **优先回流**；refuted 条目必须写明"下一步转哪个新假设" |
| 被证伪的假设路径 | Black-cat：killed 也写 ledger，证伪知识可复用 | 同上，status 推进到 refuted |
| 覆盖缺口 | ACS：条目密度计数暴露薄域 | 收尾时盘点本命中文件的条目密度，薄区在 changelog 标注 |
| 成功手法 | 常规回流 | 五段式齐备才可写入 |

**写入前门槛（回流检查清单，可脚本静态校验）**：

- [ ] 五段式齐备，裁决词属于标准词表（`^(PASS|FAIL|INCONCLUSIVE)$`）
- [ ] 条目状态与复跑记录匹配（见 §4.1）
- [ ] 工具用法已归 `../shared/tools/`，条目内未重复工具语法（去重原则）
- [ ] 人类向叙事（writeup 复盘、长文）留在 skill 目录之外，不占知识库

> 以上清单是后续 CI 的校验面：裁决词正则 + 状态词枚举 + 复跑表存在性三项均可用静态脚本检查（对应 PORTABILITY.md"结构验证后续补 CI"条目）。
