# wtf — CTF 解题 Skill（ctf）

> 本仓库是 SKILL-DUO 双技能体系中 **ctf skill 的独立发行版**（自包含副本）。姊妹仓库 [wufufu770/wpt](https://github.com/wufufu770/wpt) 为授权渗透测试 skill。

## 用途

为任何支持 SKILL.md 约定（Anthropic Agent Skills 规范 / agentskills.io 事实标准）的 Agent 提供一套 **CTF 解题**知识底座：十题型知识库（web / pwn / reverse / crypto / forensics / misc / AI 安全 / 移动安全 / 信息搜集·数据安全 / 编码分析，v0.5 五段式假设条目 158 条）+ 六域策略页（「这类题怎么想」16 条 + 机读 strategy.jsonl）+ REFLIGHT 经验回流协议（含 7 条本机可复现实战闭环记录）。

## 目录结构

```
wtf/
├── ctf/                      # skill 本体（加载单元）
│   ├── SKILL.md              # 索引 + 触发 + 题型路由表 + 收尾回流
│   └── references/           # 17 份：category-* 10 份（十题型）+ strategy-{cross,pwn,crypto,forensics,recon,web}.md 六域策略页 + strategy.jsonl（机读）
├── shared/                   # 双 skill 共用层（本仓库为自包含副本，见下方同步义务）
│   ├── REFLIGHT.md           # 回流协议：五态状态机 + 裁决词 + 复跑记录
│   └── tools/                # 工具用法唯一真相源（6 份 + INDEX 路由表）
├── tests/
│   ├── trigger-regression.md # 触发回归用例（20 条；C-01~C-05 与全部负例适用本仓库）
│   └── reflight-static-check.py  # REFLIGHT 静态校验
├── PORTABILITY.md            # 跨 Agent 通用性说明
└── README.md
```

## 加载方式

- **形态 A（推荐）**：整个仓库克隆后以目录树为单位注册/加载，`ctf/SKILL.md` 中的 `../shared/...` 相对路径直接生效。
- **形态 B（单目录装载）**：将 `ctf/` 目录单独拷入仅支持单 skill 目录的运行时——此时 `../shared/` 引用会悬空，必须先将 `shared/` 内容并入 `ctf/` 内并同步修正引用路径（自包含降级，详见 PORTABILITY.md §2）。

## 触发场景

触发逻辑全部写在 `ctf/SKILL.md` 的 description 字段内（无平台专有路由依赖）。典型触发话术：CTF 赛题、flag 格式（flag{...}）、pcap 流量取证题、pwn 附件（ELF/NX/canary）、RSA/AES 密文参数、crackme 逆向。干扰排除：数学竞赛题、密室逃脱解谜、无 flag 的恶意样本分析、开发任务等**不触发**。回归用例见 `tests/trigger-regression.md`。

## shared/ 同步义务（形态 B：复制 + 重新同步）

本仓库的 `shared/` 是从 SKILL-DUO 源项目**复制**而来的自包含副本，与姊妹仓库 [wpt](https://github.com/wufufu770/wpt) 的 `shared/` 保持同源（当前字节一致）。依据 `shared/tools/INDEX.md` 的去重维护规则：

- **任一仓库对 `shared/` 的修改（含 REFLIGHT.md 与 tools/ 任一文件），必须同步回另一个仓库**，否则两仓库共享层漂移；
- 同步校验方法：对两仓库 `shared/` 目录做 `diff -r`，应零差异；
- 上游合并方向：SKILL-DUO 源项目（如仍在维护）→ 本仓库与 wpt 仓库。

## 版本记录

- **v0.3（2026-10-16）**：初始发布（7c9e336，六题型 24 条）+ 题型扩容（c5c7dd1，新增 aiml / mobile / recon / encoding 四文件，共十题型 40 条五段式假设条目）。
- **v0.4（2026-10-16）**：Cairn/CTF-Agent 前沿设计借鉴（源自《reArtex 启发系列二》调研 5 条落点）——① ctf/SKILL.md 新增 §5「单题工作区」（四件套：challenge.md / metadata.json / attachments / notes.md+artifacts，状态放文件树不放对话历史，边界：单题入口而非隐藏状态系统）；② shared/REFLIGHT.md §5 增熵控五问回流结构门槛 + INDEX 查重链；③ §1 增死锁条款（同一假设连续 FAIL ≥3 禁止原路复跑，强制转新假设或标 inconclusive），收尾回流段引用；④ 六份题型文件「升级」字段边化（`→ [[条目名]]` 图边引用，当前图 9 边 / 60 节点）；⑤ tests/reflight-static-check.py 增第 4 检（图边引用存在性）。shared/ 与 tests/ 与 wpt 仓库及 SKILL-DUO 源字节同源（`diff -r` 零差异）；16 个知识文件静态校验 0 违例；ctf/SKILL.md 76 行（≤150）、frontmatter 仅 name/description、纯 markdown 相对路径——硬约束不回退。
- **v0.5（2026-10-29）**：蒸馏批次入库（P1+P2）——① 知识库十库扩容：并入 ctf-corpus 蒸馏层 P1 试点 30 + P2 中段困难档 104 = 134 条五段式条目（全部 hypothesis/待复跑，REFLIGHT §1 二手知识纪律），累计 158 条（web 27 / crypto 33 / forensics 26 / reverse 20 / pwn 19 / mobile 7 / recon 7 / misc 10 / encoding 5 / aiml 4）；② 策略层首建：`references/strategy-{cross,pwn,crypto,forensics,recon,web}.md` 六域策略页 16 条（cross 7 / pwn 4 / crypto 2 / forensics 1 / recon 1 / web 1）+ 机读 `strategy.jsonl`（镜像自 ctf-corpus 策略库，源库六检 6/6，状态 hypothesis 5 / verifying 11）；③ SKILL.md v0.5：题型路由表 6→10 行 + 策略层行 + 策略跳转规则（首跳受挫加载对应策略档位，命中/失效回写应用记录），78 行（≤150 硬约束不回退）；④ tests/reflight-static-check.py 四检全绿（状态词/裁决词/复跑表/图边引用，退出码 0）。
- **v0.5.1（2026-10-30）**：reflight 回流复跑轮（v0.5 四新类收口）——① aiml/mobile/recon/encoding 四库 23 条 hypothesis 逐条亲复跑全裁决：**8 PASS / 0 FAIL / 15 INCONCLUSIVE**（缺口如实分级留痕：环境/网络型 3、素材缺失型 9、活体 OSINT 型 3；REFLIGHT §1 纪律——无判据条目不推进状态，不放水）；② 库内计数：条目总数 158 不变，硬裁决 21→44（21 旧 + 23 新）、待复跑 157→134，图边 96 / 节点 194；③ 复跑要点：encoding 三条求解器按 raw 原文重写 v3 亲复跑（Vigenère 唯一解复现 / Noita int 列表全等 / Bacon 三配置收敛同旗）、torch.load pickle RCE 亲复现（对照组确证 torch ≥2.6 weights_only 默认防护）、InjuredAndroid 开源全源码四数据面审计 + firebase 双端点活体 HTTP 200、CSAW 2015 逐跳链活体 10+ 年存活抽检一致；④ 证据归档 `shared/wtf-reflight-evidence-20261030/`（19 文件，含接手 A 亲复跑汇总日志 rerun-A-20261030.log）；⑤ tests/reflight-static-check.py 四检全绿（22 文件、条目裁决词 178、0 违例，退出码 0）。

## 许可证

License 占位（待定）：TBD。正式发布前需确定（候选：MIT / Apache-2.0 / CC-BY-4.0）。
