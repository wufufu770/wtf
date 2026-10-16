# wtf — CTF 解题 Skill（ctf）

> 本仓库是 SKILL-DUO 双技能体系中 **ctf skill 的独立发行版**（自包含副本）。姊妹仓库 [wufufu770/wpt](https://github.com/wufufu770/wpt) 为授权渗透测试 skill。

## 用途

为任何支持 SKILL.md 约定（Anthropic Agent Skills 规范 / agentskills.io 事实标准）的 Agent 提供一套 **CTF 解题**知识底座：十题型知识库（web / pwn / reverse / crypto / forensics / misc / AI 安全 / 移动安全 / 信息搜集·数据安全 / 编码分析，v0.3 已填充五段式假设条目 40 条）+ REFLIGHT 经验回流协议（含 7 条本机可复现实战闭环记录）。

## 目录结构

```
wtf/
├── ctf/                      # skill 本体（加载单元）
│   ├── SKILL.md              # 索引 + 触发 + 题型路由表 + 收尾回流
│   └── references/           # 10 份：category-web / pwn / reverse / crypto / forensics / misc / aiml / mobile / recon / encoding
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

## 许可证

License 占位（待定）：TBD。正式发布前需确定（候选：MIT / Apache-2.0 / CC-BY-4.0）。
