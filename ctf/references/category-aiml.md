---
verified: "2026-10-30 | 回流复跑轮（接手 A）：4 条全裁决——1 PASS / 3 INCONCLUSIVE（缺口留痕见各条）；torch 2.15.0+cpu venv + 本机 Python3.12，见各条复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "ctf-corpus 蒸馏层 P1+P2 批次（distill/by-category/aiml），原始 WP 见 ctf-corpus/raw/ 与 meta/register.jsonl"
changelog:
  - "[2026-10-30] 回流复跑轮：4 条全裁决（torch.load RCE PASS；LLM UCT / embedding 时压 / Poe 注入 INCONCLUSIVE 缺环境与活体通道，缺口清单入条目）；证据归档 shared/wtf-reflight-evidence-20261030/"
  - "[2026-10-29] v0.5 新库：蒸馏 P1+P2 批次建库并入 4 条（hypothesis 待复跑，REFLIGHT §1 二手知识纪律）｜11→10 库映射见 ctf-wp 采集规划 §4.4"
---

# 题型：AI 安全

> 读取时机：模型文件/推理框架载入、prompt 注入、模型反序列化与数据投毒类题面（本条目主库）

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态；changelog 每次结构变更一行留痕（append-only）。
4. 「升级」字段跳转目标用双中括号图边引用，必须命中全库某个 ### 级条目标题（第 4 检；字面示例只准放 frontmatter）。
5. 未经复跑的条目状态只允许 hypothesis（REFLIGHT §1 二手知识纪律）。

## 条目区（TOC）
1. [torch.load 反序列化 RCE（pickle 载体模型文件）](#torchload-反序列化-rcepickle-载体模型文件)（verified）
2. [LLM 约束解码 + UCT 树搜索恢复审查文本](#llm-约束解码-uct-树搜索恢复审查文本)（inconclusive）
3. [embedding 余弦相似度时压题自动化（OpenAPI 规格驱动）](#embedding-余弦相似度时压题自动化openapi-规格驱动)（inconclusive）
4. [LLM bot prompt 注入泄漏系统提示（Poe 部署面）](#llm-bot-prompt-注入泄漏系统提示poe-部署面)（inconclusive）

### torch.load 反序列化 RCE（pickle 载体模型文件）
- **分层**：困难档·复合链
- **假设**：服务端以 `torch.load()` 载入选手上传的模型文件且无沙箱 → `.pt` 本质是 pickle 序列化 → 构造 `__reduce__` 返回 `os.system`（或 subprocess）即可在加载瞬间执行任意命令；若前端在异常后仍读取固定的结果文件路径，则只需把 flag 写入该路径即完成外带。
- **验证步骤**：1) 审题面（PyTorch 1.9.1、上传 `.pt`、前端读 `/tmp/result.json`）；2) 本地构造 evil.pt：类 `__reduce__` → `os.system("cat /flag > /tmp/result.json")`；3) 训练/上传接口提交；4) 前端回读 result.json（异常被忽略）。
- **判定标准**：PASS = result.json 落盘且页面回显 flag；FAIL = 服务端启用 `weights_only=True`（≥2.6 默认）→ 转模型格式其他 RCE 面（自定义 reduce 链在 weights_only 下失效）。
- **裁决词**：PASS
- **来源**：Hackergame 2022 二次元神经网络（web 250p）｜USTC-Hackergame（官方+选手，题解 volltin/taoky）｜raw/github-repos/hackergame2022/2022_hackergame_h_cn-36853f.md（构造思路与前端「忽略异常读结果」行为在 WP；本地 pip 装 torch 1.9.1 可全重放）
- **关联**：同族 [[Java XMLDecoder 签名文件反序列化 RCE]]——关键差异 = 载体为 pickle 协议且「前端忽略异常仍读结果文件」使 payload 无需稳定回显通道。
- **陷阱备注**：`torch.load` 的危险面在 2.6 前无任何默认缓解——「模型文件 = 数据」直觉是本题认知陷阱。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 本机 venv Python3.12 + torch 2.15.0+cpu（B 会话装机，A 接手轮亲复跑） | r4-torchload-solver.py（构造 model_exp.pt：__reduce__ 写 result.json） | PASS | shared/wtf-reflight-evidence-20261030/r4-torchload-v2.log | 注入代码执行落盘（result.json：RCE-REFLIGHT-PROOF）；对照组默认参数 UnpicklingError——torch≥2.6 weights_only 防护已生效、原载荷失效（环境演进如实留痕；vulnerable 路径显式复现成功） |
### LLM 约束解码 + UCT 树搜索恢复审查文本
- **分层**：困难档·复合链
- **假设**：审查系统按字符替换（敏感词→'x'）保留长度与上下文统计特征 → 本地跑同款量化模型（Qwen2.5-3B q8 GGUF + llama.cpp），逐 token 推理时把「与密文模式冲突的 token」概率置 0（语法掩码）→ 生成空间坍缩为搜索树，叶子 = EOG；用 MCTS 的 UCT 公式（利用先验概率 + 探索项）遍历，在多叶子场景收敛到满足 hash 校验的原文。
- **验证步骤**：1) 定位采样函数（llama-cpp-python top-p/top-k 为概率向量函数）；2) 逐位置 mask 后取可行 token 分支；3) UCT 遍历至 EOG；4) sha512 前 16 位拼 flag 校验。
- **判定标准**：PASS = 12 分钟量级（4060）得出命中 hash 的原文；FAIL = 纯 DFS 卡死在次优分支（出题人故意挑了次优分支多的样本）→ 必须引入探索项，剪枝改 top-p 阈值。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：① llama.cpp 工具链未装（本机无 llama-cli/llama-server/ollama，venv 仅有 torch CPU 轮）且 WP 记录的 exp.patch 补丁本体未随 corpus 入库；② HuggingFace 出站不可达（GGUF 直链 curl 超时，约 3GB 模型无下载通道）；③ CPU 推理预算 ≥1h 超本轮会话时限。torch venv 无法替代——条目核心是 llama.cpp 约束解码补丁栈。
- **来源**：Hackergame 2024 先不说关于我从零开始独自在异世界转生成某大厂家的 LLM 龙猫女仆这件事（AI 150/350p）｜emc2314｜raw/github-repos/hackergame2024/2024_hackergame_h_llm.md（解题基于 llama.cpp patch，exp.patch 在附件；CPU 1 小时亦可行）
- **陷阱备注**：lv2 有多个达 EOG 的叶子——「贪心 argmax 一条路走到黑」必然失败；UCT 是本题核心而非可选项。C 端无显卡时需把计算量控制在桌面 CPU 1 小时内（作者实测可行）。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 本机环境核查（llama.cpp/GGUF 可行性探测） | which llama-cli/ollama + curl HF 直链（详见环境核查记录） | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/aiml24-env-check.md | 三缺口见上；工具链补齐（llama.cpp 编译 + exp.patch 提取 + GGUF 就位）后可续跑 |
### embedding 余弦相似度时压题自动化（OpenAPI 规格驱动）
- **分层**：困难档·自动化链
- **假设**：网页宣称「10 轮 × 每轮 3 秒」人工不可能 → 服务是 FastAPI 且暴露 `/openapi.json` → 先读规格拿到 `/round`（GET）与 `/answer`（POST）schema，再写脚本本地 numpy 算 cosine 相似度全流程闭环，把「时压」变「脚本时延」。
- **验证步骤**：1) `curl /` 与 `/openapi.json` 摸清 schema（AnimalVector{name,vector} / RoundResponse / AnswerRequest）；2) GET /round 取目标向量与候选集；3) 归一化点积取 argmax；4) 3 秒内 POST /answer × 10 轮。
- **判定标准**：PASS = 10/10 轮正确出 flag；FAIL = 422 → 字段名/类型对不上（读 schema 校验），或遇「服务每小时整点重启」→ 重连。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：① 活体服务已下线（ch.hackeyeaster.com NXDOMAIN 实测，端到端不可复现）；② mock 契约复放虽 10/10 闭环（0.001s/轮 ≪ 3s 限速，round1 数据取 WP 原样、argmax pig=0.983801 与 WP 记录一致），但 2-10 轮正确性判定由 mock 自身闭合（循环论证），不构成独立复算证据——如实不采信为 PASS。
- **来源**：Hacky Easter 2026 Fauna in Feature Space（ai·medium）｜ngroegli｜raw/github-repos/ngroegli/hacky-easter-2026/Level6-MediumRare/FaunainFeatureSpace/README.md（openapi.json 与完整解题脚本在 WP 附件）
- **陷阱备注**：正解的第一步是发现 OpenAPI 规格端点而非逆向 JS——「先读接口合同再写代码」的自动化纪律。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 本机 venv Python3.12（Mock FastAPI 契约复放） | aiml3-fauna-mock.py（按 WP openapi.json 契约构造 mock，round1=WP 原样数据） | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/aiml3-fauna-mock.log | 10/10 轮 correct/completed，0.001s/轮；可复算子项=round1 数据与 argmax 选择同 WP；活体复活或取到 WP 附件 openapi.json 原件后可续跑 |
### LLM bot prompt 注入泄漏系统提示（Poe 部署面）
- **分层**：困难档·单点
- **假设**：题目 bot（Poe 平台部署的 ChatGPT）系统提示词内嵌 flag → 直接把题目描述原文回贴/要求复述内部指令即可绕过「不透露」约束，模型按指令优先级输出 flag。
- **验证步骤**：1) 访问 bot 页面读 description（「CTF通靈師」）；2) 把挑战描述原文作为消息发送；3) 收集输出中的 `hkcert23{...}`。
- **判定标准**：PASS = 单轮对话内出 flag；FAIL = 平台侧过滤命中 → 转角色扮演/编码（base64/拼写变形）再注入。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：① 沙箱对 poe.com 出站不可达（curl rc=124 超时、agent-browser Page.navigate 超时，B/A 两会话同现象）；② 对话重放需 Poe 登录态 + 实时 JS 会话，本环境不可完成。已证子项：web_reader 旁路确认 bot 页存活（标题 `HKCERT23Psychic - Poe`）。
- **来源**：HKCERT CTF 2023 Psychic AI（misc）｜siunam321｜raw/github-repos/siunam321/HKCERT-CTF-2023/misc/Psychic-AI.md（bot 链接与对话截图在 WP；本地可对任意 LLM 重放同型注入）
- **关联**：Q1 边界——同「注入取数据」族但对象是模型上下文而非数据库，与 [[sqlmap 基线用法]] 互为表层/上下文两端。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 沙箱网络 + web_reader 旁路 | poe_probe.sh（curl/agent-browser 双探） + web_reader 读取 bot 页 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/poe-probe.log + aiml24-env-check.md | 直连全超时（B 会话空壳日志同因）；旁路确认页面存活；具备 Poe 登录态的运行环境可续跑 |
