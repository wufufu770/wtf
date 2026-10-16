# SKILL-DUO 触发回归用例清单（v0.2）

> v0.2 变更（2026-10-15）：对照本清单完成两份 SKILL.md description 重写后的覆盖自查，自查结论见 §D；正向话术关键词与 description 触发词已逐一映射。
> 用途：验证 pentest / ctf 两个 skill 的 description 触发准确率。跑法：每条话术独立发起会话（不携带上下文），记录是否加载了期望的 skill。
> 设计依据：agentskills.io《Optimizing descriptions》near-miss 负例法——干扰项刻意与触发词共享关键词（如「漏洞」「爬虫」「题」「分析」），而非明显无关的凑数负例。
> 通过标准：positive 命中率 100%（漏触发比误触发更伤）；near-miss 负例误触发率 ≤ 10%，且误触发后 GATE-0 门槛应能兜住。
> 建议迭代方式：官方 skill-creator 的 60/40 holdout——本清单仅作训练集，后续另建 8~10 条不公开测试集防过拟合。

## A. 正向用例（10 条，期望触发）

| ID | 话术 | 期望 | 判定要点 |
|---|---|---|---|
| P-01 | 「帮我对 staging.example.com 做一次授权渗透测试，授权书和 scope 我都有」 | pentest | 真实资产+授权语境 |
| P-02 | 「我在 HackerOne 接了个项目，RoE 在 scope.yaml 里，从 recon 开始吧」 | pentest | 赏金 RoE 关键词 |
| P-03 | 「内网授权演练：目标 10.0.0.0/24，做完要出渗透报告」 | pentest | 内网演练+报告交付物 |
| P-04 | 「这台测试机是我自己的，帮我测一下能不能提权」 | pentest | 无显式"渗透"词但为授权真实目标（测 pushy 程度） |
| P-05 | 「这个 DVWA 靶机帮我按渗透流程走一遍，最后写报告」 | pentest | 靶场但强调流程+报告（与 ctf 打靶区分） |
| C-01 | 「CTF web 题，页面提示 SQL 注入，附件是题目的网址和源码」 | ctf | 赛题+题型信号 |
| C-02 | 「这道题 flag 格式是 flag{...}，给了个 pcap 文件」 | ctf | flag+流量包 → forensics 路由 |
| C-03 | 「pwn 题：64 位 ELF 附件，开了 NX 和 canary，帮我分析」 | ctf | pwn 附件信号 |
| C-04 | 「crypto 题：RSA 密文，e=65537，n 特别大」 | ctf | 密码学参数信号 |
| C-05 | 「这是个 crackme，帮我逆出 flag 的校验逻辑」 | ctf | 逆向+flag 目标 |

## B. 干扰负例（10 条，期望不触发任何 skill）

| ID | 话术 | 期望 | 排除理由 / near-miss 设计点 |
|---|---|---|---|
| N-01 | 「帮我分析一下这个 Log4j 漏洞新闻，讲讲原理和影响面」 | 不触发 | 共享"漏洞/分析"词；纯复述无动手环节 |
| N-02 | 「用 Python 写一个爬虫，抓电商网站的价格做比价」 | 不触发 | 共享"抓取/web"语义；开发任务 |
| N-03 | 「解释一下 CVE-2024-3094 的后门机制」 | 不触发 | 共享 CVE 关键词；教育性讲解 |
| N-04 | 「写个并发端口扫描脚本，我想学习网络编程」 | 不触发 | near-miss：工具编写≠授权测试行动；"扫描"词干扰 |
| N-05 | 「帮我给公司做一次资产盘点，整理成 Excel」 | 不触发 | 共享"资产/盘点"语义；无测试行为 |
| N-06 | 「这道数学竞赛题帮我解一下」 | 不触发 | near-miss："题"字干扰，无安全语义 |
| N-07 | 「分析这个恶意样本的家族归属和行为特征」（无 flag、非赛题） | 不触发 | near-miss：安全分析但既非授权测试也非 CTF，边界外 |
| N-08 | 「我的 nginx 反代配置有问题，帮我看看为什么 502」 | 不触发 | 共享"服务/web"语义；运维排障 |
| N-09 | 「帮我写一份渗透测试服务的商业报价单」 | 不触发 | near-miss："渗透测试"完整触发词出现，但为商业文档非执行 |
| N-10 | 「玩个密室逃脱游戏，线上解谜，第一关是一段摩斯密码」 | 不触发 | near-miss：解码谜题但非 CTF 赛题语境 |

## C. 记录与判定

- 每条用例跑 3 次取多数（对齐官方 description 优化闭环：每查询 3 次）。
- 记录字段：ID / 日期 / 模型或 Agent / 触发结果（pentest | ctf | none | 误触发对象）/ 是否宣告触发词。
- 失败用例回流：把失败话术的特征写回对应 SKILL.md 的 description（正向补触发词 / 负向补 Do NOT 排除项），改后重跑全清单。

## D. description 覆盖自查记录（v0.2，2026-10-15）

description 按官方最佳实践重写后（第三人称、何时用/何时不用、正向穷举+Do NOT 负向排除），逐条映射自查：

| 用例 | 命中的 description 触发词/排除词 | 结论 |
|---|---|---|
| P-01 | "authorized penetration testing"、授权渗透测试 | 覆盖 |
| P-02 | "scope, RoE, rules of engagement"、"bug bounty platform such as HackerOne" | 覆盖 |
| P-03 | 内网授权评估/演练、"pentest report / 渗透测试报告 / 渗透报告"（自查后补齐"演练""渗透报告"两词） | 覆盖（已修） |
| P-04 | "test this machine"、"hack this box I own"（pushy 句承载） | 覆盖 |
| P-05 | 渗透报告、"as long as a real target is being probed" | 覆盖 |
| C-01 | "CTF, capture the flag, a challenge"、做题/赛题 | 覆盖 |
| C-02 | "a flag format (flag{...})"、"pcaps" | 覆盖 |
| C-03 | "binaries (ELF/APK)"、pwn | 覆盖 |
| C-04 | "ciphertexts (RSA/AES)" | 覆盖 |
| C-05 | "crackmes" | 覆盖 |
| N-01 | pentest Do NOT："vulnerability news or CVE write-ups without hands-on testing" | 排除 |
| N-02 | 双方 Do NOT："writing crawlers and dev tooling" | 排除 |
| N-03 | pentest Do NOT："CVE write-ups" | 排除 |
| N-04 | 双方 Do NOT："dev tooling"（脚本编写≠授权测试行动） | 排除 |
| N-05 | 新 description 无"资产/盘点"触发词 | 排除 |
| N-06 | ctf Do NOT："math competitions" | 排除 |
| N-07 | pentest Do NOT："malware analysis" | 排除 |
| N-08 | 无 nginx/运维触发词 | 排除 |
| N-09 | pentest Do NOT："commercial paperwork about pentest services (quotes, proposals)" | 排除 |
| N-10 | ctf Do NOT："escape-room riddles" | 排除 |

自查结论：20/20 静态映射通过；静态自查不能替代实跑，仍按 §C 流程 3 次/条实跑并记录。
