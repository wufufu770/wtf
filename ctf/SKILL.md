---
name: ctf
description: Solve CTF competition challenges and flag-based security puzzles across web, pwn, reverse, crypto, forensics, misc, AI security (LLM/prompt injection), mobile, OSINT/recon/encoding categories. Use when the user mentions CTF, capture the flag, a challenge, a flag format (flag{...}, CTF{...}), lab platforms like HackTheBox/HTB, TryHackMe/THM, BUUCTF, crackmes, or hands-on puzzle solving with provided binaries (ELF/APK), pcaps, ciphertexts (RSA/AES), stego images, LLM chatbot challenges, or a web instance; also when the user says 做题, 赛题, 解题, 打靶 with a security context. Make sure to use this skill whenever a challenge file or flag format is present, even if the user just says "help me solve this". Do NOT use for authorized real-world penetration testing (use the pentest skill instead), for vulnerability news or CVE analysis without a challenge, for general reverse-engineering with no flag involved, for math competitions or escape-room riddles with no security context, or for writing crawlers and dev tooling.
---

# CTF Skill（夺旗赛解题）

## 1. 定位与边界

- 本 skill 是 **CTF 解题的知识底座与题型路由器**：正文只做题型分流与纪律，具体技术外置到 references/，按需加载。
- 知识分层：本文件（常驻索引）→ `references/category-*.md`（题型深化）→ `../shared/tools/`（双 skill 共用工具用法，去重层，只引用不复制）→ `../shared/REFLIGHT.md`（双 skill 共用回流协议）。
- 与 pentest skill 的分工：**有 flag/赛题/一次性靶场环境**走本 skill；**有授权边界与真实资产**走 pentest skill。CTF 环境默认授权充分，无需走 scope 门槛，但同样禁止把赛题手法用于未授权真实目标。

## 2. 题型路由表（先分流，再加载）

| 题型信号 | 载入文件 | 典型线索 |
|---|---|---|
| Web | `references/category-web.md` | 网址实例、SQL 注入、XSS、SSRF、反序列化、JWT、PHP/Java 特性 |
| Pwn | `references/category-pwn.md` | ELF 附件、栈溢出、堆利用、ROP、格式化字符串、kernel 题 |
| Crypto | `references/category-crypto.md` | 密文串、RSA/AES/椭圆曲线参数、编码套娃、随机数弱点 |
| Reverse | `references/category-reverse.md` | 二进制/APK 校验逻辑、反编译、混淆、自修改代码 |
| Forensics | `references/category-forensics.md` | pcap 流量包、图片隐写、内存镜像、磁盘恢复、日志分析（隐写分析主库） |
| AI 安全 | `references/category-aiml.md` | LLM chatbot、prompt 泄露/注入、越狱、模型文件附件（.gguf/.pkl） |
| Mobile | `references/category-mobile.md` | APK/IPA 附件、adb/frida、证书锁定、root 检测绕过 |
| 信息搜集 | `references/category-recon.md` | 只给域名/用户名/照片、OSINT、泄露数据、数据安全甄别 |
| 编码分析 | `references/category-encoding.md` | 乱码串、非常规编码、零宽字符、无密钥解码 |
| Misc | `references/category-misc.md` | 杂项：PPC 编程题、区块链、编码迷宫（OSINT/编码已拆出） |

分流规则：

- 先按附件与题面关键词定主题型，只加载对应一个 category 文件；判定拿不准时看附件（二进制→pwn/reverse，数据文件→forensics/crypto）。
- 题目跨类（如 web+crypto 组合）允许追加加载第二个 category 文件，最多两个，不要全量读入。
- 需要工具具体语法时查 `../shared/tools/`（索引见 `../shared/tools/INDEX.md`），工具知识一律不在题型文件里重复。

## 3. 解题纪律

- **假设驱动**：每一步对应五段式假设条目「假设 → 验证步骤 → 判定标准 → 裁决词 → 来源」（REFLIGHT §3）；工具阴性结果（sqlmap 无注入、strings 无线索）是**新假设的输入**，不是终点。
- **限制条件的利用**：题目给的每一个附件、每一个异常参数都默认是有意线索；解不出时回头盘点未解释的线索，而不是堆砌暴力枚举。
- **低自由区间**：payload 构造、环境复现命令写精确命令；思路发散阶段（找入口点、猜编码）给方向性步骤。
- **15 分钟规则**：单题无突破且无新假设可生成时，明确切换下一题或请求提示，不无限硬耗。
- 机器可校验的唯一裁决 = **拿到 flag**：拿到 flag 恒为裁决词 PASS 的充分条件，其余按 REFLIGHT §2 词表落 **PASS / FAIL / INCONCLUSIVE**；一切「应该差不多」的结论都要落到可执行验证。

## 4. 共享工具层（去重引用）

- 工具索引：`../shared/tools/INDEX.md`
- 二进制与密码学：`../shared/tools/binary-crypto.md`（gdb/pwntools/ghidra/openssl/sage 等）
- 取证与隐写：`../shared/tools/forensics-stego.md`（binwalk/file/strings/tshark/exiftool，forensics 题主力）
- Web 利用：`../shared/tools/web-exploitation.md`（burp/curl/编码解码链等）
- 侦察扫描类：`../shared/tools/recon-scanning.md`（nmap/ffuf，赛题环境探测用）
- 证据与报告类：`../shared/tools/evidence-and-reporting.md`（writeup 素材留存规范）

## 5. 单题工作区（workspace，v0.4）

- 解题状态放文件树，不放对话历史。每题在当前工作目录建 `workspace/<题号-短名>/`，固定布局：
  - `challenge.md`：人机共读题面——原始描述、附件清单、自己复述的解题目标；
  - `metadata.json`：脚本可读元数据——题型、分值、连接信息、flag 格式；
  - `attachments/`：原始附件，只读不改动；
  - `notes.md`：过程态——当前假设、死路记录、临时 payload；**长输出与中间数据一律落 `artifacts/`，notes 里只写相对路径引用，不整段贴回对话**（增量纪律：题面复述只写增量，长数据引用而非粘贴）；
  - `artifacts/`：exploit 脚本、反编译产物等生成物。
- 边界：workspace 是**单题入口**，不是隐藏状态系统——题目的持久知识仍按五段式回流 `references/category-*.md`（§6）；workspace 只承载本题执行态，归档时只保留可回流部分。

## 6. 收尾回流条款（必须执行，协议见 `../shared/REFLIGHT.md`）

题目结束（无论解出与否）时，把新学到的技术写回知识库，遵守 REFLIGHT 协议：

1. 条目模板 = 五段式假设条目：**假设 / 验证步骤 / 判定标准 / 裁决词 / 来源**（REFLIGHT §3），一技术一条目，写入本次命中的 `references/category-*.md`；「升级」字段跳转目标用 `→ [[条目名]]` 图边引用（REFLIGHT §3）。
2. 裁决词只允许标准词 **PASS / FAIL / INCONCLUSIVE**（REFLIGHT §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（REFLIGHT §1）；本机跑通的标 verified，仅思路的停在 hypothesis。
3. **失败样本优先回流**：卡壳超过阈值时长的思路盲区、被证伪的假设路径，单独记 refuted 条目，必须附 FAIL 复跑记录 + 失败原因 + "下一步转哪个新假设"——这是下一轮出题方的老套路。**死锁条款（REFLIGHT §1）**：同一假设连续 FAIL ≥3 次禁止原路复跑，强制转新假设或标 inconclusive 写明缺口。
4. 状态与复跑记录必须匹配（verified ≥1 条 PASS 记录，见 REFLIGHT §4）；工具新用法写回 `../shared/tools/` 对应文件，不进题型文件（去重原则）；新条目写入前过 INDEX 查重 + 熵控五问（REFLIGHT §5）。
5. writeup 级复盘属于人类向产出，放 skill 目录之外，不占知识库。

## 7. 触发与停用逻辑

- 触发词：CTF / capture the flag / 赛题 / 做题 / 解题 / flag / flag{...} / HTB、THM、BUUCTF 等平台名 / 附件题（给了 ELF、pcap、密文、隐写图）/ crackme / 打靶挑战。
- 停用信号：真实目标授权测试（转 pentest skill）、漏洞新闻与 CVE 复述（无需加载）、爬虫与开发任务（无需加载）、数学竞赛与密室解谜（无安全语境，无需加载）、无 flag 的常规逆向作业（无需加载）。
- 触发后宣告："使用 ctf skill，先做题型分流。"，然后从第 2 节路由表开始。
