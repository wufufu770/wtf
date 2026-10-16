---
verified: "[结构文件：2026-10-15 建仓时核验目录树]"
status: verified
source: "SKILL-DUO M1/B1 建仓产物"
changelog:
  - "[2026-10-15] 建仓：建立双 skill 共享工具层索引"
  - "[2026-10-15] v0.3：M2 新增取证隐写工具文件（forensics-stego.md），5 份工具文件填充 20 条用法条目"
  - "[2026-10-16] v0.4：维护规则增第 5 条——新条目过本表路由查重后，还须过 REFLIGHT §5 熵控五问方可写入"
---

# 共享工具层索引（shared/tools）

> 定位：pentest 与 ctf 两个 skill 的**去重层**。工具用法知识只在此维护一份，两个 skill 的 SKILL.md 与 references 均以相对路径 `../shared/tools/` 引用，禁止复制。
> 读取时机：需要某个工具的具体命令语法、或不确定用哪个工具时，先查本表再进对应文件。

## 工具 → 深化文件路由表

| 场景 | 文件 | 典型工具 |
|---|---|---|
| 侦察与扫描 | [recon-scanning.md](recon-scanning.md) | nmap、ffuf、amass、subfinder、masscan |
| Web 利用 | [web-exploitation.md](web-exploitation.md) | burp、curl、sqlmap、ffuf 编码链、jwt 工具 |
| 二进制与密码学 | [binary-crypto.md](binary-crypto.md) | gdb、pwntools、ghidra、openssl、sage、RsaCtfTool |
| 取证与隐写 | [forensics-stego.md](forensics-stego.md) | binwalk、file、strings、tshark、exiftool、dd |
| 证据留存与报告 | [evidence-and-reporting.md](evidence-and-reporting.md) | 截图/抓包留存、证据目录结构、报告模板 |

## 维护规则（去重性的保障）

1. **单向引用**：pentest/SKILL.md、ctf/SKILL.md 及其 references → 本目录；本目录内容不回指任何 skill 的 references，避免循环引用。
2. **一处修改全局生效**：工具用法升级、报错变通方案只改本目录对应文件。
3. **判定归属**：与具体题型/阶段流程绑定的知识留在 skill 侧 references；通用命令语法归本层。拿不准时问一句「ctf 和 pentest 都会用吗」——是则入本层。
4. 若运行时只复制单个 skill 目录加载（不保留项目树），见根目录 PORTABILITY.md 的两种装载形态说明。
5. **查重链（v0.4）**：新知识条目先过本表路由查重（场景是否已有归属文件）→ 再过 `../REFLIGHT.md` §5 熵控五问（边界问题/可下沉/可复现/有重名/边界稳）→ 才允许写入。工具条目与题型条目同样适用，防止本层与 skill 侧重复膨胀。
