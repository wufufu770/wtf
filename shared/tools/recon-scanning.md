---
verified: "未复跑（本会话无网络靶场）"
status: hypothesis
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../shared/REFLIGHT.md §1）
source: "nmap/ffuf 官方文档；CTF 赛题环境实践惯例"
changelog:
  - "[2026-10-15] 初始空壳，等待首个回流条目"
  - "[2026-10-15] v0.2：条目模板升级为五段式假设条目 + 机器可校验裁决词（REFLIGHT 回流协议，见 ../shared/REFLIGHT.md）"
  - "[2026-10-15] v0.3：M2 填充 2 条工具条目（均为 hypothesis，待靶场复跑）"
---

# 侦察与扫描工具

> 读取时机：需要 nmap/ffuf/amass/subfinder 等侦察扫描命令语法时
> 本文件为 pentest 与 ctf 双 skill 的**去重共享层**：工具用法只在此维护一份，两个 skill 仅以相对路径引用（../shared/tools/），禁止在任何一侧复制粘贴工具内容。

## 填充规范

1. 条目格式：**工具名 + 一句话用途 + 精确命令模板 + 常见坑**；一个工具用法一条目。
2. frontmatter 的 verified/status/source/changelog 语义同各 skill references（最近验证日期+环境 / 五态 / 出处 / 追加式变更记录）；条目状态机与机器可校验裁决词（PASS/FAIL/INCONCLUSIVE）见 ../shared/REFLIGHT.md。
3. 平台差异（如 Windows/Linux 参数不同）单列小节，不拆文件。
4. 本文件超过 100 行时补 TOC；条目过多时按工具名首字母排序。

## 条目区

### nmap 赛题环境探测
- **用途**：CTF 打靶/HTB 场景的端口与服务第一步。
- **命令模板**：
  ```bash
  nmap -sV -sC -p- --min-rate 2000 <target>          # 全端口快扫+版本+默认脚本
  nmap -p <open ports> -sV --version-intensity 5 <target>   # 二次精扫
  nmap -sU --top-ports 50 <target>                   # UDP 抽样
  ```
- **常见坑**：`-p-` 全端口必须配 `--min-rate` 否则超时；HTB/赛题机器禁用真实攻击脚本（`--script` 只留 default）；UDP 扫描极慢，只抽样。
- **状态**：hypothesis（本会话无靶场网络，未复跑）｜裁决词：待复跑

### ffuf 目录/参数爆破
- **用途**：Web 题隐藏路径、参数名、vhost 快速爆破。
- **命令模板**：
  ```bash
  ffuf -u http://host/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 -t 40
  ffuf -u "http://host/api?FUZZ=1" -w params.txt -fs <基线响应大小>   # 按大小过滤
  ```
- **常见坑**：先取基线响应大小用 `-fs/-fc` 过滤软 404，否则全是噪声；`-t` 并发过高会打挂靶机（赛题环境 40 起步）；无 ffuf 时 dirb/gobuster 同型替代。
- **状态**：hypothesis（本会话无靶场网络，未复跑）｜裁决词：待复跑
