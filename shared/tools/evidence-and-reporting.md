---
verified: "2026-10-15 | 本地复跑：M2 回流实战 evidence 目录（m2-evidence/）实操留存"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../shared/REFLIGHT.md §1）
source: "M2 实测复跑（2026-10-15）；REFLIGHT §4 复跑记录格式"
changelog:
  - "[2026-10-15] 初始空壳，等待首个回流条目"
  - "[2026-10-15] v0.2：条目模板升级为五段式假设条目 + 机器可校验裁决词（REFLIGHT 回流协议，见 ../shared/REFLIGHT.md）"
  - "[2026-10-15] v0.3：M2 填充 2 条工具条目（verified 1 / hypothesis 1）"
---

# 证据留存与报告工具

> 读取时机：需要证据落盘路径规范、截图/抓包/报告模板用法时
> 本文件为 pentest 与 ctf 双 skill 的**去重共享层**：工具用法只在此维护一份，两个 skill 仅以相对路径引用（../shared/tools/），禁止在任何一侧复制粘贴工具内容。

## 填充规范

1. 条目格式：**工具名 + 一句话用途 + 精确命令模板 + 常见坑**；一个工具用法一条目。
2. frontmatter 的 verified/status/source/changelog 语义同各 skill references（最近验证日期+环境 / 五态 / 出处 / 追加式变更记录）；条目状态机与机器可校验裁决词（PASS/FAIL/INCONCLUSIVE）见 ../shared/REFLIGHT.md。
3. 平台差异（如 Windows/Linux 参数不同）单列小节，不拆文件。
4. 本文件超过 100 行时补 TOC；条目过多时按工具名首字母排序。

## 条目区

### 解题证据目录留存（solve log）
- **用途**：RELFIGHT 回流的证据底座——每题一个证据目录，复跑记录表里的「工件路径」指向这里。
- **命令模板**：
  ```bash
  mkdir -p evidence/<date>-<题目slug>
  # 每次关键复跑：命令 + 输出 + 工件（样本文件/脚本）全部落盘，命名 T<n>-<主题>
  # 如 evidence/2026-10-15/T1-commonmodulus/（脚本+输出+样本密文）
  ```
- **常见坑**：证据文件只追加不覆盖（与复跑记录表 append-only 同纪律）；工件路径写相对路径（跨 Agent 通用性约束）；样本密文/图片本身也是工件，别只存文字输出。
- **状态**：verified（PASS 复跑 2026-10-15：M2 七组证据 T1-T8 均按此结构落盘，复跑可追溯）｜裁决词：PASS

### flag 提交前格式校验
- **用途**：脚本解出候选明文后，提交前用正则核对 flag 格式，防"解出来了但抄错/编码错"。
- **命令模板**：
  ```bash
  python3 -c "import re,sys; s=sys.stdin.read().strip(); \
  print(repr(s)); print(bool(re.fullmatch(r'(flag|ctf|CTF)\{[^}]+\}', s)))"
  ```
- **常见坑**：明文可能带前后缀零字节/换行（RSA 解密常尾随 \x00），先 `strip()`/去 NUL 再匹配；平台大小写敏感时对照赛题 flag 格式说明。
- **状态**：hypothesis（本会话以 repr 目检代替，未纳入标准流程复跑）｜裁决词：待复跑

## 复跑记录（verified 条目必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | M2 回流实战 | T1-T8 七组证据落盘（m2-evidence/） | PASS | evidence/2026-10-15/ | 目录结构+工件留存全流程走通 |
