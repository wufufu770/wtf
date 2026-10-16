---
verified: "2026-10-15 | 本地复跑：Python 3.12.13 + pycryptodome 3.23.0（Linux 容器），见条目1复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "0rangec3t/Black-cat（techniques/web.md 五段式范式）、PayloadsAllTheThings、book.hacktricks.xyz、M2 实测复跑（2026-10-15）"
changelog:
  - "[2026-10-15] 初始空壳，等待首个回流条目"
  - "[2026-10-15] v0.2：条目模板升级为五段式假设条目 + 机器可校验裁决词（REFLIGHT 回流协议，见 ../../shared/REFLIGHT.md）"
  - "[2026-10-15] v0.3：M2 填充 4 条（verified 1 / inconclusive 1 / hypothesis 2）"
---

# 题型：Web

> 读取时机：题面为网址实例或 Web 漏洞关键词时（注入/SSRF/反序列化/JWT 等条目主库）

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态：verified=最近一次复现日期+环境；source=条目主要出处；changelog 追加一行/次，不删除历史。
4. **失败样本优先回流**：refuted 条目必须附 FAIL 复跑记录、失败原因与"下一步转哪个新假设"，失败样本优先级高于成功经验。
5. verified/refuted/inconclusive 条目必须附复跑记录表（格式见 ../../shared/REFLIGHT.md §4）；未经复跑的条目状态只允许 hypothesis。
6. 工具具体用法归 ../../shared/tools/ 对应文件，此处不重复（去重原则）；五段式的「验证步骤」只保留最小可执行命令骨架。
7. 本文件超过 100 行时，在本节下方补 TOC 目录。

## 条目区（TOC）

1. [JWT alg=none 签名绕过](#jwt-algnone-签名绕过)（verified）
2. [sqlmap 阴性 → 转查 ORM/Mass Assignment](#sqlmap-阴性--转查-ormmass-assignment)（inconclusive）
3. [PHP 弱比较 == 与 0e MD5 魔术哈希](#php-弱比较--与-0e-md5-魔术哈希)（hypothesis）
4. [SSRF 打云 metadata 与内网](#ssrf-打云-metadata-与内网)（hypothesis）

### JWT alg=none 签名绕过
- **假设**：题面给 JWT 且改 payload 后返回 401/签名错误 → 服务端 JWT 库可能接受 `alg:"none"`（把 alg 当分支而非白名单校验），可空签名伪造任意身份。
- **验证步骤**：手写最小校验器对照（生产上等价于往目标发两个 token 对比响应）：
  ```bash
  # header={"alg":"none","typ":"JWT"} payload={"user":"admin"}
  # token = base64url(header).base64url(payload).（空签名）
  # 若无 python/jwt 工具，直接 base64 手工拼装后 curl -H "Authorization: Bearer <token>" <目标>
  ```
  本机对照实验（2026-10-15）：缺陷实现（`if alg=="none": return True`）接受空签名 token；算法白名单实现（`alg!="HS256" → reject`）拒绝同一 token。
- **判定标准**：PASS = 目标以 admin 身份返回 200/受保护资源；FAIL = 两种 token 响应无差异且签名校验报错。
- **裁决词**：PASS
- **来源**：M2 实测复跑（最小校验器对照，evidence T3）；RFC 8725 §3.1（算法白名单原则）；PayloadsAllTheThings JWT
- **升级**：PASS 后用同一身份探越权接口拿 flag；FAIL 转 jku/kid 注入新假设。
- **关键差异**：模型盲区——容易只试改 payload 忘了同步清空签名段；且 `alg` 必须从 token 里读出来后**白名单比对**，而不是"支持 none 就放行"。

### 复跑记录（verified / refuted / inconclusive 必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 本地 Python 3.12.13 最小校验器对照 | 手写 vulnerable_verify / correct_verify 对照（见验证步骤） | PASS | evidence/T3-jwt-alg-none | 缺陷实现接受空签名 token=True，白名单实现=False；未打真实靶场 |

### sqlmap 阴性 → 转查 ORM/Mass Assignment
- **假设**：sqlmap 报无注入（阴性）≠ 无漏洞 → Black-cat 状态机范式：`sqlmap 阴性 = 转查 Mass Assignment / ORM 关系穿越的新假设，而非"没有 SQLi"`。
- **验证步骤**：1) 抓注册/更新接口的完整参数表；2) 追加 `role=admin` / `is_admin=true` 类字段重放；3) 对 ORM 框架接口尝试关系穿越字段（如 `{"user":{"admin":true}}`）。
- **判定标准**：PASS = 服务端接受未暴露字段并提升权限/泄露关联对象；FAIL = 字段被过滤且无新信息。
- **裁决词**：INCONCLUSIVE
- **来源**：0rangec3t/Black-cat techniques/web.md（ORM Leaking 条目+关键差异注记）；shared/安全方向skill与知识库组织调研.md 特点3
- （inconclusive 缺口清单）本机无 sqlmap、无可重放靶场实例；需 HTB/BUUCTF Web 实例或本地起 Juice Shop 才能补验证。
- **关键差异**：模型盲区——payload 全是合法 ORM 查询，AI 只会想到 SQLi 想不到关系穿越。

### 复跑记录（verified / refuted / inconclusive 必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 无靶场（本机无 sqlmap） | 未执行 | INCONCLUSIVE | - | 缺口：缺 Web 靶场实例 + sqlmap；下次在 HTB/BUUCTF Web 题补 |

### PHP 弱比较 == 与 0e MD5 魔术哈希
- **假设**：题面为 PHP 源码审计且出现 `==` 比较 md5/数值 → 弱比较下 `"0e123"=="0e456"` 为 true（科学计数法全零），`md5($x)==$s` 可用 0e 开头哈希碰撞绕过；数组传参 `x[]=` 使 `md5(数组)==字符串` 报 NULL 相等。
- **验证步骤**：1) 审计比较语句确认是 `==` 非 `===`；2) 构造 `?a=240610708&b=QNKCDZO`（两值 md5 均为 0e 开头）提交；3) 数组场景 `?a[]=1&a[]=2` 绕 `md5(a)==md5(b)` 与 `strcmp` 比较。
- **判定标准**：PASS = 服务端进入原本被比较语句挡住的分支/输出 flag；FAIL = 使用强比较或类型校验，无变化。
- **裁决词**：待复跑
- **来源**：PayloadsAllTheThings（PHP tricks / Magic Hashes）；CTF-wiki PHP 弱类型
- （可选）**升级**：PASS 后同思路检查 `in_array` 第三参缺省、`json_decode` 类型混淆。

### SSRF 打云 metadata 与内网
- **假设**：题面/靶场允许提交 URL 且服务端发起请求（头像拉取、webhook、预览）→ 存在 SSRF，可访问 `http://169.254.169.254/`（云 metadata）或内网服务。
- **验证步骤**：1) 提交 `http://127.0.0.1:80` 与 `http://169.254.169.254/latest/meta-data/` 观察响应差异；2) 被过滤时尝试重定向跳转、DNS rebinding、`0.0.0.0`/十进制 IP/`[::]` 等等价写法。
- **判定标准**：PASS = 返回非公开内容（metadata/内网页面）；FAIL = 全部写法被统一拦截（先怀疑解析层白名单，回炉看过滤规则）。
- **裁决词**：待复跑
- **来源**：book.hacktricks.xyz SSRF 章节；PayloadsAllTheThings SSRF
- （可选）**关键差异**：模型盲区——只试 `127.0.0.1` 不试等价网络写法；有出网差异（回显 vs 盲打）时先确定观测通道。
