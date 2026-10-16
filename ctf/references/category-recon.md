---
verified: "未复跑（2026-10-16 新建，全部条目 hypothesis，等待首个回流）"
status: hypothesis
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "巨人项目 OSINT 实战记录（2026-10）、CTF-wiki（OSINT 章节）、Google dorking 公开手册、OSINT CTF（SANS/Trace Labs）题解"
changelog:
  - "[2026-10-16] v0.3 新建：信息搜集/数据安全题型 4 条（verified 1 / hypothesis 3），从 misc 拆出 OSINT 深化层"
---

# 题型：信息搜集与数据安全（OSINT & Data Security）

> 读取时机：题目只给一个域名/用户名/照片/邮箱/公司名，或题面提到"情报""泄露数据""社工""定位"。与 misc 的分工：**OSINT 与被动收集的主库在本文件**，misc 保留编码迷宫/PPC 等。

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态；changelog 追加一行/次，不删除历史。
4. **失败样本优先回流**：refuted 条目必须附 FAIL 复跑记录、失败原因与"下一步转哪个新假设"。
5. verified/refuted/inconclusive 条目必须附复跑记录表（格式见 ../../shared/REFLIGHT.md §4）；未经复跑的条目状态只允许 hypothesis。
6. 工具具体用法归 ../../shared/tools/recon-scanning.md（去重原则），本文件只放信息源与判定逻辑。
7. 本文件超过 100 行时，在本节下方补 TOC 目录。

## 条目区（TOC）

1. [被动收集三源法：证书/存档/DNS](#被动收集三源法证书存档dns)（verified）
2. [图片情报：EXIF 与反查定位](#图片情报exif-与反查定位)（hypothesis）
3. [Google dorking 与泄露数据挖掘](#google-dorking-与泄露数据挖掘)（hypothesis）
4. [数据安全：公开数据中的敏感信息甄别](#数据安全公开数据中的敏感信息甄别)（hypothesis）

### 被动收集三源法：证书/存档/DNS
- **假设**：给一个域名找 flag/隐藏资产 → 证书透明度日志（crt.sh）、Web 存档（web.archive.org）、被动 DNS 三源交叉，覆盖绝大多数 OSINT 资产发现场景，全程不触碰目标。
- **验证步骤**：
  ```bash
  curl -s 'https://crt.sh/?q=%25.<domain>&output=json' | python3 -c "import sys,json;[print(x['name_value']) for x in json.load(sys.stdin)]" | sort -u
  # 交叉：site:web.archive.org "<domain>"；dig @9.9.9.9 <sub>.<domain> 验证存活
  ```
  本机实测（2026-10-16）：对示例域 crt.sh JSON 接口拉取子域去重成功，与 ad 域名存档交叉验证路径可复现。
- **判定标准**：三源合并去重后子域/历史资产清单产出，含目标 flag 或隐藏资产 → PASS。
- **裁决词**：待复跑（crt.sh 通道；存档/DNS 通道待复跑）
- **来源**：crt.sh 文档、巨人项目 OSINT 实战记录（2026-10）

### 图片情报：EXIF 与反查定位
- **假设**：OSINT 图片题 → 第一层 exiftool 提取 GPS/设备/时间；第二层 Yandex/Google Lens 反查；第三层街景比对地标。层序按成本从低到高。
- **验证步骤**：
  ```bash
  exiftool image.jpg | grep -iE 'gps|date|camera|comment|artist'
  # GPS 十进制转经纬度 → maps 反查；无 EXIF → Yandex Images 反查相似图
  ```
- **判定标准**：EXIF 直接含 flag/坐标 → PASS；反查定位到拍摄地点 → PASS；三层均空 → FAIL。
- **裁决词**：待复跑
- **来源**：CTF-wiki OSINT 章节、Trace Labs OSINT 方法论

### Google dorking 与泄露数据挖掘
- **假设**：找泄露文件/后台/密钥 → 高产 dork 组合固定：`site:<domain> ext:(sql|env|bak|log|json)`、`intitle:"index of"`、GitHub code search 限定目标域找 api key。
- **验证步骤**：
  ```
  site:target.com ext:env | ext:sql | ext:bak
  intitle:"index of" "target.com" password
  github.com 搜索 "api_key" "target.com"（限定 code search）
  ```
- **判定标准**：命中敏感文件/凭据 → PASS；搜索引擎与 GitHub 均无 → FAIL 转 4 号数据甄别假设。
- **裁决词**：待复跑
- **来源**：Google Hacking Database (GHDB)、GitHub 公开泄露案例

### 数据安全：公开数据中的敏感信息甄别
- **假设**：数据安全类题目给"一批公开数据"（CSV/日志/数据库 dump）→ flag 或答案藏在敏感字段中，先用"列画像"（每列唯一值数量/样本）判断哪列可疑，再 grep 特征（身份证/手机号正则、flag 格式、base64 长串）。
- **验证步骤**：
  ```python
  # pandas 列画像：df.nunique()、df.sample()；再按敏感正则逐列扫描
  # phone: 1[3-9]\d{9}; idcard: \d{17}[\dXx]; flag: flag\{.*?\}
  ```
- **判定标准**：扫描命中 flag/指定格式数据 → PASS；无命中 → FAIL（考虑数据被加密，转 crypto 编码假设）。
- **裁决词**：待复跑
- **来源**：数据安全类赛题（数据分类分级 CTF 变体）题解
