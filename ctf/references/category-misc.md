---
verified: "2026-10-15 | 本地复跑：Python 3.12.13 + gzip/base64（Linux 容器），见条目1复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "CTF-wiki（misc）、0rangec3t/Black-cat（假设-证据范式）、巨人项目 OSINT 实战记录（2026-10）、M2 实测复跑"
changelog:
  - "[2026-10-15] 初始空壳，等待首个回流条目"
  - "[2026-10-15] v0.2：条目模板升级为五段式假设条目 + 机器可校验裁决词（REFLIGHT 回流协议，见 ../../shared/REFLIGHT.md）"
  - "[2026-10-15] v0.3：M2 填充 4 条（verified 1 / hypothesis 3）"
---

# 题型：Misc

> 读取时机：编码套娃、隐写杂项、OSINT、PPC 编程题、社会工程条目主库

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态：verified=最近一次复现日期+环境；source=条目主要出处；changelog 追加一行/次，不删除历史。
4. **失败样本优先回流**：refuted 条目必须附 FAIL 复跑记录、失败原因与"下一步转哪个新假设"，失败样本优先级高于成功经验。
5. verified/refuted/inconclusive 条目必须附复跑记录表（格式见 ../../shared/REFLIGHT.md §4）；未经复跑的条目状态只允许 hypothesis。
6. 工具具体用法归 ../../shared/tools/ 对应文件，此处不重复（去重原则）；五段式的「验证步骤」只保留最小可执行命令骨架。
7. 本文件超过 100 行时，在本节下方补 TOC 目录。

## 条目区（TOC）

1. [编码套娃链识别与解链](#编码套娃链识别与解链)（verified）
2. [zip 伪加密](#zip-伪加密)（hypothesis）
3. [OSINT：证书透明度与被动域收集](#osint证书透明度与被动域收集)（hypothesis）
4. [PPC 脚本题约束建模](#ppc-脚本题约束建模)（hypothesis）

### 编码套娃链识别与解链
- **假设**：misc 题给一长串"乱码"→ 多为 base64（+/= 字符集）→ gzip（\x1f\x8b 魔数）等 2~4 层编码/压缩套娃；逐层解到明文 flag，每层由字节特征识别而不是猜。
- **验证步骤**：
  ```python
  # 循环：看头字节特征 -> base64.b64decode / gzip.decompress / zlib.decompress
  # 直到输出可读（printable 占比高）
  ```
  本机实测（2026-10-15）：构造 `b64(b64(gzip(flag)))` 三层样本，按"两次 b64decode + 一次 gzip.decompress"解链，完整还原 `flag{enc0d1ng_n3st3d_9}`。
- **判定标准**：PASS = 解链输出 flag 格式明文；FAIL = 某层解码报错（padding 异常 → 补 `=`；魔数对不上 → 换 zlib/bz2/lzma 再试）。
- **裁决词**：PASS
- **来源**：M2 实测复跑（evidence T5）；CTF-wiki 编码与压缩
- **升级**：解出的是文件再走 forensics 文件识别；嵌套超 4 层考虑脚本自动化循环（按头字节路由解码器）。
- **关键差异**：模型盲区——逐层特征识别（b64 字符集/gzip `\x1f\x8b`/zlib `\x78`）替代"猜哪种编码"；解码报错时先补 padding 再换算法。

### 复跑记录（verified / refuted / inconclusive 必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 本地 Python 3.12.13 | b64decode×2 + gzip.decompress 循环解链 | PASS | evidence/T5-encodingchain | 三层样本完整还原 flag |

### zip 伪加密
- **假设**：zip 打开提示密码错误但结构无异常 → 伪加密：本地文件头/中央目录的 general purpose bit flag 第 0 位（0x0001）被手工置 1，实际未加密。
- **验证步骤**：1) 十六进制搜本地文件头 `PK\x03\x04`，看第 7-8 字节；2) 搜中央目录 `PK\x01\x02` 同位对照；3) 将置位字节改回 0 后重新解压。
- **判定标准**：PASS = 改位后无密码直接解出；FAIL = 真加密（转 crc32 明文攻击/字典爆破）。
- **裁决词**：待复跑
- **来源**：ZIP APPNOTE.TXT（general purpose bit flag）；CTF-wiki zip 伪加密
- （可选）**关键差异**：本地头与中央目录**要两头都改**——只改一处仍报密码错误，是本题最高频卡点。

### OSINT：证书透明度与被动域收集
- **假设**：给域名/公司名找资产线索 → crt.sh（证书透明度日志）枚举子域可用性高；urlscan.io 查历史扫描快照；wayback（web.archive.org）作历史页面补充但超时率高需多次重试。
- **验证步骤**：1) `https://crt.sh/?q=%25.<domain>&output=json` 拉证书日志聚合子域；2) urlscan.io `page.domain:<domain>` 查历史快照；3) 交叉比对去重后逐个验证存活。
- **判定标准**：PASS = 找到题目指向的隐藏子域/泄露页面；FAIL = 主域不在日志（换 whoip/ip 段反查新假设）。
- **裁决词**：待复跑
- **来源**：巨人网络安全测试-信息收集项目实战记录（2026-10：crt.sh 与 urlscan 实测有效、wayback 连续超时的第一手经验）；OSINT 标准流程
- （可选）**升级**：主域线索穷尽转证书 fingerprint 反查与 ASN 段扫。

### PPC 脚本题约束建模
- **假设**：PPC/脚本题给"在 N 秒内完成 M 轮运算/游戏" → 核心是把题面约束转成程序状态机（recv 解析→计算→send），坑通常在协议细节而非算法难度。
- **验证步骤**：1) 手动交互一轮记录完整输入输出格式（含提示符/换行）；2) 照抄格式写循环脚本；3) 注意 socket 缓冲与逐字节读。
- **判定标准**：PASS = 脚本连续通过全部轮次拿 flag；FAIL = 中途格式不匹配（回到第 1 步逐字节 diff）。
- **裁决词**：待复跑
- **来源**：CTF-wiki misc/PPC；pwntools process/remote 用法（../shared/tools/binary-crypto.md）
- （可选）**关键差异**：模型盲区——先抓一轮真实交互样本再写脚本，凭题面想象写的解析器 90% 死在分隔符上。
