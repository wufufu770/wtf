---
verified: "2026-10-15 | 本地复跑：Python 3.12.13（struct 模块，Linux 容器），见条目1复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "0rangec3t/Black-cat（假设-证据范式）、CTF-wiki（misc/取证）、M2 实测复跑（2026-10-15）"
changelog:
  - "[2026-10-15] 初始空壳，等待首个回流条目"
  - "[2026-10-15] v0.2：条目模板升级为五段式假设条目 + 机器可校验裁决词（REFLIGHT 回流协议，见 ../../shared/REFLIGHT.md）"
  - "[2026-10-15] v0.3：M2 填充 4 条（verified 1 / inconclusive 1 / hypothesis 2）"
---

# 题型：Forensics

> 读取时机：pcap、磁盘/内存镜像、图片隐写、文件修复条目主库

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态：verified=最近一次复现日期+环境；source=条目主要出处；changelog 追加一行/次，不删除历史。
4. **失败样本优先回流**：refuted 条目必须附 FAIL 复跑记录、失败原因与"下一步转哪个新假设"，失败样本优先级高于成功经验。
5. verified/refuted/inconclusive 条目必须附复跑记录表（格式见 ../../shared/REFLIGHT.md §4）；未经复跑的条目状态只允许 hypothesis。
6. 工具具体用法归 ../../shared/tools/ 对应文件，此处不重复（去重原则）；五段式的「验证步骤」只保留最小可执行命令骨架。
7. 本文件超过 100 行时，在本节下方补 TOC 目录。

## 条目区（TOC）

1. [PNG chunk 解析定位尾随隐写](#png-chunk-解析定位尾随隐写)（verified）
2. [binwalk 多镜像/固件提取](#binwalk-多镜像固件提取)（inconclusive）
3. [JPG FFD9 尾部附加数据](#jpg-ffd9-尾部附加数据)（hypothesis）
4. [pcap HTTP 对象导出](#pcap-http-对象导出)（hypothesis）

### PNG chunk 解析定位尾随隐写
- **假设**：PNG 文件结构为 `8 字节魔数 + [4B长度][4B类型][数据][4B CRC]`×N 直到 IEND → IEND 之后若仍有数据即手工附加的隐写内容（最简隐写形态），顺带可暴露 chunk 级异常（自定义类型/长度越界）。
- **验证步骤**：
  ```python
  # struct.unpack(">I") 逐 chunk 步进：off += 12 + len；遇 IEND 后 data[off:] 即尾随数据
  ```
  本机实测（2026-10-15）：构造 IEND 后附加 `flag{png_tr4il3d_d4t4}` 的 PNG，手工解析 chunk 链 `[IHDR, IDAT, IEND]`，IEND 偏移 59 字节处完整取出尾随 flag。
- **判定标准**：PASS = IEND 后存在可读/可解数据；FAIL = IEND 即文件尾（转 LSB/调色板/IDAT 压缩流分析）。
- **裁决词**：PASS
- **来源**：M2 实测复跑（evidence T4）；PNG 规范（ISO/IEC 15948 chunk 结构）
- **升级**：PASS 后对取出数据按 `../shared/tools/forensics-stego.md` 的 file/魔数条目二次识别嵌套文件；FAIL 转 LSB 与 CRC 校验（改宽高隐写 CRC 必错）。
- **关键差异**：模型盲区——只顾像素不看结构；chunk 解析还能暴露"改宽高"隐写（IDAT 数据量与宽高不匹配）。

### 复跑记录（verified / refuted / inconclusive 必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 本地 Python 3.12.13 struct 手工解析 | 构造样本 + chunk 步进解析 | PASS | evidence/T4-pngtrail | IEND 偏移 59B，尾随 flag 完整取出 |

### binwalk 多镜像/固件提取
- **假设**：附件为固件/磁盘镜像/含嵌套文件的"图片" → binwalk 扫描魔数签名自动 carving 出嵌入文件（squashfs/zlib/压缩包等）。
- **验证步骤**：1) `binwalk <img>` 看签名命中表；2) `binwalk -e` 自动提取，`-Me` 递归；3) 对提取目录逐层 file。
- **判定标准**：PASS = 提取出嵌套文件并找到线索；FAIL = 无签名命中（转 raw 搜索字符串/熵分析）。
- **裁决词**：INCONCLUSIVE
- **来源**：binwalk 官方 README；CTF-wiki 取证工具
- （inconclusive 缺口清单）本机无 binwalk、无镜像样本；思路仅来自官方文档。替代路径（hypothesis）：file + 手写魔数扫描（`strings | grep` / python 逐偏移比对常见魔数表）可覆盖部分场景，待实测比对召回率。

### JPG FFD9 尾部附加数据
- **假设**：JPEG 以 `FF D9` 结尾 → 其后若有数据即附加文件（zip/文本/另一张图），与 PNG 尾随数据同型。
- **验证步骤**：1) 二进制中搜 `FF D9` 最后一次出现偏移；2) `dd if=chall.jpg of=tail.bin skip=<off+2> bs=1`；3) `file tail.bin`。
- **判定标准**：PASS = 尾部数据为可识别文件且含线索；FAIL = FFD9 即 EOF（转 EXIF、量化表异常、steghide）。
- **裁决词**：待复跑
- **来源**：JPEG 文件结构（ITU-T T.81）；CTF-wiki 图片隐写
- （可选）**关键差异**：缩略图/多帧 JPEG 会在中间出现 FFD9，必须取**最后一次**出现。

### pcap HTTP 对象导出
- **假设**：流量题的敏感数据在 HTTP 明文传输 → tshark 直接导出全部 HTTP 对象（文件/图片）比逐包阅读快一个量级。
- **验证步骤**：1) `tshark -r chall.pcapng --export-objects http,outdir -q`；2) 对 outdir 逐文件 file/grep flag 格式；3) 明文不在 HTTP 时查 DNS/ICMP 隐蔽信道。
- **判定标准**：PASS = 导出对象含 flag/关键文件；FAIL = 全加密（转 TLS keylog 导入或流统计）。
- **裁决词**：待复跑
- **来源**：tshark 官方手册（--export-objects）；CTF-wiki 流量分析
- （可选）**升级**：`-z conv,tcp` 先看会话分布，大流量会话优先——别按包序硬读。
