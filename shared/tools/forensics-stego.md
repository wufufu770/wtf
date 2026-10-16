---
verified: "2026-10-15 | 本地复跑：Python 3.12.13 + GNU binutils strings + file 命令（Linux 容器），见条目1/2复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../shared/REFLIGHT.md §1）
source: "M2 实测复跑（2026-10-15）；PNG 规范（ISO/IEC 15948）；binwalk/tshark/exiftool 官方文档"
changelog:
  - "[2026-10-15] 新增文件（M2）：ctf forensics/misc 高频工具从 recon/web 层拆出，建立取证隐写工具真相源"
---

# 取证与隐写工具

> 读取时机：需要 binwalk/file/strings/tshark/exiftool 等取证隐写工具用法时
> 本文件为 pentest 与 ctf 双 skill 的**去重共享层**：工具用法只在此维护一份，两个 skill 仅以相对路径引用（../shared/tools/），禁止在任何一侧复制粘贴工具内容。

## 填充规范

1. 条目格式：**工具名 + 一句话用途 + 精确命令模板 + 常见坑**；一个工具用法一条目。
2. frontmatter 的 verified/status/source/changelog 语义同各 skill references（最近验证日期+环境 / 五态 / 出处 / 追加式变更记录）；条目状态机与机器可校验裁决词（PASS/FAIL/INCONCLUSIVE）见 ../shared/REFLIGHT.md。
3. 平台差异（如 Windows/Linux 参数不同）单列小节，不拆文件。
4. 本文件超过 100 行时补 TOC；条目过多时按工具名首字母排序。

## 条目区（TOC）

1. [PNG chunk 手工解析（python struct）](#png-chunk-手工解析python-struct)（verified）
2. [file + strings 零依赖侦察](#file--strings-零依赖侦察)（verified）
3. [binwalk 签名扫描与提取](#binwalk-签名扫描与提取)（hypothesis）
4. [tshark 流量分析](#tshark-流量分析)（hypothesis）
5. [exiftool 元数据提取](#exiftool-元数据提取)（hypothesis）
6. [dd 尾部数据提取](#dd-尾部数据提取)（hypothesis）

### PNG chunk 手工解析（python struct）
- **用途**：无 binwalk 环境时用 struct 手工步进 PNG chunk 链，定位 IEND 后尾随数据与异常 chunk。
- **命令模板**：
  ```python
  import struct
  data = open('chall.png','rb').read(); assert data[:8] == bytes.fromhex("89504e470d0a1a0a")
  off = 8
  while off < len(data):
      ln, typ = struct.unpack(">I", data[off:off+4])[0], data[off+4:off+8]
      off += 12 + ln
      if typ == b"IEND": break
  print(data[off:])    # IEND 之后 = 尾随数据
  ```
- **常见坑**：步进公式 `off += 4长度+4类型+数据+4CRC` 别漏 CRC 的 4 字节；遇 IEND 必须停，否则把尾随数据误当 chunk 解析报错；宽高隐写看 IHDR 的宽高与 IDAT 数据量是否匹配（详见 ../ctf/references/category-forensics.md 条目1）。
- **状态**：verified（PASS 复跑 2026-10-15：IEND 偏移 59B，尾随 flag 完整取出）｜裁决词：PASS

### file + strings 零依赖侦察
- **用途**：任何附件的第一步：类型判定 + 明文线索提取（CTF 容器环境的兜底组合）。
- **命令模板**：
  ```bash
  file chall.bin                 # 魔数判定真实类型（扩展名常骗人）
  strings -n 6 chall.bin | grep -iE "flag|ctf|key"
  strings -el chall.bin          # -e l 抓 UTF-16LE 宽字符串（Windows 产物必查）
  ```
- **常见坑**：strings 输出可能被相邻字符合并/截断，命中关键词即算成功勿期待完整字面量；加壳后命中率骤降，先看 file 是否报壳；`-n` 阈值 6 起步控噪声。
- **状态**：verified（PASS 复跑 2026-10-15：ELF 内嵌标记部分命中 `SECRET_CH`，验证截断坑真实存在）｜裁决词：PASS

### binwalk 签名扫描与提取
- **用途**：镜像/图片内嵌套文件的签名扫描与自动 carving。
- **命令模板**：
  ```bash
  binwalk chall.img              # 签名命中表
  binwalk -e chall.img           # 自动提取；-Me 递归提取
  ```
- **常见坑**：`-e` 会生成 `_<文件名>.extracted` 目录，体积可能爆炸（先看命中表再决定）；误报（false positive）常见于压缩数据巧合——命中后逐个 file 核实；环境缺 binwalk 时用 file+python 手写魔数扫描替代（召回率待实测比对）。
- **状态**：hypothesis（本机无 binwalk，未复跑；语法来自官方 README）｜裁决词：待复跑

### tshark 流量分析
- **用途**：pcapng/pcap 命令行分析，HTTP 对象批量导出。
- **命令模板**：
  ```bash
  tshark -r chall.pcapng --export-objects http,outdir -q   # 导出全部 HTTP 对象
  tshark -r chall.pcapng -z conv,tcp -q                    # 会话统计，大流量优先
  tshark -r chall.pcapng -Y "http.request" -T fields -e http.request.full_uri
  ```
- **常见坑**：`-Y` 是显示过滤器（wireshark 语法）不是 capture filter（BPF）；TLS 流量需 `-o tls.keylog_file:<file>` 才可读；导出目录已存在会报错，先清空。
- **状态**：hypothesis（本机无 tshark，未复跑）｜裁决词：待复跑

### exiftool 元数据提取
- **用途**：图片/PDF 元数据一键提取（作者/GPS/注释里藏 flag 的常规位）。
- **命令模板**：
  ```bash
  exiftool chall.jpg             # 全量元数据
  exiftool -Comment -Artist chall.jpg   # 按字段取
  exiftool "-Comment<=payload.txt" chall.jpg   # 写入（反向构造题）
  ```
- **常见坑**：EXIF 可被无痕清除，零命中别急着排除图片题（转像素级隐写）；Comment 支持任意二进制——输出异常时 `| xxd` 看原始字节。
- **状态**：hypothesis（本机无 exiftool，未复跑）｜裁决词：待复跑

### dd 尾部数据提取
- **用途**：从 JPEG（FFD9）/PNG（IEND）等确定终止魔数的文件中切出尾部附加数据。
- **命令模板**：
  ```bash
  off=$(python3 -c "d=open('chall.jpg','rb').read();print(d.rfind(b'\xff\xd9')+2)")
  dd if=chall.jpg of=tail.bin bs=1 skip=$off 2>/dev/null
  file tail.bin
  ```
- **常见坑**：JPEG 中间缩略图也会出现 FFD9，必须取**最后一次**（`rfind` 而非 `find`）；`bs=1 skip=<字节>` 大文件慢，可换 `iflag=skip_bytes` + 大块读。
- **状态**：hypothesis（思路来自 JPEG/PNG 结构规范；头部魔数侧的 PNG 解析已实测，尾部切取待复跑）｜裁决词：待复跑

## 复跑记录（verified 条目必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 本地 Python 3.12.13 | struct 步进 chunk 链 | PASS | evidence/t4.png | IEND 偏移 59B，尾随 flag 完整取出 |
| 2 | 2026-10-15 | 本地 binutils strings | strings -n 6 + grep | PASS | evidence/t7_fmt | 命中即算成功，验证截断坑真实存在 |
