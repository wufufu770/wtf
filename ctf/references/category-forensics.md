---
verified: "2026-10-15 | 本地复跑：Python 3.12.13（struct 模块，Linux 容器），见条目1复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "0rangec3t/Black-cat（假设-证据范式）、CTF-wiki（misc/取证）、M2 实测复跑（2026-10-15）"
changelog:
  - "[2026-10-29] v0.5：蒸馏 P1+P2 批次并入 22 条（hypothesis 待复跑，REFLIGHT §1 二手知识纪律）｜源：ctf-corpus/distill 候选池（candidates.jsonl）+ distill/pilot/01-蒸馏批次报告-P2-20261029.md"
  - "[2026-10-15] 初始空壳，等待首个回流条目"
  - "[2026-10-15] v0.2：条目模板升级为五段式假设条目 + 机器可校验裁决词（REFLIGHT 回流协议，见 ../../shared/REFLIGHT.md）"
  - "[2026-10-15] v0.3：M2 填充 4 条（verified 1 / inconclusive 1 / hypothesis 2）"
  - "[2026-10-16] v0.4：「升级」字段边化——跳转目标改 [[条目名]] 图边引用（REFLIGHT §3）"
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
5. [steghide 空口令隐写探测](#steghide-空口令隐写探测)（hypothesis）
6. [补条建议：编码套娃链识别与解链——链头数字标记密码类型](#补条建议编码套娃链识别与解链链头数字标记密码类型)（hypothesis）
7. [终端模拟器 DECRQSS 回显 RCE（日志注入转义序列）](#终端模拟器-decrqss-回显-rce日志注入转义序列)（hypothesis）
8. [ZFS 删除队列与快照恢复（lz4 压缩剥层）](#zfs-删除队列与快照恢复lz4-压缩剥层)（hypothesis）
9. [pcap DC++ 文件传输 TTH 哈希爆破补缺](#pcap-dc-文件传输-tth-哈希爆破补缺)（hypothesis）
10. [PNG IEND 尾随增量字节提取（逆写入器）](#png-iend-尾随增量字节提取逆写入器)（hypothesis）
11. [APNG 帧拆解重组（fdAT → IDAT 修正）](#apng-帧拆解重组fdat-idat-修正)（hypothesis）
12. [C2 指令流还原（双 ;;分隔协议 + push 分组过滤）](#c2-指令流还原双-分隔协议-push-分组过滤)（hypothesis）
13. [pcap 碎片合成 QR（HTTP 对象导出 + ImageMagick）](#pcap-碎片合成-qrhttp-对象导出-imagemagick)（hypothesis）
14. [音频信道分离 FSK 解调 + XOR 奇偶仲裁（SSTV 目标 CRC）](#音频信道分离-fsk-解调-xor-奇偶仲裁sstv-目标-crc)（hypothesis）
15. [TSPL 打印指令还原（BAR 矩形渲染取旗）](#tspl-打印指令还原bar-矩形渲染取旗)（hypothesis）
16. [多源碎片雕刻与权威哈希仲裁（NXFR 记录）](#多源碎片雕刻与权威哈希仲裁nxfr-记录)（hypothesis）
17. [Linux 内存镜像取证（banners 定版 → profile → 进程现场）](#linux-内存镜像取证banners-定版-profile-进程现场)（hypothesis）
18. [acropalypse 截图裁剪漏洞恢复（尾数据 + 尺寸差）](#acropalypse-截图裁剪漏洞恢复尾数据-尺寸差)（hypothesis）
19. [ISO→maildir→PGP→outguess 四段链取证](#isomaildirpgpoutguess-四段链取证)（hypothesis）
20. [OLE/Word97 头修复 + foremost 嵌套提取](#oleword97-头修复-foremost-嵌套提取)（hypothesis）
21. [BMP 位平面隐写读取（跟随写入器逻辑）](#bmp-位平面隐写读取跟随写入器逻辑)（hypothesis）
22. [hex 文本修复 JPEG + steghide 双层 + morse/ROT13](#hex-文本修复-jpeg-steghide-双层-morserot13)（hypothesis）
23. [文本空白字符隐写（空格/制表符二进制）](#文本空白字符隐写空格制表符二进制)（hypothesis）
24. [E01 取证镜像挂载与删除文件恢复](#e01-取证镜像挂载与删除文件恢复)（hypothesis）
25. [sqlmap 注入日志轨迹取证（服务端视角拼旗）](#sqlmap-注入日志轨迹取证服务端视角拼旗)（hypothesis）
26. [音频帧重排恢复（排列指示数组）](#音频帧重排恢复排列指示数组)（hypothesis）

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
- **升级**：PASS 后对取出数据按 [[file + strings 零依赖侦察]] 二次识别嵌套文件；FAIL 转 LSB 与 CRC 校验新假设（改宽高隐写 CRC 必错）。
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
- （可选）**升级**：`-z conv,tcp` 先看会话分布（属 [[tshark 流量分析]] 用法），大流量会话优先——别按包序硬读。

### steghide 空口令隐写探测
- **分层**：简单档·可复现强
- **假设**：JPEG 隐写题在题面无任何口令提示时，**先试 steghide 空口令**（直接回车）——出题方常默认空口令；`steghide info` 即可确认嵌入（回显 embedded file 名/尺寸/`rijndael-128, cbc`/压缩标记），无需先盲扫全家桶。
- **验证步骤**：1) `steghide info img.jpg`（passphrase 留空回车）；2) 确认回显含 "embedded file" 字段；3) `steghide extract -sf img.jpg -xf shell.txt`（仍空口令）。
- **判定标准**：PASS = info 报告 embedded file 且 extract 成功；FAIL = 无嵌入或口令非空 → 转口令线索（题面/EXIF/资源段）或其他格式族（outguess/F5/LSB）。
- **裁决词**：待复跑
- **来源**：TrendMicro CTF 2019 Quals RE-100 尾环（shell.txt 1.2KB，rijndael-128 cbc 加密嵌入）｜p4｜raw/github-repos/p4/2019_trendmicro-quals_e_re-100.md（`steghide info` 完整回显在 WP，可对照重放）
- **关键差异**：p4 是"各种流行工具试尽"之后才命中 steghide 空口令——**基线检查应前置**（第一动作而非最后手段）；与现库 forensics 条目（PNG chunk/FFD9 尾附/binwalk）互补，不重叠。

### 补条建议：编码套娃链识别与解链——链头数字标记密码类型
- **分层**：简单档·可复现强｜**动作：关键差异补条**（熵控五问 Q1 判定为现有条目边界情况，不新建独立条目）
- **假设**：套娃链变体：密文**每块前缀数字即密码类型标记**（如 1=rot13、2=base64、3=caesar，自加密 50 轮）→ 解链无需频率/特征判型，按前缀路由解码器即可；密文常藏于 pcap 的非 HTTP 对象流（源码在导出对象里、密文在 Follow TCP Stream 里——双路都要看）。
- **验证步骤**：1) 观察密文头部「数字-字母串」交替模式；2) 按数字索引选解码器逐块剥；3) 终态以可读 flag 校验；4) pcap 场景先 Export Objects 拿加密器源码、再 Follow TCP Stream 找密文。
- **判定标准**：PASS = 按标记解完全链得旗；FAIL = 标记缺失 → 回退现库条目的特征判型路径。
- **裁决词**：待复跑
- **来源**：CSAW 2015 transfer（forensics 100p，541 solves）｜p4｜raw/github-repos/p4/2015_csaw_e_transfer.md（加密器 python 源码 + `enc_ciphers = ['rot13','b64e','caesar']` 全在 WP）
- **目标条目**：[[编码套娃链识别与解链]]（wtf 现库）——差异点：① 自描述链头标记；② pcap 场景「对象导出 + Follow Stream」双路取证动作。

### 终端模拟器 DECRQSS 回显 RCE（日志注入转义序列）
- **分层**：困难档·复合链
- **假设**：Web 服务把未过滤的用户输入（URL 路径）回显到终端日志，而旧版终端模拟器（zutty 0.12）实现 DECRQSS 时会把非法参数原样回显为可执行转义序列（CVE-2008-2383 xterm 同族、iTerm2 CVE-2022-45872 跨 14 年重犯）⇒ 在请求路径中注入 DCS $ q…ST 序列，令终端「自己向自己」发出命令实现 RCE；另第一问可由「卡死单线程 Rust 服务器」达成（fork 子进程 connect 后 sleep，父进程退出）。
- **验证步骤**：1) 从 Dockerfile 锁终端模拟器版本；2) 对照 upstream shortlog 定位修复 commit 与回显行为；3) 构造含 DCS $ q 的 GET 路径写入访问日志；4) 终端渲染时执行序列读取 chroot 外 flag。
- **判定标准**：PASS = 终端内触发命令执行拿到 flag（两问通吃）；FAIL = 版本已修（回显为 cancel 序列）→ 转单纯视觉伪造（光标回退重绘日志行 / Sixel 图片）仅取第一问。
- **裁决词**：待复跑
- **来源**：Hackergame 2024 动画分享（general）｜USTC-Hackergame（官方+选手，taoky）｜raw/github-repos/hackergame2024/2024_hackergame_h_cn-432868.md（DEF CON 31 两讲座索引与 payload 全量在 WP，本地 zutty 可重放）
- **陷阱备注**：ANSI/DCS 转义是「纯文本协议」里被忽视的执行通道——取证视角看日志时「眼见不为实」（回退序列可重写历史行）。

### ZFS 删除队列与快照恢复（lz4 压缩剥层）
- **分层**：困难档·复合链
- **假设**：ZFS 删除不即时清数据，先入 delete queue 保持事务一致性；镜像里 `zfs list -rt all` 暴露快照 `data@mysnap`（REFER 与父卷差值即隐藏占用）⇒ 被删文件藏在快照的 delete queue 对象中，dump 后还需剥开 lz4 压缩与间接块层才见明文。
- **验证步骤**：1) Ubuntu/PVE 自带 zfs.ko 挂载镜像（免 DKMS）；2) `zfs list -rt all` 确认快照；3) 对快照跑 `zdb -dddd` 定位 delete queue 对象编号并 dump；4) 识别 lz4 魔数与对象布局，解压得明文（第一问文本文件 / 第二问结构化对象再拼装）。
- **判定标准**：PASS = 两个被删文件内容完整恢复；FAIL = 对象在 dump 中只有引用计数 → 检查 dnode 遍历是否漏 SPA 层。
- **裁决词**：待复跑
- **来源**：Hackergame 2024 ZFS 文件恢复｜USTC-Hackergame（官方+选手）｜raw/github-repos/hackergame2024/2024_hackergame_h_zfs.md（zdb 命令序列与解压思路在 WP；本地 zpool 即可造样重放）
- **关联**：Q1 边界——同「镜像分层恢复」族 [[E01 取证镜像挂载与删除文件恢复]]，关键差异 = 事务性文件系统的删除语义与压缩层。

### pcap DC++ 文件传输 TTH 哈希爆破补缺
- **分层**：困难档·复合链
- **假设**：流量中两份 ADC/DC++ FileListing XML 对同名文件 fl3g.txt 给出相同 TTH 哈希但正文中无内容 ⇒ 已知 14 字节长度与 flag 格式先验，把未知字符做成小空间，爆破候选内容使 Tiger Tree Hash 命中目标 TTH。
- **验证步骤**：1) tshark 导出会话重组 XML；2) 比对两份 listing 的 TTH/Size 锁定目标；3) 按 flag{} 格式枚举未知 4 字节；4) base32(TTH) 与 pcap 记录比对。
- **判定标准**：PASS = 唯一命中还原文件内容；FAIL = TTH 空间超界 → 扩用 DC++ 协议侧其它字段（Size/CID）交叉。
- **裁决词**：待复跑
- **来源**：BITSCTF 2017 woodstock（pcap/OSINT 350）｜p4（波兰战队）｜raw/github-repos/p4/2017_bitsctf_h_woodstock.md（两份 FileListing XML 与爆破思路在 WP，TTH 本地可复算）
- **关联**：同「哈希先验约束爆破」思想 [[RSA 最低有效字节甲骨文（LSB×8 预算约束）]]——把搜索空间压到哈希可验证的小域。

### PNG IEND 尾随增量字节提取（逆写入器）
- **分层**：困难档·复合链
- **假设**：程序逐次调用图像库把 flag 字符追加写到 PNG 尾部（IEND 之后）⇒ 对每个 PNG 提取 IEND 后字节流并按调用序合并即得 flag；逆向 APK/二进制定位调用逻辑以确认拼接顺序。
- **验证步骤**：1) strings/binwalk 探 IEND 后尾数据；2) 逆向确认写入函数与字符顺序（含排序/编码变换）；3) 脚本批量提取全部 PNG 尾字节；4) 按序拼接校验 flag 格式。
- **判定标准**：PASS = 拼出合法 flag；FAIL = 尾数据带每文件异或/索引 → 按逆向出的变换先解码。
- **裁决词**：待复跑
- **来源**：picoCTF 2019 Investigative Reversing 1｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2019_investigative-reversing-1-md_h_investigative-reversing-1.md（逆向定位与提取代码在 WP）
- **关联**：升级 [[JPG FFD9 尾部附加数据]]/[[PNG chunk 解析定位尾随隐写]] 到「多文件增量」形态——关键差异 = 单文件尾数据 → 文件集按序拼接。

### APNG 帧拆解重组（fdAT → IDAT 修正）
- **分层**：困难档·单点
- **假设**：PNG 含 acTL/fcTL/fdAT 动画块且 CRC 被写坏（题目暗示手工构造）⇒ 手工遍历 chunk：fdAT 去头 4 字节序列号后视作 IDAT、配 IHDR/IEND 即成单帧 PNG，CRC 不校直接提取，逐帧解码拼 flag。
- **验证步骤**：1) PNG 签名后逐 chunk 打印 type/length；2) 对每个 fdAT 重打包成独立 PNG（IHDR+IDAT+IEND）；3) 批量解码；4) 帧序列即 flag 字符序。
- **判定标准**：PASS = 每帧可解码且序拼成旗；FAIL = 首帧 IDAT 缺失 → 用静态帧补齐再拼。
- **裁决词**：待复跑
- **来源**：ASIS CTF Finals 2016 p1ng｜p4（波兰战队）｜raw/github-repos/p4/2016_asis-final_h_p1ng.md（PHP 拆包函数全量在 WP，本地可重放）
- **关联**：与 [[PNG chunk 手工解析（python struct）]] 同族进阶——关键差异 = 动画块结构（acTL/fcTL/fdAT）与坏 CRC 容错。

### C2 指令流还原（双 ;;分隔协议 + push 分组过滤）
- **分层**：困难档·复合链
- **假设**： pcap 中 C2 通信为文本行协议（`;;` 分隔：bot id/指令/参数/SHA 校验）⇒ Wireshark 按 `tcp.flags.push == 1` 过滤导出 JSON，按流重组还原指令表，从 `download;;…;;/tmp/flag;;URL` 指令定位随后 HTTP 传输即 flag。
- **验证步骤**：1) tshark 过滤 push 分组导出；2) 解码 ;;字段（编码与同赛 Connection 题共用）；3) 重建指令时间线（ready/wait/accepted/download）；4) 按指令中 URL 追 HTTP 流取旗。
- **判定标准**：PASS = 完整指令表 + flag；FAIL = 分片跨段重组错位 → 按 seq 去重后重排。
- **裁决词**：待复跑
- **来源**：The Catch 2020 Botnet master｜vernjan｜raw/github-repos/vernjan/write-ups/TheCatch2020/02-malware-research-facility/05-botnet-master/README.md（packets.json 与解析器在 WP 附件）
- **关联**：同「流量→指令语义」族 [[tshark 流量分析]]，关键差异 = push 过滤偏排与双分隔符协议重建。

### pcap 碎片合成 QR（HTTP 对象导出 + ImageMagick）
- **分层**：困难档·复合链
- **假设**：流量里若干小 PNG 各含 flag 棋子图片的局部 ⇒ 导出 HTTP 对象全集，用 convert -append/+append 按位置拼贴出完整棋盘图，其上 QR 码经反色/锐化后可扫描。
- **验证步骤**：1) Wireshark 导出 HTTP objects；2) 观察碎片编号与边缘特征定行列；3) ImageMagick 网格拼接；4) zbarimg 扫描。
- **判定标准**：PASS = QR 解码出旗；FAIL = 碎片顺序不明 → 按 pcap 抓包次序先排。
- **裁决词**：待复跑
- **来源**：CSAW-HSF 2017 qr-200（forensics 200）｜perfect blue（战队）｜raw/github-repos/perfectblue/2017_csaw-hsf_h_qr-200.md（拼贴命令与扫描流程在 WP）
- **关联**：同「碎片重组」族 [[多源碎片雕刻与权威哈希仲裁（NXFR 记录）]] 的低配形态——无哈希权威时以图像连续性定序。

### 音频信道分离 FSK 解调 + XOR 奇偶仲裁（SSTV 目标 CRC）
- **分层**：困难档·复合链
- **假设**：双声道 WAV 左右信道各藏数据（音频 FSK 遥测 + SSTV 图像/权威 CRC 表）⇒ minimodem --rx 解调 FSK 得 NXPKT 分组流；分组声明式 CRC 会放行陈旧重传，须以目标侧权威 CRC 为准筛选，再对缺口分组用 XOR 奇偶组（A⊕D0⊕D1⊕D3 = D2）恢复，最后 GZIP 魔数校验重组。
- **验证步骤**：1) ffmpeg 分离声道；2) minimodem 解调十包遥测；3) 按 len/WIRECRC 过滤 + 对照权威 CRC 拒掉 decoy（NX-770）与陈旧重试；4) 奇偶 XOR 补缺块 → 5757 字节 GZIP 解压取旗。
- **判定标准**：PASS = 重组 GZIP 完整解压出旗；FAIL = 误信用「首个 CRC 合法」重传 → 奇偶组损坏（本条即陷阱记录）。
- **裁决词**：待复跑
- **来源**：CSS CTF 2026 Return of Nexus Ghost Frequency｜hax1ng｜raw/github-repos/hax1ng_css-ctf-2026-return-of-nexus/forensics/ghost-frequency/README.md（reassemble.py 全量在 WP）
- **关联**：与 [[多源碎片雕刻与权威哈希仲裁（NXFR 记录）]] 同一「层级化 CRC 信任」纪律（同一赛事姊妹题）。

### TSPL 打印指令还原（BAR 矩形渲染取旗）
- **分层**：困难档·单点
- **假设**：pcapng 中打印机作业为 TSPL/TSPL2 语言（TSC 打印机指令集）⇒ 提取载荷按 `BAR x,y,w,h` 逐条在画布上画矩形，渲染结果即 flag 位图。
- **验证步骤**：1) 定位含指令流的分组（如 no.675）；2) 识别 TSPL 语法（BAR/TEXT/BITMAP）；3) PIL 按坐标批量绘制；4) 输出 PNG 读旗。
- **判定标准**：PASS = 渲染图可读出 flag；FAIL = 含 BITMAP 光栅段 → 按位解包光栅而非矩形。
- **裁决词**：待复跑
- **来源**：RCTF 2019 printer｜Balsn｜raw/github-repos/balsn/slices/20190518-rctf2019/printer.md（BAR 指令序列全量在 WP，本地渲染可重放）
- **关联**：Q1 边界——按技术实质（工业协议渲染）归 forensics；与 [[tshark 流量分析]] 互补的「协议即图」思路。

### 多源碎片雕刻与权威哈希仲裁（NXFR 记录）
- **分层**：困难档·复合链
- **假设**：同一文件碎片散布三个源（ext4 缓存 blob、已清索引未清记录的环形 spool、被动监听 pcap），均为大端 NXFR 记录（session/sequence/total/len/crc32）⇒ 目录 SQLite 为权威（SHA-256 只对 payload），只有 CRC32 与权威 SHA-256 双验通过的碎片才可信；「CRC 合法但目录哈希不符」的环形残留/重传副本是陷阱。
- **验证步骤**：1) `icat` 提取五类文件（维护说明/格式规范/relay.db/三缓存）；2) 全源扫 NXFR 魔数解析头；3) 对每 (session,seq) 取双验通过副本；4) 按 sequence 拼接、截断到目录声明的总长取旗。
- **判定标准**：PASS = 拼接对象校验通过；FAIL = 采信「先到 CRC 合法」副本 → 重组对象哈希不符（陷阱即反例记录）。
- **裁决词**：待复跑
- **来源**：CSS CTF 2026 Return of Nexus Signal Fracture｜hax1ng｜raw/github-repos/hax1ng_css-ctf-2026-return-of-nexus/forensics/signal-fracture/README.md（recover.py 全量在 WP）
- **关联**：Q1 查重——与 [[音频信道分离 FSK 解调 + XOR 奇偶仲裁（SSTV 目标 CRC）]] 互为姊妹证据（同赛事、同「权威哈希仲裁」纪律、不同载体），支持策略层升格。

### Linux 内存镜像取证（banners 定版 → profile → 进程现场）
- **分层**：困难档·复合链
- **假设**：raw 内存 dump 无法直接读 ⇒ volatility3 `banners.Banners` 扫内核版本串锁定 Ubuntu 内核 5.4.0-84；下载对应 profile 后以 linux.ps/linux.bash/strings 提取进程命令行与现场数据取旗。
- **验证步骤**：1) `vol.py -f dump.mem banners.Banners`；2) 去 volatilityfoundation/profiles 取 Ubuntu18.04(5.4.0-84) profile；3) `linux.ps`/`linux.bash`/`linux.procpid cmdline` 逐层查；4) 命中 flag 格式收束。
- **判定标准**：PASS = banners 唯一定版且 profile 可用并出旗；FAIL = 版本混布（多 banner）→ 按地址聚类取主流内核。
- **裁决词**：待复跑
- **来源**：RITSEC CTF 2023 Missing Piece Part 1（forensics 397p）｜siunam321｜raw/github-repos/siunam321/RITSEC-CTF-2023/Forensics/Missing-Piece-Part-1.md（volatility 命令序列在 WP）
- **陷阱备注**：dump 里多内核 banner 是烟雾——先聚类再挑 profile，盲挂第一个 banner 的 profile 会 plugin 全空。

### acropalypse 截图裁剪漏洞恢复（尾数据 + 尺寸差）
- **分层**：困难档·单点
- **假设**：Pixel 系统截图工具裁剪图片时只把新数据覆盖原文件头部、不截断原长 ⇒ IEND 之后残留未覆盖区，而漏洞恢复只依赖「文件实际长度 − 声明长度」与压缩流尾；老型号（Pixel 3）恢复站点 acropalypse.app 直接解出原图。
- **验证步骤**：1) binwalk/zsteg 探 IEND 后尾数据；2) 计算长度差判断裁剪量；3) 按 Pixel 3 机型在恢复站上传；4) 恢复图读旗。
- **判定标准**：PASS = 恢复出未裁剪原图；FAIL = 声明与实际长度一致（新机已修）→ 转纯尾数据分析路线。
- **裁决词**：待复跑
- **来源**：Hackergame 2023 奶奶的睡前 flag 故事｜USTC-Hackergame（官方+选手，lly）｜raw/github-repos/hackergame2023/2023_hackergame_h_flag_p2.md（漏洞原理分析与机型试错在 WP）
- **关联**：同「PNG 尾数据」族 [[PNG IEND 尾随增量字节提取（逆写入器）]]，关键差异 = 残留由「覆盖不截断」产生，恢复以结构差而非内容拼接。

### ISO→maildir→PGP→outguess 四段链取证
- **分层**：困难档·复合链
- **假设**：ISO 挂载后 grep 线索词定位 maildir 附件 SaintGiong.jpg.pgp（base64 解码后真 PGP）；密钥按指纹在镜像 `etc/mail/private.asc` 内 grep 命中 → gpg 解密得 jpg；隐写口令从正文藏头（首字母）读出 → outguess 提取取旗。
- **验证步骤**：1) mount ISO 后 `grep -ri 线索词 .`；2) base64 -d + gpg --import 私钥 --decrypt；3) 藏头字母拼 passphrase；4) outguess -r 取数据。
- **判定标准**：PASS = 四段全通出旗；FAIL = PGP 解密失败 → 核对 keyid 与私钥指纹一致性。
- **裁决词**：待复跑
- **来源**：WhiteHat 2018 misc02｜p4（波兰战队）｜raw/github-repos/p4/2018_whitehat_h_misc02.md（全程命令在 WP）
- **关联**：Q1 边界——链式取证入口 [[steghide 空口令隐写探测]] 之上，关键差异 = 口令以文本藏头提供而非空口令。

### OLE/Word97 头修复 + foremost 嵌套提取
- **分层**：困难档·复合链
- **假设**：损坏 .doc 实为旧版 Word 二进制（ bjbjj 魔数）⇒ 修复头部后文件内嵌 zip/png；foremost 按签名 carving 出嵌套对象，文本提示「Maybe she will help」指向图片隐写位，解开后双重 base64 得旗。
- **验证步骤**：1) file/xxd 验旧 doc 魔数并修头；2) foremost Fix_me.doc；3) 审 audit.txt 取 zip/png；4) 逐层解包 + 双 base64。
- **判定标准**：PASS = 嵌套对象全提取得旗；FAIL = foremost 误报 → 按偏移手工 dd。
- **裁决词**：待复跑
- **来源**：CheckPoint CSA 2020 Fix me if you can｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2020_fix-me-if-you-can-md_h_fix-me-if-you-can.md（foremost audit 与解码链在 WP）
- **关联**：与 [[zip 伪加密]] 互补的「容器损坏类」首步：先辨格式代际再谈 carving。

### BMP 位平面隐写读取（跟随写入器逻辑）
- **分层**：困难档·复合链
- **假设**：逆向出写入器按「跳过像素/字节 + 位序」规则把 flag 逐位写进 BMP 数据位 ⇒ 不是盲跑 zsteg 滤镜，而是把逆向出的提取参数（步长、起始偏移、位权）转成读取脚本，按位还原。
- **验证步骤**：1) 逆向程序定位写入循环（定位 BMP 像素数组偏移与位操作）；2) 参数化提取脚本；3) 位拼字节按 ASCII 校验；4) 对拍程序逻辑确认无误。
- **判定标准**：PASS = 提取字节为合法 flag 文本；FAIL = 位序反 → LSB/MSB 双向试跑取合法者。
- **裁决词**：待复跑
- **来源**：picoCTF 2019 Investigative Reversing 3｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2019_investigative-reversing-3-md_h_investigative-reversing-3.md（逆向定位与提取思路在 WP）
- **关联**：Q1 边界——技术实质是「逆向定义的隐写格式」；与 [[逆向问答链：strcmp 常量答案 → 常量变换 → RC4 资源口令]] 同为逆向驱动取证。

### hex 文本修复 JPEG + steghide 双层 + morse/ROT13
- **分层**：困难档·复合链
- **假设**：给的是纯十六进制文本而非二进制 ⇒ `xxd -r -p` 还原 JPEG（头部需补 FF D8 段），steghide 以弱口令 123 提出内层图；再提一次得 morse 文本，解码后套 ROT13 得旗。
- **验证步骤**：1) xxd -r -p 重建文件并核对 JPEG 段结构；2) steghide extract -p 123 两层；3) morse 解码表转换；4) ROT13 收束。
- **判定标准**：PASS = 四段全通；FAIL = steghide 报损坏 → 检查 JPEG 头重建是否丢段。
- **裁决词**：待复跑
- **来源**：CultRang 2026 island prison escape（forensics）｜Pranav-m7｜raw/github-repos/Pranav-m7_IIT-Goa-CTF-Writeups-CultRang/forensics/island-prison-escape/README.md（命令序列全量在 WP）
- **关联**：[[steghide 空口令隐写探测]] 的「弱口令猜解」分支；编码层与 [[编码套娃链识别与解链]] 同族（morse→ROT13 双层）。

### 文本空白字符隐写（空格/制表符二进制）
- **分层**：困难档·单点
- **假设**：大段自然语言文本行尾藏空白字符隐写（空格=0、制表符=1）⇒ 正则逐行抽取行尾空白序列转 bit 流，unbits 解码即旗。
- **验证步骤**：1) `cat -A` 或正则 `\t* *$` 检视行尾；2) 每行抽取空白映射 01；3) 拼位流按 8bit 切；4) ASCII 解码校验 flag 格式。
- **判定标准**：PASS = 解码出可读旗；FAIL = 行首/词间空白才是载体 → 移动正则锚点重抽。
- **裁决词**：待复跑
- **来源**：Technion 2020 700k（stego）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2020_700k-md_h_700k.md（solve.py 正则与 unbits 在 WP）
- **陷阱备注**：编辑器默认吞行尾空白——文件必须以二进制方式查看（cat -A / xxd）才不致漏载体。

### E01 取证镜像挂载与删除文件恢复
- **分层**：困难档·复合链
- **假设**：EWF/E01 镜像不可直接挂载 ⇒ ewfmount 转裸设备后 fdisk 读 GPT 分区表，按 `offset=起始扇区×512` 只读挂 NTFS 数据分区；取证目标在 $MFT 残留/回收站/用户目录中恢复。
- **验证步骤**：1) `ewfmount x.E01 dir`；2) `fdisk -l dir/ewf1` 记分区起点；3) `mount -o ro,loop,offset=… show_sysfiles`；4) 审 $MFT/删除项与用户痕迹取旗。
- **判定标准**：PASS = 挂载成功并恢复出目标文件；FAIL = offset 单位错（扇区 vs 字节）→ 统一乘 512 重挂。
- **裁决词**：待复跑
- **来源**：BSidesTLV 2020 Check yourself（forensics 100）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2020_check-yourself-so-you-wont-wreck-yourself-md_h_check-yourself-so-you-wont-wreck-yourself.md（完整命令链在 WP）
- **关联**：同「镜像分层恢复」族 [[ZFS 删除队列与快照恢复（lz4 压缩剥层）]]，关键差异 = 商业取证格式经 ewfmount 转挂而非原生 zfs.ko。

### sqlmap 注入日志轨迹取证（服务端视角拼旗）
- **分层**：困难档·单点
- **假设**：nginx access log 记录了攻击者全程 sqlmap 注入请求 ⇒ urldecode 还原 payload 序列，识别「探测→爆库→逐位爆破」的阶段特征（每位以 != 收尾的盲注判别式），抽出每次命中的字符按序拼旗。
- **验证步骤**：1) 提取注入 URI 序列并 urldecode；2) 定位逐位盲注段（substring+比较+!= 终止）；3) 人工/脚本抽每步判定字符；4) 按请求时序拼接校验。
- **判定标准**：PASS = 拼出完整 flag；FAIL = 日志乱序 → 按时间戳重排再拼。
- **裁决词**：待复跑
- **来源**：RCTF 2015 Analysis nginx's log（MISC 50）｜六星战队（中国）｜raw/github-repos/sixstars/2015_rctf_h_writeup.md（判别式特征描述在 WP）
- **关联**：Q1 边界——[[sqlmap 基线用法]] 是攻击侧工具纪律，本条是防守侧流量取证；「识别自动化工具指纹」是 SOC 视角新知点。

### 音频帧重排恢复（排列指示数组）
- **分层**：困难档·单点
- **假设**：wav 被 0-8349 的一个排列打乱帧序而元信息帧总数为 835000（百倍关系）⇒ strings 在文件尾发现排列数组（字符串形式），按「第 k 帧应放到 A[k] 处」逆置换重排帧后播放即闻旗。
- **验证步骤**：1) strings 审文件尾找数字数组；2) 校验其为 0..N-1 排列；3) numpy 按索引重写帧序；4) 播放/频谱收旗。
- **判定标准**：PASS = 重排后音频可辨识出旗；FAIL = 置换方向反 → 正逆两向取可听者。
- **裁决词**：待复跑
- **来源**：RCTF 2015 I can't hear that（MISC 150）｜六星战队（中国）｜raw/github-repos/sixstars/2015_rctf_h_writeup.md（重排规则在 WP；wave 模块本地可重放）
- **关联**：同「无头媒体重排」族 [[无头视频流分辨率搜索（RGB 字节流重排 + 尾帧取证）]]——关键差异 = 该条搜索几何参数、本条恢复置换映射。
