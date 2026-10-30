---
verified: "2026-10-15 | 本地复跑：Python 3.12.13 + gzip/base64（Linux 容器），见条目1复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "CTF-wiki（misc）、0rangec3t/Black-cat（假设-证据范式）、巨人项目 OSINT 实战记录（2026-10）、M2 实测复跑"
changelog:
  - "[2026-10-30] v0.6：修正批同步 1 处（46 修正批涉已入库条目 D80，pilot/04-修正简报）｜P3 批次无 misc 分区，条目数不变"  - "[2026-10-29] v0.5：蒸馏 P1+P2 批次并入 6 条（hypothesis 待复跑，REFLIGHT §1 二手知识纪律）｜源：ctf-corpus/distill 候选池（candidates.jsonl）+ distill/pilot/01-蒸馏批次报告-P2-20261029.md"
  - "[2026-10-15] 初始空壳，等待首个回流条目"
  - "[2026-10-15] v0.2：条目模板升级为五段式假设条目 + 机器可校验裁决词（REFLIGHT 回流协议，见 ../../shared/REFLIGHT.md）"
  - "[2026-10-15] v0.3：M2 填充 4 条（verified 1 / hypothesis 3）"
  - "[2026-10-16] v0.4：「升级」字段边化——跳转目标改 [[条目名]] 图边引用（REFLIGHT §3）"
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
5. [git 历史考古取旗（log 提交信息 / blame 作者 / 丢失提交找回）](#git-历史考古取旗log-提交信息-blame-作者-丢失提交找回)（hypothesis）
6. [π 有理下界的非负函数积分构造（凸组合自动化）](#π-有理下界的非负函数积分构造凸组合自动化)（hypothesis）
7. [无头视频流分辨率搜索（RGB 字节流重排 + 尾帧取证）](#无头视频流分辨率搜索rgb-字节流重排-尾帧取证)（hypothesis）
8. [数据库迷宫转储寻路（BFS 路径串旗）](#数据库迷宫转储寻路bfs-路径串旗)（hypothesis）
9. [bash 受限字符逃逸（变量名切片拼命令）](#bash-受限字符逃逸变量名切片拼命令)（hypothesis）
10. [受限 sudo Docker 白名单三路绕过（SUID 走私 / procfs 穿越 / 选项覆盖）](#受限-sudo-docker-白名单三路绕过suid-走私-procfs-穿越-选项覆盖)（hypothesis）

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
- **升级**：解出的是文件再走 [[file + strings 零依赖侦察]] 与 [[binwalk 签名扫描与提取]]；嵌套超 4 层考虑脚本自动化循环（按头字节路由解码器）。
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

### git 历史考古取旗（log 提交信息 / blame 作者 / 丢失提交找回）
- **分层**：简单档·可复现强（三题同族归并条目）
- **假设**：题目只给 `.git` 目录而工作区无旗 ⇒ 旗藏**历史**而非当前版本：提交信息（`git log`）、blame 作者名（`git blame <file>`）、被覆盖/丢弃的历史版本（`git log -p` / `git show <hash>` / reflog / `fsck --lost-found`）——「cat 读不到 = 题面明示陷阱」。
- **验证步骤**：1) unzip 后先 `git log --oneline` 全览提交史；2) `git log -p` / `git show` 逐历史版本 rg 旗格式；3) `git blame` 定可疑行作者（作者名即旗的变体）；4) 无果转 `git reflog` / `git fsck --lost-found` 找 dangling commit；5) 终极兜底 `git cat-file --batch-all-objects` 全对象库扫描。
- **判定标准**：PASS = 历史任一路径命中旗格式；FAIL = 历史干净 → 转对象库/分支引用全量扫描；再失败则旗不在 repo（回到常规文件分析）。
- **裁决词**：待复跑
- **来源**：picoCTF 2024 time-machine（提交信息即旗）+ blame-game（blame 作者名即旗）+ commitment-issues（历史版本找回旗）｜cajac｜raw/github-repos/cajac/2024_picoctf_e_time-machine.md、2024_picoctf_e_blame-game.md、2024_picoctf_e_commitment-issues.md（三题命令序列在各自 WP，可自造最小 repo 重放）
- **关键差异**：三题同族一技术——「工作区没有的，去历史找」；题面 hint「cat won't help you here」即分流信号。与现库 misc 条目（zip 伪加密/PPC 建模）无重叠。

### π 有理下界的非负函数积分构造（凸组合自动化）
- **分层**：困难档·构造链
- **假设**：对任意 p/q < π 恒可构造整数系数非负 f 使 ∫₀¹f = π − p/q——利用 ∫₀¹ 4/(1+x²) dx = π 作「π 源」，取非负多项式 g（∫g/denom = I₀ > 0 足够小），令 w = (p/q)/(π − I₀) ∈ (0,1)，提交 f = (w·g + (1−w)·4)/(1+x²)：积分为 π − p/q 且被积函数非负（两项均为非负组合），SymPy 可秒级机检非负性与定积分。
- **验证步骤**：1) 预构造非负 g（低次多项式、I₀ 小）；2) pwntools 连远程解析 p/q；3) 按公式算 w、生成 f 字符串；4) 本地 SymPy 先验校验（integrate == pi − p/q、区间非负）再提交。
- **判定标准**：PASS = 全部关卡通过且函数字符串在长度限制内；FAIL = 长度超限 → 换更低次 g；非负判定超时 → 因式分解形式。
- **裁决词**：待复跑
- **来源**：Hackergame 2024 优雅的不等式（math 150/250p）｜mingliangz｜raw/github-repos/hackergame2024/2024_hackergame_h_cn-090fea.md（完整 SymPy 自动解题脚本在 WP；本地 SymPy 可全重放）
- **关联**：同「机器可检构造」族 [[PPC 脚本题约束建模]]——关键差异 = 约束是分析学命题（非负性+定积分值）而非离散搜索，解法是凸组合闭式而非枚举。
- **陷阱备注**：Hard 档长度限制逼出「低次紧凑表示」；「常数 π 源 + 权重收缩」是通用套路（e、ln2 等其他常数同理换源）。

### 无头视频流分辨率搜索（RGB 字节流重排 + 尾帧取证）
- **分层**：困难档·复合链
- **假设**：附件是无封装连续 RGB 字节流（总长 = W·H·3·帧数），分辨率未知但画面内容人眼可辨识 → 把流 reshape 成候选 (W,H) 实时渲染，画面「连贯稳定」即正确分辨率；flag 藏在末帧。
- **验证步骤**：1) 文件总字节数整除性试探（定帧数/通道序）；2) numpy reshape + PyQt 滑杆播放器（可由 LLM 生成代码）实时调 W、H；3) 先固定已知侧（如 H）扫 W 至画面横向稳定，再微调 H 消除撕裂；4) 截取尾帧读旗。
- **判定标准**：PASS = 画面连贯且尾帧可读；FAIL = 总长不能被 3 整除 → 存在头/封装/通道序变体 → 转文件签名分析路线。
- **裁决词**：待复跑
- **来源**：Hackergame 2023 流式星球（general）｜USTC-Hackergame（官方+选手）｜raw/github-repos/hackergame2023/2023_hackergame_h_cn-905ab6.md（PyQt 交互播放器代码全量在 WP，numpy 即可离线重放）
- **关联**：Q1 边界——按挑战实类归 misc（选材线登记为 aiml 系合集归类）；同「媒体结构先验」族 [[PNG chunk 手工解析（python struct）]]，关键差异 = 无封装先验缺失，分辨率本身是搜索对象。
- **陷阱备注**：一维滑杆逐维扫描（先 W 后 H）比二维盲搜快一个数量级；「GPT4 写渲染代码」本身是该题演示的工作流。

### 数据库迷宫转储寻路（BFS 路径串旗）
- **分层**：困难档·单点
- **假设**：maze.db dump 出的 50×50 网格每节点存 1 字节 ⇒ 入口到出口的最短路（BFS + 回溯）途经节点字节按序拼接即旗。
- **验证步骤**：1) db 转储为文本矩阵；2) 标记起终点；3) BFS 求最短路并 backtrace；4) 沿路径收集字节拼接。
- **判定标准**：PASS = 拼串成旗（长十六进制串形态）；FAIL = 字节序/路径取错 → 对最短路与次短路分别试拼。
- **裁决词**：待复跑
- **来源**：QIWI CTF 2016 BFS（ppc 400）｜p4 (波兰战队)｜raw/github-repos/p4/2016_qiwi_h_bfs.md（BFS 与回溯代码全量在 WP）
- **关联**：同「网格搜索」族 [[PPC 脚本题约束建模]]——关键差异 = 数据藏在图节点而非约束在题面。
- **陷阱备注**：Q1 归位说明——按 PPC 实类归 misc（选材线记 reverse 系合集归类）。

### bash 受限字符逃逸（变量名切片拼命令）
- **分层**：困难档·单点
- **假设**：shell jail 禁用大部分命令字符与关键字时，变量名本身可作为字符串原料——`cat readme.txt` 的字符可由内置变量名拼接获得（`$PWD`、`$HOME`、`$0` 等 + ${var:offset:length} 切片 + ${var//x/y} 替换拼接），空格用 `${IFS}` 代偿 ⇒ 无需外部工具即可拼出任意读文件命令。
- **验证步骤**：1) 盘点可用字符集与被禁关键字；2) 枚举环境/位置变量找到可切出目标字符者；3) 切片拼接 `cat`/`nl` 等读命令；4) `${IFS}` 作分隔执行。
- **判定标准**：PASS = 拼出命令读出旗；FAIL = 变量原料缺字符 → 试 `set` 内置枚举全部 shell 变量再选。
- **裁决词**：待复跑
- **来源**：Hackergame 2024 PowerfulShell｜USTC-Hackergame（官方+选手）｜raw/github-repos/hackergame2024/2024_hackergame_h_powerfulshell.md（全套变量切片构造在 WP，本地 bash 3.2 可重放）
- **关联**：同「受限环境构造」族 [[只读文件系统的 nc 代理流式投递]]——关键差异 = 该条绕文件系统限制、本条绕字符集限制。
- **陷阱备注**：出题者意在 jailbreak 但元字符/字母大量放行，非预期用 `head`/`tail` 等命令直接读——边界说明「先确认禁令的实际覆盖面再谈逃逸」。

### 受限 sudo Docker 白名单三路绕过（SUID 走私 / procfs 穿越 / 选项覆盖）
- **分层**：困难档·复合链
- **假设**：sudo 只放行 `docker image load / run -u 1000 --security-opt=no-new-privileges` 等受限组合时，白名单的 corner case 三条路可破：① 依赖 image load 走私含 SUID 程序（su-exec）的镜像 + `run -v /:/host` 挂根提权；② `--privileged`/`--device` 被禁但 /var/lib/docker 挂载点无 nodev、旗在 /dev/vdb 固定设备号 → 镜像内 `mknod` + `chown 1000` 预制设备文件，容器跑 sleep 后在宿主 procfs 经 `/proc/<pid>/root` 进入容器命名空间读旗；③ `--security-opt=no-new-privileges:false` 显式覆盖（布尔选项解析接受带值形式，CLI 源码证伪「不可覆盖」假设）。
- **验证步骤**：1) `sudo -l` 精确审计白名单（含选项约束）；2) `mount` 看挂载选项（nodev/noexec 缺席点）；3) 按可行路走私镜像（ZMODEM 上传注意 tmpfs 接收）；4) 验证取旗。
- **判定标准**：PASS = 三路至少一条读出旗；FAIL = sudoers 严格化（无 image load）→ 转内核漏洞路线。
- **裁决词**：待复跑
- **来源**：Hackergame 2024 Docker for Everyone Plus（general 200p×2）｜RTXUX/USTC-Hackergame｜raw/github-repos/hackergame2024/2024_hackergame_h_docker-for-everyone-plus.md（三个 Dockerfile 与附注反思在 WP；本地 Docker 环境可全重放）
- **关联**：[[STG-X01 勿信补丁——修复覆盖面以 diff 验证]] 的运维版——「加了限制≠限制闭环」，布尔选项可被带值覆盖是 CLI 解析的经典缺口。
- **陷阱备注**：Q1 归位说明——按 Linux 提权实类归 misc（选材线记 mobile 系合集归类）；ZMODEM 上传须落在 tmpfs（只读 FS 会静默 skip）。
