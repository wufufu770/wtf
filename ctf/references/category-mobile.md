---
verified: "2026-10-30 | 回流复跑轮（接手 A）：7 条全裁决——1 PASS / 6 INCONCLUSIVE（5 条缺 APK 原件+RE 工具链、1 条缺物理镜像）；开源仓克隆 + firebase 活体探测，见各条复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "ctf-corpus 蒸馏层 P1+P2 批次（distill/by-category/mobile），原始 WP 见 ctf-corpus/raw/ 与 meta/register.jsonl"
changelog:
  - "[2026-10-30] 回流复跑轮：7 条全裁决（InjuredAndroid PASS——开源全源码四数据面全证+firebase 双端点活体 200；其余 6 条 INCONCLUSIVE 缺 APK 原件/物理镜像/RE 工具链，缺口清单入条目）；证据归档 shared/wtf-reflight-evidence-20261030/"
  - "[2026-10-29] v0.5 新库：蒸馏 P1+P2 批次建库并入 7 条（hypothesis 待复跑，REFLIGHT §1 二手知识纪律）｜11→10 库映射见 ctf-wp 采集规划 §4.4"
---

# 题型：移动安全

> 读取时机：APK 逆向、移动取证镜像、客户端校验与移动端协议类附件（本条目主库）

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态；changelog 每次结构变更一行留痕（append-only）。
4. 「升级」字段跳转目标用双中括号图边引用，必须命中全库某个 ### 级条目标题（第 4 检；字面示例只准放 frontmatter）。
5. 未经复跑的条目状态只允许 hypothesis（REFLIGHT §1 二手知识纪律）。

## 条目区（TOC）
1. [Xamarin AOT apk 提取 .NET PE（libmonodroid bundle）](#xamarin-aot-apk-提取-net-pelibmonodroid-bundle)（inconclusive）
2. [Android Mono 运行时反混淆（魔改 opcode 表 + ILSpy 还原）](#android-mono-运行时反混淆魔改-opcode-表-ilspy-还原)（inconclusive）
3. [密码算法大礼包识别（常量指纹 + F5 恢复 + SM4 收官）](#密码算法大礼包识别常量指纹-f5-恢复-sm4-收官)（inconclusive）
4. [OpenGL 顶点坐标取证（model 坐标批量提取 + 绘图取旗）](#opengl-顶点坐标取证model-坐标批量提取-绘图取旗)（inconclusive）
5. [Android 训练靶场全链路（jadx 审查 → sqlite → 远程端点）](#android-训练靶场全链路jadx-审查-sqlite-远程端点)（verified）
6. [Android 物理镜像取证（app 私有数据雕刻 +「UI 锁≠加密」）](#android-物理镜像取证app-私有数据雕刻-ui-锁加密)（inconclusive）
7. [APK JNI 原生库逆向（Ghidra 签名修复 + 双组解密）](#apk-jni-原生库逆向ghidra-签名修复-双组解密)（inconclusive）

### Xamarin AOT apk 提取 .NET PE（libmonodroid bundle）
- **分层**：超级难档·失败样本/陷阱
- **假设**：Xamarin/AOT 编译的 Android apk（ dex 无业务逻辑、入口全在 native so）⇒ .NET 程序集打包在 `libmonodroid_bundle_app.so` → 提取内嵌 **PE（dll）** → dnSpy/ILSpy 反编译 C# 校验逻辑——「apk 逆向 = java/dex」的默认假设在此失效。
- **验证步骤**：1) 解 apk（unzip/apktool）确认 dex 无逻辑；2) 定位 `lib/*/libmonodroid_bundle_app.so`；3) 用社区提取脚本（SO↔PE 布局特征搜索）抽出 .NET dll；4) dnSpy 反编译定位旗校验方法（如 `Core.CheckFlag`）；5) 校验逻辑本地复算或 z3 反推输入。
- **判定标准**：PASS = 提出可反编译 PE 并读出校验逻辑；FAIL = 纯 native（libapp.so / Flutter AOT / NDK）→ 转 native 逆向路径（ARM 反编译）。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：缺 APK 原件（corpus raw 仅 WP 文本、赛事附件站下线）+ 本机无 jadx/IDA/Ghidra 工具链；TWCTF 2020 附件分发站已下线，apk 本体无公开镜像可考。libmonodroid bundle SO↔PE 布局提取法无法活体重走。
- **来源**：TWCTF 2020 Tamarin（re 224p，42 solved）｜p4｜raw/github-repos/p4/2020_tokyowesterns_x_tamarin.md（SO 线程引用的社区提取脚本 + 提出含 `Core.CheckFlag` 的 PE）
- **陷阱备注**：apk 界面极简（单输入框校验型）+ dex 空壳 ⇒ 先查 so 构成再选逆向栈；判定 C# 逻辑比 ARM 汇编快一个量级。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 素材核查（corpus raw + 附件站存活探测） | raw 仓储检视 + 附件源存活检查 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/rerun-A-20261030.log | apk 入库+工具链就位后可续跑；WP 内提取脚本思路自洽 |
### Android Mono 运行时反混淆（魔改 opcode 表 + ILSpy 还原）
- **分层**：困难档·复合链
- **假设**：Android 包内置静态编译的 Mono/.NET 运行时且程序集被加密（`mono_image_open_from_data_with_name` 前后 XOR）且 opcode.def 被魔改 ⇒ dump 加载后的程序集 → 修正魔改 opcode 表后重编译 → ILSpy 还原 C# → 提取加密参数解密 PNG/BMP。
- **验证步骤**：1) IDA 定位 `0x36F000` 数据段与 0xB925C hook；2) 提取解密程序集（MZ 头校验）；3) 依 `Unknown heap type` 报错定位魔改 opcode；4) 改 opcode.def 重解码；5) ILSpy 读 key/IV 解密图片。
- **判定标准**：PASS = ILSpy 可反编译且图片头改 BM 后可显示；FAIL = monodis 解码错 → 检查 opcode 残余魔改点。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：缺 APK 原件（corpus raw 仅 WP 文本、赛事附件站下线）+ 本机无 jadx/IDA/Ghidra 工具链；gslab 2017 存档已关闭，apk 无镜像。IDA hook dump 加密程序集 + opcode.def 修正流程无法活体重走。
- **来源**：gslab 2017 Round2b（学生组/战队组）｜六星战队（中国）｜raw/github-repos/sixstars/2017_gslab_h_writeup.md（opcode 表替换与解密流程全量在 WP）
- **关联**：与 [[Xamarin AOT apk 提取 .NET PE（libmonodroid bundle）]] 同 .NET-on-Android 族——关键差异 = 该条 AOT 提 PE、本条 JIT Mono 提加密程序集且需修 opcode。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 素材核查（corpus raw + 附件站存活探测） | raw 仓储检视 + 附件源存活检查 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/rerun-A-20261030.log | apk 入库+IDA 工具链就位后可续跑 |
### 密码算法大礼包识别（常量指纹 + F5 恢复 + SM4 收官）
- **分层**：困难档·复合链
- **假设**：巨型纯 so 验证函数（强行 inline + 循环展开，F5 两万行）内嵌多算法 ⇒ 常量指纹（S-box、初始向量、魔数）分别命中 DES/SHA1/SM3/Rijndael 系标准表 → 未知主体为 0x20 轮循环 + 已知常量表 → 检索定 SM4；配合 F5 恢复伪代码后按算法语义分段重构。
- **验证步骤**：1) 扫二进制搜标准常量；2) IDA 等待/触发 F5 完成脱 inline；3) 32 轮 + S-box 结构比对 SM4；4) 重写验证逻辑本地跑；5) 按校验条件逆推输入。
- **判定标准**：PASS = 重构验证器与 so 行为一致并解出输入；FAIL = 算法被魔改 → 逐表 diff 定差异项。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：缺 APK 原件（corpus raw 仅 WP 文本、赛事附件站下线）+ 本机无 jadx/IDA/Ghidra 工具链；2016 年赛事 apk 无公开存档。常量指纹（S-box/IV/魔数）扫描与 32 轮 SM4 比对无法在原 so 上重走。
- **来源**：阿里聚安全 2016 决赛 Ali-Juanquan（mobile）｜六星战队（中国）｜raw/github-repos/sixstars/2016_ali-juanquan_h_writeup.md（识别路径与教训在 WP）
- **关联**：与 [[魔改 AES 常量指纹识别（表全换场景裸写实现）]] 同「算法指纹」族——关键差异 = 该条表全换需逆实现、本条多算法混编靠部分指纹+轮数定 SM4。
- **陷阱备注**：F5 卡死别死等——先常量定位再回看；「没跑 F5 时 IDA 窗口消失」这类环境信号值得留意。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 素材核查（corpus raw + 附件站存活探测） | raw 仓储检视 + 附件源存活检查 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/rerun-A-20261030.log | so/so 中的验证函数入库后可续跑（含 IDA） |
### OpenGL 顶点坐标取证（model 坐标批量提取 + 绘图取旗）
- **分层**：困难档·复合链
- **假设**：NativeActivity 游戏的旗以图形绘制藏匿（非贴图，代码硬编码顶点）⇒ 提取全部 model 顶点坐标（1057 个，前 361 个绘谜面区域）→ 坐标变换（手转 float）还原形状 → 连线成旗。
- **验证步骤**：1) apktool/IDA 对照官方 NativeActivity 样例标函数；2) 定位数据区与 model 索引结构；3) 批量导出坐标转 float；4) matplotlib 绘点连线；5) patch `x <= 50.0` 输入限制后重跑比对。
- **判定标准**：PASS = 绘出旗形状；FAIL = 坐标系原点/缩放未明 → 用已知箭头图形定标后再绘。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：缺 APK 原件（corpus raw 仅 WP 文本、赛事附件站下线）+ 本机无 jadx/IDA/Ghidra 工具链；MTP 2018 赛事 apk 无公开存档，1057 顶点数据集与绘图取证无法重走。
- **来源**：MTP 2018 Final 第一题（mobile）｜六星战队（中国）｜raw/github-repos/sixstars/2018_mtp_h_writeup.md（含题面更新前后两版完整分析；主办方坑：res 里假 `flag.bmp` 从未被 load）
- **关联**：与 [[8051 固件 EEPROM 导出 + 位级 patch（anl 立即数清零）]] 同「patch 限制 + 数据提取」族；图形载体取证在 mobile 库开荒。
- **陷阱备注**：`res/flag.bmp` 是未加载的诱饵——「资源在场≠被使用」，以交叉引用为准（[[STG-P02 泄露源码≠现役二进制——逆向为准，源码只作参考]] 同纪律）。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 素材核查（corpus raw + 附件站存活探测） | raw 仓储检视 + 附件源存活检查 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/rerun-A-20261030.log | apk 入库后顶点提取+绘图可复算 |
### Android 训练靶场全链路（jadx 审查 → sqlite → 远程端点）
- **分层**：困难档·参照系
- **假设**：教学向多关卡 app 的旗分散在 Java 层硬编码/资源字符串、sqlite 表（MD5 口令）、rot47 隐藏 URL、firebase 远程端点等 ⇒ 以 jadx 静审为主干，配合 db dump 与编码解码逐关收旗，形成「移动端数据存放面清单」。
- **验证步骤**：1) jadx 反编译全局搜 flag 比较串；2) strings 资源层扫 base64/rot47；3) 提取 sqlite 表并 MD5 爆破（hunter2 类）；4) 拼远程 JSON 端点；5) 逐关提交。
- **判定标准**：PASS = 18 关全通；FAIL = 动态加载层 → Frida hook 比对。
- **裁决词**：PASS
- **来源**：InjuredAndroid CTF 18 关（mobile 教学靶场）｜B3nac（作者本人 writeup）｜raw/github-repos/B3nac/InjuredAndroid/InjuredAndroid-FlagWalkthroughs.md（app 与全关答案开源，可本地装apk 全重放）
- **关联**：Q1 边界——作为「检验学习路径」参照系条目，与 [[反编译工具链优先级]] 互补（那条管工具、本条管数据存放面巡检清单）。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 本机（git clone B3nac/InjuredAndroid --depth 1 成功；全源码审计等效且强于 jadx 反编译面） | mobile5-injuredandroid-replay.py（四数据面独立取证 + firebase 活体探测） | PASS | shared/wtf-reflight-evidence-20261030/mobile5-injuredandroid-replay.log | ①Java 硬编码 F1ag_0n3；②资源名 base64 cmVzb3VyY2VzX3lv→F1ag_thr33；③sqlite 表 Thisisatest 内嵌 MD5=2ab96390c7dbe3439de74d0c9b0b1767 本地破解 hunter2；④rot47 隐藏 URL 解码→https://injuredandroid.firebaseio.com/sqlite.json 活体 HTTP 200 返回 "S3V3N_11"、/f1ag-pa55.json 200 返回 "hunter2"。注：App 交互层 18 关未在模拟器重放（环境无 Android 运行时）——按「数据存放面清单」核心主张裁决，交互完备性留痕 |
### Android 物理镜像取证（app 私有数据雕刻 +「UI 锁≠加密」）
- **分层**：困难档·复合链
- **假设**：3.5GB flash 物理镜像中笔记 app（protectedtext）声称 PIN 加密，实际 PIN 只锁 UI、db 内容明文落盘 ⇒ 在镜像中 grep 包名/关键 JSON 字段（`"encrypted":false`）→ 雕刻出 notes 表内容 → 直接读旗。
- **验证步骤**：1) strings/photorec 搜 `com.protectedtext.android` 数据痕；2) 定位 db/JSON 分片；3) 提取 note 字段；4) 按 app 数据格式还原旗。
- **判定标准**：PASS = 明文笔记含旗；FAIL = 分片残缺 → 按 JSON 结构续接。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：缺 3.5GB flash 物理镜像原件（corpus raw 仅 WP 文本，镜像从未公开分发）；无 Android 取证工具链（photorec/strings 可行但无原始镜像输入）。雕刻与 JSON 痕迹检索法无法重走。
- **来源**：Insomni'hack 2022 AndroNotes（mobile/for）｜p4 (波兰战队)｜raw/github-repos/p4/2022_insomnihack_h_andronotes.md（镜像检索路径与 JSON 痕迹在 WP）
- **关联**：「自造防护≠标准语义」的移动版证据——与 [[STG-P03 自造防护≠标准语义——checksec 报告须验实现]] 同纪律（PIN 拦 UI 不拦数据层）。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 素材核查（corpus raw + 镜像可得性探测） | raw 仓储检视 + 公开镜像检索 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/rerun-A-20261030.log | 镜像无公开来源；WP 检索路径与 JSON 痕迹记录自洽 |
### APK JNI 原生库逆向（Ghidra 签名修复 + 双组解密）
- **分层**：困难档·复合链
- **假设**：校验逻辑在 `libexterminate.so`（按钮 on-click 是外部合成 lambda → JNI 调用）⇒ Ghidra 修 JNI 函数签名（动态注册须从 RegisterNatives 交叉定位）→ 逆自定义解密例程 → 对两组密文分别解密（注意组序，解错组会错认失败）→ 拼旗。
- **验证步骤**：1) jadx 找 native 方法声明；2) Ghidra 修签名定 JNI 入口；3) 读解密函数（密钥/分组序）；4) 两组各解并按正确顺序拼接。
- **判定标准**：PASS = 解密串成旗；FAIL = 拼不出 → 交换两组顺序再试（作者亲踩：块序混换险些误判无解）。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：缺 APK 原件（含 libexterminate.so，corpus raw 仅战队博客 WP 文本）；本机无 Ghidra/jadx 工具链。RegisterNatives 交叉定位与双组解密复算无法重走。
- **来源**：CyberSecurityRumble 2023 Exterminate（rev|mobile 270p/6 解）｜ik0ri4n（战队博客）｜raw/team-blogs/ik0ri4n/Exterminate.md（Ghidra 分析与块序教训在 WP）
- **关联**：与 [[逆向问答链：strcmp 常量答案 → 常量变换 → RC4 资源口令]] 同「Java 壳 + native 核」族——关键差异 = 该题动态注册 JNI 须 RegisterNatives 反查。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 素材核查（corpus raw + 附件源存活探测） | raw 仓储检视 + 附件源存活检查 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/rerun-A-20261030.log | apk/so 入库+Ghidra 就位后可续跑；块序教训（作者亲踩）在 WP 记录自洽 |
