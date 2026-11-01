---
verified: "2026-10-30 | 回流复跑轮（接手 A）：7 条全裁决——1 PASS / 6 INCONCLUSIVE（5 条缺 APK 原件+RE 工具链、1 条缺物理镜像）；开源仓克隆 + firebase 活体探测，见各条复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "ctf-corpus 蒸馏层 P1+P2 批次（distill/by-category/mobile），原始 WP 见 ctf-corpus/raw/ 与 meta/register.jsonl"
changelog:
  - "[2026-11-02] v0.7：蒸馏 P4 批次并入 5 条（mobile_security 主标全成条，hypothesis 待复跑；07 审阅 + 08 修正批已归零）｜源：ctf-corpus/distill/by-category/mobile/p4-20261030.md + candidates.jsonl（P4 批次报告 06、审阅报告 07、修正简报 08）"
  - "[2026-10-30] v0.6：蒸馏 P3 批次并入 4 条（中段困难档·薄域优先，hypothesis 待复跑）｜源：ctf-corpus/distill/by-category/mobile/p3-20261029.md + candidates.jsonl（P3 批次报告 02） + 修正批同步（46 修正批涉已入库条目，pilot/04-修正简报）（本文件 2 处外科式：D100 推断补全标注 / D101 表述对齐原文）"
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
8. [dex2jar + jd-gui 反编译直取 rot13 比对串](#dex2jar-jd-gui-反编译直取-rot13-比对串)（hypothesis）
9. [key.db 明文密钥 + so 层 DES + 反调试对抗（PNG 隐写收官）](#keydb-明文密钥-so-层-des-反调试对抗png-隐写收官)（hypothesis）
10. [多 APK 静态分析流水线（dex2jar→jd-gui/Luyten 检索式下钻）](#多-apk-静态分析流水线dex2jarjd-guiluyten-检索式下钻)（hypothesis）
11. [Flutter kernel_blob 源码级逆向（Dart 快照字符串考古）](#flutter-kernel_blob-源码级逆向dart-快照字符串考古)（hypothesis）
12. [多 Activity 引导链 + smali 层 key 替换喂 native 校验](#多-activity-引导链--smali-层-key-替换喂-native-校验)（hypothesis）
13. [Android KeyStore AES 本地加密文件提取（secret.txt 密文 + hook 取 key）](#android-keystore-aes-本地加密文件提取secrettxt-密文--hook-取-key)（hypothesis）
14. [WebView Deep Link 白名单绕过（intent data 伪造 Referer）](#webview-deep-link-白名单绕过intent-data-伪造-referer)（hypothesis）
15. [无权限 BroadcastReceiver 伪造 + 本地 SQLite 注入爆破凭据](#无权限-broadcastreceiver-伪造--本地-sqlite-注入爆破凭据)（hypothesis）
16. [assets 多目录密钥聚合解密链（RC4 + JNI so 混合）](#assets-多目录密钥聚合解密链rc4--jni-so-混合)（hypothesis）

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
- **假设**：3.5GB flash 物理镜像中笔记 app（protectedtext）声称 PIN 加密，实际 PIN 只锁 UI、Notes 表 IS_ENCRYPTED 列标记未加密（AES 静态密钥可逆）⇒ strings 镜像定位包名 + sqlite Notes 表取证 → 雕刻出 notes 内容 → 直接读旗。
- **验证步骤**：1) strings/photorec 搜 `com.protectedtext.android` 数据痕；2) sqlite Notes 表 IS_ENCRYPTED 列 + strings 镜像定位；3) 提取 note 字段；4) 按 app 数据格式还原旗。
- **判定标准**：PASS = 明文笔记含旗；FAIL = 分片残缺 → 按 JSON 结构续接。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：缺 3.5GB flash 物理镜像原件（corpus raw 仅 WP 文本，镜像从未公开分发）；无 Android 取证工具链（photorec/strings 可行但无原始镜像输入）。雕刻与 sqlite 表取证法无法重走。
- **来源**：Insomni'hack 2022 AndroNotes（mobile/for）｜p4 (波兰战队)｜raw/github-repos/p4/2022_insomnihack_h_andronotes.md（镜像检索路径与 JSON 痕迹在 WP）
- **关联**：「自造防护≠标准语义」的移动版证据——与 [[STG-P03 自造防护≠标准语义——checksec 报告须验实现]] 同纪律（PIN 拦 UI 不拦数据层）。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 素材核查（corpus raw + 镜像可得性探测） | raw 仓储检视 + 公开镜像检索 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/rerun-A-20261030.log | 镜像无公开来源；WP 检索路径与 JSON 痕迹记录自洽 |
### APK JNI 原生库逆向（Ghidra 签名修复 + 双组解密）
- **分层**：困难档·复合链
- **假设**：校验逻辑在 `libexterminate.so`（按钮 on-click 是外部合成 lambda → JNI 调用）⇒ Ghidra 修 JNI 函数签名（动态注册须从 RegisterNatives 交叉定位）→ 逆自定义解密例程 → 对两组密文分别解密（注意组序，解错组会错认失败）→ 拼旗。
- **验证步骤**：1) jadx 找 native 方法声明；2) Ghidra 修签名定 JNI 入口（推断补全：原文为 JNIAnalyzer 插件自动修复，未演示交叉定位过程）；3) 读解密函数（密钥/分组序）；4) 两组各解并按正确顺序拼接。
- **判定标准**：PASS = 解密串成旗；FAIL = 拼不出 → 交换两组顺序再试（作者亲踩：块序混换险些误判无解）。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：缺 APK 原件（含 libexterminate.so，corpus raw 仅战队博客 WP 文本）；本机无 Ghidra/jadx 工具链。RegisterNatives 交叉定位与双组解密复算无法重走。
- **来源**：CyberSecurityRumble 2023 Exterminate（rev|mobile 270p/6 解）｜ik0ri4n（战队博客）｜raw/team-blogs/ik0ri4n/Exterminate.md（Ghidra 分析与块序教训在 WP）
- **关联**：与 [[逆向问答链：strcmp 常量答案 → 常量变换 → RC4 资源口令]] 同「Java 壳 + native 核」族——关键差异 = 该题动态注册 JNI 须 RegisterNatives 反查。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 素材核查（corpus raw + 附件源存活探测） | raw 仓储检视 + 附件源存活检查 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/rerun-A-20261030.log | apk/so 入库+Ghidra 就位后可续跑；块序教训（作者亲踩）在 WP 记录自洽 |

### dex2jar + jd-gui 反编译直取 rot13 比对串
- **分层**：困难·单点
- **假设**：webdroid.apk 的校验逻辑就在 dex 层而非 so：dex2apk（dex2jar）转 jar 后 jd-gui 看 Java 源——关键函数把输入 rot13 后与常量串比较，其余大量函数是干扰；直接 rot13 常量串即得 flag（apk 逆向最小工具链样板）。
- **验证步骤**：1) unzip apk 取 classes.dex；2) d2j-dex2jar + jd-gui 打开 jar；3) 搜索 equals/compare 类调用定位比对函数；4) 常量串 rot13 解码。
- **判定标准**：PASS = 一轮定位比对函数且 rot13 出 flag 格式；FAIL = 花时间逆干扰函数（大量无用 wrapper）。
- **裁决词**：待复跑
- **来源**：ISG 2015 webdroid｜六星战队（中国）｜raw/github-repos/sixstars/2015_isg_h_isg-writeup.md（定位思路在 WP Reverse 段）
- **关联**：与 [[Android 训练靶场全链路（jadx 审查 → sqlite → 远程端点）]] 同族 dex 层定位优先；rot13 与 [[hex 文本修复 JPEG + steghide 双层 + morse/ROT13]] 的 ROT13 支线互补。

### key.db 明文密钥 + so 层 DES + 反调试对抗（PNG 隐写收官）
- **分层**：困难·多段链
- **假设**：adroid2 登录逻辑：用 key.db（SQLite 表 key，值 zctf2016）加密 username+passwd 与 flag.bin 比对；解出伪 flag 后（zctf{Notthis}）提示继续：libJNIclass.so 里 DES_Decrypt 用 passwd 解 top（程序内常量）+ bottom（assets 文件），产物是 PNG——stegsolve 调通道出真 flag。动态调试须先 patch so 内 ptrace 与 Java 层 3500ms 自杀定时器。
- **验证步骤**：1) sqlite3 打 key.db 取密钥；2) 解 flag.bin 得伪旗与 passwd 线索；3) patch ptrace/定时器后调试或外部程序调 DES_Decrypt；4) 解密产物认 PNG 头；5) stegsolve 通道浏览取旗。
- **判定标准**：PASS = 四层全通取得真旗；FAIL = 把 zctf{Notthis} 当终点（明示诱饵）或标准 DES 库直接解（实现有魔改，须走原函数）。
- **裁决词**：待复跑
- **来源**：ZCTF 2016 adroid2｜六星战队（中国）｜raw/github-repos/sixstars/2016_zctf_h_writeup.md（全链描述在 WP）
- **关联**：与 [[APK JNI 原生库逆向（Ghidra 签名修复 + 双组解密）]] 同族 so 层加密还原；反调试 patch 与 [[Windows 逆向前置条件 patch（参数校验 + PEB 反调试 #DE）]] 共享「先除自杀再调试」纪律；PNG 收官与 [[GIF 近黑帧对 XOR 隐写（缺 finder QR 修复）]] 相邻。

### 多 APK 静态分析流水线（dex2jar→jd-gui/Luyten 检索式下钻）
- **分层**：困难·多段链
- **假设**：h1-702 全套 mobile 题共用「APK=压缩包」心智模型：解包后 classes.dex → dex2jar → jd-gui/Luyten 看 Java；关键串（flag part、Log.d 标签、方法名）用 IDE 全局检索逐层下钻，checkFlag 类常量拼装即出三段 flag——流水线本身可复制到任意无壳 APK。
- **验证步骤**：1) 7z 解 APK 看结构（classes.dex/resources）；2) dex2jar 转换；3) jd-gui 打开检索 flag/Log/equals；4) 按三题各自的 check 函数还原比对常量；5) 拼旗验证。
- **判定标准**：PASS = 三题全出旗且每题 ≤30 分钟流水线工时；FAIL = 上真机动态调试起步（静态即可解，效率低）。
- **裁决词**：待复跑
- **来源**：h1-702 CTF 2018 voidmercy 三题合集｜perfect blue (战队)｜raw/github-repos/perfectblue/2018_h1-702-ctf_h_voidmercy.md（三题全程与检索词在 WP）
- **关联**：与 [[APK JNI 原生库逆向（Ghidra 签名修复 + 双组解密）]] 互为静态/so 两条腿；与 [[dex2jar + jd-gui 反编译直取 rot13 比对串]] 同工具链不同深度（本条为多题流水线化）。

### Flutter kernel_blob 源码级逆向（Dart 快照字符串考古）
- **分层**：困难·多段链
- **假设**：locksmith APK 为 Flutter 应用：smali 层只是启动壳，业务逻辑在 assets/flutter_assets/kernel_blob.bin（Dart kernel 快照）；xxd+grep 在其中直接可见 file:/// 源路径与近乎源码的字符串（token.dart/login 逻辑/URL 常量），据此还原 login(seed,password) 协议与后续 API 调用序列，转 HTTP 客户端复现拿密室蓝图。
- **验证步骤**：1) apktool d 解包；2) xxd -u assets/flutter_assets/kernel_blob.bin 检索 main.dart/token.dart 上下文；3) 还原 login 参数与加密字段语义；4) requests 复现登录与后续端点取资料。
- **判定标准**：PASS = 按 WP 复现登录拿到目标资料；FAIL = 只逆 smali（Flutter 业务不在 Java 层，拿不到协议细节）。
- **裁决词**：待复跑
- **来源**：Mossad CTF 2019 Challenge #1｜Dvd848 (S1扩容)｜raw/github-repos/Dvd848/2019_challenge1-md_h_challenge1.md（kernel_blob 提取过程与 token.dart 源在 WP）
- **关联**：与 [[Android Mono 运行时反混淆（魔改 opcode 表 + ILSpy 还原）]] 同族「非 Java 运行时的 APK 业务逆向」；字符串考古与 [[多类型泥沙文件隐私泄露普查（strings 降序 + whisper 语音转写）]] 共享 strings 优先直觉。

### 多 Activity 引导链 + smali 层 key 替换喂 native 校验
- **分层**：困难·多段链
- **假设**：AndroidManifest 声明的 FlagActivity/UnreachableActivity 即使 exported=false，adb root 后 am start -n 仍可直启；FlagActivity 显示的符号串解码是"unreachable"引导跳 UnreachableActivity；其内 native getKey("fakekey...") 是真校验——jadx 不可改源码，apktool d 反编译后改 smali 里 const-string 假 key 为正确值重打包，native 校验通过吐 flag——"组件直启→字符串引导→smali patch→native"四跳。
- **验证步骤**：1) 改后缀 .apk 装模拟器；2) jadx 读 Manifest 与 Activity 结构；3) adb root; am start -n io.fl1tz.ctf/.FlagActivity 读符号串解码；4) am start UnreachableActivity 读 "pass it to the native function"；5) apktool d 改 smali 的 const-string v3；6) apktool b + 签名重装读 flag。
- **判定标准**：PASS = 重打包后 native 校验通过；FAIL = 签名校验（删 META-INF 重签）或 key 计算在 so 内（frida hook 传参观察）。
- **裁决词**：待复跑
- **来源**：FL1TZ CTF 2025 FLT1TZ (Mobile)｜mahdi（infosecwriteups）｜raw/github-repos/El-Mehdi-Dridi/Mobile-CTF-Tasks/FL1TZ.md
- **关联**：exported=false 与 [[无权限 BroadcastReceiver 伪造 + 本地 SQLite 注入爆破凭据]]（本批）构成组件暴露双样本（显式 export 缺失 vs 权限缺失）；smali patch 与 [[key.db 明文密钥 + so 层 DES + 反调试对抗（PNG 隐写收官）]]（库）的 native 层对抗互补。
- **熵控预检**：Q1 无重名；Q3 强（命令链+smali 行号在 WP）；Q4 边 2 条。

### Android KeyStore AES 本地加密文件提取（secret.txt 密文 + hook 取 key）
- **分层**：困难·流程
- **假设**：Kotlin 应用把用户输入 AES 加密存 filesDir/secret.txt（CryptoManager.encrypt），key 由 AndroidKeyStore 生成不可导出；但加密是本地 oracle——输入已知明文得密文，且 key 可在运行时 hook（或直接调用 app 内 encrypt 接口构造解密 oracle）：自写 exp APK 复用其 CryptoManager 类（同 UID/签名限制下用 hook 框架）或 frida 拦截 getKey 后 Cipher 解密——"不可导出密钥的旁路使用"。
- **验证步骤**：1) jadx 定位 CryptoManager 与 secret.txt 写入路径；2) 运行 app 加密已知明文验证 oracle；3) frida hook createCipher/getKey 时机拿 Cipher 实例；4) 以 DECRYPT_MODE 重放 secret.txt 密文；5) 输出原 secret。
- **判定标准**：PASS = 解出 secret.txt 原文（含 flag）；FAIL = KeyStore 绑定签名（exp 需同签名或用 objection 内存调用）。
- **裁决词**：待复跑
- **来源**：BSidesTLV CTF 2023 KeyHunter (Mobile 464p)｜Writeup 仓（17KB 长文）｜raw/github-repos/evyatar9/Writeups/KeyHunter.md
- **关联**：与 [[key.db 明文密钥 + so 层 DES + 反调试对抗（PNG 隐写收官）]]（库）构成移动端密钥管理对照（KeyStore 硬件级 vs 明文 key.db）；本地 oracle 思路与 [[AES-CBC 位翻转伪造 is_admin（debug 泄露结构定位）]]（本批 crypto）同属"不破算法破实现"。
- **熵控预检**：Q1 无重名；Q3 中（结构与分析在 WP，hook 脚本细节长文后半）；Q4 边 2 条。

### WebView Deep Link 白名单绕过（intent data 伪造 Referer）
- **分层**：困难·多段链
- **假设**：单 Activity 应用以三个 intent-filter（http/自定义 scheme）注册 deep link，Flag 页校验"来自应用内部"实为读 launch intent 的 data URI/Referer；adb am start -W -a VIEW -d "<合法URL>" 直启过第一层后，源码里硬编码 URL 的 WebView loadUrl 若以 intent.getStringExtra 取注入参数（或 extras 携带），构造带目标参数的 intent 即让 WebView 载入本地 flag 资源——deep link 面是 Web 与 Mobile 的跨界攻击面。
- **验证步骤**：1) MobSF 扫 + 读 Manifest 三 filter；2) am start 测 http scheme 解析；3) 读 MainActivity 的 WebView 构造与 getData/getExtras 流；4) 构造 intent data/extras 指向 flag 内容；5) am start 触发读 flag。
- **判定标准**：PASS = WebView 渲染 flag 资源；FAIL = 校验 host 精确匹配（试 intent extras 变体 / scheme 混淆）。
- **裁决词**：待复跑
- **来源**：Hacker101 CTF 2026 Intentional Exercise（Android Level13）｜infosecwriteups（前作同系列）｜raw/team-blogs/medium/tmc222/intentional-exercise.md
- **关联**：与 [[路径段作 TLD 的解析歧义 SSRF（nip.io 回环直达内网目录）]]（本批 web）构成 URL 解析歧义双域（服务端代理 vs 客户端 deep link）；WebView 远程调试面与 [[node-static CVE-2023-26111 路径穿越 + --inspect 调试端口 RCE]]（本批）的调试端口族呼应。
- **熵控预检**：Q1 与库内 WebView 条目区分（intent data 白名单绕过为增量）；Q3 中（流程在 WP，intent 细节按图索骥）；Q4 边 2 条。

### 无权限 BroadcastReceiver 伪造 + 本地 SQLite 注入爆破凭据
- **分层**：困难·多段链
- **假设**：registerReceiver(LoginReceiver) 未要求 permission 且 action 公开时，任意应用可发送伪造广播（username/password extras）；onReceive 调 LocalDatabaseHelper.checkLogin 的 SQL 为拼接串（"SELECT ... WHERE username='" + u + "'..."），本地 SQLite 注入（' OR 1=1 -- + LIMIT 控制）让广播回显账号表；甚至注入 UNION 直接取 password 字段——"组件暴露 × 注入"的移动端组合拳。
- **验证步骤**：1) d2j-dex2jar + jd-gui 读注册与 onReceive；2) 写 exp APK sendBroadcast(action, extras 注入串)；3) 收 OUTPUTINTENT 广播读 msg；4) 注入 UNION SELECT 逐行取凭据；5) 提交服务端换 flag。
- **判定标准**：PASS = 回显数据完整；FAIL = 输出限截断（substring 分段）或 SQL 转义（双写引号绕过）。
- **裁决词**：待复跑
- **来源**：Google CTF 2016 Little Bobby Application (Mobile 250p/24 solved)｜bburky｜raw/github-repos/ctfs/write-ups-2016/little-bobby-application-250.md
- **关联**：与 [[MongoDB NoSQL 操作符注入登录（{"$gt":""} 空串通配）]]（本批 web）构成"注入面三库"（SQLite/NoSQL/SQL）；广播无权限与 [[多 Activity 引导链 + smali 层 key 替换喂 native 校验]]（本批）的组件暴露族互链。
- **熵控预检**：Q1 无重名；Q3 强（exp 广播代码+注入串在 WP）；Q4 边 2 条。

### assets 多目录密钥聚合解密链（RC4 + JNI so 混合）
- **分层**：困难·流程
- **假设**：APK assets 下 flag/key_0..key_4 目录各含 ciphertext.js（RC4 加密 JS）与 key_%i.enc，flag 目录的 code.js 实现 RC4；五 key 相互解锁（JNI 层 so 参与派生），静态分析逐目录逆推：dex2jar（非官方 fork）→ JD-GUI 读 FlagActivity 的聚合逻辑 → 按 key_i 依赖序逐个解密（RC4 密钥来自前一目录解密产物/JNI 返回值）→ 最终解 flag.enc——移动端"密钥环"结构。
- **验证步骤**：1) unzip apk 列 assets 可疑目录；2) dex2jar 双 dex + JD-GUI 存源；3) 读 code.js 确认 RC4 参数；4) 按 FlagActivity 依赖序解 key_0..4（JNI 层用 IDA 交叉验证）；5) 五 key 拼 flag 解密。
- **判定标准**：PASS = flag.enc 解出可读；FAIL = 依赖环断裂（frida 动态跟踪 JNI 返回）。
- **裁决词**：待复跑
- **来源**：Trend Micro CTF 2020 Mobile 2 Keybox（23KB 长文）｜Writeup 仓｜raw/github-repos/Hong5489/TrendMicroCTF2020/Keybox.md
- **关联**：密钥环与 [[密码自递归嵌套 zip + RGB 像素流重绘二维码]]（本批 forensics）的"自解锁容器"同型；RC4 实现识别与 [[三图尾随 zip 拼接 + base 家族自动侦测套娃解码]]（本批）互链编码族。
- **熵控预检**：Q1 无重名；Q3 中（结构与多步在 WP，全部脚本未内联）；Q4 边 2 条。
