---
verified: "未复跑（2026-10-16 新建，全部条目 hypothesis，等待首个回流）"
status: hypothesis
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "OWASP Mobile Top 10、Android CTF (picoCTF/ctf 平台 mobile 题) 公开题解、frida 官方文档"
changelog:
  - "[2026-10-16] v0.3 新建：移动安全题型 4 条（hypothesis 4），承接用户对 skill 覆盖移动安全的要求"
---

# 题型：移动安全（Mobile Security）

> 读取时机：附件是 APK/IPA/ipa/Android 备份/移动流量包，或题面提到安卓模拟器、frida、抓包绕过证书校验。APK 逆向逻辑题与 reverse 有重叠：**逻辑分析归 reverse（category-reverse.md），本文件管移动特有攻击面**。

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态；changelog 追加一行/次，不删除历史。
4. **失败样本优先回流**：refuted 条目必须附 FAIL 复跑记录、失败原因与"下一步转哪个新假设"。
5. verified/refuted/inconclusive 条目必须附复跑记录表（格式见 ../../shared/REFLIGHT.md §4）；未经复跑的条目状态只允许 hypothesis。
6. 工具具体用法归 ../../shared/tools/ 对应文件，此处不重复（去重原则）。
7. 本文件超过 100 行时，在本节下方补 TOC 目录。

## 条目区（TOC）

1. [APK 拆解与字符串级速查](#apk-拆解与字符串级速查)（hypothesis）
2. [本地存储与备份泄露](#本地存储与备份泄露)（hypothesis）
3. [Root/沙箱/调试 检测绕过](#root沙箱调试-检测绕过)（hypothesis）
4. [移动端流量与证书校验绕过](#移动端流量与证书校验绕过)（hypothesis）

### APK 拆解与字符串级速查
- **假设**：APK 题第一层先用"拆包 + 字符串速查"零成本排查，命中 flag/密钥/URL 的概率不低于 50%，未命中再进 smali/frida 深挖。
- **验证步骤**：
  ```bash
  unzip -o app.apk -d app_out
  strings -n 8 app_out/classes.dex | grep -iE 'flag|secret|apikey|http'
  # 未命中：apktool d app.apk → grep smali/；资源文件（assets/res/raw）逐个 file + strings
  ```
- **判定标准**：字符串命中 flag 或可解密密文 → PASS；未命中 → FAIL，转 reverse 逻辑分析或 2 号本地存储假设。
- **裁决词**：待复跑
- **来源**：Android CTF (ctf.hackthebox mobile 题) 通用解法；apktool 文档

### 本地存储与备份泄露
- **假设**：flag 藏在 app 本地数据：SharedPreferences XML、SQLite、内部文件、Android backup（.ab）——运行 app 一次后拉取比对，比纯静态更准。
- **验证步骤**：
  ```bash
  adb shell run-as <pkg> ls shared_prefs/    # debug 包直接看
  # ab 备份还原：java -jar abe.jar unpack backup.ab out.tar
  sqlite3 databases.db ".tables" && sqlite3 databases.db "select * from sqlite_master;"
  ```
- **判定标准**：本地数据中出现 flag/密文 → PASS；无 → FAIL 转 3 号检测绕过假设。
- **裁决词**：待复跑
- **来源**：OWASP MSTG-STORAGE 系列条款；Android CTF 题解

### Root/沙箱/调试 检测绕过
- **假设**：app 带反调试/Root 检测（isDebuggerConnected、/su 路径、frida-server 端口 27042 检测）→ 用 frida 注入 hook 检测函数返回值绕过，脚手架：<10 行脚本。
- **验证步骤**：
  ```js
  // frida -U -f <pkg> -l hook.js
  Java.perform(function(){
    var A=Java.use("com.example.Anti");
    A.checkRoot.implementation=function(){return false;};
  });
  ```
- **判定标准**：app 在绕过后进入原被拦截的功能分支（显示 flag 页/通过校验）→ PASS；仍有二级检测（Play Integrity/模拟器检测）→ FAIL 记录检测点清单。
- **裁决词**：待复跑
- **来源**：frida 官方文档、OWASP MASVS-RESILIENCE 条款

### 移动端流量与证书校验绕过
- **假设**：app 只在 HTTPS 流量里出现 flag/逻辑（服务端校验）→ 证书锁定（SSL pinning）是主要障碍，用 frida 绕 pinning + mitmproxy 透明代理抓包。
- **验证步骤**：
  ```bash
  # 1. 系统级：在模拟器装用户 CA 并改 trust store（Android 7+ 需 Magisk 模块或 adb remount）
  # 2. 应用级：frida 绕 pinning（okhttp CertificatePinner / X509TrustManager 置空）
  # 3. 抓包：mitmproxy --mode transparent，app 流量经代理后 grep flag
  ```
- **判定标准**：抓到含 flag/密钥的响应包 → PASS；pinning 绕过失败或流量加密 → FAIL（转 frida hook 加解密函数在内存中取明文）。
- **裁决词**：待复跑
- **来源**：OWASP MASVS-NETWORK；objection/frida-pin-bypass 公开脚本生态
