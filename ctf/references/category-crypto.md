---
verified: "2026-10-15 | 本地复跑：Python 3.12.13 + pycryptodome 3.23.0 + OpenSSL 3.5.6（Linux 容器），见条目1/3复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "CTF-wiki（crypto 章节）、PayloadsAllTheThings（RSA）、M2 实测复跑（2026-10-15）"
changelog:
  - "[2026-11-02] v0.7：蒸馏 P4 批次并入 9 条（cryptography 主标 + 隐写批次路由 1（partial key exposure），hypothesis 待复跑；07 审阅 + 08 修正批已归零）｜源：ctf-corpus/distill/by-category/crypto/p4-20261030.md + candidates.jsonl（P4 批次报告 06、审阅报告 07、修正简报 08）"
  - "[2026-10-30] v0.6：蒸馏 P3 批次并入 8 条（中段困难档·薄域优先，hypothesis 待复跑）｜源：ctf-corpus/distill/by-category/crypto/p3-20261029.md + candidates.jsonl（P3 批次报告 02） + 修正批同步（46 修正批涉已入库条目，pilot/04-修正简报）（本文件 2 处）"
  - "[2026-10-29] v0.5：蒸馏 P1+P2 批次并入 29 条（hypothesis 待复跑，REFLIGHT §1 二手知识纪律）｜源：ctf-corpus/distill 候选池（candidates.jsonl）+ distill/pilot/01-蒸馏批次报告-P2-20261029.md"
  - "[2026-10-15] 初始空壳，等待首个回流条目"
  - "[2026-10-15] v0.2：条目模板升级为五段式假设条目 + 机器可校验裁决词（REFLIGHT 回流协议，见 ../../shared/REFLIGHT.md）"
  - "[2026-10-15] v0.3：M2 填充 4 条（verified 1 / refuted 1 / hypothesis 2）；条目3为 REFLIGHT 失败样本优先回流的首条 refuted 实例"
---

# 题型：Crypto

> 读取时机：密文串、RSA/AES/椭圆曲线参数、编码套娃、随机数弱点条目主库

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态：verified=最近一次复现日期+环境；source=条目主要出处；changelog 追加一行/次，不删除历史。
4. **失败样本优先回流**：refuted 条目必须附 FAIL 复跑记录、失败原因与"下一步转哪个新假设"，失败样本优先级高于成功经验。
5. verified/refuted/inconclusive 条目必须附复跑记录表（格式见 ../../shared/REFLIGHT.md §4）；未经复跑的条目状态只允许 hypothesis。
6. 工具具体用法归 ../../shared/tools/ 对应文件，此处不重复（去重原则）；五段式的「验证步骤」只保留最小可执行命令骨架。
7. 本文件超过 100 行时，在本节下方补 TOC 目录。

## 条目区（TOC）

1. [RSA 共模攻击（Håstad）](#rsa-共模攻击håstad)（verified，REFLIGHT 全链路演示条目）
2. [openssl padding 模式错配静默返回伪随机](#openssl-padding-模式错配静默返回伪随机)（refuted）
3. [RSA 小明文攻击（e=3 无填充）](#rsa-小明文攻击e3-无填充)（hypothesis）
4. [AES-ECB 块特征与逐字节爆破](#aes-ecb-块特征与逐字节爆破)（hypothesis）
5. [RSA LSB 甲骨文二分恢复明文](#rsa-lsb-甲骨文二分恢复明文)（hypothesis）
6. [RSA 偶数模数退化（p=2 直接解密）](#rsa-偶数模数退化p2-直接解密)（hypothesis）
7. [RSA 私钥加密·多公钥盲试解密](#rsa-私钥加密多公钥盲试解密)（hypothesis）
8. [取模映射解码（mod 37 查表 / mod 41 逆元双分支）](#取模映射解码mod-37-查表-mod-41-逆元双分支)（hypothesis）
9. [块内换位还原（3 字符循环移位）](#块内换位还原3-字符循环移位)（hypothesis）
10. [替换密码·旗即密钥（密钥表重建）](#替换密码旗即密钥密钥表重建)（hypothesis）
11. [补条建议：RSA 小明文攻击（e=3 无填充）——任意小 e 整数根分支](#补条建议rsa-小明文攻击e3-无填充任意小-e-整数根分支)（hypothesis）
12. [RSA 最低有效字节甲骨文（LSB×8 预算约束）](#rsa-最低有效字节甲骨文lsb8-预算约束)（hypothesis）
13. [「后量子」外观先代数化简（Ring-LWE 伪装拆穿）](#后量子外观先代数化简ring-lwe-伪装拆穿)（hypothesis）
14. [AES-CTR 常量 counter keystream 生日碰撞差分](#aes-ctr-常量-counter-keystream-生日碰撞差分)（hypothesis）
15. [小素数域线性反馈·已知明文恢复](#小素数域线性反馈已知明文恢复)（hypothesis）
16. [ZK 电路缺位长检查（Groth16 非预期整数表示）](#zk-电路缺位长检查groth16-非预期整数表示)（hypothesis）
17. [Merkle 登录系统伪树证明（注册矮树 / 登录深树）](#merkle-登录系统伪树证明注册矮树-登录深树)（hypothesis）
18. [CBC 填充预言机解密（逐字节差分）](#cbc-填充预言机解密逐字节差分)（hypothesis）
19. [RSA 密钥再生素数复用（(e0,d0) 泄漏恢复 p/q）](#rsa-密钥再生素数复用e0d0-泄漏恢复-pq)（hypothesis）
20. [Merkle-Damgård 长度扩展攻击（hashpumpy 伪造 token）](#merkle-damgård-长度扩展攻击hashpumpy-伪造-token)（hypothesis）
21. [魔改 AES 常量指纹识别（表全换场景裸写实现）](#魔改-aes-常量指纹识别表全换场景裸写实现)（hypothesis）
22. [AES-CBC 位翻转伪造明文（空格填充 + 回显）](#aes-cbc-位翻转伪造明文空格填充-回显)（hypothesis）
23. [近似素数构造 RSA（q = a·p + ε 的 Coppersmith 分解）](#近似素数构造-rsaq-ap-ε-的-coppersmith-分解)（hypothesis）
24. [已知文件结构先验恢复自定义比特密码（PNG 锚定）](#已知文件结构先验恢复自定义比特密码png-锚定)（hypothesis）
25. [多环 XOR 加密字典恢复（crib 拖拽）](#多环-xor-加密字典恢复crib-拖拽)（hypothesis）
26. [RSA 大 e 小 d（Wiener 连分数攻击）](#rsa-大-e-小-dwiener-连分数攻击)（hypothesis）
27. [时间轮转密钥全轮收集（互素步长扫表）](#时间轮转密钥全轮收集互素步长扫表)（hypothesis）
28. [AVX2 轮函数对称逆推（无密钥加密器）](#avx2-轮函数对称逆推无密钥加密器)（hypothesis）
29. [未知小 e 枚举 + 模逆还原（签名方向 RSA）](#未知小-e-枚举-模逆还原签名方向-rsa)（hypothesis）
30. [Double DES 中间相遇（6 位数字键空间）](#double-des-中间相遇6-位数字键空间)（hypothesis）
31. [密钥长度侧信道 + Vigenère 解码（LEN(KEY) oracle）](#密钥长度侧信道-vigenère-解码lenkey-oracle)（hypothesis）
32. [Hill 矩阵加密的三段攻破（差分恢复 / 核空间失效 / CVP 可打印化）](#hill-矩阵加密的三段攻破差分恢复-核空间失效-cvp-可打印化)（hypothesis）
33. [Shamir 秘密分享的「一次多项式复用」崩溃（逐字符独立爆破）](#shamir-秘密分享的一次多项式复用崩溃逐字符独立爆破)（hypothesis）
34. [已知 padding 的 RSA related-message 消元（e=3 三密文线性化）](#已知-padding-的-rsa-related-message-消元e3-三密文线性化)（hypothesis）
35. [dq 泄漏分解 RSA 模数（部分涂抹私钥恢复）](#dq-泄漏分解-rsa-模数部分涂抹私钥恢复)（hypothesis）
36. [重复密钥 XOR 的空格频率攻击（互移位重合计数定键长）](#重复密钥-xor-的空格频率攻击互移位重合计数定键长)（hypothesis）
37. [RSA 解密权游戏数论陷阱（d=1 与 c^{-1} 旁路）](#rsa-解密权游戏数论陷阱d1-与-c-1-旁路)（hypothesis）
38. [DOS/Win16 载体内嵌异或密钥（中断向量表作 key）](#doswin16-载体内嵌异或密钥中断向量表作-key)（hypothesis）
39. [PKI 中间 CA 证书链伪造（mTLS 客户端认证旁路）](#pki-中间-ca-证书链伪造mtls-客户端认证旁路)（hypothesis）
40. [硬件指纹口令逆向（盘符序列+MAC+BIOS SN 拼装）](#硬件指纹口令逆向盘符序列macbios-sn-拼装)（hypothesis）
41. [游戏源码 diff 钓鱼后门（定种子 RNG + RC2 解密）](#游戏源码-diff-钓鱼后门定种子-rng-rc2-解密)（hypothesis）
42. [模 2^64 次幂开方链（Tonelli-Shanks + 单位根幂枚举收敛）](#模-264-次幂开方链tonelli-shanks--单位根幂枚举收敛)（hypothesis）
43. [模逆求解 + 加 p 平移枚举还原 ASCII（divm 短除陷阱）](#模逆求解--加-p-平移枚举还原-asciidivm-短除陷阱)（hypothesis）
44. [SHA1 选择性碰撞工程应用（sha1collider 构造同哈希异内容双 QR）](#sha1-选择性碰撞工程应用sha1collider-构造同哈希异内容双-qr)（hypothesis）
45. [AES-CBC 位翻转伪造 is_admin（debug 泄露结构定位）](#aes-cbc-位翻转伪造-is_admindebug-泄露结构定位)（hypothesis）
46. [截屏取证逆向 + glibc rand 种子重放（栈溢出控种子）](#截屏取证逆向--glibc-rand-种子重放栈溢出控种子)（hypothesis）
47. [RSA 密文数字置换混淆（10! 枚举逆置换）](#rsa-密文数字置换混淆10-枚举逆置换)（hypothesis）
48. [动态步长 XOR 的最低位恢复攻击（奇偶驱动自同步）](#动态步长-xor-的最低位恢复攻击奇偶驱动自同步)（hypothesis）
49. [RSA 故障签名挖掘 + 部分 d 低位恢复（n/4 LSB 定理）](#rsa-故障签名挖掘--部分-d-低位恢复n4-lsb-定理)（hypothesis）
50. [四字符分组独立哈希的逐组爆破（弱结构分治）](#四字符分组独立哈希的逐组爆破弱结构分治)（hypothesis）

### RSA 共模攻击（Håstad）
- **假设**：同一明文 m 用同一模数 n、两个互质指数 e1/e2 加密（c1=m^e1 mod n, c2=m^e2 mod n）→ 由扩展欧里得找 a,b 使 a·e1+b·e2=1，则 m = c1^a · c2^b mod n，无需分解 n。
- **验证步骤**：
  ```python
  # egcd(e1,e2) 得 (g,a,b)；a<0 时 c1 替换为 pow(c1,-1,n)（模逆元）
  m = pow(c1,a,n)*pow(c2,b,n) % n ; long_to_bytes(m)
  ```
  本机实测（2026-10-15，n=2×512bit 质数，e1=3/e2=5，明文 `flag{c0mm0n_m0du1u5_p4ss}`）：完整恢复明文，逐字节一致。
- **判定标准**：PASS = long_to_bytes(m) 输出可读明文/flag 格式；FAIL = gcd(e1,e2)≠1（此路不通，转公共素数因子或 Wiener）。
- **裁决词**：PASS
- **来源**：M2 实测复跑（evidence T1）；CTF-wiki RSA 共模攻击；R. Håstad 1988 原始论文思路
- **升级**：PASS 拿 flag 收尾；题目给同一 n 多组密文时先 gcd(n_i, n_j) 查公共素数。
- **关键差异**：模型盲区——负指数要转模逆元而不是报错放弃；"两个密文同 n 不同 e"的信号藏在题目给的两组参数里，先比对 n 是否相同再谈分解。

### 复跑记录（verified / refuted / inconclusive 必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 本地 Python 3.12.13 + pycryptodome 3.23.0 | egcd + pow(c1,a,n)*pow(c2,b,n)%n | PASS | evidence/T1-commonmodulus | 输出=flag{c0mm0n_m0du1u5_p4ss}，与原明文一致 |

### openssl padding 模式错配静默返回伪随机
- **假设**：❝openssl pkeyutl -decrypt 默认参数可以解出任何 padding 模式的 RSA 密文；padding 不匹配时会报错提示❞ —— 该假设被证伪。
- **验证步骤**：用 pycryptodome 无 padding 原始模式生成密文（`pow(m,e,n)` 定长字节），`openssl pkeyutl -decrypt -inkey priv.pem -in c_raw.bin` 默认参数解密；对照组显式加 `-pkeyopt rsa_padding_mode:none`。
- **判定标准**：PASS = 默认参数解出原明文或明确报错；FAIL = 默认参数 **exit 0 且输出伪随机字节**（≠明文），仅显式 no-padding 对照组解出正确明文。
- **裁决词**：FAIL
- **来源**：M2 实测复跑（evidence T2，OpenSSL 3.5.6）；OpenSSL 3.2+ RSA PKCS#1 v1.5 隐式拒绝（implicit rejection）机制——padding 校验失败返回伪随机而非报错（防 Bleichenbacher oracle），疑似即本现象成因
- **下一步转哪个新假设**：openssl 解密"成功"但输出乱码且无报错时 → 新假设 = padding 模式错配/隐式拒绝；逐个显式尝试 `rsa_padding_mode:none|pkcs1|oaep` 并核对输出长度与可读性。
- **关键差异**：exit 0 + 伪随机输出的"静默失败"极具欺骗性——工具不报错 ≠ 解密正确；判定必须核对输出内容而非退出码。

### 复跑记录（verified / refuted / inconclusive 必备，append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 本地 OpenSSL 3.5.6 + pycryptodome 1024bit RSA | `openssl pkeyutl -decrypt -inkey priv.pem -in c_raw.bin` | FAIL | evidence/T2-padding | 默认 padding：exit=0，stdout 9 字节伪随机 `06671e9d8f1a...`；显式 no-padding 对照组正确解出 |

### RSA 小明文攻击（e=3 无填充）
- **假设**：e 很小（3）、明文短、无 padding（textbook RSA）且 m^e < n → c=m^e 为精确整数，直接整数开 e 次方（不走模运算）即得 m；多接收方同 e 加密同一 m 则升级为 Håstad 广播攻击（CRT 合并后开方）。
- **验证步骤**：1) 检查 c 的 e 次方根是否整数（Python `gmpy2.iroot(c,3)` 或手写二分开方）；2) `long_to_bytes(root)` 看可读性。
- **判定标准**：PASS = 开方精确整数且 long_to_bytes 输出可读明文；FAIL = 不整除（padding 存在或明文过长，转 Coppersmith）。
- **裁决词**：待复跑
- **来源**：CTF-wiki RSA 小明文攻击；PayloadsAllTheThings RSA
- （可选）**升级**：m^e 略超 n 时按 k·n 枚举后开方（k < e）。

### AES-ECB 块特征与逐字节爆破
- **假设**：密文长度为 16 字节整数倍且相同明文块对应相同密文块（ECB 特征）→ 可用"逐字节喂入+对比首块密文"爆破出加密 oracle 后的明文（经典 ECB byte-at-a-time），或对已知结构密文做块重排攻击。
- **验证步骤**：1) 统计密文长度 %16 与重复块（`collections.Counter` 按 16 字节切片）；2) oracle 可控前缀时逐位补齐爆破；3) 重排攻击先画出块边界图。
- **判定标准**：PASS = 爆破恢复出完整明文/flag；FAIL = 相同明文块密文不同（ CBC/CTR，转 IV 重用或 nonce 分析）。
- **裁决词**：待复跑
- **来源**：CTF-wiki 分组密码；Cryptopals Set 2（ECB 检测与爆破经典题源）
- （可选）**关键差异**：模型盲区——先看块重复特征再选攻击路径，别一上来就爆破；块重排攻击需要明文块边界图，画图比猜快。

### RSA LSB 甲骨文二分恢复明文
- **分层**：简单档·可复现强
- **假设**：解密 oracle 只回明文最低位（奇偶）时，把密文乘 `pow(2,e,n)` 即等价于明文倍乘（ct' 解密得 2m mod n）；n 为两素数积必为奇数，故 2m mod n 为偶 ⇒ m < n/2，为奇 ⇒ m > n/2 → 每次查询二分一次区间，log2(n) 次收敛出 m。
- **验证步骤**：1) 取旗密文 c；2) 构造 ct' = c·pow(2,e,n) mod n 送 oracle；3) 回显 LSB=0 → 区间取下半、=1 → 取上半；4) 迭代至区间宽度 <1；5) `long_to_bytes(m)` 验可读。
- **判定标准**：PASS = 收敛唯一整数且解码出可读旗；FAIL = oracle 对倍乘不响应/回显恒定（转字节 oracle）。
- **裁决词**：待复跑
- **来源**：SharifCTF 7 2016 LSB Oracle（crypto 150p）｜p4｜raw/github-repos/p4/2016_sharifctf7_e_lsb.md（n/e/c 与 oracle 交互全记录于 WP，oracle 可本地模拟 → 本机可复跑）
- **升级**：查询预算不足 log2(n) 时（如限 150 次）转 [[RSA 最低有效字节甲骨文（LSB×8 预算约束）]]

### RSA 偶数模数退化（p=2 直接解密）
- **分层**：简单档·可复现强
- **假设**：模数 N 为偶数 ⇒ 必含素因子 2（p=2），N=2q，φ(N)=q-1，e 可逆即得私钥 → 整题退化为一行 pow；「每次请求重新生成」的服务题先比对多轮 N（题面 hint 常指向「别信任随机性」）。
- **验证步骤**：1) 断言 n%2==0；2) q = n//2；3) d = pow(e, -1, q-1)；4) `long_to_bytes(pow(c, d, n))`。
- **判定标准**：PASS = 解出可读旗；FAIL = N 为奇数（正常 RSA，转因数分解路径）；多轮 N 不同 → 先固定单次会话参数再解。
- **裁决词**：待复跑
- **来源**：picoCTF 2025 EVEN RSA CAN BE BROKEN???（easy 200p）｜cajac｜raw/github-repos/cajac/2025_picoctf_e_even-rsa-can-be-broken.md（WP 含完整 n/e/c 实参数，本机直接复算）

### RSA 私钥加密·多公钥盲试解密
- **分层**：简单档·可复现强
- **假设**：密文用私钥 d 加密（c = m^d mod n）而公开的是公钥 e → 「解密」即做一次加密 `pow(c, e, n)`；给出多把公钥时逐把盲试、按输出可读性筛出唯一匹配。
- **验证步骤**：1) 解析公钥列表（n_i, e_i）；2) 对每把算 m_i = pow(c, e_i, n_i)；3) `long_to_bytes` 后按题面关键词（如战士名）筛。
- **判定标准**：PASS = 唯一公钥输出可读明文；FAIL = 全部乱码（方向理解错或密钥不在列表 → 重读题面）。
- **裁决词**：待复跑
- **来源**：nullcon 2016 crypto-5 RSA（500p）｜p4｜raw/github-repos/p4/2016_nullcon_e_crypto-5.md（49 把干扰公钥 + 1 把真公钥，文件 warrior.txt/all_keys.txt 附件在源 repo）
- **陷阱备注**：题面「用 RSA 私钥加密文件」少见，第一反应别去找 d——加密方向的逆还是加密。

### 取模映射解码（mod 37 查表 / mod 41 逆元双分支）
- **分层**：简单档·可复现强
- **假设**：数字串明文 = 字符序号经取模映射，同框架两分支：① 余数直接当序号（mod 37 表：0-25→A-Z、26-35→0-9、36→`_`）；② 序号是输入的模逆元（mod 41，字母表 37 项）→ 求逆还原。
- **验证步骤**：1) 先查表分支：逐项索引 37 表拼接；2) 不可读则求逆分支：`pow(x, -1, 41)` 得序号再查表；3) 套 flag{} 校验。
- **判定标准**：PASS = 全项落表内且成文；FAIL = 值超界或无逆元（gcd(x,41)≠1）→ 换模数（26/37/41）与映射方向重试。
- **裁决词**：待复跑
- **来源**：picoCTF 2022 basic-mod1 + basic-mod2｜cajac｜raw/github-repos/cajac/2022_picoctf_e_basic-mod1.md、2022_picoctf_e_basic-mod2.md
- **关键差异**：两题同框架，分支只在映射函数（查表 vs 求逆）——先查表后求逆，避免先验押错分支。

### 块内换位还原（3 字符循环移位）
- **分层**：简单档·可复现强
- **假设**：明文按 3 字符分块、每块首字符移到块尾（`The`→`heT`）→ 解码 = 每块按 [c2, c0, c1] 重组。
- **验证步骤**：1) 校验 len%3==0；2) `flag += s[i+2]+s[i]+s[i+1]`（i 步进 3）；3) 首块已知明文校验（还原出 The）。
- **判定标准**：PASS = 首块还原出合理词且全文可读；FAIL = 块长非 3 → 试 2/4/5 及镜像排列变体。
- **裁决词**：待复跑
- **来源**：picoCTF 2022 transposition-trial｜cajac｜raw/github-repos/cajac/2022_picoctf_e_transposition-trial.md（密文全文在 WP，本机可重放）

### 替换密码·旗即密钥（密钥表重建）
- **分层**：简单档·可复现强（认知陷阱样本）
- **假设**：单表替换加密服务里**映射表本身就是旗**（明文无旗）——有加密/解密 oracle 时按序收集映射对，补全 26 项字母表 → 密钥串即 flag。
- **验证步骤**：1) 加密覆盖各字母的已知串收集映射对；2) 填表至 26 项完整；3) 密钥字母序列套 flag{}。
- **判定标准**：PASS = 重建出完整 26 项映射；FAIL = 表不完整 → 继续喂缺字母（注意服务端输入长度下限，如 ≥5 字符 → 重复填充绕过）。
- **裁决词**：待复跑
- **来源**：CSAW 2015 notesy（crypto 100p，1064 solves）｜p4｜raw/github-repos/p4/2015_csaw_e_notesy.md（映射对 ABCD…↔UNHM… 全记录于 WP）
- **陷阱备注**：p4 被卡约 20 小时——flag 不在明文而在密钥；hint「既有加密又有解密时，flag 是什么」即指此。

### 补条建议：RSA 小明文攻击（e=3 无填充）——任意小 e 整数根分支
- **分层**：简单档·可复现强｜**动作：关键差异补条**（熵控五问 Q1 判定为现有条目边界情况，不新建独立条目）
- **假设**：e 不必为 3——任意小 e（如 e=20）且 M^e < n（无填充短明文）⇒ c = M^e 为精确整数，`gmpy2.iroot(c, e)` 直接开方即得 m。
- **验证步骤**：1) 看 e 大小与 c 位数预判 i=0 分支；2) `iroot(c, e)` 断言整除；3) `long_to_bytes`。
- **判定标准**：PASS = 根为精确整数且可读；FAIL = 不整除（M^e>n → 转 k·n 枚举 / Coppersmith）。
- **裁决词**：待复跑
- **来源**：picoCTF mini（CMU-Africa）crack-the-power｜cajac｜raw/github-repos/cajac/0000_picomini-by-cmu-africa_e_crack-the-power.md
- **目标条目**：[[RSA 小明文攻击（e=3 无填充）]]（wtf 现库 ctf/references/category-crypto.md）——差异点：e 泛化（3 → 任意小 e）+ i=0 精确根判据。

### RSA 最低有效字节甲骨文（LSB×8 预算约束）
- **分层**：超级难档·失败样本/陷阱
- **回流优先级：refuted 候选**——所记「经典 LSB 逐 bit 二分（约 log2(n)≈1024 查询）」路径在 150 次查询预算下不可行，为 WP 记录的显式失败假设；待本机模拟复跑 FAIL 后附复跑记录转正。
- **假设**：oracle 回显的是解密值**最低字节**（8 bit 信息量，非单 bit）时，用 `enc(2^8)` 作倍乘子一次推进 8 bit；每字符恢复用 256 种 bit 进位组合（`itertools.product([0,1], repeat=8)`）模拟 `res = x·2^k − k·n` 的低字节与 oracle 回显比对，唯一命中即得该字节 8 bit 状态。
- **验证步骤**：1) 倍乘子 mult = `pow(2**8, e, n)`（或服务端 enc 接口喂 2^8）；2) 逐字符枚举 8-bit 组合模拟回显字节；3) 命中后 shift 到下一字节循环恢复全文。
- **判定标准**：PASS = 预算内（≤150 查询）恢复完整旗；FAIL = oracle 只回 1 bit → 回退经典二分 [[RSA LSB 甲骨文二分恢复明文]]。
- **裁决词**：待复跑
- **来源**：HITCON 2018 Lost Key（crypto 257p，29 solved）｜p4｜raw/github-repos/p4/2018_hitcon_x_rsa.md（另含 e 已知时 gcd(2^e−c2, 3^e−c3) 恢复未知 n 技巧；150 次操作上限是题面约束）
- **关键差异**：与母技术 [[RSA LSB 甲骨文二分恢复明文]] 同 oracle 族——每 bit 一查 vs 每字节一查（×8 加速），预算约束场景首选本条。

### 「后量子」外观先代数化简（Ring-LWE 伪装拆穿）
- **分层**：超级难档·失败样本/陷阱
- **回流优先级：refuted 候选**——「Ring-LWE/格归约攻击」假设为 WP 开篇即拆穿的伪装（"similar to Ring-LWE, but not quite"）；待复跑转正。
- **假设**：密码学外观题先手推方程化简再选攻击算法：把登录流程全部方程展开 → `pt = M·x·y + y·garbage`（garbage 系数小到取整后归零），纯线性、无格结构；「登录失败回显泄漏多项式」是数据源；未知 Q/M 用系数直方图聚类（间距 ≈10^14 量级）线性拟合解码，不必精确知道参数。
- **验证步骤**：1) 写出服务全部方程并化简至 M·x·y + y·garbage 形；2) 故意登录失败收集泄漏；3) 用 +1/−1 解系（线性解/Z3）恢复注册口令 y；4) 直方图聚类估 Q/M → 解码出明文；5. 按 Recap 五步（steal → login → reset）拿旗。
- **判定标准**：PASS = 化简后闭式可解且按流程登录成功；FAIL = 化简后仍残留格结构（真 LWE）→ 转 LLL/BKZ。
- **裁决词**：待复跑
- **来源**：0CTF 2022 login｜perfect blue｜raw/github-repos/perfectblue/2022_0ctf_x_login.md（"no post-quantum cryptography involved"）
- **陷阱备注**：外观关键词（多项式环/取整/小系数噪声）≠ 需要高级攻击；第一动作是代数展开验「装不装」。

### AES-CTR 常量 counter keystream 生日碰撞差分
- **分层**：超级难档·失败样本/陷阱
- **回流优先级：refuted 候选**——WP 显式记录失败假设：「uint8 计数器 size+1 在 255 时溢出回绕制造异常长度」→ 实为 `size as usize` 零扩展不溢出；待复跑转正。
- **假设**：AES-CTR 把常量 IV 当 counter 传（每请求 keystream 恒定）⇒ 服务端哈希 oracle = 「输入 XOR KEY」的哈希 → 构造等长前缀对（`letter·(x+y+1)` 型串）：随机化前 4 字节 AxBy、翻转计数器位找 x+y==v+z 且 A==B 的哈希碰撞 ⇒ 解密后明文字节相等 ⇒ `KEY[i]^KEY[i+2] = payload[i]^payload[i+2]`；逐对恢复偶数位、错位 1 字节起扫恢复奇数位、首字节小空间枚举 → 全 keystream。
- **验证步骤**：1) 确认服务端 decrypt 每请求用同一 counter（读源码 fragment.rs 的 `Some(&iv)` 常量路径）；2) 固定 4 字节 AxBy 随机化+计数器位翻转生成碰撞；3) 碰撞即得一对 KEY 差分；4) 滑窗 2 字节递推 + 偏移 1 字节补奇数位；5) 首字节 256 空间猜 → 解 encrypted_secret。
- **判定标准**：PASS = 恢复完整 keystream 且解出旗文件；FAIL = counter 每次随机（真 CTR）→ 转重放/其他 oracle 面。
- **裁决词**：待复跑
- **来源**：Google CTF 2018 dogestore（crypto 267p，27 solved）｜p4｜raw/github-repos/p4/2018_google-ctf_x_dogestore.md（fragment.rs 服务端源码随题给出）

### 小素数域线性反馈·已知明文恢复
- **分层**：超级难档·失败样本/陷阱（cn-platform 采集源样本）
- **假设**：输出序列为 16-bit 素域 p 上的 4 阶线性反馈（状态比由相邻输出比值链恢复），明文前缀已知（flag{）→ 枚举 (max(o), 65536) 内全部素数 p，逐项恢复密文字节并以「全部落在可打印 ASCII」过滤——唯一候选 p 后用已知明文逆推初始状态 k，正向全模拟与 output 逐字节验证。
- **验证步骤**：1) output.txt 数值化（每行 hex）；2) 枚举 p，按公式逐项恢复 c[5..41] 过滤 ASCII；3) 唯一 p → 拼已知前缀 flag{ 与 UUID 尾格式校验；4) 从状态 X[4] 逆推 x0=y0/c… 得初始 k；5) 正向模拟 42 字符与原文比对。
- **判定标准**：PASS = 唯一 p 候选 + 全模拟逐字节一致；FAIL = 多候选 → 加强已知明文/格式过滤（UUID 长度与尾部 `}`）。
- **裁决词**：待复跑
- **来源**：网鼎杯 2022 青龙组 grasshopper（26 solved）｜lkok123（bugku WP 库）｜raw/cn-platforms/bugku/wp-md/wp_1874.md（完整 exp 在 WP；md 版仍有转码空格吞噬，待 B-7 采集侧补修）
- **陷阱备注**：先验「p 是标准参数」的假设不成立——p 本身是要枚举的未知量；已知明文 + ASCII 过滤是小域参数恢复的通用筛。

### ZK 电路缺位长检查（Groth16 非预期整数表示）
- **分层**：困难档·电路审计型
- **假设**：circom 电路对秘密输入只约束「数值语义」（如数独格子 1..9）而未约束比特位长（缺 Num2Bits / LessThan 位宽不足）→ 攻击者可用高位整数「溢出后等值」表示通过同一约束——修复 = 上下界同时约束（Num2Bits(n) + 双向比较取交集）构成完整 Range Proof。
- **验证步骤**：1) 读电路源定位每条私密信号的约束生成逻辑；2) 找仅用等式/低比较的信号；3) snarkjs groth16 prove/verify 复跑诚实输入；4) 构造高位溢出输入验证漏洞版通过、补约束版拒绝。
- **判定标准**：PASS = 恶意表示被补约束后拒绝且诚实证明仍通过；FAIL = 电路约束完备 → 转查欠约束信号（zk-bug-tracker 第二类在野漏洞）。
- **裁决词**：待复跑
- **来源**：hackergame 2024 零知识数独·无解之谜（math 三档 300p）｜tl2cents｜raw/github-repos/hackergame2024/2024_hackergame_h_cn-09d7f9.md（电路+验证密钥+exp 全随题开源；snarkjs 本地可复算）
- **陷阱备注**：zk-bug-tracker（0xPARC）在野漏洞库是该类审计的第一入口；环境坑：circom 不走 npm、clone 官方仓 cargo 编译。

### Merkle 登录系统伪树证明（注册矮树 / 登录深树）
- **分层**：困难档·协议逻辑型
- **假设**：登录系统仅存 Merkle 根 + 验证「叶子+路径→根」→ 注册阶段提交仅含少量用户的「矮树」，登录阶段出示同一根下更深层树中 admin 叶子的证明（真实用户集被隐藏在未提交子树里）→ 无需哈希碰撞即完成身份伪造。
- **验证步骤**：1) 复现注册/登录协议的哈希链计算；2) 枚举密码使叶子哈希满足服务器解码约束（可 UTF-8 解码 + 恰一个冒号分隔）；3) 处理左右子树大小序约束（左 < 右时交换构造）；4) 拼接深层 proof 提交。
- **判定标准**：PASS = 服务器接受伪造 admin 登录；FAIL = 根绑定完整树高或提交时校验全部叶子 → 转哈希函数本身弱点面。
- **裁决词**：待复跑
- **来源**：hackergame 2023 O(1) 用户登录系统（math 250p）｜zzh1996｜raw/github-repos/hackergame2023/2023_hackergame_h_o-1.md（源码 o1login.py 随题给出，服务协议可本地重放）
- **陷阱备注**：SHA-1 已知公开碰撞对本题无帮助（长度与前缀约束严苛）——「算法弱点不等于攻击路径」的实证样本。

### CBC 填充预言机解密（逐字节差分）
- **分层**：困难档·oracle 型
- **假设**：服务端解密后回显「padding 合法/非法」→ 对前一密文块逐字节枚举（0..255），命中合法填充即得 D(C) 末字节 → 差分关系恢复整块中间值 → 全密文无需密钥恢复明文。
- **验证步骤**：1) 密文按块切分（16B）；2) 末字节枚举至合法填充（同时校验倒数第二字节以确认非歧义）；3) 固定已知 P_i 前缀推进恢复整块；4) IV 作第 0 块继续；5) 本地自建 AES-CBC + 校验回显器重放（原服务不可达）。
- **判定标准**：PASS = 全部块恢复出可读明文且首块由 IV 恢复；FAIL = 无填充回显差异 → 转时间侧信道或其他解密回显面。
- **裁决词**：待复跑
- **来源**：shwas 2017（上海大学生信息安全竞赛）is aes secure｜六星战队（sixstars）｜raw/github-repos/sixstars/2017_shwas_h_readme.md（exp 外链，oracle 逻辑可自建重放）
- **关联**：与 [[AES-ECB 块特征与逐字节爆破]] 互补——ECB 面走加密 oracle、CBC 面走解密回显；两者先判分组模式再选攻击。

### RSA 密钥再生素数复用（(e0,d0) 泄漏恢复 p/q）
- **分层**：困难档·结构泄漏型
- **假设**：服务 regenkey 只轮换指数 e（p/q/n 不变）→ 一旦泄漏任一 (n, e0, d0)：k = e0·d0 − 1 分解 2 的幂 + 随机基 x 求 gcd(x^{2^t·m} ± 1, n) 即可恢复 p, q → 对新 e1 直接求 d1 解密任意新密文。
- **验证步骤**：1) 本地生成 RSA 对模拟「再生密钥」（p/q 不变换 e）；2) 用 (e0, d0) 标准算法分解 n；3) 由 p, q, e1 求 d1；4) 解密新密文与原生明文比对。
- **判定标准**：PASS = 分解成功且解密一致；FAIL = k 无平方因子分解路径不收敛 → 换基重试（概率算法，3 次以上才判 FAIL）。
- **裁决词**：待复跑
- **来源**：shwas 2017 rrrsa｜六星战队（sixstars）｜raw/github-repos/sixstars/2017_shwas_h_readme.md（攻击链为多步复合，p/q 复用前提清晰可本地模拟）
- **陷阱备注**：入口常是权限伪造（本题为长度扩展攻击伪造 root token）——复合链题先拆「入口漏洞 × 密码原语缺陷」两层。

### Merkle-Damgård 长度扩展攻击（hashpumpy 伪造 token）
- **分层**：困难档·原语缺陷型
- **假设**：token = H(secret ‖ msg) 且 secret 长度已知或可枚举 → MD 迭代结构允许从哈希值恢复内部状态，续算 H(secret ‖ msg ‖ suffix) 无需知道 secret → 向 msg 尾部追加权限字段（如 admin 判定）伪造合法 token。
- **验证步骤**：1) 自造 H(secret‖msg) 样例（secret 长度已知）；2) hashpumpy / hash_extender 续算扩展哈希；3) 与真重算结果比对；4) 构造带权限后缀的伪造 token 验证服务端接受。
- **判定标准**：PASS = 扩展哈希与真实值一致且伪造 token 通过校验；FAIL = 哈希非 MD 结构（SHA-3/BLAKE）→ 转前缀碰撞或其他认证缺陷。
- **裁决词**：待复跑
- **来源**：shwas 2017 rrrsa 前置链（上海大学生信息安全竞赛）｜六星战队（sixstars）｜raw/github-repos/sixstars/2017_shwas_h_readme.md（本地自造样例完全可复算）
- **关联**：Q1 边界说明——现库无长度扩展条目；与 [[AES-ECB 块特征与逐字节爆破]] 同属「原语误用族」但哈希侧独立成条。

### 魔改 AES 常量指纹识别（表全换场景裸写实现）
- **分层**：困难档·自定义原语识别型
- **假设**：二进制里魔改 AES 的结构指纹可识别——sbox 256 字节无重复、expand 后轮密钥 176 字节（128bit×11）、轮循环 10 次、mix columns 系数恰为 9/11/13/14——但常量全被魔改（expand 用 sbox 异于主 sbox、轮密钥倒序使用、每 4 字节两两反转）→ 正确姿势是放弃套标准库，跟流程裸写正向实现对拍，再对称写逆实现（mix columns 逆系数 3/1/1/2）。
- **验证步骤**：1) 提取常量表核指纹（去重计数/长度/系数扫描）；2) 裸写 encrypt 与二进制行为对拍（随机 key 多轮）；3) 对称写 decrypt（轮序反转 + 表逆置）；4) 解出目标 code。
- **判定标准**：PASS = 对拍一致且解密出明文；FAIL = 指纹部分命中（如 12 轮/192bit）→ 按实际参数改写再对拍。
- **裁决词**：待复跑
- **来源**：mtp 2018 qualification advance｜六星战队（sixstars）｜raw/github-repos/sixstars/2018_mtp_h_writeup_p2.md（逆向流程逐项记录在 WP，提取常量后本地可对拍）
- **关联**：与 [[反编译工具链优先级]] 衔接——工具链先做结构侦察，指纹命中后转裸写路线。

### AES-CBC 位翻转伪造明文（空格填充 + 回显）
- **分层**：困难档·oracle 型
- **假设**：cookie 为 AES-CBC 且服务端解密结果全回显、填充为空格（非 PKCS）→ 改前一密文块（或 IV）第 i 字节即按位改写下一块明文第 i 字节；从末块向前构造：发送全零块读回显得 D(C)，与目标明文 XOR 得需设置的「前块」值，迭代至 IV → 产出解密为任意目标串的合法密文。
- **验证步骤**：1) 本地自建 AES-CBC + 解密回显器；2) 全零块探测 D(C)；3) 逆序逐块差分构造；4) 首块借 IV 自由翻转。
- **判定标准**：PASS = 构造密文解密出任意指定明文；FAIL = 回显截断/含校验和 → 转盲 oracle（二分/字典）路径。
- **裁决词**：待复跑
- **来源**：nuit-du-hack 2018 Cryptolol（crypto/web 复合）｜p4（波兰战队）｜raw/github-repos/p4/2018_nuit-du-hack_h_cryptolol.md（完整构造过程与脚本）
- **关联**：与 [[AES-ECB 块特征与逐字节爆破]] 同族（分组模式攻击面分科）；Q2 检查：CBC 位翻转三行骨架已属工具级——建议随 PR 下沉 shared/tools。

### 近似素数构造 RSA（q = a·p + ε 的 Coppersmith 分解）
- **分层**：困难档·结构泄漏型
- **假设**：生成器用线性关系造素数（q = 19·p + ε，ε < 2^512 未知）→ q ≈ √(19n) 得近似值 q_approx，构造多项式 f(x) = q_approx − x 在模 n 上跑 Coppersmith small_roots（X = 2^hidden，beta = 0.5）→ 恢复精确 q 直接分解 n。
- **验证步骤**：1) 由 n 与线性系数估 q_approx；2) sage small_roots 求偏移 δ；3) q = q_approx − δ，p = n/q；4) 求解密出明文。参数全在 WP（Ruby 源码含生成逻辑）。
- **判定标准**：PASS = δ 落在 X 界内且 n 精确整除；FAIL = ε 上界超 Coppersmith 界（beta/X 参数失配）→ 转 LLL 格基调整。
- **裁决词**：待复跑
- **来源**：Tokyo Westerns CTF 2017 Baby RSA（crypto）｜p4（波兰战队）｜raw/github-repos/p4/2017_tokyo_h_rsa.md（enc.rb 生成源码 + sage exp 全在 WP，本地可复算）
- **关联**：与 [[RSA 共模攻击（Håstad）]] / [[RSA 小明文攻击（e=3 无填充）]] 互补——素数生成侧缺陷一族。

### 已知文件结构先验恢复自定义比特密码（PNG 锚定）
- **分层**：困难档·复合链
- **假设**：自定义多轮密码（XOR + 比特自移位差分，轮数未知 ≤1337，key 循环）不可直接逆 → 但密文明文是 PNG（魔数/结构/调色板偏移 0x329 可预知）→ 用已知前缀逐字节试解对拍密钥流，流性质传播使恢复可持续到全文件。
- **验证步骤**：1) 自造 PNG 加密样本重放（同轮函数）；2) 前缀 8 字节锚定逐字节恢复；3) 命中调色板偏移后转「已知密钥流后明文推演」；4) 恢复像素重组 PNG。
- **判定标准**：PASS = 重组 PNG 可打开且含旗；FAIL = 差分非线性使对拍失效 → 转块级/结构级已知明文锚。
- **裁决词**：待复跑
- **来源**：ASIS CTF Finals 2019 true_zero（RE 477p，2 solved）｜p4（波兰战队）｜raw/github-repos/p4/2019_asis-finals_h_true-zero.md（encrypt_fast 复写与 keystream 恢复脚本全在 WP）
- **陷阱备注**：明文结构先验（文件魔数/偏移）是「不可逆密码」的通用破口——先问明文是什么再谈算法。

### 多环 XOR 加密字典恢复（crib 拖拽）
- **分层**：困难档·已知明文型
- **假设**：密文 = 多层「随机短语加密 XOR key 循环」嵌套 → 每层短语本身是明文空间受限的英语短语（字典）→ 逐层做 crib dragging（候选短语 ⊕ 密文段 → 可读性校验）恢复各层 key 片段 → 层层剥除后 flag ⊕ key 直接可读。
- **验证步骤**：1) 自造同结构样本（短语表 + 循环 key）；2) 字典短语逐层拖拽打分；3) 命中层去除；4) 末层 XOR 恢复。
- **判定标准**：PASS = 逐层命中字典短语并恢复 flag；FAIL = key 长度与短语对齐破坏拖拽 → 先估 key 周期（重复距离统计）再拖。
- **裁决词**：待复跑
- **来源**：picoCTF 2021（redpwn 出题）XtraORdinary（crypto 150p）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2021_xtraordinary-md_h_xtraordinary.md（encrypt.py 全文在 WP，自造样本可复算）
- **关联**：Q1 边界——与 [[python 标准库：编码解链循环]] 的解码主题不同（本条为密钥恢复攻击），独立成条。

### RSA 大 e 小 d（Wiener 连分数攻击）
- **分层**：困难档·结构泄漏型
- **假设**：e 异常大（与 n 同量级）⇒ d 很小（d < n^0.25/3 时 Wiener 必中）→ 对 e/n 做连分数展开，逐收敛子 k/h 当作 (e·d − 1)/d 试分解 n；现成工具路径 = RsaCtfTool --attack wiener。
- **验证步骤**：1) 观测量级 |e| ≈ |n| 且连接密钥为短 d 服务（nc 一次性给 c/n/e）；2) 连分数收敛子枚举（或直接跑工具）；3) 中者求 d 解密。
- **判定标准**：PASS = 某收敛子给出合法 d 且解出旗；FAIL = d 略超界 → 转 Boneh-Durfee（d < n^0.292，格攻击）。
- **裁决词**：待复跑
- **来源**：picoCTF 2018 Super Safe RSA 2（crypto 425p）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2018_super-safe-rsa-2-md_h_super-safe-rsa-2.md（c/n/e 全在 WP，本地复算零依赖）
- **陷阱备注**：「指数大 = 更安全」是常见反直觉样本——e 大反而把 d 挤小。

### 时间轮转密钥全轮收集（互素步长扫表）
- **分层**：困难档·协议逻辑型
- **假设**：服务每秒用轮转密钥表（周期 77 槽，步长 43 与周期互素）重加密同一旗 → 已知前缀（旗格式 CSSCTF{）随时间扫过全表，每 tick 暴露 1 槽 1 字节差分 → 60 秒采集即覆盖全表（互素保证遍历），无需知道绝对起始相位。
- **验证步骤**：1) 采集 60s 滚动密文流；2) 逐 tick 以已知前缀对齐求 key 槽；3) 相位推演验证（77/43 互素遍历性）；4) 二次采集对齐绝对时间戳；5) 本地模拟轮转服务全链重放。
- **判定标准**：PASS = 重建 77 槽全表并解出任意时刻密文；FAIL = 步长与周期不互素 → 需更长采集窗或相位泄露路径。
- **裁决词**：待复跑
- **来源**：CSS CTF 2026 Return of Nexus Chrono II（crypto 100p，385 solved）｜hax1ng｜raw/github-repos/hax1ng_css-ctf-2026-return-of-nexus/crypto/chrono-ii/README.md（轮转逻辑与互素遍历推导全在 WP，本地可模拟）
- **陷阱备注**：「密文一直在变」≠ 安全——轮转结构若周期有限且明文不变，时间轴本身就是攻击面。

### AVX2 轮函数对称逆推（无密钥加密器）
- **分层**：困难档·自定义原语识别型
- **假设**：无外部密钥的加密器（纯置换/混淆网络）整体必可逆——AVX2 指令不熟的块（vshufnet 不可逆混淆）不必直接逆，先逆数据依赖明确的算术轮（r0..r3 可计算逆），逐轮剥除 8 轮后得解密器 → 解密产物以文件结构（JPG 头）自证。
- **验证步骤**：1) IDA 静态读 AVX2 汇编（反编译器不支持 → 直接攻汇编）；2) 标记 256bit「yword」语义；3) 对可逆算术轮求逆；4) 8 轮逆序组合；5) 解密验证 JPG 魔数。
- **判定标准**：PASS = 解出完整 JPG 且含旗；FAIL = 某轮真不可逆（信息丢弃）→ 定位丢弃点转穷举该轮输入。
- **裁决词**：待复跑
- **来源**：InsomniHack Teaser 2017 encryptor（crypto 400p）｜nneonneo / pwning（S1 扩容源）｜raw/github-repos/pwning/2017_insomnihack-teaser_h_readme.md（逐轮逆推分析在 WP，decrypt.py 同思路可重写）
- **关联**：与「魔改 AES 常量指纹识别（表全换场景裸写实现）」同族（自定义原语逆推），按载体分条。

### 未知小 e 枚举 + 模逆还原（签名方向 RSA）
- **分层**：困难档·结构泄漏型
- **假设**：服务做「用私钥加密」（C = (2·flag)^d mod N）且只给 C 与 N、e < 65537 未公开 → 枚举奇数 e（3,5,…65535），计算 C^e mod N 再乘 2 的模逆（放大系数还原），以已知旗前缀（如 hctf）校验命中 → 单机分钟级。
- **验证步骤**：1) 读协议确认「私钥方向」输出；2) 奇 e 枚举；3) pow(C,e,N)·inverse(2,N)；4) 前缀/可打印过滤命中。
- **判定标准**：PASS = 唯一命中 e 并解出旗；FAIL = e 空间被扩（>2^20）→ 转共模/广播收集路径。
- **裁决词**：待复跑
- **来源**：HCTF 2017 babyRSA｜六星战队（sixstars）｜raw/github-repos/sixstars/2017_hctf_h_hctf.md（交互协议与枚举脚本在 WP；e 空间小本地枚举快）
- **关联**：Q1 边界——与 [[RSA 小明文攻击（e=3 无填充）]] 同「小参数空间」族但方向相反（私钥侧），关键差异 = 枚举对象是 e 且需模逆还原放大系数。

### Double DES 中间相遇（6 位数字键空间）
- **分层**：困难档·复合链
- **假设**：双重 DES（E_k2(E_k1(m))）本身 MITM 攻击理论 2^57，但本题 key 生成自 6 位数字（pad 至 8B）⇒ 每层仅 10^6 → 加密侧全枚举建表、解密侧全枚举查碰撞 → 中间值命中即得 (k1, k2)。
- **验证步骤**：1) 取一对明密文（服务可查询）；2) 10^6 明文加密表；3) 10^6 密文解密逐一查表；4) 命中键对后验证另样本。
- **判定标准**：PASS = 唯一命中键对；FAIL = 多解（padding 歧义）→ 加样本消歧。
- **裁决词**：待复跑
- **来源**：picoCTF 2021 Double DES（crypto 120p）｜Dvd848（S1 扩容源）｜raw/github-repos/Dvd848/2021_double-des-md_h_double-des.md（服务源码+枚举脚本在 WP，本地可全重放）
- **陷阱备注**：键空间收缩（6 位数字）是「2DES 不安全」命题成立的前提修正——攻击复杂度取决于实际键空间而非名义层数。

### 密钥长度侧信道 + Vigenère 解码（LEN(KEY) oracle）
- **分层**：困难档·复合链
- **假设**：服务回显 `len(KEY)` 而数据以 Vigenère 加密 ⇒ 控制发送数据长度即可逐位推断 key 周期与内容（new len - old len 暴露 key 起始偏移）→ 恢复 key → 解出 base64+Vigenère 叠层的 PNG 旗图。
- **验证步骤**：1) 发不同长度明文记录 len 变化，定位 key 周期；2) 周期内逐位差分恢复 key；3) 解密 payload 得 base64；4) 解码落 PNG 查图。
- **判定标准**：PASS = 解出可读 PNG；FAIL = key 含不可打印 → 按周期对齐后只取可打印解。
- **裁决词**：待复跑
- **来源**：CSAW CTF 2016 sleeping-guard（crypto 100p）｜p4 (波兰战队)｜raw/github-repos/p4/2016_csaw_h_sleeping-guard.md（len 差分与解码链在 WP；本地重放轻量）
- **关联**：与 [[取模映射解码（mod 37 查表 / mod 41 逆元双分支）]] 互为边界（古典密码族），「长度泄漏」侧信道是本条独有增量。

### Hill 矩阵加密的三段攻破（差分恢复 / 核空间失效 / CVP 可打印化）
- **分层**：困难档·复合链
- **假设**：GF(257) 上 128×128 Hill 加密 M 的三问各有独立破法——① oracle 对输入先 ⊕flag 再加密但「密文≠明文才输出」⇒ 单比特差分可控（⊕flag 项相消）→ 选择差分恢复 M 整列乃至特征值 λ；② 让加密失效 = 找 M 的本征值 1 本征向量（M·p = p 直通）；③ 强迫症旗 = 构造 M·p = p 且 p 可打印 → CVP/格约化找最近可打印向量。
- **验证步骤**：1) 128 组单比特差分交互按列恢复 M（或 λ 观察）；2) 解本征方程 (M−I)p=0 取核基；3) 核向量上加可打印目标做格基约化（BABAS/BKZ）求 p；4) 三问分别提交。
- **判定标准**：PASS = 三问全过（含 λ、核、可打印三态）；FAIL = 约化超界 → 分段小格逐片求解。
- **裁决词**：待复跑
- **来源**：Hackergame 2023 不可加密的异世界 2（math 250p/175p/100p）｜USTC-Hackergame（官方+选手）｜raw/github-repos/hackergame2023/2023_hackergame_h_2-303301.md（exp.sage 全量在 WP 附件；Sage 本地可重放）
- **关联**：与 [[AES-CBC 位翻转伪造明文（空格填充 + 回显）]] 同「密码组件线性结构」族——Hill 纯线性无扩散，线性代数即密码分析；[[STG-K01 高级外观先做减法——代数化简优先于重武器]] 的密码学正面证据。
- **陷阱备注**：Q1 归位说明——按密码分析实类归 crypto（选材线记 steganography 合集归类）；Sage 与 numpy 域内求解实现有差异须对齐 GF(257)。

### Shamir 秘密分享的「一次多项式复用」崩溃（逐字符独立爆破）
- **分层**：困难档·单点
- **假设**：SSS 对每字符用同一多项式（Shamir 对象只建一次）⇒ 31 个字符共享同一 (a1..ak) 分享点集 ⇒ 每字符独立解小有限域线性方程组（GF(p) 32 位素域），穷举字符集对每列点集验证多项式一致性即还原旗。
- **验证步骤**：1) 抓取每字符的 (x,y) 分享点；2) 尝试固定候选字符 c 解 a 系数方程；3) 全部点过方程则该位为 c；4) 逐位拼旗。
- **判定标准**：PASS = 全字符位恢复；FAIL = 域参不明 → 从 challenge 源码提 prime。
- **裁决词**：待复跑
- **来源**：Midnight Sun CTF 2018 Finals badchair (crypto)｜p4 (波兰战队)｜raw/github-repos/p4/2018_midnightsun-finals_h_badchair-crypto.md（爆破脚本全量在 WP；GF 线代本地秒级重放）
- **关联**：与 [[RSA 密钥再生素数复用（(e0,d0) 泄漏恢复 p/q）]] 同「密钥材料跨实例复用」族——复用点在多项式 vs 素数，共因都是实现层偷懒。

### 已知 padding 的 RSA related-message 消元（e=3 三密文线性化）
- **分层**：困难·单点
- **假设**：服务允许对同一明文 x 加「自定义但已知」的 sha256 padding 后以 e=3 加密并输出密文；设 (x+pad_i)^3 ≡ c_i (mod n)，三组方程经结式/手工消元先消 x^3、再消 x^2，剩一次方程即可解出 x——padding 数值大不碍事，关键只是「已知」。
- **验证步骤**：1) 三次交互取 c1,c2,c3（各自 padding p1,p2,p3 已知）；2) 展开三多项式 g_i(x)=(x+p_i)^3-c_i；3) 两两取结式消去最高次项得线性余式；4) 模逆解一次方程得 x，hex 解码验证明文语义。
- **判定标准**：PASS = 解出 x 满足 flag 模板；FAIL = 试图把 padding 当未知量（不可解）或只拿两方程硬凑（e=3 两方程消元后仍二次，三方程才稳定降次）。
- **裁决词**：待复跑
- **来源**：N1CTF 2018 rsa_padding｜六星战队｜raw/github-repos/sixstars/2018_n1ctf_h_writeup.md（n/ct/ans 全量在 WP，sage 可本地复算）
- **关联**：与 [[近似素数构造 RSA（q = a·p + ε 的 Coppersmith 分解）]] 同属「多项式方程组降次攻 RSA」族；与 [[dq 泄漏分解 RSA 模数（部分涂抹私钥恢复）]] 互补构成「私钥侧信息泄漏」双视角。

### dq 泄漏分解 RSA 模数（部分涂抹私钥恢复）
- **分层**：困难·单点
- **假设**：私钥 PEM 涂黑后残留两段：头部完整给 n、e；按 ASN.1 版式推第二段为 exponent2=dq。由 edq≡1 (mod q-1) 知 dq·e-1=k·(q-1)，遍历 k=1..e 的因子 i 使 (dq·e-1)%i==0，取 q=((dq·e-1)/i)+1 且 n%q==0 即分解成功。
- **验证步骤**：1) base64 解私钥残文 → ASN.1 解析定 n/e/dq 位置；2) for i in 1..e: 若 (dq*e-1)%i==0 且 n%(((dq*e-1)//i)+1)==0 则得 q；3) p=n/q；4) phi=(p-1)(q-1)，gmpy2.invert(e,phi) 得 d；5) RSA.construct 重组 PEM，openssl pkeyutl -decrypt 解密文。
- **判定标准**：PASS = 重组私钥可解出 flag；FAIL = 误把残留段当 dp（与 dq 位置对调则 q 换 p，等价）或漏乘 e（直接用 dq-1 试除永不出因子）。
- **裁决词**：待复跑
- **来源**：Google CTF 2024 bq Redacted RSA 2｜Dvd848 (S1扩容)｜raw/github-repos/Dvd848/2024_redacted-rsa-2-md_h_redacted-rsa-2.md（双段 ASN.1 解析+解题脚本全量在 WP）
- **关联**：与 [[RSA 密钥再生素数复用（(e0,d0) 泄漏恢复 p/q）]] 同族「私钥部分信息→模数分解」；涂抹版式分析与 [[PNG IEND 尾随增量字节提取（逆写入器）]] 共享「结构残留先读版式再谈恢复」直觉。

### 重复密钥 XOR 的空格频率攻击（互移位重合计数定键长）
- **分层**：困难·单点
- **假设**：多字节 XOR 流密码（密钥周期 21）。英文文本空格最频且与字母异或后仍可区分：① shift 比对重合数在 key_len 倍数处出现峰值定周期；② 每个密钥位列内取众数 = 空格候选，c_i ^ 0x20 即该位密钥字节。
- **验证步骤**：1) for key_len in 1..100 计算 count_same(data, shift(data,key_len))，峰值处取 21；2) 按列 Counter 统计，取各列最频字符假设为空格；3) 列密钥 = 该字符 ^ 0x20；4) 全量异或解密，按可读性微调个别列。
- **判定标准**：PASS = 解密全文为可读英文且含 flag；FAIL = 峰值误读（重合数未归一化比较会把长周期当峰值）或众数误设为 'e'（空格才是英文众数）。
- **裁决词**：待复跑
- **来源**：HCTF 2018 xor game｜六星战队｜raw/github-repos/sixstars/2018_hctf_h_hctf.md（key_len=21 判定与逐列频率脚本全量在 WP）
- **关联**：与 [[16 字符字母表 Vigenère（b16 前置 + 逐位独立密钥爆破）]] 同为「周期密码逐列频率攻击」，本条差异在密文空间为任意字节且空格 0x20 作 crib；与 [[多环 XOR 加密字典恢复（crib 拖拽）]] 互为字节级/单词级 crib 双路线。

### RSA 解密权游戏数论陷阱（d=1 与 c^{-1} 旁路）
- **分层**：困难·多段链
- **假设**：远端提供「选 d、拿 c、得 m=c^d mod n」的解密服务。两个非预期解：① d=1 时 m≡c（幂退化为恒等，直接把目标密文当 m 交）；② 目标格 c 与 n 非互素且服务端实现未校验时，交 invert(c,n) 类旁路；另有 n=c-m 形态的恒等式可从方程侧反推。逐关切换恒等式/求逆即可过全关。
- **验证步骤**：1) 枚举服务允许的 d 边界值（1、n-1、φ(n) 近邻）；2) 对每关先试 d=1 恒等直通；3) 不通则试把 c 交给「加密」方向反求 m；4) 用 python pow(c,d,n) 本地对照服务输出验证假设的运算语义。
- **判定标准**：PASS = 每关不爆破 d 全部通关且本地 pow 复算一致；FAIL = 掉进「必须求真实 d」的思路陷阱（服务语义允许恒等幂）。
- **裁决词**：待复跑
- **来源**：骇极杯 2018 rsaaaaa｜六星战队｜raw/github-repos/sixstars/2018_haijibei_h_haijibei2018.md（逐关交互脚本与失败尝试记录在 WP）
- **关联**：与 [[RSA LSB 甲骨文二分恢复明文]] 同属「把 RSA 交互服务当神谕玩语义边界」；失败样例价值与 [[相邻变量覆写改认证标志（authenticated 旁路）]] 呼应——先审服务语义再谈数学。

### DOS/Win16 载体内嵌异或密钥（中断向量表作 key）
- **分层**：困难·多段链
- **假设**：challenge.flp 为 320KB FAT12 软盘镜像：解出后含 Win3.x NE 格式样本与 DOS MZ 引导器。样本的加密/校验密钥来自 DOS INT 21h 35h 取回的中断向量（INT 0x00/0x05/0x06 入口地址字节），因向量值取决于宿主环境，静态拿 0x00F0 之类的占位值必错——须在模拟器内运行取真值再 XOR 回密文。
- **验证步骤**：1) file/7z 识别 flp 并解包；2) Ghidra 加载 NE/MZ 定位 INT 21 35 调用与异或循环；3) DOSBox 运行断点/转储取真实向量值；4) 以向量字节流 XOR 密文段核对 flag 模板。
- **判定标准**：PASS = 模拟器内取值解出 flag；FAIL = 用静态反汇编里的占位向量值异或（环境相关性导致错钥）。PADDING 填充段为干扰项须剔除。
- **裁决词**：待复跑
- **来源**：BSidesTLV 2019 DoSaTTaCK｜Dvd848 (S1扩容)｜raw/github-repos/Dvd848/2019_dosattack-md_h_dosattack.md（Ghidra 反编译+软盘结构全量在 WP）
- **关联**：与 [[8051 固件 EEPROM 导出 + 位级 patch（anl 立即数清零）]] 共享「古董平台逆向」域；密钥环境依赖性与 [[glibc rand() 状态恢复（z3 约束求解 31 状态字）]] 同属「运行时状态作密钥」类。

### PKI 中间 CA 证书链伪造（mTLS 客户端认证旁路）
- **分层**：困难·多段链
- **假设**：目标 Web 服务要求客户端证书（类 mTLS）。站点注册流程会替用户生成私钥+CSR 并由服务端签名，但签发程序未做 basicConstraints 防御：可提交自造「中间 CA」身份的 CSR，服务端以 CA:TRUE 签回；再自签一张终端用户证书挂在其下组成链，Web 容器校验链路时放行。
- **验证步骤**：1) 抓注册流程 JS 确认 privatekey/CSR 隐藏域；2) openssl 生成中间 CA 密钥与含 CA:TRUE 的 CSR 提交；3) 拿回签发证书后自签 leaf 证书；4) 组 PKCS#12 装入 curl/浏览器完成客户端认证，取武器控制面板的关闭指令。
- **判定标准**：PASS = 伪造链通过服务端校验并执行动作；FAIL = 只伪造 leaf 而无 CA 路径（单证书不在服务端信任 CA 链上被拒）。
- **裁决词**：待复跑
- **来源**：Mossad CTF 2019 Challenge #2｜Dvd848 (S1扩容)｜raw/github-repos/Dvd848/2019_challenge2-md_h_challenge2.md（证书链构造脚本与 TLS 握手对照全量在 WP）
- **关联**：与 [[Kerberos AS-REP Roast（无预认证用户哈希离线爆破）]] 同为「认证协议信任链弱点」；链构造纪律与 [[ISO→maildir→PGP→outguess 四段链取证]] 共享「逐层凭证装配」直觉。

### 硬件指纹口令逆向（盘符序列+MAC+BIOS SN 拼装）
- **分层**：困难·多段链
- **假设**：EncryptSoftware.exe（Win32）要求输入口令，真口令由运行机器的硬件标识拼装：GetVolumeInformation 磁盘序列、网卡 MAC、BIOS 序列号按固定 checksum/拼接规则组合，再以自定义流混淆（RC4 变体/异或链）加密目标文件；脱离原机需在 Ghidra 还原拼装算法并在本机伪造同等标识。
- **验证步骤**：1) Ghidra 反编译定位 hardware API 调用点与拼装循环；2) 提取 checksum 算法与字符集映射表；3) 在本地伪造标识（改注册表/虚拟 MAC/伪造 BIOS 字段）按算法计算口令；4) 运行程序以口令解密样本核对 PNG 头。
- **判定标准**：PASS = 复算口令通过程序校验且解出文件头合法；FAIL = 把字符串表里的诱饵口令当真口令（诱饵常见于未交叉引用的死代码）。
- **裁决词**：待复跑
- **来源**：Mossad CTF 2019 Challenge #3｜Dvd848 (S1扩容)｜raw/github-repos/Dvd848/2019_challenge3-md_h_challenge3.md（Ghidra 重命名后反编译与 main 全链在 WP）
- **关联**：与 [[Windows SAM bootKey 转储 + SilentEye 隐写双密钥链]] 同族「系统指纹作密钥材料」；checksum 复算纪律与 [[语音念码留白的哈希约束恢复（小写/大小写双 SHA1 夹逼）]] 共享「约束反推」方法论。

### 游戏源码 diff 钓鱼后门（定种子 RNG + RC2 解密）
- **分层**：困难·多段链
- **假设**：赛题基于开源 Commander Keen 源码魔改，flag 未直接藏于字符串，而在游戏状态机：diff 官方源码可定位改动点——gamestate 结构体新增 second_flag[24]，由数组 arr2 灌入、RC2 解密、通关才显示；关键差异还有 US_InitRndT(false)（固定种子 RNG）使密钥/流程可确定性重放。
- **验证步骤**：1) 官方源码与赛题源码 diff 定位新增/改动函数；2) 读 second_flag 赋值与 rc2_cc_decrypt 调用链得密钥来源；3) 取 RC2 参考实现按密钥流程解 arr2；4) 或在 DOSBox+Borland C++ 2.0 编译原逻辑直接跑出（确定性种子保证可复现）。
- **判定标准**：PASS = 解密串满足 CSA{...} 格式；FAIL = 直接跑游戏期望通关显示（第二 flag 仅在特定高分屏路径显示，且隐藏菜单注明 Status Window 不是它）。
- **裁决词**：待复跑
- **来源**：Check Point CSA 2020 Stateful Keen｜Dvd848 (S1扩容)｜raw/github-repos/Dvd848/2020_stateful-keen-md_h_stateful-keen.md（diff 与 RC2 集成代码全量在 WP）
- **关联**：与 [[编译期 CFG 深度乘积水印提取（小素数编码）]] 共享「开源基线 diff 出后门」方法论；确定性 RNG 与 [[rand() 未播种的服务端门禁（SSL 回显可预测）]] 同属固定种子缺陷族。

### 模 2^64 次幂开方链（Tonelli-Shanks + 单位根幂枚举收敛）
- **分层**：困难·流程
- **假设**：ct = m^(2^64) mod p（p-1 = 2^30·q）时解不唯一：Tonelli-Shanks 求一个平方根起点 m，再乘以 2^30 次本原单位根 k 的幂（k 由 (p-1) 反复开方得非二次剩余），枚举 m·k^r 全解空间中满足 TWCTF{ 前缀与 42 字符长度约束者即真值——"多解空间+格式约束收敛"范式。
- **验证步骤**：1) 分解 p-1 得 2 的幂次；2) Tonelli-Shanks 递降 64 层取一个 m；3) 求 2^30 次单位根 k（非 QR 即不可再开方）；4) 并行枚举 r 使 m·k^r 解码满足前缀/长度；5) 输出 flag。
- **判定标准**：PASS = 枚举命中前缀完整串；FAIL = k 求解次幂不足（按 2^t 调整）或约束不满足（放宽长度尝试）。
- **裁决词**：待复跑
- **来源**：TWCTF 2020 sqrt (216p/45 solved)｜f0xtr0t｜raw/github-repos/pwning/2020_twctf_h_sqrt.md
- **关联**：Tonelli-Shanks 与库内 Rabin 解密类条目互链（同为模平方根族）；"多解+约束收敛"与 [[RSA 故障签名挖掘 + 部分 d 低位恢复（n/4 LSB 定理）]]（本批）同型。
- **熵控预检**：Q1 无重名；Q3 强（双脚本+Rust 并行版在 WP）；Q4 边 1 条。

### 模逆求解 + 加 p 平移枚举还原 ASCII（divm 短除陷阱）
- **分层**：困难·单点
- **假设**：c = a·b mod p 已知 b 求 a 时 gmpy2.divm 直接给最小非负解，但解码可能非 ASCII——模运算下 a+kp 均为解，逐次加 p 平移枚举直至串以已知前缀（HV18）开头即真值；"%x" 补零奇偶位是 int→bytes 的坑点。
- **验证步骤**：1) a0 = gmpy2.divm(c, b, p)；2) int_to_text(zfill 补齐)；3) while not pt.startswith('HV18'): a += p；4) 输出。
- **判定标准**：PASS = 前缀命中且余下可读；FAIL = 平移上界溢出（前缀错则检查 b/c 抄录）。
- **裁决词**：待复跑
- **来源**：Hackvent 2018 Day 11 Crypt-o-math 3.0（medium/RSA）｜Writeup 仓（IceCTF 官方格式）｜raw/github-repos/shiltemann/2018_hackvent_h_day-11-crypt-o-math-3-0.md
- **关联**：加 p 平移与 [[模 2^64 次幂开方链（Tonelli-Shanks + 单位根幂枚举收敛）]]（本批）的多解枚举同型；int_to_text 补零技巧是编码转换通用件。
- **熵控预检**：Q1 无重名；Q3 强（gmpy2 会话全在 WP）；Q4 边 1 条。

### SHA1 选择性碰撞工程应用（sha1collider 构造同哈希异内容双 QR）
- **分层**：困难·流程
- **假设**：服务端要求两文件 SHA1 相同但 QR 内容不同（"Hackvent" vs "Hacky Easter"）时，sha1collider（SHAttered 同族）对含差异的 PDF 前缀生成碰撞块即可批量构造；QR 生成后嵌 PDF 再 collide——密码学碰撞从理论到工程落地的完整样本。
- **验证步骤**：1) qrencode 生成两张内容不同的 QR png；2) convert 转 PDF；3) python3 sha1collider/collide.py a.pdf b.pdf --progressive；4) 双文件上传触发服务端校验。
- **判定标准**：PASS = 服务端返回 egg；FAIL = QR 解码失败（PDF 转换损失，改嵌入 PNG 容器变体）。
- **裁决词**：待复跑
- **来源**：HackyEaster 2018 Same Same (medium)｜Writeup 仓｜raw/github-repos/shiltemann/2018_hackyeaster_h_same-same.md
- **关联**：与库内哈希条目构成"碰撞工程"增量（首个可复现碰撞应用链）；上传校验双条件（内容异+哈希同）的绕过面反哺 web 上传审计。
- **熵控预检**：Q1 无重名（库内无 SHA1 碰撞工程条目）；Q3 强（工具链命令在 WP）；Q4 边 1 条。

### AES-CBC 位翻转伪造 is_admin（debug 泄露结构定位）
- **分层**：困难·单点
- **假设**：cookie token 为 base64(AES-128-CBC(JSON)) 且站点开 debug cookie 时 console.log 打印明文结构 {"id":..,"is_admin":0,"username":".."}，则已知明文+CBC 分组链接性质允许翻转前一分组对应比特改变后一分组明文位：P2[bit] ^= C1[bit] 使 is_admin 由 0→1——无需密钥的密文操控。
- **验证步骤**：1) 开 debug 读 console.log 明文结构定位字段偏移；2) base64 解 token 分 16 字节组；3) 对 is_admin 所在位异或翻转（P[i-16] ^= \x01）；4) 重组 base64 替换 cookie；5) 访问 admin panel。
- **判定标准**：PASS = 面板放行；FAIL = 前一分组对应字节被 MAC/校验（找无校验字段）或偏移算错（逐位试翻转观察 debug 输出变化）。
- **裁决词**：待复跑
- **来源**：SharkyCTF 2020 Backflip in the kitchen｜Writeup 仓（ orangescape ）｜raw/github-repos/apoirrier/2020_sharkyctf_h_backflip.md
- **关联**：与库内 padding oracle 条目构成 CBC 双攻击（位翻转 vs 填充预言，前者无需错误信道）；debug 端点泄露结构与 [[node-static CVE-2023-26111 路径穿越 + --inspect 调试端口 RCE]]（本批 web）的调试面泄漏同族。
- **熵控预检**：Q1 与 padding oracle 条目区分（无 oracle 信道为增量）；Q3 强（结构与偏移在 WP）；Q4 边 2 条。

### 截屏取证逆向 + glibc rand 种子重放（栈溢出控种子）
- **分层**：困难·多段链
- **假设**：无附件的"视频题"实为侦察题：screencast 中的源码/gcc 命令/反汇编截图拼出程序逻辑（scanf("%79s") 溢出覆盖未初始化 seed）——超长无空格用户名即可控制 srand(seed)；此后 numbers 数组按 rand()%5/rand()%26（模乘实现）生成，本地同 seed 重放即预测全部题目答案——"视频侦察→逆向重建→PRNG 重放"三段。
- **验证步骤**：1) 逐帧抽源码/gcc(-fno-stack-protector)/汇编截图；2) 重建 C 源（initialize() 中 srand + 两处模乘取模）；3) 长名输入定 seed；4) 本地编译输出预测序列；5) 管道喂 nc 服务。
- **判定标准**：PASS = 20 题全对拿到 flag；FAIL = rand 实现差异（glibc vs musl，按靶机 libc 选）或 scanf 截断长度不同。
- **裁决词**：待复跑
- **来源**：UIUCTF 2018 Important Videos (Misc 200p/10 solves)｜Writeup 仓｜raw/github-repos/perfectblue/2018_uiuctf_h_important-videos-200.md
- **关联**：种子重放三连（[[exiftool 时间戳作随机种子的像素坐标洗牌还原]]、[[xlsx 零宽字符文档水印溯源（MagicText XOR + 种子重放）]]，本批）；"截屏考古"侦察法与 recon 域 OSINT 互证。
- **熵控预检**：Q1 无重名；Q3 强（重建 C 源与命令在 WP）；Q4 边 2 条。

### RSA 密文数字置换混淆（10! 枚举逆置换）
- **分层**：困难·单点
- **假设**：RSA 后再叠加数字替换置换（perm[str(x)]）的混合加密，因置换空间仅 10!≈3.6M 且 n 可 FactorDB 分解，直接枚举全部 digit permutation 逐个解 RSA 比分析置换更快——"低熵外层暴力+高熵内层查库"的混合攻击策略。
- **验证步骤**：1) FactorDB 查 n 得 p,q（96bit×2）；2) itertools.permutations(range(10)) 生成逆置换；3) 对每个置换还原 c_rev；4) 标准 RSA 解密 long_to_bytes；5) grep "ctf" 过滤。
- **判定标准**：PASS = 某置换解出 ctf{...}；FAIL = n 不在库（转 yafu 分解）。
- **裁决词**：待复跑
- **来源**：BxMCTF 2023 RAID Safety Assays, But Fixed｜daffainfo（github WP 仓）｜raw/github-repos/daffainfo/2023_bxmctf_h_raid-safety-assays-but-fixed.md
- **关联**：与库内 RSA 条目构成"外层混淆剥离"增量；10! 枚举与 [[蚁剑 RSA 编码器流量解密 + 字符替换密钥穷举]]（本批 recon）的穷举法同型（3^k vs 10!）。
- **熵控预检**：Q1 无重名；Q3 强（枚举脚本全在 WP）；Q4 边 1 条。

### 动态步长 XOR 的最低位恢复攻击（奇偶驱动自同步）
- **分层**：困难·流程
- **假设**：加密器 c[i] = p[i] ^ p[i+space]，space 随 p[i] 奇偶 ±1 漂移时，cipher 最低位仅依赖两个 plaintext 位（parity 链），先解最低位方程组恢复全部 LSB，再以 LSB 已知为前提逐字节前向推导（space 序列由已恢复段决定）——分两阶段的已知明宣攻击（known-prefix："DCTF"）。
- **验证步骤**：1) 用已知前缀+假设 space 初值推 LSB 链；2) verify 函数逐步校验 cipher 最低位一致性；3) LSB 全恢复后前向逐字节解 p[i]=c[i]^p[i+space]；4) 结尾字符按 space 越界分支校验。
- **判定标准**：PASS = 解出可读 flag；FAIL = space 初值假设错（10 起点邻域扫描）或前缀不足（延长已知段）。
- **裁决词**：待复跑
- **来源**：DCTF 2015 Crypto 300 custom-function｜p4 (波兰战队)｜raw/github-repos/p4/2015_dctf_h_custom-function.md
- **关联**：最低位侧信道与 [[RSA LSB 甲骨文二分恢复明文]]（库）的 LSB 主题呼应（泄露面 vs 攻击面）；自同步性分析可反哺流密码审计。
- **熵控预检**：Q1 无重名；Q3 强（两阶段脚本与 PHP 转 Python 在 WP）；Q4 边 2 条。


### RSA 故障签名挖掘 + 部分 d 低位恢复（n/4 LSB 定理）
- **分层**：困难·流程
- **假设**：坏盒子签名服务（CRT 参数注入故障）仅能泄露 d 的部分低位时，只要拿到 n/4 个 LSB 且 e 较小，即可用 partial key exposure 攻击恢复完整私钥：solve_mod 解 e*d0*X - k*X*(n-X+1) + k*n == X（mod 2^kbits）得 p 高位近似 p0，再 Coppersmith small_roots(X=2^(nbits/2-kbits), beta=0.3) 补齐 p，gcd 分解 n。
- **验证步骤**：1) 挖掘故障签名还原 d0 低 300bit（同 broken_box 方法）；2) sage find_p 对 k=1..e 逐一试解；3) partial_p 用 small_roots 求根；4) gcd(2^kbits*x0+p0, n) 得 p；5) 标准解密。
- **判定标准**：PASS = 分解出 p 且解出 flag；FAIL = kbits 不足（降 e 或增挖签名）或 beta 调参失败（0.3→0.4）。
- **裁决词**：待复跑
- **来源**：CSAW 2016 Still Broken Box (Crypto 400p)｜p4 (波兰战队)｜raw/github-repos/p4/2016_csaw_h_still-broken-box.md
- **关联**：与 [[RSA LSB 甲骨文二分恢复明文]]（库）、[[RSA 最低有效字节甲骨文（LSB×8 预算约束）]] 构成 RSA LSB 三部曲（明文 oracle / 故障签名 / 部分私钥），本条是"密钥侧"收官；定理出处 UMD honors 报告 lowexprsa.pdf。
- **熵控预检**：Q1 与库内 RSA 条目区分（partial d 为增量）；Q3 强（sage 脚本全文在 WP）；Q4 边 3 条。


### 四字符分组独立哈希的逐组爆破（弱结构分治）
- **分层**：困难·单点
- **假设**：自定义哈希若按 4 字符分组独立压缩（每组产 2 hex），则 8 组目标可分治为 8 个 4 字符小空间（26^4≈45 万/组），itertools.permutations 逐组命中即拼出完整原象——"结构独立性发现"比逆向压缩函数本身更省力。
- **验证步骤**：1) 读 hash 源码确认分组独立（无跨组状态）；2) target 按两位切分；3) 逐组枚举 4 字母组合计算比对；4) 拼接 32 字符口令。
- **判定标准**：PASS = 8 组全中且口令可用；FAIL = 存在 padding 组（末组含 chr(n) 填充，按 pad 规则枚举）。
- **裁决词**：待复跑
- **来源**：easyCTF 2015 H4sh3D｜Writeup 仓（IceCTF 官方格式）｜raw/github-repos/shiltemann/2015_easyctf_h_h4sh3d.md
- **关联**：分治爆破与 [[RSA 密文数字置换混淆（10! 枚举逆置换）]]（本批）的低熵层剥离同型；"先找结构弱点再动手"与 [[动态步长 XOR 的最低位恢复攻击（奇偶驱动自同步）]] 的两阶段法方法论一致。
- **熵控预检**：Q1 无重名；Q3 强（哈希源码+爆破脚本在 WP）；Q4 边 1 条。
