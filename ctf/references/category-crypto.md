---
verified: "2026-10-15 | 本地复跑：Python 3.12.13 + pycryptodome 3.23.0 + OpenSSL 3.5.6（Linux 容器），见条目1/3复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "CTF-wiki（crypto 章节）、PayloadsAllTheThings（RSA）、M2 实测复跑（2026-10-15）"
changelog:
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
- **来源**：网鼎杯 2022 青龙组 grasshopper（26 solved）｜lkok123（bugku WP 库）｜raw/cn-platforms/bugku/wp-detail/wp_1874.html（完整 exp 在 WP；正文 HTML 转换丢空格问题见试点报告 §7-B7）
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
- **来源**：HCTF 2017 babyRSA｜六星战队（sixstars）｜raw/github-repos/sixstars/2017_hctf_h_readme.md（交互协议与枚举脚本在 WP；e 空间小本地枚举快）
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
