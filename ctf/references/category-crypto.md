---
verified: "2026-10-15 | 本地复跑：Python 3.12.13 + pycryptodome 3.23.0 + OpenSSL 3.5.6（Linux 容器），见条目1/3复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "CTF-wiki（crypto 章节）、PayloadsAllTheThings（RSA）、M2 实测复跑（2026-10-15）"
changelog:
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
