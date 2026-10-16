---
verified: "2026-10-15 | 本地复跑：Python 3.12.13 + pycryptodome 3.23.0 + OpenSSL 3.5.6 + gcc 13 + binutils readelf/objdump（Linux 容器），见条目复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../shared/REFLIGHT.md §1）
source: "M2 实测复跑（2026-10-15）；OpenSSL/GNU binutils 官方文档；pwntools/CTF-wiki 文档"
changelog:
  - "[2026-10-15] 初始空壳，等待首个回流条目"
  - "[2026-10-15] v0.2：条目模板升级为五段式假设条目 + 机器可校验裁决词（REFLIGHT 回流协议，见 ../shared/REFLIGHT.md）"
  - "[2026-10-15] v0.3：M2 填充 6 条工具条目（verified 4 / hypothesis 2）"
---

# 二进制与密码学工具

> 读取时机：需要 gdb/pwntools/ghidra/openssl/sage 等用法时
> 本文件为 pentest 与 ctf 双 skill 的**去重共享层**：工具用法只在此维护一份，两个 skill 仅以相对路径引用（../shared/tools/），禁止在任何一侧复制粘贴工具内容。

## 填充规范

1. 条目格式：**工具名 + 一句话用途 + 精确命令模板 + 常见坑**；一个工具用法一条目。
2. frontmatter 的 verified/status/source/changelog 语义同各 skill references（最近验证日期+环境 / 五态 / 出处 / 追加式变更记录）；条目状态机与机器可校验裁决词（PASS/FAIL/INCONCLUSIVE）见 ../shared/REFLIGHT.md。
3. 平台差异（如 Windows/Linux 参数不同）单列小节，不拆文件。
4. 本文件超过 100 行时补 TOC；条目过多时按工具名首字母排序。

## 条目区（TOC）

1. [openssl pkeyutl RSA 解密（padding 显式化）](#openssl-pkeyutl-rsa-解密padding-显式化)（verified + refuted 姊妹条）
2. [python pycryptodome：RSA 数论脚本骨架](#python-pycryptodome-rsa-数论脚本骨架)（verified）
3. [readelf / objdump ELF 结构侦察](#readelf--objdump-elf-结构侦察)（verified）
4. [python 标准库：编码解链循环](#python-标准库编码解链循环)（verified）
5. [gdb + GEF/pwndbg 插件](#gdb--gefpwndbg-插件)（hypothesis）
6. [pwntools 核心用法](#pwntools-核心用法)（hypothesis）

### openssl pkeyutl RSA 解密（padding 显式化）
- **用途**：命令行 RSA 加解密/签名；CTF 场景主要用来交叉验证 python 脚本算出的明文。
- **命令模板**：
  ```bash
  openssl pkeyutl -decrypt -inkey priv.pem -in c.bin                    # 默认 PKCS#1 v1.5
  openssl pkeyutl -decrypt -inkey priv.pem -in c.bin -pkeyopt rsa_padding_mode:none   # 原始/textbook RSA
  openssl pkeyutl -decrypt -inkey priv.pem -in c.bin -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256                                          # OAEP（注意同时指定 hash）
  ```
- **常见坑**：padding 不匹配时**不报错、exit 0、输出伪随机字节**（OpenSSL 3.2+ 隐式拒绝机制，详见 ../ctf/references/category-crypto.md 条目2 的 refuted 复跑记录）——判定必须核对输出内容/长度而非退出码；负指数场景 openssl 无对应参数，回 python 模逆元。
- **状态**：verified（PASS 复跑 2026-10-15，no-padding 显式模式正确解出；姊妹 FAIL 记录证伪了"默认参数万能"假设）｜裁决词：PASS

### python pycryptodome：RSA 数论脚本骨架
- **用途**：CTF RSA 题的主力脚本库（无 gmpy2 环境时的兜底）。
- **命令模板**：
  ```python
  from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime, inverse
  m = pow(c, d, n)                    # 常规解密
  mi = inverse(c1, n)                 # 模逆元（负指数/共模攻击用）
  # 扩展欧里得手写（pycryptodome 无 egcd）：
  def egcd(a,b):
      if b==0: return (a,1,0)
      g,x,y = egcd(b,a%b); return (g,y,x-(a//b)*y)
  ```
- **常见坑**：`pow(c,-1,n)` 需 Python 3.8+；`long_to_bytes` 输出无前导零——按 n 的位长补齐 128/256 字节再判格式；老脚本用 `Crypto` 导入名，新版包名 pycryptodome 不变。
- **状态**：verified（PASS 复跑 2026-10-15：共模攻击 egcd 骨架完整恢复明文，见 ../ctf/references/category-crypto.md 条目1）｜裁决词：PASS

### readelf / objdump ELF 结构侦察
- **用途**：零依赖环境下的 ELF 结构与反汇编侦察（无 Ghidra/IDA 时的第一步）。
- **命令模板**：
  ```bash
  readelf -h bin | head -8        # 魔数/架构/入口：确认 32/64 位与 PIE
  readelf -S bin                  # 节表：壳特征节名（UPX0/UPX1）与异常空节
  objdump -d -M intel bin | head -40   # intel 语法反汇编，比 AT&T 可读
  ```
- **常见坑**：stripped 二进制无符号表，objdump 反汇编从 `_start` 起读需先 `readelf -h` 找 entry；动态段看 `readelf -d` 找依赖库。
- **状态**：verified（PASS 复跑 2026-10-15：ELF64/PIE 判定与 intel 反汇编均正常输出）｜裁决词：PASS

### python 标准库：编码解链循环
- **用途**：misc 编码套娃的通用解链器（无 CyberChef 环境时）。
- **命令模板**：
  ```python
  import base64, gzip, zlib, bz2, lzma
  d = open('cipher.txt','rb').read()
  for _ in range(2): d = base64.b64decode(d)   # 按层特征手动编排
  d = gzip.decompress(d)
  ```
- **常见坑**：b64 padding 缺失先补 `=`（`d += b"="*(-len(d)%4)`）；gzip/zlib/bz2/lzma 按头字节路由（`\x1f\x8b`/`\x78`/`BZh`/`\xfd7zXZ`）；urlsafe 变体用 `urlsafe_b64decode`。
- **状态**：verified（PASS 复跑 2026-10-15：b64×2+gzip 三层链完整解出，见 ../ctf/references/category-misc.md 条目1）｜裁决词：PASS

### gdb + GEF/pwndbg 插件
- **用途**：动态调试 ELF：断点/内存查看/ exploiting 时的寄存器与栈观测。
- **命令模板**：
  ```bash
  gdb -q ./chall
  # GEF 插件下：
  #   pattern create 200 / pattern offset <RIP值>   # 栈偏移定位（无 pwntools 时）
  #   vmmap / checksec / x/20gx $rsp
  b *main+42 ; run ; ni / si / c
  ```
- **常见坑**：gdb 默认 ASLR 关闭，地址与真实运行有差（用 `set disable-randomization off` 复现真实布局）；插件二选一安装（GEF 与 pwndbg 同装会冲突）；容器环境常缺 gdb，先 `which gdb` 探测。
- **状态**：hypothesis（本机无 gdb，未复跑）｜裁决词：待复跑

### pwntools 核心用法
- **用途**：pwn 题 exploit 脚本框架：交互、payload 构造、偏移定位。
- **命令模板**：
  ```python
  from pwn import *
  p = process('./chall')  # 或 remote('host', port)
  p.sendline(cyclic(200))                    # 偏移定位
  cyclic_find(p.poll(True)[:8])              # 崩溃 RIP 反查偏移
  payload = flat({offset: p64(target)})      # 按偏移布局
  ```
- **常见坑**：`context.arch='amd64'` 忘设导致 asm/p64 字节序错；本地与远程 libc 不同时勿直接复用偏移；容器环境常未安装（`pip install pwntools`），缺环境时用标准库 socket + 手写 De Bruijn 替代。
- **状态**：hypothesis（本机无 pwntools，未复跑；共模/格式化字符串条目的 python 兜底路径均已实测）｜裁决词：待复跑

## 复跑记录（verified 条目必备，append-only；详细工件见 ../ctf/references 对应条目）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-15 | 本地 OpenSSL 3.5.6 | pkeyutl -decrypt（no-padding 对照组） | PASS | evidence/T2-padding | 默认 padding 组为姊妹 FAIL 记录（见 category-crypto.md 条目2） |
| 2 | 2026-10-15 | 本地 Python 3.12.13 + pycryptodome 3.23 | egcd 共模攻击脚本 | PASS | evidence/T1-commonmodulus | flag 完整恢复 |
| 3 | 2026-10-15 | 本地 binutils | readelf -h + objdump -d -M intel | PASS | evidence/t7_fmt | ELF64/PIE 判定正常 |
| 4 | 2026-10-15 | 本地 Python 3.12.13 | b64×2+gzip 解链 | PASS | evidence/t5.txt | 三层链完整解出 |
