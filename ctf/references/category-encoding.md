---
verified: "未复跑（2026-10-16 新建，全部条目 hypothesis，等待首个回流）"
status: hypothesis
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "M2 实测复跑（2026-10-15 编码套娃）、CTF-wiki（编码）、CyberChef 使用范式"
changelog:
  - "[2026-10-16] v0.3 新建：编码分析题型 4 条（verified 1 / hypothesis 3），从 misc/crypto 拆出编码主库"
---

# 题型：编码分析（Encoding Analysis）

> 读取时机：题面给一串"乱码"、神秘字符串、一堆数字/符号，无密钥特征（区别于 crypto：**编码无密钥、加密有密钥**）。与 misc 分工：编码套娃主判据沉淀在本文件。

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态；changelog 追加一行/次，不删除历史。
4. **失败样本优先回流**：refuted 条目必须附 FAIL 复跑记录、失败原因与"下一步转哪个新假设"。
5. verified/refuted/inconclusive 条目必须附复跑记录表（格式见 ../../shared/REFLIGHT.md §4）；未经复跑的条目状态只允许 hypothesis。
6. 工具具体用法归 ../../shared/tools/ 对应文件（去重原则）。
7. 本文件超过 100 行时，在本节下方补 TOC 目录。

## 条目区（TOC）

1. [按字符集特征逐层识别编码链](#按字符集特征逐层识别编码链)（verified）
2. [非常规编码家族：数字系与符号系](#非常规编码家族数字系与符号系)（hypothesis）
3. [Unicode 隐形字符与零宽注入](#unicode-隐形字符与零宽注入)（hypothesis）
4. [编码与加密的分界判定](#编码与加密的分界判定)（hypothesis）

### 按字符集特征逐层识别编码链
- **假设**：编码识别不靠猜，靠字节特征表：`+/=`→base64、`0-9A-F`偶长→hex、`\x1f\x8b`→gzip、`\x78\x9c`/`\x78\x01`→zlib、纯 01→二进制、`.- `三符→摩斯。逐层剥到明文。
- **验证步骤**：
  ```python
  # 循环：查首字节特征 -> 选解码器 -> 解一层 -> 重复，直到 printable 占比 >90%
  # 套娃上限经验：CTF 题一般 2~5 层；超过 5 层考虑第一层判断就错了
  ```
  M2 实测（2026-10-15，继承自 misc 条目1）：`b64(b64(gzip(flag)))` 三层样本按特征解链完整还原，复现路径 `b64decode ×2 → gzip.decompress`。
- **判定标准**：还原出 flag/可读文本 → PASS；层数穷尽仍未明文 → FAIL 转 2 号非常规编码假设。
- **裁决词**：待复跑（base64/gzip 链路实测；hex/zlib 特征同表待补充实测样本）
- **来源**：M2 REFLIGHT 实战闭环（2026-10-15）、CTF-wiki 编码章节

### 非常规编码家族：数字系与符号系
- **假设**：字符集特征表命不中时，按"数字系/符号系/图形系"三家族排查：数字系（ook!、brainfuck 变体、坐标数对、book code 页行词）、符号系（JSFuck、符号Brainfuck、颜文字 AA）、图形系（二维码/条码/盲文/旗语）。
- **验证步骤**：
  ```bash
  # 数字系：先看数字对数与分组（偶数组→坐标/书码页行）；OOK: .?.. 形态
  # 符号系：全由 []+!() 组成 → JSFuck eval；zcoin 颜文字 → aaencode
  # 图形系：file/QR 识别工具直接解码
  ```
- **判定标准**：对应家族解码出 flag → PASS；三家族全试无果 → FAIL 转 crypto 假设（可能是带密钥的加密）。
- **裁决词**：待复跑
- **来源**：CTF-wiki misc、CyberChef Magic 操作码表

### Unicode 隐形字符与零宽注入
- **假设**：文本"看起来什么都没有"或字符串长度与可见字符数不符 → 存在零宽字符（U+200B/200C/200D/FEFF）或 Unicode 混排隐写，按位组合还原二进制。
- **验证步骤**：
  ```python
  s = open('msg.txt', encoding='utf-8').read()
  hidden = [c for c in s if ord(c) in (0x200b,0x200c,0x200d,0xfeff,0x2060)]
  # 每类零宽字符映射 0/1 → 拼二进制 → bytes
  print(len(s), len(hidden))
  ```
- **判定标准**：隐形字符按位解码出 flag → PASS；无隐形字符或解码乱码 → FAIL。
- **裁决词**：待复跑
- **来源**：Zero-width stego 公开工具（zwsp-steg）、Unicode 隐写赛题题解

### 编码与加密的分界判定
- **假设**：拿到乱码先回答"这是编码还是加密"：无密钥/密钥即算法名 → 编码（本文件）；有明确密钥材料（RSA 参数/密钥串）→ crypto（category-crypto.md）。判定错方向是编码题第一大浪费源。
- **验证步骤**：
  ```text
  1. 有无密钥线索（题面 key、附件 .key/.pem）？无 → 编码系优先
  2. 解码尝试 2~3 层失败且输出高熵 → 转 crypto（可能是 AES/RC4 密文）
  3. 输出低熵但不可读（如 Base85 的 b'' 边界）→ 换家族重试
  ```
- **判定标准**：30 分钟内按分界路径找到正确家族 → PASS；反复跨家族乱试 → FAIL（复盘记录分界信号缺失点）。
- **裁决词**：待复跑
- **来源**：M2 复盘经验（编码套娃实战）、CyberChef Magic 自动识别逻辑
