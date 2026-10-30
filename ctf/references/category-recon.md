---
verified: "2026-10-30 | 回流复跑轮（接手 A）：7 条全裁决——3 PASS / 4 INCONCLUSIVE（OSINT 活体链与权威 NS 缺口留痕）；本机 Python3.12 + 活体 web 复走，见各条复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "ctf-corpus 蒸馏层 P1+P2 批次（distill/by-category/recon），原始 WP 见 ctf-corpus/raw/ 与 meta/register.jsonl"
changelog:
  - "[2026-10-30] v0.6：蒸馏 P3 批次并入 29 条（中段困难档·薄域优先，hypothesis 待复跑）｜源：ctf-corpus/distill/by-category/recon/p3-20261029.md + candidates.jsonl（P3 批次报告 02）"
  - "[2026-10-30] 回流复跑轮：7 条全裁决（CSAW 逐跳链/EXIF 原图/w3w 三条 PASS——A 亲复跑抽检活体一致；聚餐/MV/采购三条 INCONCLUSIVE 但锚点级抽查全部命中；DNS storage INCONCLUSIVE 权威 NS 双亡）；证据归档 shared/wtf-reflight-evidence-20261030/"
  - "[2026-10-29] v0.5 新库：蒸馏 P1+P2 批次建库并入 7 条（hypothesis 待复跑，REFLIGHT §1 二手知识纪律）｜11→10 库映射见 ctf-wp 采集规划 §4.4"
---

# 题型：信息搜集（OSINT/数据安全）

> 读取时机：OSINT 画像、地理定位、公开数据交叉、数据泄露甄别类题面（本条目主库）

## 填充规范（回流时遵守）

1. 条目模板 = 五段式假设条目：**假设 → 验证步骤 → 判定标准 → 裁决词 → 来源**（完整模板见 ../../shared/REFLIGHT.md §3），一技术一条目。
2. 裁决词只允许机器可校验标准词 **PASS / FAIL / INCONCLUSIVE**（词表见 ../../shared/REFLIGHT.md §2）；状态机：hypothesis → verifying → verified / refuted / inconclusive（§1）。
3. frontmatter 记录本文件最新验证状态；changelog 每次结构变更一行留痕（append-only）。
4. 「升级」字段跳转目标用双中括号图边引用，必须命中全库某个 ### 级条目标题（第 4 检；字面示例只准放 frontmatter）。
5. 未经复跑的条目状态只允许 hypothesis（REFLIGHT §1 二手知识纪律）。

## 条目区（TOC）
1. [recon 逐跳链解（人物 OSINT → 兴趣 → 常量异或谜面）](#recon-逐跳链解人物-osint-兴趣-常量异或谜面)（verified）
2. [多人聚餐时空定位（帖文 × 同行者评价 × 店内照交叉）](#多人聚餐时空定位帖文-同行者评价-店内照交叉)（inconclusive）
3. [MV 取景地反查（步道桥 → 近邻新开咖啡馆）](#mv-取景地反查步道桥-近邻新开咖啡馆)（inconclusive）
4. [跨语言公共采购数据链（新闻 → 招标额 → 中标企业 CEO）](#跨语言公共采购数据链新闻-招标额-中标企业-ceo)（inconclusive）
5. [EXIF 原图泄露与场景指纹定位（体育场 → 航班）](#exif-原图泄露与场景指纹定位体育场-航班)（verified）
6. [what3words 三词地址批量转坐标（免 API key 路线）](#what3words-三词地址批量转坐标免-api-key-路线)（verified）
7. [DNS 区记录存储枚举（TXT 名踩点 → 保险柜码）](#dns-区记录存储枚举txt-名踩点-保险柜码)（inconclusive）
8. [权限配置×操作日志双文件交叉违规检测（四违规码）](#权限配置操作日志双文件交叉违规检测四违规码)（hypothesis）
9. [数据安全治理操作链（脱敏→识别→备份→隔离→勒索恢复→共享）](#数据安全治理操作链脱敏识别备份隔离勒索恢复共享)（hypothesis）
10. [多类型泥沙文件隐私泄露普查（strings 降序 + whisper 语音转写）](#多类型泥沙文件隐私泄露普查strings-降序-whisper-语音转写)（hypothesis）
11. [HTTP 对象字母大小写矩阵二值化 QR（42×42）](#http-对象字母大小写矩阵二值化-qr4242)（hypothesis）
12. [Windows EFS（cipher.exe）密钥归档恢复（dpapi 私钥+主密钥）](#windows-efscipherexe密钥归档恢复dpapi-私钥主密钥)（hypothesis）
13. [Windows SAM bootKey 转储 + SilentEye 隐写双密钥链](#windows-sam-bootkey-转储-silenteye-隐写双密钥链)（hypothesis）
14. [AES-ECB 模式泄漏比对（跨帧同前缀 128bit）+ FF 异或](#aes-ecb-模式泄漏比对跨帧同前缀-128bit-ff-异或)（hypothesis）
15. [SMB 会话凭据还原 + 社工字典命名规律（姓名+生日）+ 后门账号回溯](#smb-会话凭据还原-社工字典命名规律姓名生日-后门账号回溯)（hypothesis）
16. [冰蝎已知密钥流量解密 + des3 salt 容器 + emoji 拼音密文](#冰蝎已知密钥流量解密-des3-salt-容器-emoji-拼音密文)（hypothesis）
17. [Webshell RSA 加密请求解码（双重 base64 + URL 解码 + 私钥回溯）](#webshell-rsa-加密请求解码双重-base64-url-解码-私钥回溯)（hypothesis）
18. [S7 写操作隐蔽通道重组（WRITE-only 过滤 + 凯撒 3 提示 + 红鲱鱼甄别）](#s7-写操作隐蔽通道重组write-only-过滤-凯撒-3-提示-红鲱鱼甄别)（hypothesis）
19. [MQTT 消息字段导出即明文尾巴（tshark -e mqtt.msg）](#mqtt-消息字段导出即明文尾巴tshark--e-mqttmsg)（hypothesis）
20. [DES 四密钥轮换密文共头比对（key_id 分组 + 明文头对齐）](#des-四密钥轮换密文共头比对key_id-分组-明文头对齐)（hypothesis）
21. [TPKT 常量甄别 + 倒数字节 ZIP 重组](#tpkt-常量甄别-倒数字节-zip-重组)（hypothesis）
22. [双日志分段文件重组 + 盲水印取密码](#双日志分段文件重组-盲水印取密码)（hypothesis）
23. [SMB2 NTLMv2 哈希提取与 hashcat 离线爆破](#smb2-ntlmv2-哈希提取与-hashcat-离线爆破)（hypothesis）
24. [自定义填充 AES-CBC 批量脱敏加密（长度前缀双层 + 行列序 MD5）](#自定义填充-aes-cbc-批量脱敏加密长度前缀双层-行列序-md5)（hypothesis）
25. [CobaltStrike Beacon 流量特征识别（submit.php+心跳）与元数据解密](#cobaltstrike-beacon-流量特征识别submitphp心跳与元数据解密)（hypothesis）
26. [SMB2 NTLMv2 脚本提取 + 认证后文件回溯](#smb2-ntlmv2-脚本提取-认证后文件回溯)（hypothesis）
27. [挖矿 IR 问卷链（路径→矿池→持久化，md5 口径留痕）](#挖矿-ir-问卷链路径矿池持久化md5-口径留痕)（hypothesis）
28. [自定义字母表 Base64 变体（IDA 加密函数逆向回推）](#自定义字母表-base64-变体ida-加密函数逆向回推)（hypothesis）
29. [DNS 外带重组（子域分片重排）+ 文件解密](#dns-外带重组子域分片重排-文件解密)（hypothesis）
30. [GTFS 公交实时/历史数据集定位（车番视觉提取 → 数据集回查）](#gtfs-公交实时历史数据集定位车番视觉提取-数据集回查)（hypothesis）
31. [FR24 航班快照画像（ICAO/注册号 → 机型航线画像描述题）](#fr24-航班快照画像icao注册号-机型航线画像描述题)（hypothesis）
32. [街景照片设施定位（双语检索 + 现地语正式名称）](#街景照片设施定位双语检索-现地语正式名称)（hypothesis）
33. [TLE 轨道外推最近过顶（历史 TLE 数据集 + Skyfield 传播）](#tle-轨道外推最近过顶历史-tle-数据集-skyfield-传播)（hypothesis）
34. [Modbus 功能码载荷 PDF 重组（9 字节偏移）+ 摩斯密码外链](#modbus-功能码载荷-pdf-重组9-字节偏移-摩斯密码外链)（hypothesis）
35. [冰蝎默认密钥识别 + 同形字双马甄别（she1l vs shell）](#冰蝎默认密钥识别-同形字双马甄别she1l-vs-shell)（hypothesis）
36. [NTLMv2 响应手工拆解（字段级 hash 形态）](#ntlmv2-响应手工拆解字段级-hash-形态)（hypothesis）

### recon 逐跳链解（人物 OSINT → 兴趣 → 常量异或谜面）
- **分层**：简单档·可复现强
- **假设**：人物题是逐跳链（每跳 URL 段 = 上一跳答案）：LinkedIn 定大学 → 大学黑客俱乐部缩写 → YouTube 对局视频定游戏主角色 → PNG 内藏下一跳 → 末跳 JS 常量异或（`^0x04` 自逆）解出路径段——**载体类型逐跳轮换**（网页/视频/图片/代码）是判别特征。
- **验证步骤**：1) 从题给人物定背景（LinkedIn/个人主页）；2) 每跳按题面模板拼接 URL（`/csaw2015/<answer>` 型）；3) 非文本载体（PNG）先 `strings`/16 进制查看器直查内嵌文本再上结构解析；4) 题面附带 JS 加密代码时直接原样复算（XOR 常量密钥自逆：`they_see_me_rollin`）；5) 末跳收旗。
- **判定标准**：PASS = 五跳贯通拿到旗；FAIL = 某跳线索不在预期载体 → 回查上一跳题面修饰语（"my super smash brothers main" 型提示兴趣载体）；人物信息缺口 → 换 OSINT 源（LinkedIn/YouTube/学术页）。
- **裁决词**：PASS
- **来源**：CSAW 2015 Alexander Taylor（recon 100p，424 solves）｜p4｜raw/github-repos/p4/2015_csaw_e_alexander-taylor.md（fuzyll.com 五跳实例全记录：wcsc → base64 谜面 → Marth → PNG → XOR）
- **关键差异**：与现库 recon 条目（证书透明度/被动域收集）互补：那是**面向域/资产**的 recon，本条是**面向人物**的逐跳 OSINT——两者路由不撞。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 活体 fuzyll.com（链路存活 10+ 年） | curl 逐跳 + base64 -d + PNG strings + XOR 0x4（B 全链重走） | PASS | shared/wtf-reflight-evidence-20261030/csaw2015/REPLAY-LOG.md | 5 跳全活体重放与 WP 一致（hop1/2/hop4/5 + PNG strings）；A 接手轮抽检 hop1/hop2 活体逐字一致；OSINT 三跳（wcsc/yoshi/enigma）采 WP 记录答案（人物历史事实不可改写） |
### 多人聚餐时空定位（帖文 × 同行者评价 × 店内照交叉）
- **分层**：困难档·复合链
- **假设**：三人首次同席的时间地点可由多平台碎片交叉锁定——同席者 SNS 帖（时间/食物）、同行者历史打卡评价（同行人数/点餐细节）、店内实景照片与 Google Maps 已传店内照比对（相似即同店）⇒ 汇聚出「日期+时刻+连锁品牌+分店名」。
- **验证步骤**：1) 拉取三人公开帖文建时间线；2) 交叉同行者的餐饮评价（汉堡细节/同行 2 人）；3) 店内照比对 Maps 分店相册；4) 用官方站点日文表记规范拼旗。
- **判定标准**：PASS = 唯一候选分店且格式校验通过；FAIL = 多候选 → 用「时刻+菜单细节」再收敛（免并列店名歧义）。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：全链活体重走未完成——SNS 帖文需 X 登录态（登录墙拦截，具体帖文 status id 不可免登录读取）。锚点级抽查已命中：①旗中分店 デニーズ大井町駅前店 活体存活（tabelog 129 评论、2026-09 在访 + 招聘页双源，店名/地址逐字一致）；②lilica X 账号存活（登录墙元数据可见，bio 与 WP 记录一致）。
- **来源**：Swimmer OSINT CTF 2026 ops_swimmer（457p/75 解）｜diver-osint-ctf（官方 writeup 仓）｜raw/github-repos/diver-osint-ctf/writeups/swimmer2026/ops_swimmer/ops_swimmer.md（判定依据链在 WP）
- **关联**：同「多源交叉」族 [[OSINT：证书透明度与被动域收集]]——关键差异 = 该条被动技术指纹、本条主动社媒行为链。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 活体 web 检索 + web_reader | 店名/地址检索 + X 账号旁路读取 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/recon234-osint-anchors.md | 锚点全命中（店存活/账号存活）；具备 X 登录态环境可续跑全链重走（日历+三人时间线+店内照比对） |
### MV 取景地反查（步道桥 → 近邻新开咖啡馆）
- **分层**：困难档·复合链
- **假设**：公开放送的音乐视频含可识别地标（步道桥护栏/路形）⇒ 逐帧截取地标 → 搜索/卫星图匹配具体桥位 → 半径内检索近年新开咖啡馆并核对街景。
- **验证步骤**：1) 抽帧定位含桥场景；2) 以护栏样式/周边建筑特征反查坐标；3) Maps 检索桥头近邻 cafe；4) 按题意取最近者拉丁转写。
- **判定标准**：PASS = 单一最近店；FAIL = 多候选歧义（赛事方曾追加等价旗）→ 按题面附加条件（年代/风格）弃权。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：全链活体重走未完成（MV 逐帧截取与街景比对未重走）。锚点级抽查已命中：Yandex Maps org 92586457895 活体解析为同名店 `Qara Qazan`（Almaty, ulitsa Zhansugurova 1，电话/营业时间齐全）——与 WP 记录答案一致；备选歧义旗 `Lagmankhana-halal` 的追认公告在 WP 记录自洽。
- **来源**：Diver OSINT CTF 2026 stargazing（417p/104 解）｜diver-osint-ctf（官方 writeup 仓）｜raw/github-repos/diver-osint-ctf/writeups/diver2026/geo/stargazing.md（含赛中对歧义旗的追认公告）
- **陷阱备注**：主办方因「题面条件不足以弃权等价店」追加了第二答案——出题侧应预留弃权条件，解题侧应报告歧义而非硬猜。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | web_reader Yandex Maps 旁路 | org 92586457895 直读 + 检索交叉 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/recon234-osint-anchors.md | 地标锚点命中（Qara Qazan 存活且同 org id）；MV 抽帧重定位列入剩余队列 |
### 跨语言公共采购数据链（新闻 → 招标额 → 中标企业 CEO）
- **分层**：困难档·复合链
- **假设**：阿拉伯语区的公共新闻与招标门户构成可追溯链——视频新闻定位设施 → 政府采购门户检索该设施关联标段 → 第 3 位投标额企业名 → 企业官网 about-us 页取 CEO 英文名。
- **验证步骤**：1) 视频元信息定位设施（阿曼）；2) 采购门户按时间窗（2024-10/11）检索 wells/pipeline 标段；3) 解析投标金额排序列表取第 3 名；4) 官网核名。
- **判定标准**：PASS = CEO 名与官网拼写一致；FAIL = 门户语言障碍 → 翻译工具逐栏比对后重试。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：中段活体重走未完成（阿拉伯语维基消歧跳转、门户开标列表 JS 交互视图、citypopulation.de 反爬拦截）。双端锚点已活体命中：①官方 etendering.tenderboard.gov.om 检索仍返回 Tender No. 1190/2023/MAFWR/DGAWRDK-94- Recall - 1（标题含 AL-BASHAYER VETERINARY HOSPITAL...WILAYAT ADAM，与 WP 逐字一致）；②goldensandsoman.com/about-us 活体读取 CEO=`Bader Al Malki`（=旗本体，同页多高管名与 WP 一致）。
- **来源**：Diver OSINT CTF 2025 bid｜diver-osint-ctf（官方 writeup 仓）｜raw/github-repos/diver-osint-ctf/writeups/diver2025/company/bid.md（门户检索路径在 WP）
- **关联**：Q2 候选——「各国公共采购门户清单」可下沉为工具条目。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | web_search 官方门户 + web_reader 企业官网 | etendering 检索 + goldensandsoman.com/about-us 直读 | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/recon234-osint-anchors.md | 双端锚点逐字命中（招标记录+CEO 名）；中间消歧跳转重走列入剩余队列 |
### EXIF 原图泄露与场景指纹定位（体育场 → 航班）
- **分层**：困难档·复合链
- **假设**：手机原图携带完整 EXIF（版本/品牌/ISO/日期/镜头参数）且画面含独特建筑（圆顶体育场横幅）⇒ EXIF 直答技术参数、地标检索定位城市（千叶海洋球场）→ 反推酒店方位；电梯/航班细节再由画面时间线（降落复飞）反查航班号段。
- **验证步骤**：1) exiftool 全字段导出；2) 横幅文字检索定位地标；3) 影子角度/时间交叉验证；4) 航班按机场+时刻窗筛两字航司+班号。
- **判定标准**：PASS = 全部子问题答对出旗；FAIL = 班号歧义 → 用机型/复飞记录收敛。
- **裁决词**：PASS
- **来源**：Hackergame 2022 旅行照片 2.0（general 100+150p）｜USTC-Hackergame（官方+选手，regymm）｜raw/github-repos/hackergame2022/2022_hackergame_h_2-0-200ced.md（EXIF 泄露风险科普+定位链在 WP）
- **关联**：与 [[acropalypse 截图裁剪漏洞恢复（尾数据 + 尺寸差）]] 同属「手机图像元数据/残留泄露」族——EXIF 是显式元数据、acropalypse 是隐式尾残留。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 本机 Python3.12 + PIL（原图 1.69MB JPEG） | exiftool/PIL 全字段导出 + 子问题答案独立复算 + 时区谜底重推 | PASS | shared/wtf-reflight-evidence-20261030/recon5-travel-photo-exif.log | 原件六项 EXIF（ExifVersion 2.31/Xiaomi/sm6115/ISO 84/2022-05-14 18:23:35/Flash 16）亲复算与 WP 全等；A 接手轮 PIL 独立抽验一致；注：GitHub raw 直链曾遭 rate-limit，原件经归档克隆路径取得（工作区留 rate-limit 残留文件如实记录） |
### what3words 三词地址批量转坐标（免 API key 路线）
- **分层**：困难档·单点
- **假设**：购物清单以 what3words 三词地址给出 ⇒ 借助 geocachingtoolbox 等第三方免 key 转换服务批量还原经纬度 → 按顺序连线，折线在地图上拼出旗形。
- **验证步骤**：1) 提取全部三词组；2) 批量转换坐标；3) 依清单顺序连点成图；4) 依连线方向确定起终点读旗。
- **判定标准**：PASS = 折线可读出旗；FAIL = 点序不明 → 试排列组合使笔画连续。
- **裁决词**：PASS
- **来源**：Hacky Easter 2026 Connect the Dots（misc medium）｜ngroegli｜raw/github-repos/ngroegli/hacky-easter-2026/Level4-4x4Overdrive/ConnecttheDots/README.md（转换服务与坐标清单在 WP）
- **关联**：[[数据库迷宫转储寻路（BFS 路径串旗）]] 的地理版——「路径即数据」同构，载体从网格换成地球表面。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 本机 Python3.12 + matplotlib | recon6-w3w-plot.py（三词组批量坐标转换 + 折线渲染 + 组序列复原） | PASS | shared/wtf-reflight-evidence-20261030/recon6-w3w-replay.log | 9+4+9+9 点折线渲染成图，组序列 he2026{H4PPY_3AST3R;_3v3RY0/ON3} 复现；A 接手轮亲复跑全复现（坐标转换基于 WP 已解三词表复算——what3words 在线服务有轮次限制，如实留痕） |
### DNS 区记录存储枚举（TXT 名踩点 → 保险柜码）
- **分层**：困难档·单点
- **假设**：AI 把自己的秘密写进特定 zone 的 TXT 记录（`*.mysterious-delivery.tcc`）⇒ 已知权威 NS → 逐名 dig TXT（子域名字典踩点：ot-secret-upon-flag 等语义名）→ 命中记录 base64 解码即旗。
- **验证步骤**：1) dig NS 找权威服务器；2) 语义子域名字典枚举 TXT；3) base64 -d 解码收旗。
- **判定标准**：PASS = 命中含密记录；FAIL = 枚举字典穷 → 从 pcap/题面提示语反推子域名构词。
- **裁决词**：INCONCLUSIVE
- **缺口清单**：①两台权威 NS（78.128.216.18 / 78.128.246.141）UDP/TCP 实测全超时（服务下线），NSEC 链活体踩点不可重走；②`.tcc` 从未进公网根区（根区 NSEC 覆盖 `tc.`），无第三方镜像/转储；③附件 dns_dump.txt 未入库，链中段仅 WP 自述。已复算子项：终跳 TXT base64 `RkxBR3tZcjMxLVhvWEUtNEZxOC02UElzfQ==` → `FLAG{Yr31-XoXE-4Fq8-6PIs}`（A 亲复算一致）；NSEC 链语义与 DNSSEC 记录（RRSIG/DNSKEY/SoA 2022100101）自洽。
- **来源**：The Catch 2022 DNS storage（misc）｜vernjan｜raw/github-repos/vernjan/write-ups/TheCatch2022/03-miscellaneous/03-dns-storage/README.md（dig 命令与记录内容在 WP）
- **关联**：与 [[OSINT：证书透明度与被动域收集]] 互补——CT 是被动旁路、DNS TXT 主动区踩点是「DNS 当存储信道」的新形态。
### 复跑记录（append-only）
| # | 日期 | 环境/靶场 | 命令或脚本 | 裁决词 | 工件路径 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 2026-10-30 | 活体 DNS（dig UDP/TCP + 根区 trace + base64 复算） | dig @权威 NS SOA/TXT + dig +trace + base64 -d | INCONCLUSIVE | shared/wtf-reflight-evidence-20261030/recon7-dns-storage-replay.log | 权威双亡 + 无公网授权（详缺口清单）；可复算子项 base64 旗与 NSEC 语义自洽；dns_dump.txt 附件入库或权威复活后可续跑 |

### 权限配置×操作日志双文件交叉违规检测（四违规码）
- **分层**：困难·单点
- **假设**：给出用户权限配置（用户/表/SQL 权限/root 位）与操作日志（时间/用户/表/SQL/IP），违规检测可穷举为四类码：越权账号（不在权限配置中）、无权表、无权 SQL 类型（超权限操作）、非 root 权限设置——双文件交叉比对即可程序化判定。
- **验证步骤**：1) 解析权限表为 (user,table)->perm set 映射；2) 逐行日志抽取四元组；3) 按四违规码逐项断言（账号存在性→表归属→SQL 类型∈权限→root 约束）；4) 按日志序拼接「违规码-日志号」（如 2-1,3-2,1-3,4-4）并取 32 位小写 MD5 输出。
- **判定标准**：PASS = 四码检测全覆盖且样例日志复检零漏判（示例答案 d320）；FAIL = 只做关键词黑名单（如 detect "DROP"）漏掉权限矩阵类违规。
- **裁决词**：待复跑
- **来源**：能源网络安全大赛 2025 数据库审计｜CTF-Archives 官方存档｜raw/cn-events/energy2025/2025_energy2025_数据库审计-2.md（四违规码表+示例全在存档）
- **关联**：数据安全治理主线；与 [[数据安全治理操作链（脱敏→识别→备份→隔离→勒索恢复→共享）]] 同母库；检测算法与 [[SQL 调试日志暗格式还原（gzdeflate+b64 双层）+ DNS 外带痕迹重建]] 的日志侧互补。

### 数据安全治理操作链（脱敏→识别→备份→隔离→勒索恢复→共享）
- **分层**：困难·流程
- **假设**：数据安全治理类赛题以《参赛手册》形式给出多子任务操作链：Oracle 字段脱敏规则、敏感数据识别（正则/字典双通道）、备份完整性校验、隔离区处置、勒索恢复时序、共享审批——按手册步骤序执行即合规流水线。
- **验证步骤**：1) 抽取手册各子任务判定口径（如手机号保留前 3 后 4）；2) 逐任务执行并留中间产物；3) 按提交格式（md5/CSV）组装；4) 与手册样例互验。
- **判定标准**：PASS = 各子任务产物与手册样例一致且总提交校验通过；FAIL = 跳过隔离/审批类「无产出」步骤导致链断裂。
- **裁决词**：待复跑
- **来源**：数信杯 2024 ZL01 新型数据安全治理参赛手册｜CTF-Archives 官方存档｜raw/cn-events/shuxincup2024/2024_shuxincup2024_zl01新型数据安全治理参赛手册.md（六任务链全在 WP）
- **关联**：与 [[权限配置×操作日志双文件交叉违规检测（四违规码）]] 同母库双形态（操作链 vs 检测器）；与 [[自定义填充 AES-CBC 批量脱敏加密（长度前缀双层 + 行列序 MD5）]] 共享脱敏-加密边界。

### 多类型泥沙文件隐私泄露普查（strings 降序 + whisper 语音转写）
- **分层**：困难·单点
- **假设**：三目录各 100 文件（txt/pdf/wav）中混有隐私泄露与恶意代码样本，可分型漏斗筛查：txt 人工正则（手机号/身份证/地址）、pdf 先 strings 转文本按文件大小降序（XSS 注入行显著拉长）、wav 用 whisper 转写筛口播敏感词——15 份目标可全回收。
- **验证步骤**：1) txt 正则跑三类 PII；2) PDF 批量 strings→txt 并按大小降序抽查；3) whisper base 模型中文转写全部 wav；4) 15 文件名按 txt,wav,pdf 字典序 _ 连接取 md5。
- **判定标准**：PASS = 三型各 5 份命中且拼接 md5 可提交；FAIL = 语音样本靠人工逐个听漏检（whisper 批处理为正解）。
- **裁决词**：待复跑
- **来源**：TSCTF-J 2025 BadFile（一血）｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_tsctf-j_h_badfile-一血.md（三型漏斗+md5 拼接脚本在 WP）
- **关联**：数据安全普查主线；与 [[千文件泥沙类型指纹漏斗（file+grep 单点筛选）]] 构成「找文件 vs 找内容」双漏斗；whisper 用法与多类型 PII 甄别可复用至合规审计。

### HTTP 对象字母大小写矩阵二值化 QR（42×42）
- **分层**：困难·单点
- **假设**：rar 解压密码藏在 HTTP 对象 hello.html 的字符墙中：全部字符按序排成 42×42 方阵，外围一圈为定位特征；大小写二值化（大写=1/小写=0）逐位绘 42×42 位图即 QR，扫描得解压密码。
- **验证步骤**：1) tshark/--export-objects 导出 HTTP 对象；2) 提取字符流验证长度=42²；3) 按大小写映射 0/1，PIL 绘图（scale 放大）；4) 扫码得 rar 密码→解出 falg.rar。
- **判定标准**：PASS = 位图外围定位符完整且扫码出可读密码；FAIL = 把字符墙当字典爆破（WP 明示非字典）。
- **裁决词**：待复跑
- **来源**：天山固网 2025 to｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_天山固网_h_to.md（42×42 位图脚本全量在 WP）
- **关联**：与 [[子图语义二分类重建 QR（87×87 比特矩阵）]] 同族（非像素载体 QR 重建）；与 [[迷宫染色 QR 修复（非白即黑 + 邻接反色）]] 共享「QR 残缺先重绘」直觉。

### Windows EFS（cipher.exe）密钥归档恢复（dpapi 私钥+主密钥）
- **分层**：困难·多段链
- **假设**：VHD 挂载后 public 目录 flag.jpg 仍加密 → 系统级 cipher/EFS 加密；EFS 解密需文件所有者（mark）的 dpapi 主密钥与 RSA 私钥，二者归档在 C:\Users\mark\AppData\Roaming\Microsoft\{Protect,Crypto}，PowerShell 历史/凭据可补口令。
- **验证步骤**：1) 磁盘精灵挂载 VHD 确认 EFS 属性与 owner；2) 提取 Protect/Crypto 双目录密钥档案；3) 用用户登录口令（或 DPAPI 官方工具）解主密钥；4) 导出证书私钥 → cipher /d 或直接解密 flag.jpg。
- **判定标准**：PASS = 私钥导出成功且 flag.jpg 可读；FAIL = 把 EFS 加密当 NTFS 权限问题或 BitLocker 处理。
- **裁决词**：待复跑
- **来源**：DubheCTF 2024 Cipher｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2024_dubhectf_h_cipher.md（EFS/dpapi 参考链+密钥路径在 WP）
- **关联**：Windows 数据安全主线；与 [[Windows SAM bootKey 转储 + SilentEye 隐写双密钥链]] 共享「系统凭据库优先」直觉；与 [[钓鱼 DFIR 报告链（邮件→msc→VBScript 解混淆→白 EXE 黑 DLL→RAT）]] 的主机取证侧互补。

### Windows SAM bootKey 转储 + SilentEye 隐写双密钥链
- **分层**：困难·多段链
- **假设**：sam+system 附件走 impacket-secretsdump 取 bootKey 与本地 NTLM 哈希（Administrator:500）；哈希可离线爆破（复用历史赛事口令）；strings sam 兜底出第二口令；binwalk -e system 内嵌 JPG 有 SilentEye 痕迹（黑白灰斑点），以爆出口令为 key 解出 openssl-AES256 密文——「系统凭据→隐写密钥」双链。
- **验证步骤**：1) secretsdump.py -sam -system 取 bootKey+NTLM；2) hashcat 离线爆破（历史哈希复用库）；3) strings sam 直读 p@s4w0rd；4) binwalk -e system→JPG→SilentEye（key=!checkerboard1）得 AES256 密文+盐值头。
- **判定标准**：PASS = Salted__ 头密文可用双口令链解开；FAIL = 只用单一口令硬套两种容器（系统口令≠隐写口令）。
- **裁决词**：待复跑
- **来源**：楚慧杯 2026 SAM_and_Steg｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2026_ev_h_sam-and-steg.md（NTLM 哈希与 hex 密文全量在 WP）
- **关联**：与 [[Windows EFS（cipher.exe）密钥归档恢复（dpapi 私钥+主密钥）]] 同为 Windows 凭据双链；SilentEye 甄别与 [[zsteg 多通道输出甄别（真通道 + 字体文件第二跳）]] 的工具族谱互补。

### AES-ECB 模式泄漏比对（跨帧同前缀 128bit）+ FF 异或
- **分层**：困难·单点
- **假设**：UDP data 帧中 hex 段揭示 AES-ECB（无 IV）；两帧密文前 16 字节全同 → ECB 同明文块同密文块的模式泄漏；FF 值为异或辅助钥——模式比对可定位密钥关系与明文结构。
- **验证步骤**：1) tshark 过滤 UDP，逐帧取 data hex；2) CyberChef 解码 frame4/5 得算法与 FF 提示；3) 比对 frame7 与 frame31 前 128bit 全同 → 确认 ECB 分组；4) 按 key=FF 异或流还原明文差异段。
- **判定标准**：PASS = 同前缀比对锁定 ECB 且异或后明文可读；FAIL = 按 CBC 找 IV（WP 明示无偏移量）。
- **裁决词**：待复跑
- **来源**：红明谷 2024 加密流量｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2024_hongminggu_h_加密流量.md（双帧密文同前缀证据在 WP）
- **关联**：加密流量主线；与 [[DES 四密钥轮换密文共头比对（key_id 分组 + 明文头对齐）]] 构成分组密码模式泄漏双条；与 [[CobaltStrike Beacon 流量特征识别（submit.php+心跳）与元数据解密]] 共享 UDP/HTTP 载荷解剖纪律。

### SMB 会话凭据还原 + 社工字典命名规律（姓名+生日）+ 后门账号回溯
- **分层**：困难·多段链
- **假设**：弱口令命名规律「姓名拼音+出生年月日」可由泄露通讯录构造社工字典；流量包中 SMB 会话含认证与 webshell 上传痕迹；后门账号密码藏于 webshell 上传会话——全链可由 pcap 重建并 md5(四元组) 提交。
- **验证步骤**：1) pcap 过滤 SMB2 会话与认证包；2) 按命名规律字典爆破得泄露凭据；3) 追踪 SMB 写入对象定位 webshell 文件名；4) 从后续会话提取后门账号密码；5) 按 flag 格式拼接 md5。
- **判定标准**：PASS = 四元组（泄露账号_密码_后门账号_密码）md5 自洽；FAIL = 漏掉后门账号段（只交泄露凭据）。
- **裁决词**：待复跑
- **来源**：泰山杯 2025 流量分析｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_ev_h_流量分析.md（场景+md5 拼接口径全在 WP）
- **关联**：NTLMv2 家族第三条（与 [[SMB2 NTLMv2 哈希提取与 hashcat 离线爆破]]、[[SMB2 NTLMv2 脚本提取 + 认证后文件回溯]] 组三角）；社工字典命名规律为独立可复用规律。

### 冰蝎已知密钥流量解密 + des3 salt 容器 + emoji 拼音密文
- **分层**：困难·多段链
- **假设**：冰蝎 AES-CBC 密钥已知（16 字节会话钥）可全量解密命令流；命令流告知 flag.tar.gz 为 openssl des3 -salt 加密（口令 th1sisKey）；解出内容为 emoji 序列，映射拼音首字母得明文——「流量解密→容器解密→异构编码」三跳。
- **验证步骤**：1) 已知 key 手动解冰蝎流量，提取加密命令与 flag.tar.gz；2) openssl des3 -d -salt -k th1sisKey 解容器；3) emoji→拼音映射逐枚转写；4) 拼接得 flag。
- **判定标准**：PASS = des3 解密出完整 emoji 串且拼音转写可读；FAIL = 直接把 emoji 当 flag 原文提交。
- **裁决词**：待复跑
- **来源**：台州市网络安全大赛 2023 这是神马｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2023_ev_h_这是神马.md（des3 命令+emoji 全量在 WP）
- **关联**：与 [[冰蝎默认密钥识别 + 同形字双马甄别（she1l vs shell）]] 构成冰蝎双条（已知钥 vs 默认钥）；emoji 异构编码与 [[零宽变体选择符隐写（VS17-256 偏移分组解码）]] 同属 Unicode 载体层。

### Webshell RSA 加密请求解码（双重 base64 + URL 解码 + 私钥回溯）
- **分层**：困难·单点
- **假设**：webshell 流量的请求体为「base64(去除换行 base64(payload))」双嵌套；shell 代码用 RSA 公钥加密（hint.py 内嵌 PEM），响应侧用对应私钥解——从流量中先恢复私钥再批解请求。
- **验证步骤**：1) 追 TCP 流，base64 解响应定位 hint.py 与日记/flag 文件名；2) 双重 base64 + urldecode 还原加密 shell 代码；3) 从样本侧恢复 RSA 私钥（公钥 PEM 对应）；4) 批量解密请求得到命令与回传。
- **判定标准**：PASS = 私钥解密链跑通且 hint.py/flag.txt 命令序列还原；FAIL = 单层 base64 后直接当明文（漏 URL 解码）。
- **裁决词**：待复跑
- **来源**：NKCTF 2024 Webshell_pro｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2024_nkctf_h_webshell-pro.md（双 base64+RSA 解密脚本在 WP）
- **关联**：与 [[冰蝎默认密钥识别 + 同形字双马甄别（she1l vs shell）]] 同为 webshell 流量取证（RSA vs 对称会话钥）；私钥回溯与 [[Windows EFS（cipher.exe）密钥归档恢复（dpapi 私钥+主密钥）]] 的密钥档案思维同型。

### S7 写操作隐蔽通道重组（WRITE-only 过滤 + 凯撒 3 提示 + 红鲱鱼甄别）
- **分层**：困难·多段链
- **假设**：S7common+Modbus 混合流量中，外带数据只在 S7 WRITE 变量操作；strings 泄露的提示墙多为红鲱鱼（READ 无效/噪声标记），真实线索：ZIP 四分片、M 区数据段、DB 区 0x60 口令、口令凯撒 3——按「仅 WRITE」策略重组。
- **验证步骤**：1) tshark 抽 S7 write 操作（s7comm 数据字段）；2) 按 DB 区地址 0x60 与 M 区段位拼装四分片；3) 凯撒 3 解提示得口令线索；4) 组 zip 解密得 flag；5) 核对 strings 墙中 RED_HERRING 标记已全部排除。
- **判定标准**：PASS = WRITE-only 重组出合法 zip 且口令可解；FAIL = 把 READ 响应无效数据当载荷（WP 明示无效）。
- **裁决词**：待复跑
- **来源**：工业信息安全技能大赛 2025 工控协议隐蔽通道分析附件｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_ev_h_工控协议隐蔽通道分析附件.md（提示墙全文在 WP）
- **关联**：工控主线双条之二（与 [[TPKT 常量甄别 + 倒数字节 ZIP 重组]] 组对）；红鲱鱼甄别与 [[元数据伪旗注释的格式校验防误信]] 同构（提示层诱饵）。

### MQTT 消息字段导出即明文尾巴（tshark -e mqtt.msg）
- **分层**：困难·单点
- **假设**：mqtt 流量中 flag 以十六进制藏在消息体尾部，字段级导出（-e mqtt.msg）+ CyberChef hex 转码即可直读——无需重组会话。
- **验证步骤**：1) tshark -T fields -Y mqtt -e mqtt.msg 导出；2) hex 转文本；3) 拉到末尾读 flag。
- **判定标准**：PASS = 导出流末尾直读 flag；FAIL = 逐包手工翻找漏掉末尾分片。
- **裁决词**：待复跑
- **来源**：工业信息安全技能大赛 2025 工业控制协议流量分析-3｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_ev_h_工业控制协议流量分析-3.md（tshark 命令+flag 在 WP）
- **关联**：工控主线最简形态；与 [[TPKT 常量甄别 + 倒数字节 ZIP 重组]] 同赛事系列，字段级导出纪律相同。

### DES 四密钥轮换密文共头比对（key_id 分组 + 明文头对齐）
- **分层**：困难·单点
- **假设**：100 个 UDP 包载荷为 DES 密文，前缀同长（明文头相同）且 key_id 标记四把轮换密钥——同 key_id 分组后按共头对齐，DES 分组特性可反推密钥/明文结构。
- **验证步骤**：1) strings 导出 json 载荷并剔除干扰字符；2) 按 key_id 分四组；3) 组内比对密文共头段验证明文头相同假设；4) 按 DES 弱性（56bit/分组共头）逐组还原。
- **判定标准**：PASS = 四组全解且明文头一致假设成立；FAIL = 假设四密钥独立轮换无规律直接穷举 56bit。
- **裁决词**：待复跑
- **来源**：浙江省信息通信业职业技能竞赛 2025 capture｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_浙江省信息通信业职业技能竞赛_h_capture.md（分组+共头证据在 WP）
- **关联**：与 [[AES-ECB 模式泄漏比对（跨帧同前缀 128bit）+ FF 异或]] 组成分组密码模式泄漏双条；DES 弱密钥史实与 [[自定义填充 AES-CBC 批量脱敏加密（长度前缀双层 + 行列序 MD5）]] 的现代口径互为对照。

### TPKT 常量甄别 + 倒数字节 ZIP 重组
- **分层**：困难·单点
- **假设**：TPKT continuation_data 大量重复常量（MMS_PAYLOAD_NORMAL）为背景噪声，异常行才是载荷；密码明文在首行 hex；ZIP 数据散布于各包倒数第二字节——先过滤常量再按位拼装。
- **验证步骤**：1) tshark 导出 continuation_data；2) !=常量过滤；3) 首行 hex 解密码；4) 按倒数第二字节收集 ZIP 字节流重组，修复损坏头。
- **判定标准**：PASS = 过滤后包数骤减且 ZIP 可解密；FAIL = 不过滤常量直接全局字符串搜索（噪声淹没）。
- **裁决词**：待复跑
- **来源**：工业信息安全技能大赛 2025 工业控制协议流量分析-2｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_ev_h_工业控制协议流量分析-2.md（过滤命令+重组流程在 WP）
- **关联**：与 [[S7 写操作隐蔽通道重组（WRITE-only 过滤 + 凯撒 3 提示 + 红鲱鱼甄别）]] 组工控双条（常量背景 vs 提示墙背景）；字节位抽取与 [[SMB2 NTLMv2 哈希提取与 hashcat 离线爆破]] 的字段纪律同源。

### 双日志分段文件重组 + 盲水印取密码
- **分层**：困难·单点
- **假设**：access.log 与 error.log 中 webshell 分段上传了加密压缩包与 JPG；日志去噪拼接可复原两文件；压缩包口令藏于 JPG 盲水印——「日志取证→文件复原→隐写口令」三跳。
- **验证步骤**：1) error.log 定位 webshell 行为序列；2) 按分段边界删除无效行拼接两文件；3) 校验 JPG/PK 魔数；4) 盲水印解图得口令解压 data.csv。
- **判定标准**：PASS = 重组文件魔数正确且盲水印可读；FAIL = 直接在日志里搜 flag 错过载体链。
- **裁决词**：待复跑
- **来源**：西湖论剑 2025 easydatalog｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_ev_h_easydatalog.md（重组+盲水印流程在 WP）
- **关联**：与 [[权限配置×操作日志双文件交叉违规检测（四违规码）]] 同为双日志取证（行为链 vs 规则比对）；盲水印家族与 [[JSON 载体图 XOR 计数器流水（相似度配对 + R 通道差分）]] 的图像隐写互补。

### SMB2 NTLMv2 哈希提取与 hashcat 离线爆破
- **分层**：困难·单点
- **假设**：SMB2 NTLMv2 认证挑战响应可用开源脚本从 pcap 提取为 hashcat 格式（user::domain:challenge:blob），rockyou 字典离线爆破即得口令——无需在线交互。
- **验证步骤**：1) 脚本抽取 NTLMv2 hash（示例条目 user::PC:challenge:response:blob）；2) hashcat -m 5600 + rockyou；3) 口令 12megankirwin12 命中后按题面续链。
- **判定标准**：PASS = hashcat 命中且口令可复登录验证；FAIL = 在线重放认证（无必要且流量不可控）。
- **裁决词**：待复跑
- **来源**：鹏城杯 2025 SMB｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_ev_h_smb.md（hash 样例+口令在 WP）
- **关联**：NTLMv2 三角主条（与 [[SMB2 NTLMv2 脚本提取 + 认证后文件回溯]]、[[SMB 会话凭据还原 + 社工字典命名规律（姓名+生日）+ 后门账号回溯]] 组三角）；离线爆破纪律为凭据取证基座。

### 自定义填充 AES-CBC 批量脱敏加密（长度前缀双层 + 行列序 MD5）
- **分层**：困难·单点
- **假设**：敏感字段（手机号/身份证/银行卡/邮箱）批量加密采用自定义双层填充：第一层前置「原长字节」，第二层补齐分组；AES-CBC + 指定 key/iv，输出 hex，最后按先行后列拼接取 md5——填充口径即考点。
- **验证步骤**：1) xlsx 逐列取数；2) 实现双层填充（长度字节前置+补位）；3) AES-CBC 加密转 hex；4) 行列序拼接 md5 提交。
- **判定标准**：PASS = 填充口径与题面样例一致且 md5 自洽；FAIL = 用标准 PKCS7 替代自定义双层填充。
- **裁决词**：待复跑
- **来源**：能源网络安全大赛 2025 数据加密｜CTF-Archives 官方存档｜raw/cn-events/energy2025/2025_energy2025_数据加密-2.md（自定义填充方案全在题面存档；解法为推断）
- **关联**：数据安全治理主线（与 [[数据安全治理操作链（脱敏→识别→备份→隔离→勒索恢复→共享）]] 同链）；与 [[DES 四密钥轮换密文共头比对（key_id 分组 + 明文头对齐）]] 构成新旧对称口径对照。

### CobaltStrike Beacon 流量特征识别（submit.php+心跳）与元数据解密
- **分层**：困难·多段链
- **假设**：CS Beacon HTTP 流量以 submit.php 上线与规律心跳为特征；元数据用内嵌 RSA 公钥加密，会话钥随包派生；Beacon 配置（主机名/用户/artifact.exe）以十六进制块形式可从流量重组——非标准「给密钥对」题，需自解元数据。
- **验证步骤**：1) 流量定位 submit.php 与心跳周期；2) 按 beacon 协议解密元数据（RSA 公钥内嵌于样本）；3) 重组配置十六进制块（WIN-…\Administrator\artifact.exe）；4) 输出主机画像与载荷链。
- **判定标准**：PASS = 元数据解出且配置块字段完整；FAIL = 照搬常规 CS 题的密钥对文件假设。
- **裁决词**：待复跑
- **来源**：西湖论剑 2025 cscs｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_ev_h_cscs.md（beacon 十六进制块全量在 WP）
- **关联**：与 [[Webshell RSA 加密请求解码（双重 base64 + URL 解码 + 私钥回溯）]] 同为 RSA 元数据层；与 [[钓鱼 DFIR 报告链（邮件→msc→VBScript 解混淆→白 EXE 黑 DLL→RAT）]] 构成 C2 主线（网络侧 vs 邮件侧）。

### SMB2 NTLMv2 脚本提取 + 认证后文件回溯
- **分层**：困难·多段链
- **假设**：SMB2 NTLMv2 响应可按 user::domain:challenge:response 手工拆解（无需脚本），hashcat 破解后继续在认证后 SMB 会话中回溯所传文件——破解只是链中段。
- **验证步骤**：1) 开源项目从认证包批量提取 NTLMv2 hash；2) hashcat 破解；3) 追 SMB2 写会话回溯传输文件并续解。
- **判定标准**：PASS = hash 提取可复现且文件回溯完整；FAIL = 只交口令不续文件链。
- **裁决词**：待复跑
- **来源**：强网杯 2024 谍影重重 5.0｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2024_qwb_h_谍影重重5-0.md（参考文章清单+流程在 WP）
- **关联**：NTLMv2 三角之二（与 [[SMB2 NTLMv2 哈希提取与 hashcat 离线爆破]]、[[SMB 会话凭据还原 + 社工字典命名规律（姓名+生日）+ 后门账号回溯]] 组三角）；「破解后回溯」与 [[Windows SAM bootKey 转储 + SilentEye 隐写双密钥链]] 的双链续挖同型。

### 挖矿 IR 问卷链（路径→矿池→持久化，md5 口径留痕）
- **分层**：困难·流程
- **假设**：挖矿应急响应题以问卷链推进：出口域名告警→内网 IP 定位（CMDB）→主机取证挖矿程序路径→矿池域名→持久化方式，各问以 echo -n|md5sum 口径提交——链路顺序即取证顺序。
- **验证步骤**：1) 解压 IR.zip（口令在公告）并登主机；2) 定位挖矿进程与二进制路径；3) strings/lsof 追矿池域名与连接；4) 逐问按 md5 口径留痕。
- **判定标准**：PASS = 问卷链全通且各 md5 与官方答案口径一致；FAIL = 直接交明文不走 md5 口径。
- **裁决词**：待复跑
- **来源**：陇剑杯 2023 IR｜CTF-Archives 官方存档｜raw/cn-events/longjian2023/2023_longjian2023_ir.md（问卷链+md5 口径全在 WP）
- **关联**：IR 主线；与 [[钓鱼 DFIR 报告链（邮件→msc→VBScript 解混淆→白 EXE 黑 DLL→RAT）]] 构成应急双链（主机挖矿 vs 邮件钓鱼）；与 [[权限配置×操作日志双文件交叉违规检测（四违规码）]] 的合规口径互为审计层。

### 自定义字母表 Base64 变体（IDA 加密函数逆向回推）
- **分层**：困难·多段链
- **假设**：流量中 Base64 形态密文按标准表解码为乱码 → 程序内自定义字母表；IDA 定位加密函数（sub_…），逆向回推映射表与分组方式，用同表变体解码流量密文。
- **验证步骤**：1) 逐包定位第 33414 等含 Base64 特征包；2) IDA 反汇编加密函数提表；3) 自实现变体 base64（映射替换）；4) 解密文续链。
- **判定标准**：PASS = 回推表与样本函数行为一致且流量密文可解；FAIL = 标准表硬解（乱码当噪声）。
- **裁决词**：待复跑
- **来源**：CISCN 2025 初赛 Kiwi｜Volcania·bili33 公开 WP｜raw/cn-events/ciscn/2025_ciscn_h_kiwi__bili33.md（IDA 函数与密文样本在 WP）
- **关联**：编码变体与 [[IEND 尾注 Baconian 大小写编码（strings 尾扫 + 字母表二分）]] 同为「字母表选择」层；与 [[零宽变体选择符隐写（VS17-256 偏移分组解码）]] 的 base64 外壳任务流同型。

### DNS 外带重组（子域分片重排）+ 文件解密
- **分层**：困难·多段链
- **假设**：DNS 查询子域为分片外带（序列号嵌于子域标签），按序重组得加密文件；解密口径藏于「werid file」附件链——先重排再解密。
- **验证步骤**：1) pcap 抽全部查询并按标签序列排序；2) 剥离包装后拼装文件；3) 校验魔数；4) 按题面线索解密得 flag。
- **判定标准**：PASS = 重排后文件魔数正确且解密成功；FAIL = 按 frame 顺序直拼（序列号才是真序）。
- **裁决词**：待复跑
- **来源**：HKCERT CTF 2023 Yes, I Know I Know｜siunam321｜raw/github-repos/siunam321/HKCERT-CTF-2023/forensics/Yes-I-Know-I-Know.md（DNS Exfiltration+Decrypt 章节在 WP）
- **关联**：DNS 外带家族（与 [[DNS 间隙 Manchester 信标（查询长度二进制化）]] 组双条：分片标签 vs 查询长度）；与 [[Go 勒索器逆向 + 云端密钥端点定位（strings 锚点）]] 的外带目标侧呼应。

### GTFS 公交实时/历史数据集定位（车番视觉提取 → 数据集回查）
- **分层**：困难·单点
- **假设**：SNS 视频中公交车的车番（20094）可从画面提取；公交实时/历史位置数据（GTFS-Realtime 归档）可反查该车在指定时刻的位置——「视觉锚点→公开数据集回查」。
- **验证步骤**：1) 帧提取确认车队（Broward County Transit）与车番；2) 检索 GTFS 数据集（历史归档）；3) 按时间戳（2026-07-04 18:00 当地）过滤车辆位置；4) 地图标注。
- **判定标准**：PASS = 数据集命中该车且时刻匹配；FAIL = 只靠街景肉眼比对（数据集路径更精确）。
- **裁决词**：待复跑
- **来源**：Diver OSINT CTF 2026 250｜diver-osint-ctf 官方 writeups｜raw/github-repos/diver-osint-ctf/writeups/diver2026/transportation/250.md（车番+GTFS 路径在 WP）
- **关联**：OSINT 主线；与 [[FR24 航班快照画像（ICAO/注册号 → 机型航线画像描述题）]] 同为交通实体画像；与 [[街景照片设施定位（双语检索 + 现地语正式名称）]] 共享「公开数据集优先」纪律。

### FR24 航班快照画像（ICAO/注册号 → 机型航线画像描述题）
- **分层**：困难·流程
- **假设**：Flightradar24 快照中目标航班可由注册号/呼号反查机型、航线、归属与当日轨迹，按规则文档逐项描述即得分——画像题考信息组织而非破解。
- **验证步骤**：1) 截图读注册号/呼号/高度速度；2) FR24/公开库反查机型与航线；3) 结合 19:00UTC 时窗描述当日航迹与特征；4) 按评分规则（机型/航线/异常点）组织答案。
- **判定标准**：PASS = 各画像项均有公开源支撑；FAIL = 凭外观猜测机型不查注册号。
- **裁决词**：待复跑
- **来源**：Diver OSINT CTF 2025 unknown_aircraft｜diver-osint-ctf 官方 writeups｜raw/github-repos/diver-osint-ctf/writeups/diver2025/report/unknown_aircraft.md（题目+规则引用在 WP）
- **关联**：与 [[TLE 轨道外推最近过顶（历史 TLE 数据集 + Skyfield 传播）]] 同为航空/航天实体定位；描述题口径与 [[挖矿 IR 问卷链（路径→矿池→持久化，md5 口径留痕）]] 的「按规则作答」同构。

### 街景照片设施定位（双语检索 + 现地语正式名称）
- **分层**：困难·单点
- **假设**：照片中心建筑可通过视觉特征（入口招牌/结构）与地图服务双语检索定位；答案要求现地语正式名称——先定位后转写。
- **验证步骤**：1) 提取照片视觉锚点（建筑样式/招牌/道路）；2) 地图/街景逐区比对定位建筑；3) 查该设施现地语正式名称；4) 按 Diver25{} 格式提交。
- **判定标准**：PASS = 定位唯一且名称为官方现地语写法；FAIL = 用英文俗称代替现地语正式名称。
- **裁决词**：待复跑
- **来源**：Diver OSINT CTF 2025 night_street｜diver-osint-ctf 官方 writeups｜raw/github-repos/diver-osint-ctf/writeups/diver2025/geo/night_street.md（题目+禁爬规则在 WP）
- **关联**：与 [[GTFS 公交实时/历史数据集定位（车番视觉提取 → 数据集回查）]] 同为地理画像；禁爬规则与 [[FR24 航班快照画像（ICAO/注册号 → 机型航线画像描述题）]] 的「公开信息边界」一致。

### TLE 轨道外推最近过顶（历史 TLE 数据集 + Skyfield 传播）
- **分层**：困难·流程
- **假设**：指定时刻卫星最近地面目标可用历史 TLE（题面给定时点）+ SGP4 传播（Skyfield）计算卫星星下点，与军事机场坐标集做最近邻匹配。
- **验证步骤**：1) 取题面时点 TLE（2024-06-06 发行的数据）；2) Skyfield 传播至 2024-06-07T05:01:07Z；3) 计算星下点/高度；4) 与机场坐标集最近邻匹配得基地名（现地语）。
- **判定标准**：PASS = 高度与最近基地均为唯一解且口径（切整）符合题面；FAIL = 用 TLE 未按指定时点（历史 TLE 才准确）。
- **裁决词**：待复跑
- **来源**：Diver OSINT CTF 2024 satellite｜diver-osint-ctf 官方 writeups｜raw/github-repos/diver-osint-ctf/writeups/diver2024/military/satellite.md（题目+时点约束在 WP）
- **关联**：与 [[FR24 航班快照画像（ICAO/注册号 → 机型航线画像描述题）]] 同为空天实体定位；TLE 数据集纪律与 [[GTFS 公交实时/历史数据集定位（车番视觉提取 → 数据集回查）]] 的「找对数据集」同型。

### Modbus 功能码载荷 PDF 重组（9 字节偏移）+ 摩斯密码外链
- **分层**：困难·多段链
- **假设**：Modbus func_code=3 响应载荷承载文件字节流，头部混入 9 个垃圾字节需跳过；重组出 PDF 内含网盘外链与摩斯 txt，摩斯译文为加密 PDF 口令——「协议载荷→文件重组→外链取证」。
- **验证步骤**：1) 过滤 func_code=3 响应取载荷；2) 跳过 9 字节偏移按序拼接校验 %PDF 魔数；3) PDF 内提取 lanzouo 链接与 morse txt；4) 摩斯译码得口令解加密 PDF。
- **判定标准**：PASS = 跳偏移后魔数正确且 PDF 可打开；FAIL = 不跳偏移直拼（头部损坏误判无载体）。
- **裁决词**：待复跑
- **来源**：工业信息安全技能大赛 2025 异常的数据流量包｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_ev_h_异常的数据流量包.md（func_code=3 与 9 字节偏移口径在 WP）
- **关联**：工控主线三条会师（与 [[S7 写操作隐蔽通道重组（WRITE-only 过滤 + 凯撒 3 提示 + 红鲱鱼甄别）]]、[[TPKT 常量甄别 + 倒数字节 ZIP 重组]]、[[MQTT 消息字段导出即明文尾巴（tshark -e mqtt.msg）]] 组工控四联）；偏移跳过与 [[TPKT 常量甄别 + 倒数字节 ZIP 重组]] 的噪声剔除同构。

### 冰蝎默认密钥识别 + 同形字双马甄别（she1l vs shell）
- **分层**：困难·单点
- **假设**：冰蝎流量以默认密钥 e45e329feb5d925b 可解；但同流量并存 shell.php 与 she1l.php（同形字伪装双马），各自会话密钥不同（如 5b4582c9d56b5b33）——默认钥开第一马，流 4 解密得第二马源码后需换钥。
- **验证步骤**：1) 默认钥解前段流量确认 shell.php；2) 文件名逐字符比对发现 she1l.php 同形字；3) 解密 HTTP 流 4 得第二马源码；4) 用其内嵌会话钥解后续流量。
- **判定标准**：PASS = 双马会话均解密且源码链还原；FAIL = 默认钥通吃假设（第二马独立会话钥）。
- **裁决词**：待复跑
- **来源**：西湖论剑 2025 IceWater｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2025_ev_h_icewater.md（双马命名+第二马源码全文在 WP）
- **关联**：与 [[冰蝎已知密钥流量解密 + des3 salt 容器 + emoji 拼音密文]] 构成冰蝎双条（默认钥+同形字陷阱 vs 已知钥）；同形字甄别与 [[零宽变体选择符隐写（VS17-256 偏移分组解码）]] 的「不可见字符层」互补。

### NTLMv2 响应手工拆解（字段级 hash 形态）
- **分层**：困难·单点
- **假设**：SMB2 NTLMv2 响应可按 user::domain:challenge:response:blob 手工拆解，无需脚本；hashcat -m 5600 直接吃该形态——字段级拆解是脚本失效时的兜底。
- **验证步骤**：1) 从认证包定位 NTLMSSP_AUTH 帧取 challenge/response；2) 按 user::MicrosoftAccount:challenge:response 形态拼 hash；3) hashcat + 字典爆破；4) 口令复核登录语义。
- **判定标准**：PASS = 手工 hash 被 hashcat 接受且命中；FAIL = challenge/response 字段错位（形态不符直接报错）。
- **裁决词**：待复跑
- **来源**：DASCTF 2024 弹道偏下｜Lunatic（A1natas）｜raw/team-blogs/goodlunatic/2024_dasctf_h_弹道偏下.md（NTLMv2 hash 样例全量在 WP）
- **关联**：NTLMv2 三角之三（与 [[SMB2 NTLMv2 哈希提取与 hashcat 离线爆破]]、[[SMB2 NTLMv2 脚本提取 + 认证后文件回溯]] 组三角）；手工拆解与 [[SMB2 NTLMv2 脚本提取 + 认证后文件回溯]] 的脚本路径互为冗余双保险。
