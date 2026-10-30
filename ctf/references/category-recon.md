---
verified: "2026-10-30 | 回流复跑轮（接手 A）：7 条全裁决——3 PASS / 4 INCONCLUSIVE（OSINT 活体链与权威 NS 缺口留痕）；本机 Python3.12 + 活体 web 复走，见各条复跑记录"
status: verified
# status 取值：hypothesis（假设）| verifying（验证中）| verified（复跑通过）| refuted（证伪，需附失败原因）| inconclusive（证据不足挂起）；旧词映射 draft≡hypothesis、deprecated≡refuted（见 ../../shared/REFLIGHT.md §1）
source: "ctf-corpus 蒸馏层 P1+P2 批次（distill/by-category/recon），原始 WP 见 ctf-corpus/raw/ 与 meta/register.jsonl"
changelog:
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
