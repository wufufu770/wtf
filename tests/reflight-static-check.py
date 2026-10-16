#!/usr/bin/env python3
"""REFLIGHT 静态校验脚本（M2 落地，v0.4 增第 4 检；对应 shared/REFLIGHT.md §5 与 PORTABILITY.md「结构验证后续补 CI」）

校验四件事（均为纯文本静态检查，任何 Agent/CI 可复跑）：
1. 状态词枚举：frontmatter status ∈ 五态（含旧词映射 draft/deprecated）
2. 裁决词正则：条目裁决词 ∈ {待复跑} ∪ ^(PASS|FAIL|INCONCLUSIVE)$
3. 复跑表存在性：文件内出现 PASS/FAIL/INCONCLUSIVE 裁决 ⇒ 必须有复跑记录表（verified/refuted/inconclusive 必备，REFLIGHT §4）
4. 图边引用存在性（v0.4）：[[条目名]] 引用必须命中全库某个 ### 级条目标题（REFLIGHT §3「升级」字段边化——条目间构成可 grep 的有向图）

用法：在仓库根目录 `python3 tests/reflight-static-check.py`；退出码 0=全部通过，1=存在违例。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = sorted(
    list((ROOT / "ctf" / "references").glob("*.md"))
    + list((ROOT / "pentest" / "references").glob("*.md"))
    + list((ROOT / "shared" / "tools").glob("*.md"))
)
STATUS_OK = {"hypothesis", "verifying", "verified", "refuted", "inconclusive", "draft", "deprecated"}
VERDICT_OK = {"待复跑", "PASS", "FAIL", "INCONCLUSIVE"}
# 条目裁决词的两种写法：五段式「**裁决词**：X」与工具条目「状态：...｜裁决词：X」
RE_VERDICT = re.compile(r"(?:\*\*裁决词\*\*：|裁决词：)\s*([A-Z]+|待复跑)")
RE_TABLE = re.compile(r"\|\s*#\s*\|\s*日期\s*\|")
RE_STATUS = re.compile(r"^status:\s*(\S+)", re.M)
# v0.4 第 4 检：有向图的节点（### 级条目标题）与边（[[条目名]] 引用）
RE_ENTRY = re.compile(r"^###\s+(.+?)\s*$", re.M)
RE_EDGE = re.compile(r"\[\[([^\[\]]+)\]\]")


def entry_index(paths):
    """全库条目标题索引（图的节点集）——排除「复跑记录」表头。"""
    names = set()
    for p in paths:
        for h in RE_ENTRY.findall(p.read_text(encoding="utf-8")):
            h = h.strip()
            if not h.startswith("复跑记录"):
                names.add(h)
    return names


def check_file(path: Path, nodes: set):
    errs = []
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---", text, re.S)
    fm = m.group(1) if m else ""
    sm = RE_STATUS.search(fm)
    if not sm:
        errs.append("frontmatter 缺 status")
    elif sm.group(1) not in STATUS_OK:
        errs.append(f"status 非法词：{sm.group(1)}")
    verdicts = RE_VERDICT.findall(text)
    if not verdicts:
        if "（空——等待首个回流条目）" in text or "路由表" in text or re.search(r"^#\s+共享工具层索引", text, re.M):
            return [], [], []  # 空壳/索引文件豁免
        if path.name in {"scope-authorization.md", "scope-hook-spec.md"}:
            return [], [], []  # scope 模板/规范文件非条目库，豁免
        errs.append("未发现任何裁决词字段")
    for v in verdicts:
        if v not in VERDICT_OK:
            errs.append(f"裁决词非法：{v!r}（词表见 shared/REFLIGHT.md §2）")
    hard = [v for v in verdicts if v in {"PASS", "FAIL", "INCONCLUSIVE"}]
    if hard and not RE_TABLE.search(text):
        errs.append(f"存在硬裁决 {hard} 但无复跑记录表（REFLIGHT §4）")
    # 第 4 检只扫正文：frontmatter changelog 是元数据日志，允许出现 [[...]] 字面示例
    body = text[m.end():] if m else text
    edges = RE_EDGE.findall(body)
    for e in edges:
        e = e.strip()
        if e not in nodes:
            errs.append(f"图边引用目标不存在：[[{e}]]（REFLIGHT §3——引用必须命中全库条目标题）")
    return errs, verdicts, edges


def main():
    nodes = entry_index(TARGETS)
    total_entries, total_edges, problems = 0, 0, 0
    dist = {}
    for p in TARGETS:
        rel = p.relative_to(ROOT)
        errs, verdicts, edges = check_file(p, nodes)
        total_entries += len(verdicts)
        total_edges += len(edges)
        for v in verdicts:
            key = v if v == "待复跑" else "硬裁决"
            dist[key] = dist.get(key, 0) + 1
        if errs:
            problems += len(errs)
            for e in errs:
                print(f"[FAIL] {rel}: {e}")
        else:
            print(f"[PASS] {rel}: 裁决词 {len(verdicts)} 个，图边 {len(edges)} 条")
    print(f"\n== 校验文件 {len(TARGETS)} 个，条目裁决词共 {total_entries} 个 "
          f"（硬裁决 {dist.get('硬裁决', 0)} / 待复跑 {dist.get('待复跑', 0)}），"
          f"图边 {total_edges} 条 / 节点 {len(nodes)} 个，违例 {problems} 处 ==")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
