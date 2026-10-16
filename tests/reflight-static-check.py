#!/usr/bin/env python3
"""REFLIGHT 静态校验脚本（M2 落地，对应 shared/REFLIGHT.md §5 与 PORTABILITY.md「结构验证后续补 CI」）

校验三件事（均为纯文本静态检查，任何 Agent/CI 可复跑）：
1. 状态词枚举：frontmatter status ∈ 五态（含旧词映射 draft/deprecated）
2. 裁决词正则：条目裁决词 ∈ {待复跑} ∪ ^(PASS|FAIL|INCONCLUSIVE)$
3. 复跑表存在性：文件内出现 PASS/FAIL/INCONCLUSIVE 裁决 ⇒ 必须有复跑记录表（verified/refuted/inconclusive 必备，REFLIGHT §4）

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


def check_file(path: Path):
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
            return [], []  # 空壳/索引文件豁免
        if path.name in {"scope-authorization.md", "scope-hook-spec.md"}:
            return [], []  # scope 模板/规范文件非条目库，豁免
        errs.append("未发现任何裁决词字段")
    for v in verdicts:
        if v not in VERDICT_OK:
            errs.append(f"裁决词非法：{v!r}（词表见 shared/REFLIGHT.md §2）")
    hard = [v for v in verdicts if v in {"PASS", "FAIL", "INCONCLUSIVE"}]
    if hard and not RE_TABLE.search(text):
        errs.append(f"存在硬裁决 {hard} 但无复跑记录表（REFLIGHT §4）")
    return errs, verdicts


def main():
    total_entries, problems = 0, 0
    dist = {}
    for p in TARGETS:
        rel = p.relative_to(ROOT)
        errs, verdicts = check_file(p)
        total_entries += len(verdicts)
        for v in verdicts:
            key = v if v == "待复跑" else "硬裁决"
            dist[key] = dist.get(key, 0) + 1
        if errs:
            problems += len(errs)
            for e in errs:
                print(f"[FAIL] {rel}: {e}")
        else:
            print(f"[PASS] {rel}: 裁决词 {len(verdicts)} 个")
    print(f"\n== 校验文件 {len(TARGETS)} 个，条目裁决词共 {total_entries} 个 "
          f"（硬裁决 {dist.get('硬裁决', 0)} / 待复跑 {dist.get('待复跑', 0)}），违例 {problems} 处 ==")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
