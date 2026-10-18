#!/usr/bin/env python3
"""生成 Stryker 行级排除：行号 → 字符跨度（span）。

Stryker.NET 的细粒度过滤语法 `File.cs{start..end}` 中 start/end 是
**字符索引**（官方文档：indices of the first/last character），不是行号；
且 4.16 实证：span 排除仅在 **CLI -m 参数**下生效，config `mutate` 键会
静默忽略 span（wop-dotnet-sdk 2026-08-31 三轮对照实验：config 不生效、
CLI 生效）。因此本脚本输出 CLI 参数，由 scripts/mutation-test.sh 消费。

勿改用 ignore-methods：本仓 15 组等价点中 12 组与同方法真击杀共存
（第十轮实证：UrlEncodeJava 28killed / EncryptHeader.Parse 33 / Extract 31 /
BuildRequest 30 同方法均有真击杀），方法粒度排除会一并排掉非等价 killed、
虚化击杀率；唯 AlgorithmSuite.ctor 零误伤但单独混用两机制徒增复杂度。
字符跨度是唯一能贴合「逐条论证过的等价域」的粒度。

漂移防线（--check）只校验、不自动重定位：源码演进后由人工核对语义未变、
更新 EQUIVALENT_LINES/ANCHORS 行号，再 --init 重生成区间摘要快照。
两层校验：① ANCHORS 行前缀（快速定位失配）② 区间内容 sha256 摘要
（区间内任何变更即失败——单行前缀挡不住区间内部/尾侧改动）。

用法:
  gen-stryker-excludes.py            # 打印 span 参数（每行一条，runner 消费）
  gen-stryker-excludes.py --check    # 漂移校验（ANCHORS + 快照摘要），CI 用
  gen-stryker-excludes.py --init     # 重生成快照（更新清单后显式执行）
"""

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "Wop.Sdk"
SNAPSHOT = ROOT / "scripts" / "equivalent-span-snapshot.txt"

# 等价变异点清单（文件 → 行区间列表，行号为 2026-08-31 变基后）＋论证：
#   Codec 62-65   DecodeIndex 返回值仅进入 (idx & mask)!=0 判定，字符置换后非零性不变
#   Codec 73,138  byte 无符号，>> 与 >>> 恒等（C# 11 unsigned right shift）
#   ContentDigest 43,84 IndexOf↔LastIndexOf：恰一空格合法域两者恒等、非法域均拒
#   ContentDigest 44    sp==0 不可达（tag 为空时先落 Invalid 同码同文案）
#   SignHeader 49,50    同上两类（Trim 后 sp==0 不可达；单空格域等价）
#   EncryptHeader 20    value=null 与 "Stryker was here!" 同落 23 行同文案
#   EncryptedEnvelope 33 continue 删除后顺序执行与下轮迭代等价
#   KeyCodec 59         标准 PEM 数据行不含 '-'（base64 字母表），StartsWith↔EndsWith 不可分
#   Transport 52        baseUrl null 与 SH! 均使 Uri 构造失败、同文案
#   WopClient 85        wireBody 非 null 且空不可达（上游 { Length: > 0 } 保证）
#   WopClient 171       Verify 头字典 OrdinalIgnoreCase，To↔Upper 等价
#   WopCrypto 36,50     off 上界恒为 len-1，< ↔ <= 等价
#   WopCrypto 183-186   OpenMessage 显式 fail-fast 与 catch 兜底同 Fuzzy 文案（保留代码、排除变异）
#   AlgorithmSuite 40-48 构造函数体删除在本仓 nullable 严格编译下为 CS8618 编译错，
#                        Stryker 内部编译语境存活、不可稳定复现
EQUIVALENT_LINES: dict[str, list[tuple[int, int]]] = {
    "Codec.cs":           [(62, 65), (73, 73), (138, 138)],
    "ContentDigest.cs":   [(43, 44), (84, 84)],
    "SignHeader.cs":      [(49, 50)],
    "EncryptHeader.cs":   [(20, 20)],
    "EncryptedEnvelope.cs": [(33, 33)],
    "KeyCodec.cs":        [(59, 59)],
    "Transport.cs":       [(52, 52)],
    "WopClient.cs":       [(143, 143), (279, 279)],
    "WopCrypto.cs":       [(35, 35), (49, 49), (192, 195)],
    "AlgorithmSuite.cs":  [(40, 48)],
}

# 行号锚（漂移检测第一层）：行内容前缀 → 快速定位失配
ANCHORS: dict[tuple[str, int], str] = {
    ("Codec.cs", 62): "if (c >= 'A' && c <= 'Z')",
    ("Codec.cs", 73): "chars[i * 2] = HexLower",
    ("Codec.cs", 138): "sb.Append('%')",
    ("ContentDigest.cs", 43): "var sp = value.IndexOf",
    ("ContentDigest.cs", 44): "if (sp < 0)",
    ("ContentDigest.cs", 84): "var hex = headerValue.Substring",
    ("SignHeader.cs", 49): "var sp = trimmed.IndexOf",
    ("SignHeader.cs", 50): "if (sp <= 0)",
    ("EncryptHeader.cs", 20): "var v = (value ?? \"\").Trim()",
    ("EncryptedEnvelope.cs", 33): "continue;",
    ("KeyCodec.cs", 59): "if (t.Length == 0 || t.StartsWith",
    ("Transport.cs", 52): "_baseUrl = baseUrl ??",
    ("WopClient.cs", 143): "if (wireBody is { Length: > 0 })",
    ("WopClient.cs", 279): "headers[name.ToLowerInvariant()]",
    ("WopCrypto.cs", 35): "buffer[i] = off >= 0",
    ("WopCrypto.cs", 49): "buffer[i] = off >= 0",
    ("WopCrypto.cs", 192): "if (key.Length != suite.CekLength",
    ("AlgorithmSuite.cs", 40): "{",
}


def read_lines(name: str) -> list[str]:
    return (SRC / name).read_text(encoding="utf-8").split("\n")


def char_span(lines: list[str], start_line: int, end_line: int) -> tuple[int, int]:
    """1-based 行区间 → 0-based 字符跨度（含端点行全部内容）。"""
    start = sum(len(text_line) + 1 for text_line in lines[: start_line - 1])
    end = start + sum(len(text_line) + 1 for text_line in lines[start_line - 1 : end_line]) - 1
    return start, end


def span_digest(lines: list[str], lo: int, hi: int) -> str:
    """区间内容稳定摘要（sha256，规范入快照；区间内任何变更即失配）。"""
    body = "\n".join(lines[lo - 1 : hi])
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


def iter_spans():
    for name, ranges in sorted(EQUIVALENT_LINES.items()):
        lines = read_lines(name)
        for lo, hi in ranges:
            yield name, lo, hi, lines


def check() -> int:
    drifted = [f"ANCHOR {name}:{line} 期望前缀 {prefix!r} 实际 {actual!r}"
               for (name, line), prefix in sorted(ANCHORS.items())
               if not (actual := read_lines(name)[line - 1].strip()).startswith(prefix)]
    if not SNAPSHOT.exists():
        print(f"区间摘要快照缺失: {SNAPSHOT}（先 --init）", file=sys.stderr)
        return 1
    expected = {}
    for row in SNAPSHOT.read_text(encoding="utf-8").split("\n"):
        if row and not row.startswith("#"):
            name, lo, hi, digest = row.split(":")
            expected[(name, int(lo), int(hi))] = digest
    actual = {(name, lo, hi): span_digest(lines, lo, hi)
              for name, lo, hi, lines in iter_spans()}
    if set(expected) != set(actual):
        drifted.append(f"快照区间集失配：清单 {len(actual)} vs 快照 {len(expected)}"
                       f"（差集 {set(actual) ^ set(expected)}）")
    for key in sorted(set(expected) & set(actual)):
        if expected[key] != actual[key]:
            drifted.append(f"SPAN {key[0]}:{key[1]}-{key[2]} 区间内容摘要失配"
                           f"（区间内代码已变，核对语义后更新清单并 --init）")
    if drifted:
        for d in drifted:
            print(f"ANCHOR DRIFT: {d}", file=sys.stderr)
        return 1
    print(f"anchors ok ({len(ANCHORS)} 锚 + {len(actual)} 区间摘要全部命中)")
    return 0


def init_snapshot() -> int:
    rows = [f"{name}:{lo}:{hi}:{span_digest(lines, lo, hi)}"
            for name, lo, hi, lines in iter_spans()]
    SNAPSHOT.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"快照生成 {len(rows)} 条 → {SNAPSHOT}")
    return 0


def print_spans() -> int:
    for name, lo, hi, lines in iter_spans():
        s, e = char_span(lines, lo, hi)
        print(f"!**/{name}{{{s}..{e}}}")
    return 0


def main() -> int:
    if "--check" in sys.argv:
        return check()
    return init_snapshot() if "--init" in sys.argv else print_spans()


if __name__ == "__main__":
    sys.exit(main())
