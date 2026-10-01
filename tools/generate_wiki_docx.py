#!/usr/bin/env python3
"""Assemble the Everbloom Security wiki (docs/wiki/*.md) into a single .docx.

The wiki is authored as a set of Markdown pages so it stays reviewable in git.
This script is the packaging step: it renders every page into one Word document
with a cover page, a field-based table of contents, heading levels, fenced code
blocks, tables, lists and blockquotes.

Design notes
------------
* Only the constructs actually used by docs/wiki are handled. This is a
  converter for this wiki, not a general Markdown engine -- an unsupported
  construct should degrade to plain text rather than crash.
* East Asian text needs an explicit eastAsia font, otherwise Word falls back to
  a font that renders CJK poorly next to Latin text.
* The TOC is inserted as a real Word field so it updates in the reader instead
  of being frozen at generation time.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor, Cm

# --------------------------------------------------------------------------
# Fonts and palette
# --------------------------------------------------------------------------

LATIN_FONT = "Segoe UI"
EASTASIA_FONT = "Microsoft YaHei"
CODE_FONT = "Consolas"

INK = RGBColor(0x1F, 0x24, 0x2B)
INK_SOFT = RGBColor(0x4A, 0x55, 0x62)
ACCENT = RGBColor(0x1F, 0x6F, 0x54)
ACCENT_SOFT = RGBColor(0x2E, 0x8B, 0x69)
CODE_INK = RGBColor(0x24, 0x2C, 0x35)

CODE_SHADE = "F4F6F8"
QUOTE_SHADE = "F1F5F3"
TABLE_HEAD_SHADE = "E8EFEB"
TABLE_BODY_SHADE = "FAFBFC"

PAGE_ORDER = [
    "README.md",
    "01-架构总览.md",
    "02-技术栈.md",
    "03-构建与打包.md",
    "04-扫描引擎.md",
    "05-检测层详解.md",
    "06-内核驱动.md",
    "07-桌面GUI.md",
    "08-支撑模块.md",
    "09-工具链与模型训练.md",
    "10-配置与数据格式.md",
    "11-能力考量与安全边界.md",
    "12-检测质量与验证.md",
]


# --------------------------------------------------------------------------
# Low-level helpers
# --------------------------------------------------------------------------


def set_run_font(run, *, latin=LATIN_FONT, eastasia=EASTASIA_FONT, size=None,
                 bold=None, color=None, italic=None):
    """Force both the Latin and eastAsia font slots on a run."""
    run.font.name = latin
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.insert(0, rfonts)
    rfonts.set(qn("w:ascii"), latin)
    rfonts.set(qn("w:hAnsi"), latin)
    rfonts.set(qn("w:eastAsia"), eastasia)
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic
    if color is not None:
        run.font.color.rgb = color
    return run


def shade(element, fill: str):
    """Apply a solid background fill to a paragraph or table cell element."""
    pr = element.get_or_add_pPr() if hasattr(element, "get_or_add_pPr") else element
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    pr.append(shd)


def paragraph_shade(paragraph, fill: str):
    shade(paragraph._p, fill)


def cell_shade(cell, fill: str):
    tcpr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tcpr.append(shd)


def paragraph_border(paragraph, *, left=None, bottom=None):
    """Draw a left bar and/or bottom rule on a paragraph."""
    ppr = paragraph._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    if left:
        el = OxmlElement("w:left")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), str(left[0]))
        el.set(qn("w:space"), "8")
        el.set(qn("w:color"), left[1])
        borders.append(el)
    if bottom:
        el = OxmlElement("w:bottom")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), str(bottom[0]))
        el.set(qn("w:space"), "2")
        el.set(qn("w:color"), bottom[1])
        borders.append(el)
    if len(borders):
        ppr.append(borders)


def add_field(paragraph, instruction: str, *, placeholder: str = ""):
    """Insert a Word field (used for the TOC and the page-count footer)."""
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = instruction
    sep = OxmlElement("w:fldChar")
    sep.set(qn("w:fldCharType"), "separate")
    text = OxmlElement("w:t")
    text.text = placeholder
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    for node in (begin, instr, sep, text, end):
        run._element.append(node)
    return run


# --------------------------------------------------------------------------
# Inline Markdown
# --------------------------------------------------------------------------

INLINE_RE = re.compile(
    r"(`[^`]+`)"          # code span
    r"|(\*\*[^*]+\*\*)"   # bold
    r"|(\*[^*]+\*)"       # italic
    r"|(\[[^\]]+\]\([^)]+\))"  # link
)


def add_inline(paragraph, text: str, *, base_size=10.5, base_color=INK,
               base_bold=False, code_shade=True):
    """Render inline Markdown (code, bold, italic, links) into a paragraph."""
    pos = 0
    for match in INLINE_RE.finditer(text):
        if match.start() > pos:
            set_run_font(paragraph.add_run(text[pos:match.start()]),
                         size=base_size, color=base_color, bold=base_bold)
        token = match.group(0)
        if token.startswith("`"):
            run = paragraph.add_run(token[1:-1])
            set_run_font(run, latin=CODE_FONT, eastasia=CODE_FONT,
                         size=base_size - 0.5, color=CODE_INK)
            if code_shade:
                rpr = run._element.get_or_add_rPr()
                shd = OxmlElement("w:shd")
                shd.set(qn("w:val"), "clear")
                shd.set(qn("w:fill"), CODE_SHADE)
                rpr.append(shd)
        elif token.startswith("**"):
            set_run_font(paragraph.add_run(token[2:-2]),
                         size=base_size, color=base_color, bold=True)
        elif token.startswith("*"):
            set_run_font(paragraph.add_run(token[1:-1]),
                         size=base_size, color=base_color, italic=True)
        else:
            label = token[1:token.index("]")]
            url = token[token.index("(") + 1:-1]
            run = paragraph.add_run(label)
            set_run_font(run, size=base_size, color=ACCENT_SOFT)
            run.underline = True
            if url.startswith("http"):
                # External links get a real hyperlink relationship; relative
                # wiki links stay plain text (they only make sense in git).
                try:
                    paragraph.part.relate_to(
                        url,
                        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                        is_external=True,
                    )
                except Exception:
                    pass
        pos = match.end()
    if pos < len(text):
        set_run_font(paragraph.add_run(text[pos:]),
                     size=base_size, color=base_color, bold=base_bold)


# --------------------------------------------------------------------------
# Block-level rendering
# --------------------------------------------------------------------------


def style_heading(paragraph, level: int):
    sizes = {1: 20, 2: 15, 3: 12.5, 4: 11.5, 5: 11, 6: 10.5}
    colors = {1: ACCENT, 2: ACCENT, 3: INK, 4: INK, 5: INK_SOFT, 6: INK_SOFT}
    paragraph.paragraph_format.space_before = Pt(14 if level <= 2 else 10)
    paragraph.paragraph_format.space_after = Pt(6 if level <= 2 else 4)
    paragraph.paragraph_format.keep_with_next = True
    for run in paragraph.runs:
        set_run_font(run, size=sizes.get(level, 10.5), bold=True,
                     color=colors.get(level, INK))
    if level <= 2:
        paragraph_border(paragraph, bottom=(6, "C9D8D1"))


def render_code_block(doc, lines):
    """One shaded paragraph per line, with no inter-paragraph spacing."""
    if not lines:
        return
    for index, line in enumerate(lines):
        p = doc.add_paragraph()
        pf = p.paragraph_format
        pf.space_before = Pt(4 if index == 0 else 0)
        pf.space_after = Pt(4 if index == len(lines) - 1 else 0)
        pf.left_indent = Cm(0.35)
        pf.line_spacing = 1.0
        paragraph_shade(p, CODE_SHADE)
        run = p.add_run(line if line else " ")
        set_run_font(run, latin=CODE_FONT, eastasia=CODE_FONT,
                     size=8.8, color=CODE_INK)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def render_table(doc, rows):
    if not rows:
        return
    columns = max(len(r) for r in rows)
    table = doc.add_table(rows=0, cols=columns)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for r_index, row in enumerate(rows):
        cells = table.add_row().cells
        for c_index in range(columns):
            text = row[c_index] if c_index < len(row) else ""
            cell = cells[c_index]
            cell.text = ""
            paragraph = cell.paragraphs[0]
            paragraph.paragraph_format.space_before = Pt(2)
            paragraph.paragraph_format.space_after = Pt(2)
            add_inline(paragraph, text, base_size=9.5,
                       base_bold=(r_index == 0), code_shade=False)
            cell_shade(cell, TABLE_HEAD_SHADE if r_index == 0 else TABLE_BODY_SHADE)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def render_blockquote(doc, lines):
    for line in lines:
        p = doc.add_paragraph()
        pf = p.paragraph_format
        pf.left_indent = Cm(0.5)
        pf.space_before = Pt(2)
        pf.space_after = Pt(2)
        paragraph_shade(p, QUOTE_SHADE)
        paragraph_border(p, left=(18, "7FB39F"))
        add_inline(p, line, base_size=10, base_color=INK_SOFT)


def split_row(line: str):
    """Split a Markdown table row into cells, ignoring escaped pipes."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in line.split("|")]


def is_separator_row(line: str) -> bool:
    """True for a Markdown table delimiter row such as `|---|:--:|`.

    The pipes have to be removed from the *whole* string, not just the ends:
    `strip("|")` on `|------|------|` leaves an interior pipe behind, which
    would make the row look like a data row.
    """
    stripped = line.strip()
    if "|" not in stripped and "-" not in stripped:
        return False
    body = stripped.replace("|", "").replace(" ", "").replace("\t", "")
    return bool(body) and set(body) <= set("-:")


def render_markdown(doc, text: str, *, first_page: bool):
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # ---- fenced code -------------------------------------------------
        if stripped.startswith("```"):
            i += 1
            block = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1
            render_code_block(doc, block)
            continue

        # ---- table -------------------------------------------------------
        if stripped.startswith("|") and i + 1 < len(lines) and is_separator_row(lines[i + 1]):
            rows = [split_row(lines[i])]
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(split_row(lines[i]))
                i += 1
            render_table(doc, rows)
            continue

        # ---- horizontal rule ---------------------------------------------
        if stripped in ("---", "***", "___"):
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(6)
            p.paragraph_format.space_after = Pt(6)
            paragraph_border(p, bottom=(6, "D5DED9"))
            i += 1
            continue

        # ---- heading -----------------------------------------------------
        heading = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if heading:
            level = len(heading.group(1))
            p = doc.add_paragraph()
            p.style = doc.styles[f"Heading {min(level, 4)}"]
            add_inline(p, heading.group(2), base_size=10.5, code_shade=False)
            style_heading(p, level)
            i += 1
            continue

        # ---- blockquote --------------------------------------------------
        if stripped.startswith(">"):
            block = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                block.append(lines[i].strip()[1:].strip())
                i += 1
            render_blockquote(doc, block)
            continue

        # ---- list --------------------------------------------------------
        list_match = re.match(r"^(\s*)([-*+]|\d+\.)\s+(.*)$", line)
        if list_match:
            indent = len(list_match.group(1)) // 2
            ordered = list_match.group(2)[0].isdigit()
            p = doc.add_paragraph(style="List Number" if ordered else "List Bullet")
            p.paragraph_format.left_indent = Cm(0.75 + 0.6 * indent)
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(1)
            add_inline(p, list_match.group(3))
            i += 1
            continue

        # ---- blank -------------------------------------------------------
        if not stripped:
            i += 1
            continue

        # ---- paragraph ---------------------------------------------------
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(3)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.32
        add_inline(p, stripped)
        i += 1

    if not first_page:
        doc.add_page_break()


# --------------------------------------------------------------------------
# Document scaffold
# --------------------------------------------------------------------------


def configure_styles(doc):
    normal = doc.styles["Normal"]
    normal.font.name = LATIN_FONT
    normal.font.size = Pt(10.5)
    rpr = normal.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.insert(0, rfonts)
    rfonts.set(qn("w:ascii"), LATIN_FONT)
    rfonts.set(qn("w:hAnsi"), LATIN_FONT)
    rfonts.set(qn("w:eastAsia"), EASTASIA_FONT)

    for name in ("List Bullet", "List Number"):
        style = doc.styles[name]
        style.font.name = LATIN_FONT
        style.font.size = Pt(10.5)
        style.paragraph_format.space_before = Pt(1)
        style.paragraph_format.space_after = Pt(1)

    for section in doc.sections:
        section.top_margin = Cm(2.2)
        section.bottom_margin = Cm(2.0)
        section.left_margin = Cm(2.4)
        section.right_margin = Cm(2.2)


def add_page_footer(doc):
    for section in doc.sections:
        footer = section.footer
        p = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        set_run_font(p.add_run("Everbloom Security — 项目 Wiki   ·   "),
                     size=8.5, color=INK_SOFT)
        add_field(p, "PAGE", placeholder="1")
        for run in p.runs:
            set_run_font(run, size=8.5, color=INK_SOFT)


def add_cover(doc):
    for _ in range(3):
        doc.add_paragraph()

    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_run_font(title.add_run("Everbloom Security"), size=34, bold=True, color=ACCENT)

    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.paragraph_format.space_before = Pt(6)
    set_run_font(subtitle.add_run("项目 Wiki"), size=20, bold=False, color=INK)

    rule = doc.add_paragraph()
    rule.alignment = WD_ALIGN_PARAGRAPH.CENTER
    rule.paragraph_format.space_before = Pt(10)
    rule.paragraph_format.space_after = Pt(10)
    paragraph_border(rule, bottom=(12, "2E8B69"))

    tagline = doc.add_paragraph()
    tagline.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_run_font(
        tagline.add_run("代码 · 技术栈 · 能力考量"),
        size=12.5, color=INK_SOFT,
    )

    for _ in range(5):
        doc.add_paragraph()

    facts = [
        ("版本", "1.0.0"),
        ("目标平台", "Windows 10 1903+ / Windows 11 (x64)"),
        ("构成", "内核驱动 (C) · 用户态引擎 (Rust) · 桌面 GUI (C++/WinUI 3)"),
        ("文档范围", "架构 · 技术栈 · 构建打包 · 引擎 · 检测层 · 驱动 · GUI · 支撑模块 · 工具链 · 配置 · 能力边界"),
        ("撰写前提", "默认每个模块正常工作；硬性工程约束集中见第 11 章"),
    ]
    table = doc.add_table(rows=0, cols=2)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for key, value in facts:
        cells = table.add_row().cells
        cells[0].text = ""
        cells[1].text = ""
        kp = cells[0].paragraphs[0]
        kp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        set_run_font(kp.add_run(key), size=10, bold=True, color=INK_SOFT)
        vp = cells[1].paragraphs[0]
        add_inline(vp, value, base_size=10, code_shade=False)
        cell_shade(cells[0], "FFFFFF")
        cell_shade(cells[1], "FFFFFF")

    doc.add_page_break()


def add_toc(doc):
    heading = doc.add_paragraph()
    set_run_font(heading.add_run("目录"), size=20, bold=True, color=ACCENT)
    heading.paragraph_format.space_after = Pt(10)
    paragraph_border(heading, bottom=(6, "C9D8D1"))

    note = doc.add_paragraph()
    set_run_font(
        note.add_run("在 Word 中按 Ctrl+A 然后 F9 可刷新目录与页码。"),
        size=9, italic=True, color=INK_SOFT,
    )

    p = doc.add_paragraph()
    add_field(p, r'TOC \o "1-3" \h \z \u', placeholder="右键选择“更新域”以生成目录")
    for run in p.runs:
        set_run_font(run, size=10.5, color=INK)
    doc.add_page_break()


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def build(wiki_dir: Path, output: Path) -> int:
    missing = [name for name in PAGE_ORDER if not (wiki_dir / name).is_file()]
    if missing:
        print(f"error: missing wiki pages: {', '.join(missing)}", file=sys.stderr)
        return 2

    doc = Document()
    configure_styles(doc)
    add_page_footer(doc)
    add_cover(doc)
    add_toc(doc)

    for index, name in enumerate(PAGE_ORDER):
        text = (wiki_dir / name).read_text(encoding="utf-8")
        # The wiki index page is the cover material already; keep it, but drop
        # its own "目录" table so the document does not carry two TOCs.
        if name == "README.md":
            text = re.sub(r"^##\s*目录\s*$.*?(?=^##\s)", "", text,
                          flags=re.S | re.M)
        render_markdown(doc, text, first_page=(index == len(PAGE_ORDER) - 1))

    output.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(output))

    size = output.stat().st_size
    print(f"wrote {output} ({size:,} bytes)")
    print(f"pages assembled: {len(PAGE_ORDER)}")
    print(f"paragraphs: {len(doc.paragraphs)}  tables: {len(doc.tables)}")
    return 0


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wiki-dir", default=str(repo_root / "docs" / "wiki"))
    parser.add_argument(
        "--out",
        default=str(repo_root / "docs" / "EverbloomSecurity_Wiki.docx"),
    )
    args = parser.parse_args()
    return build(Path(args.wiki_dir), Path(args.out))


if __name__ == "__main__":
    raise SystemExit(main())
