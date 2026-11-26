"""A small PDF writer for the report, styled like the dashboard, on A4 with no dependencies.

It reads the Markdown that ``report.build_report`` produces (``#``/``##`` headings, ``|`` tables, plain
paragraphs) and lays it out with the built-in Helvetica fonts: a dark header band with the arch mark and a
log-integrity badge, summary cards, lime section markers, dark table headers and severity chips. Text that
comes from the audit log (tool names, reasons) is untrusted, so control characters are dropped and
characters the font cannot show become ``?``.
"""

from __future__ import annotations

import re

PAGE_W, PAGE_H = 595, 842          # A4 in points
MARGIN = 50
BODY = PAGE_W - 2 * MARGIN
_BASE = 32                          # first character in _WIDTHS
# Helvetica widths (1/1000 em) for ASCII 32..126.
_WIDTHS = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
)
_BOLD_FACTOR = 1.07                 # bold is a little wider; this keeps wrapped text inside its box


MAX_CELL = 1000      # characters shown per table cell or paragraph; a log value can be megabytes
MAX_ROWS = 5000      # table rows per table; the report itself already limits most tables


def clean(text: object, limit: int = MAX_CELL) -> str:
    """Printable Latin-1 only: the standard fonts cannot show anything else, and logs hold foreign text.
    Long values are cut (with ...), so one huge log entry cannot make a huge file."""
    out = []
    raw = str(text if text is not None else "")
    if len(raw) > limit:
        raw = raw[:limit] + "..."
    for ch in raw:
        if ch in "\t\n\r":
            out.append(" ")
        elif ch.isprintable() and ord(ch) < 256 and not (127 <= ord(ch) < 160):
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)


def width(text: str, size: float, bold: bool = False) -> float:
    total = sum(_WIDTHS[ord(c) - _BASE] if _BASE <= ord(c) < 127 else 556 for c in text)
    return total * size / 1000 * (_BOLD_FACTOR if bold else 1.0)


def wrap(text: str, size: float, max_width: float, bold: bool = False) -> list[str]:
    """Break text into lines no wider than max_width; a word that is too long is cut."""
    lines: list[str] = []
    line = ""
    for word in text.split(" "):
        if width(word, size, bold) > max_width:  # an unbroken string (hash, path, URL): cut it by width
            if line:
                lines.append(line)
                line = ""
            piece, used = "", 0.0
            for ch in word:
                w = width(ch, size, bold)
                if piece and used + w > max_width:
                    lines.append(piece)
                    piece, used = "", 0.0
                piece += ch
                used += w
            line = piece
            continue
        candidate = f"{line} {word}" if line else word
        if line and width(candidate, size, bold) > max_width:
            lines.append(line)
            line = word
        else:
            line = candidate
    lines.append(line)
    return lines


Color = tuple[float, float, float]


def _hex(value: str) -> Color:
    return (int(value[1:3], 16) / 255, int(value[3:5], 16) / 255, int(value[5:7], 16) / 255)


BG, SURFACE = _hex("#0f0f0f"), _hex("#1a1a1a")
INK, MUTED, MUTED_LIGHT = _hex("#161616"), _hex("#6b6b6b"), _hex("#a3a3a3")
WHITE, ACCENT, BAD = _hex("#ffffff"), _hex("#dafa9c"), _hex("#ff8a80")
ZEBRA, HAIR = _hex("#f5f6f2"), _hex("#e3e5df")
SEVERITY = {"critical": _hex("#ff8a80"), "high": _hex("#ffb870"), "medium": _hex("#ffe08a"), "low": ACCENT}
HEADER_H = 118
TOP = PAGE_H - 54            # first line on a continuation page


def _esc(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _rrect(x: float, y: float, w: float, h: float, r: float) -> str:
    """Path of a rounded rectangle (no paint operator)."""
    r = min(r, w / 2, h / 2)
    k = 0.5523 * r
    return (f"{x + r:.1f} {y:.1f} m {x + w - r:.1f} {y:.1f} l {x + w - r + k:.1f} {y:.1f} {x + w:.1f} {y + r - k:.1f} "
            f"{x + w:.1f} {y + r:.1f} c {x + w:.1f} {y + h - r:.1f} l {x + w:.1f} {y + h - r + k:.1f} "
            f"{x + w - r + k:.1f} {y + h:.1f} {x + w - r:.1f} {y + h:.1f} c {x + r:.1f} {y + h:.1f} l "
            f"{x + r - k:.1f} {y + h:.1f} {x:.1f} {y + h - r + k:.1f} {x:.1f} {y + h - r:.1f} c {x:.1f} {y + r:.1f} l "
            f"{x:.1f} {y + r - k:.1f} {x + r - k:.1f} {y:.1f} {x + r:.1f} {y:.1f} c")


def _rgb(c: Color) -> str:
    return f"{c[0]:.3f} {c[1]:.3f} {c[2]:.3f}"


class _Doc:
    def __init__(self, title: str):
        self.title = title
        self.pages: list[list[str]] = []
        self.y: float = 0
        self._new_page(first=True)

    # -- drawing primitives ---------------------------------------------------------------------
    def text(self, x: float, y: float, s: str, size: float, bold: bool = False, color: Color = INK) -> None:
        font = "F2" if bold else "F1"
        self.pages[-1].append(f"BT {_rgb(color)} rg /{font} {size} Tf {x:.1f} {y:.1f} Td ({_esc(s)}) Tj ET")

    def rect(self, x: float, y: float, w: float, h: float, color: Color) -> None:
        self.pages[-1].append(f"{_rgb(color)} rg {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f")

    def round(self, x: float, y: float, w: float, h: float, r: float, color: Color) -> None:
        self.pages[-1].append(f"{_rgb(color)} rg {_rrect(x, y, w, h, r)} f")

    def line(self, x1: float, y1: float, x2: float, y2: float, color: Color = HAIR, w: float = 0.5) -> None:
        self.pages[-1].append(f"{_rgb(color)} RG {w} w {x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S")

    def mark(self, x: float, y: float, size: float, color: Color = ACCENT) -> None:
        """The dashboard's arch: a thick U turned over, open at the bottom."""
        r = size / 2
        k = 0.5523 * r
        lw = max(1.6, size * 0.16)
        self.pages[-1].append(
            f"{_rgb(color)} RG {lw:.2f} w {x + lw / 2:.1f} {y:.1f} m {x + lw / 2:.1f} {y + r:.1f} l "
            f"{x + lw / 2:.1f} {y + r + k:.1f} {x + r - k:.1f} {y + size - lw / 2:.1f} "
            f"{x + r:.1f} {y + size - lw / 2:.1f} c "
            f"{x + r + k:.1f} {y + size - lw / 2:.1f} {x + size - lw / 2:.1f} {y + r + k:.1f} "
            f"{x + size - lw / 2:.1f} {y + r:.1f} c {x + size - lw / 2:.1f} {y:.1f} l S")

    # -- page furniture -------------------------------------------------------------------------
    def _new_page(self, first: bool = False) -> None:
        self.pages.append([])
        if first:
            self.rect(0, PAGE_H - HEADER_H, PAGE_W, HEADER_H, BG)
            self.rect(0, PAGE_H - HEADER_H, PAGE_W, 2, ACCENT)
            self.y = PAGE_H - HEADER_H - 26
        else:
            self.rect(0, PAGE_H - 30, PAGE_W, 30, BG)
            self.mark(MARGIN, PAGE_H - 23, 13)
            self.text(MARGIN + 21, PAGE_H - 21, "mcpguard", 9, True, ACCENT)
            self.text(MARGIN + 76, PAGE_H - 21, "security report", 9, False, MUTED_LIGHT)
            self.y = TOP

    def cover(self, title: str, subtitle: str, ok: bool | None, status: str) -> None:
        """The dark band at the top of the first page."""
        top = PAGE_H
        self.mark(MARGIN, top - 44, 20)
        self.text(MARGIN + 30, top - 38, "mcpguard", 13, True, ACCENT)
        self.text(MARGIN, top - 82, title, 27, True, WHITE)
        for n, line in enumerate(wrap(subtitle, 9.5, BODY - 150)[:2]):
            self.text(MARGIN, top - 100 - n * 12, line, 9.5, False, MUTED_LIGHT)
        if ok is not None:
            label = clean(status.upper(), 24)
            w = width(label, 8.5, True) + 22
            x = PAGE_W - MARGIN - w
            self.round(x, top - 44, w, 20, 10, ACCENT if ok else BAD)
            self.text(x + 11, top - 37.5, label, 8.5, True, BG)

    def _ensure(self, height: float) -> None:
        if self.y - height < MARGIN + 14:
            self._new_page()

    # -- content ----------------------------------------------------------------------------------
    def paragraph(self, s: str, size: float = 10, bold: bool = False, gap: float = 6, color: Color = INK) -> None:
        for line in wrap(s, size, BODY, bold):
            self._ensure(size * 1.4)
            self.y -= size * 1.4
            self.text(MARGIN, self.y, line, size, bold, color)
        self.y -= gap

    def heading(self, s: str, level: int = 2) -> None:
        size = 15.0 if level == 1 else 13.0
        self._ensure(size * 3.5)
        self.y -= 14
        self.rect(MARGIN, self.y - 3.5, 4, size, ACCENT)
        self.rect(MARGIN, self.y - 3.5, 4, size, ACCENT)
        self.text(MARGIN + 13, self.y, s, size, True, BG)
        self.y -= 12

    def cards(self, items: list[tuple[str, str, Color]]) -> None:
        """Summary cards in the dashboard's dark style."""
        if not items:
            return
        gap, h = 10.0, 58.0
        w = (BODY - gap * (len(items) - 1)) / len(items)
        self._ensure(h + 12)
        top = self.y - 4
        for i, (label, value, color) in enumerate(items):
            x = MARGIN + i * (w + gap)
            self.round(x, top - h, w, h, 7, SURFACE)
            self.text(x + 12, top - 19, label, 8, False, MUTED_LIGHT)
            self.text(x + 12, top - 45, value, 21, True, color)
        self.y = top - h - 10

    def chips(self, counts: list[tuple[str, str]]) -> None:
        """Severity chips, coloured like the severity they name."""
        self._ensure(26)
        x, top = float(MARGIN), self.y - 4
        for name, n in counts:
            label = f"{name}  {n}"
            w = width(label, 8.5, True) + 20
            if x + w > PAGE_W - MARGIN:
                x, top = float(MARGIN), top - 24
                self._ensure(26)
            self.round(x, top - 18, w, 18, 9, SEVERITY.get(name, ACCENT))
            self.text(x + 10, top - 12.5, label, 8.5, True, BG)
            x += w + 8
        self.y = top - 26

    def table(self, header: list[str], rows: list[list[str]]) -> None:
        size: float = 8.5
        pad: float = 5
        cols = len(header)
        longest = [max([len(header[i])] + [len(r[i]) for r in rows if i < len(r)] or [1]) for i in range(cols)]
        weights = [min(max(n, 6), 60) for n in longest]
        usable = BODY - 2 * pad * cols
        widths = [w * usable / sum(weights) + 2 * pad for w in weights]
        head_cells = [wrap(header[i], size, widths[i] - 2 * pad, True) for i in range(cols)]
        head_h = max(len(c) for c in head_cells) * size * 1.3 + 2 * pad

        def draw_head() -> None:
            top = self.y
            self.round(MARGIN, top - head_h, BODY, head_h, 3, SURFACE)
            x = float(MARGIN)
            for i, lines in enumerate(head_cells):
                for n, line in enumerate(lines):
                    self.text(x + pad, top - pad - size * 1.05 - n * size * 1.3, line, size, True, WHITE)
                x += widths[i]
            self.y = top - head_h

        self._ensure(head_h * 3)
        draw_head()
        for row_index, row in enumerate(rows, 1):
            cells = [wrap(row[i] if i < len(row) else "", size, widths[i] - 2 * pad, False) for i in range(cols)]
            height = max(len(c) for c in cells) * size * 1.3 + 2 * pad
            before = len(self.pages)
            self._ensure(height)
            if len(self.pages) != before:  # a new page: repeat the header so the columns stay labelled
                draw_head()
            top = self.y
            if row_index % 2 == 0:
                self.rect(MARGIN, top - height, BODY, height, ZEBRA)
            x = float(MARGIN)
            for i, lines in enumerate(cells):
                for n, line in enumerate(lines):
                    self.text(x + pad, top - pad - size * 1.05 - n * size * 1.3, line, size, False, INK)
                x += widths[i]
            self.line(MARGIN, top - height, PAGE_W - MARGIN, top - height)
            self.y = top - height
        self.y -= 10

    # -- output ---------------------------------------------------------------------------------
    def build(self) -> bytes:
        total = len(self.pages)
        objects: list[bytes] = []

        def add(body: str | bytes) -> int:
            objects.append(body if isinstance(body, bytes) else body.encode("latin-1"))
            return len(objects)

        add("<< /Type /Catalog /Pages 2 0 R >>")                # 1
        add("")                                                  # 2: filled in below
        f1 = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        f2 = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        info = add(f"<< /Title ({_esc(clean(self.title))}) /Producer (mcpguard) >>")
        kids = []
        for n, ops in enumerate(self.pages, 1):
            foot = _esc(f"mcpguard report  -  page {n} of {total}")
            footer = (f"{_rgb(HAIR)} RG 0.5 w {MARGIN} 42 m {PAGE_W - MARGIN} 42 l S "
                      f"BT {_rgb(MUTED)} rg /F1 8 Tf {MARGIN} 30 Td ({foot}) Tj ET")
            stream = "\n".join([*ops, footer]).encode("latin-1", "replace")
            content = add(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
            page = add(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] /Contents {content} 0 R "
                       f"/Resources << /Font << /F1 {f1} 0 R /F2 {f2} 0 R >> >> >>")
            kids.append(f"{page} 0 R")
        objects[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {total} >>".encode()

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(objects, 1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info {info} 0 R >>\n"
                f"startxref\n{xref}\n%%EOF\n").encode()
        return bytes(out)


_BOLD = re.compile(r"\*\*(.+?)\*\*")
_AMBER = _hex("#ffe08a")
_CARDS = (("Allowed calls", "Tool calls allowed", ACCENT), ("Blocked", "Tool calls blocked", BAD),
          ("Would block", "Would have blocked (monitor mode)", _AMBER),
          ("Quarantined", "Definitions quarantined", BAD),
          ("Changed tools", "Definition changes caught (rug pulls)", BAD))


def _plain(line: str) -> str:
    return _BOLD.sub(r"\1", line).replace("\\|", "|")


def _cells(block: list[str]) -> list[list[str]]:
    return [[clean(_plain(c.strip())) for c in re.split(r"(?<!\\)\|", b.strip().strip("|"))]
            for b in block if not re.fullmatch(r"\|(-+\|)+", b.strip())]


def _summary_cards(table: list[list[str]]) -> list[tuple[str, str, Color]]:
    """Cards for the headline numbers; one that is zero is drawn in white, not alarm colours."""
    values = {row[0]: row[1] for row in table[1:] if len(row) > 1}
    cards: list[tuple[str, str, Color]] = []
    for label, measure, color in _CARDS:
        if measure in values and (label == "Allowed calls" or len(cards) < 4):
            v = clean(values[measure], 12)
            cards.append((label, v, color if v not in ("0", "0 / 0") else WHITE))
    return cards[:4]


def markdown_to_pdf(markdown: str, title: str = "mcpguard report") -> bytes:
    """Lay out the report Markdown as a styled PDF."""
    lines = markdown.splitlines()
    heading = next((clean(_plain(x[2:]), 60) for x in lines if x.startswith("# ")), "Report")
    cover = next((clean(_plain(x), 160) for x in lines if x.startswith(("Covers ", "The audit log is empty"))), "")
    integ = next((_plain(x) for x in lines if x.startswith("Log integrity:")), "")
    ok = None if not integ else ("PASS" in integ.split(".")[0])
    doc = _Doc(title)
    doc.cover("Security report" if heading.lower().endswith("report") else heading, cover, ok,
              "Log intact" if ok else "Log check failed")
    if integ:
        doc.paragraph(clean(integ.replace("Log integrity: ", "Audit log: ", 1)), 9.5, color=MUTED)
    i = 0
    while i < len(lines):
        raw = lines[i]
        if raw.startswith("|"):
            block = []
            while i < len(lines) and lines[i].startswith("|"):
                block.append(lines[i])
                i += 1
            parsed = _cells(block)
            if not parsed:
                continue
            if parsed[0][:2] == ["Measure", "Count"]:
                doc.cards(_summary_cards(parsed))
            body = parsed[1:]
            if len(body) > MAX_ROWS:
                body = [*body[:MAX_ROWS], [f"... {len(parsed) - 1 - MAX_ROWS} more rows not shown"]]
            doc.table(parsed[0], body)
            continue
        i += 1
        if raw.startswith(("# ", "Covers ", "The audit log is empty", "Log integrity:")):
            continue
        if raw.startswith("## "):
            doc.heading(clean(_plain(raw[3:])), 2)
        elif raw.startswith("Findings by severity:"):
            found = re.findall(r"(critical|high|medium|low) (\d+)", raw)
            doc.paragraph("Findings by severity", 9.5, True, gap=0, color=MUTED)
            doc.chips(found)
        elif raw.strip():
            doc.paragraph(clean(_plain(raw)), 9.5, color=MUTED if raw.startswith("Showing") else INK)
    return doc.build()
