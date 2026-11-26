"""Data leakage prevention: personal and financial data in tool traffic.

Recognisers validate what they find (Luhn for cards, Verhoeff for Aadhaar, mod-97 for IBAN,
structure for PAN and SSN), so a random 12- or 16-digit number is not reported. Each data
class has an action per direction:

  results  (tool -> model):  allow | log | redact      redact masks all but the last 4 characters
  outbound (model -> tool):  allow | log | block       applied to tools that send data out

Values are never written to the audit log: findings carry the class and a count only.
Patterns are bounded and linear on any input (see tests/test_performance.py).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .detect import Finding

RESULT_ACTIONS = ("allow", "log", "redact")
OUTBOUND_ACTIONS = ("allow", "log", "block")


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in _digits(number)]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_VERHOEFF_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
               [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
               [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
               [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
               [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
               [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_ok(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(_digits(number))):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def aadhaar_ok(number: str) -> bool:
    d = _digits(number)
    return len(d) == 12 and d[0] not in "01" and len(set(d)) > 1 and verhoeff_ok(d)


def iban_ok(value: str) -> bool:
    s = re.sub(r"[\s-]", "", value).upper()
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    try:
        return int("".join(str(int(ch, 36)) for ch in moved)) % 97 == 1
    except ValueError:
        return False


def ssn_ok(value: str) -> bool:
    area, group, serial = value[:3], value[4:6], value[7:]
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"


def _grouped_like_a_number(value: str) -> bool:
    """A card number is written in even pieces (4-4-4-4, a digit per line) or as the 4-6-5 of an American
    Express card (4-6-4 for a Diners card). Columns of a table or spreadsheet are not."""
    groups = re.split(r"[ ./_-]+", value.strip())
    if len(groups) < 2:
        return True
    sizes = [len(g) for g in groups]
    return len(set(sizes[:-1])) == 1 or sizes[:3] in ([4, 6, 5], [4, 6, 4])


@dataclass(frozen=True)
class DataClass:
    name: str
    label: str
    pattern: re.Pattern
    valid: Callable[[str], bool] = lambda _s: True
    severity: str = "medium"


# (?<![\w-]) / (?![\w-]) keep numbers inside longer identifiers (order IDs, hashes) out.
CLASSES = [
    DataClass("credit_card", "payment card number",
              re.compile(r"(?<![\w-])(?:\d[ ./_-]?){12,18}\d(?![\w-])"),
              lambda s: _grouped_like_a_number(s) and luhn_ok(s), "high"),
    DataClass("aadhaar", "Aadhaar number", re.compile(r"(?<![\w-])\d{4}[ ./_-]?\d{4}[ ./_-]?\d{4}(?![\w-])"),
              aadhaar_ok, "high"),
    DataClass("us_ssn", "US Social Security number", re.compile(r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])"),
              ssn_ok, "high"),
    DataClass("iban", "bank account (IBAN)",
              re.compile(r"(?<![\w-])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![\w-])"),
              iban_ok, "high"),
    DataClass("india_pan", "PAN (Indian tax ID)",
              re.compile(r"(?<![\w-])[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z](?![\w-])")),
    DataClass("email", "email address",
              re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,5}(?![\w-])"),
              severity="low"),
    # Only shapes that are phone numbers: international (+..), an area code in brackets,
    # North American 3-3-4, or an Indian mobile. Dates and long IDs do not qualify.
    DataClass("phone", "phone number", re.compile(
        r"(?<![\w+.-])(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{2,5}(?:[ .-]?\d{2,5}){1,3}"
        r"|\(\d{2,5}\)[ .-]?\d{3,5}[ .-]?\d{3,5}|\d{3}[.-]\d{3}[.-]\d{4}|[6-9]\d{4} ?\d{5})(?![\w.-])"),
              lambda s: 10 <= len(_digits(s)) <= 15 and len(set(_digits(s))) > 2, "low"),
]
BY_NAME = {c.name: c for c in CLASSES}

DEFAULT_RESULTS = {"credit_card": "redact", "aadhaar": "redact", "us_ssn": "redact", "iban": "log",
                   "india_pan": "log", "email": "allow", "phone": "allow"}
DEFAULT_OUTBOUND = {"credit_card": "block", "aadhaar": "block", "us_ssn": "block", "iban": "log",
                    "india_pan": "log", "email": "allow", "phone": "allow"}


@dataclass
class DlpConfig:
    enabled: bool = True
    results: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_RESULTS))
    outbound: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_OUTBOUND))
    track_pii: bool = True  # personal data read by one tool and sent out by another is flagged


@dataclass
class Match:
    cls: DataClass
    value: str
    start: int
    end: int


def find(text: str, classes: list[str] | None = None) -> list[Match]:
    """Validated matches, longest first where they overlap (a card is not also a phone number)."""
    wanted = [c for c in CLASSES if classes is None or c.name in classes]
    found = [Match(c, rm.group(0), rm.start(), rm.end())
             for c in wanted for rm in c.pattern.finditer(text) if c.valid(rm.group(0))]
    found.sort(key=lambda x: (x.start, -(x.end - x.start)))
    out: list[Match] = []
    for x in found:
        if not out or x.start >= out[-1].end:
            out.append(x)
    return out


_INVISIBLE = re.compile("[\u00ad\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]")
_MARKUP = re.compile(r"<!--.*?-->|<[^<>]{0,40}>", re.S)
# Digits broken up by a few separator characters (" x ", a newline, "|", ...): one number to a reader.
_GLUE = re.compile(r"(?<=\d)[\s_*xX\u00d7|,;:.\-/]{1,4}(?=\d)")


def clean_view(text: str) -> str:
    """The text as a reader would see it: invisible characters and markup dropped, digits that were only
    separated by a few odd characters joined with a space. Used only to look for data in disguise."""
    out = _GLUE.sub(" ", _MARKUP.sub("", _INVISIBLE.sub("", text)))
    return out


def find_disguised(text: str, classes: list[str] | None = None) -> list[Match]:
    """Matches that only appear once the text is cleaned of hiding tricks (none for plain text)."""
    if len(text) > 400_000:
        return []
    cleaned = clean_view(text)
    if cleaned == text:
        return []
    plain = {normalise(m.value) for m in find(text, classes)}
    return [m for m in find(cleaned, classes)
            if normalise(m.value) not in plain and (m.cls.name not in ("credit_card", "aadhaar")
                                                    or _grouped_like_a_number(m.value))]


def mask(value: str) -> str:
    keep = re.sub(r"[\s-]", "", value)[-4:]
    return f"[redacted {len(re.sub(r'[^0-9A-Za-z]', '', value))} chars, ends {keep}]"


def redact(text: str, actions: dict[str, str]) -> tuple[str, dict[str, int]]:
    """Mask every class whose action is 'redact'. Returns (text, {class: count})."""
    classes = [n for n, a in actions.items() if a == "redact"]
    if not classes:
        return text, {}
    counts: dict[str, int] = {}
    if find_disguised(text, classes):  # hidden among invisible characters or markup: mask the cleaned text
        text = clean_view(text)
    parts, pos = [], 0
    for m in find(text, classes):
        parts += [text[pos:m.start], f"[{m.cls.label} {mask(m.value)[1:]}"]
        pos = m.end
        counts[m.cls.name] = counts.get(m.cls.name, 0) + 1
    parts.append(text[pos:])
    return "".join(parts), counts


def scan(text: str, actions: dict[str, str], direction: str, where: str) -> list[Finding]:
    """Findings for classes not set to 'allow'. 'block' (outbound) is critical so the call stops;
    everything else is low: recorded, not blocking."""
    counts: dict[str, int] = {}
    wanted = [n for n, a in actions.items() if a != "allow"]
    for m in [*find(text, wanted), *find_disguised(text, wanted)]:
        counts[m.cls.name] = counts.get(m.cls.name, 0) + 1
    out = []
    for name, n in counts.items():
        action = actions[name]
        label = BY_NAME[name].label
        if direction == "outbound" and action == "block":  # critical: "block" must block whatever the threshold
            out.append(Finding(f"dlp.{name}", "critical", f"{n} {label}{'s' if n > 1 else ''} in data sent to a tool "
                                                      "that sends data out", where))
        else:
            verb = "redacted from" if action == "redact" else "seen in"
            out.append(Finding(f"dlp.{name}", "low", f"{n} {label}{'s' if n > 1 else ''} {verb} the "
                                                     f"{'result' if direction == 'results' else 'arguments'}", where))
    return out


def tracked_values(text: str) -> list[str]:
    """Normalised personal-data values worth remembering for leak detection across calls."""
    return [normalise(m.value) for m in find(text, ["credit_card", "aadhaar", "us_ssn", "iban", "india_pan"])]


def normalise(value: str) -> str:
    return re.sub(r"[\s./_-]", "", value).upper()


class PieceTracker:
    """Personal data leaving in pieces: a card number sent four digits at a time, in one call or
    over several. A piece is a whole run of letters and digits in the outgoing arguments, at
    least four characters long, that occurs inside a tracked value. Each piece covers one stretch of the
    value; the value is reported once ``SHARE`` of it has left (all of it, for short values)."""

    SHARE = 0.8
    MAX_TOKENS = 1500
    _RUN = re.compile(r"[A-Za-z0-9]{4,}")

    def __init__(self) -> None:
        self._covered: dict[str, set[int]] = {}
        self._index: dict[str, set[str]] = {}
        self._indexed: tuple = (0, None)

    def forget(self, value: str) -> None:
        self._covered.pop(value, None)

    def check(self, text: str, values: dict[str, str]) -> tuple[str, str] | None:
        """(value, origin) of a tracked value whose pieces now add up, else None."""
        if not values:
            return None
        tokens = list(dict.fromkeys(t.upper() for t in self._RUN.findall(text[:400_000])))[:self.MAX_TOKENS]
        if not tokens:
            return None
        # Only values that contain one of the tokens' first four characters can gain anything.
        if self._indexed != (len(values), next(reversed(values), None)):
            self._index = {}
            for value in values:
                for i in range(len(value) - 3):
                    self._index.setdefault(value[i:i + 4], set()).add(value)
            self._indexed = (len(values), next(reversed(values), None))
        candidates = set().union(*(self._index.get(tok[:4], ()) for tok in tokens)) | set(self._covered)
        hit = None
        for value in candidates:
            if value not in values:
                continue
            origin = values[value]
            before = self._covered.get(value, set())
            covered = set(before)
            for tok in tokens:
                if len(tok) >= len(value):
                    continue  # the whole value is the ordinary check's job
                best: set[int] = set()
                start = value.find(tok)
                while start != -1:  # a repeated piece ("1111") covers one new stretch per sighting
                    new = set(range(start, start + len(tok))) - covered
                    if len(new) > len(best):
                        best = new
                    start = value.find(tok, start + 1)
                covered |= best
            if covered != before:
                self._covered[value] = covered
                # Short values (SSN, PAN) must leave completely: two chance 4-digit matches
                # would otherwise be enough.
                need = len(value) if len(value) < 12 else self.SHARE * len(value)
                if hit is None and len(covered) >= need:
                    hit = (value, origin)
        return hit
