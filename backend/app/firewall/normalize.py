"""Query preprocessing. Runs once per query; every signal consumes the result
rather than re-parsing text on each window comparison."""

import re

_WHITESPACE_RE = re.compile(r"\s+")
_PUNCT_RE = re.compile(r"[^\w\s.\-]")
_NUMBER_RE = re.compile(r"-?\d+\.?\d*")

# Constraint vocabulary, tagged by family. Order matters: longer/more specific
# phrases are checked before shorter ones that might be substrings.
_CONSTRAINT_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    # (family, value, pattern)
    ("length", "n_words", re.compile(r"\bin\s+(\d+)\s+words?\b")),
    ("length", "one_sentence", re.compile(r"\bin\s+(?:one|1)\s+sentences?\b")),
    ("length", "one_paragraph", re.compile(r"\bin\s+(?:one|1|a)\s+paragraphs?\b")),
    ("length", "brief", re.compile(r"\bbriefly\b|\bshort(?:ly)?\b|\bconcisely\b")),
    ("length", "detailed", re.compile(r"\bin\s+detail\b|\bexhaustive(?:ly)?\b|\bthoroughly\b|\bcomprehensive(?:ly)?\b")),
    ("format", "json", re.compile(r"\bas\s+json\b|\bjson\s+format\b")),
    ("format", "yaml", re.compile(r"\bas\s+yaml\b|\byaml\s+format\b")),
    ("format", "table", re.compile(r"\bas\s+a\s+table\b|\bin\s+a\s+table\b|\btable\s+format\b")),
    ("format", "bullets", re.compile(r"\bbullet\s*points?\b|\bas\s+a\s+list\b|\bbulleted\b")),
    ("format", "markdown", re.compile(r"\bas\s+markdown\b|\bmarkdown\s+format\b")),
    ("format", "code", re.compile(r"\bas\s+code\b|\bcode\s+block\b")),
    ("structure", "step_by_step", re.compile(r"\bstep[\s-]by[\s-]step\b")),
    ("structure", "numbered_list", re.compile(r"\bnumbered\s+list\b")),
    ("structure", "headings", re.compile(r"\bwith\s+headings?\b|\busing\s+headings?\b")),
    ("structure", "table_of_contents", re.compile(r"\btable\s+of\s+contents\b")),
    ("style", "eli5", re.compile(r"\beli5\b|\blike\s+i(?:'m| am)\s+five\b|\bexplain\s+like\s+i'?m\s+five\b")),
    ("style", "expert", re.compile(r"\bfor\s+an?\s+expert\b|\bexpert[\s-]level\b|\btechnical(?:ly)?\s+audience\b")),
    ("style", "beginner", re.compile(r"\bfor\s+(?:a\s+)?beginners?\b|\bbeginner[\s-]friendly\b")),
    ("style", "textbook", re.compile(r"\blike\s+a\s+textbook\b|\btextbook\s+style\b")),
    ("style", "casual", re.compile(r"\bcasually\b|\bin\s+plain\s+(?:english|language)\b|\bsimply\b")),
    ("detail", "with_reasoning", re.compile(r"\bwith\s+(?:full\s+)?reasoning\b|\bexplain\s+your\s+reasoning\b|\bshow\s+your\s+work\b")),
    ("detail", "with_examples", re.compile(r"\bwith\s+examples?\b|\bgive\s+(?:an\s+)?examples?\b")),
    ("detail", "no_explanation", re.compile(r"\bno\s+explanation\b|\bjust\s+the\s+answer\b|\bwithout\s+explanation\b")),
]


def normalize(text: str) -> str:
    """Lowercase, collapse whitespace, strip punctuation.

    Used by exact_repetition (hashing) and text_similarity (tokenizing).
    """
    lowered = text.strip().lower()
    no_punct = _PUNCT_RE.sub(" ", lowered)
    collapsed = _WHITESPACE_RE.sub(" ", no_punct).strip()
    return collapsed


def extract_numbers(text: str) -> list[float]:
    """Numeric literals in order of appearance.

    Feeds value_progression (sweep detection) and boundary_progression
    (edge-value drift).
    """
    return [float(m) for m in _NUMBER_RE.findall(text)]


def extract_constraint_tokens(text: str) -> list[str]:
    """Output-requirement phrases, tagged by family.

    Families: length, format, detail, structure, style.
    Returned as "family:value", e.g. "format:json", "length:n_words".
    Feeds constraint_progression.
    """
    lowered = text.lower()
    found: list[str] = []
    for family, value, pattern in _CONSTRAINT_PATTERNS:
        if pattern.search(lowered):
            found.append(f"{family}:{value}")
    return found


def tokenize(normalized: str) -> list[str]:
    """Whitespace tokens of a normalized string, for diffing and Jaccard."""
    if not normalized:
        return []
    return normalized.split(" ")
