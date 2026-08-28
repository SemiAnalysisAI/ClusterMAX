"""Startup banner for the ClusterMAX command line interface.

The CLI opens straight into a check list or a progress region, so a long
campaign gives an operator no visual mark for where one invocation starts.
A screenshot of a mid-run terminal therefore does not show which tool produced
it. This module draws the SemiAnalysis mark and the product name once at the
top of a run.

Three things degrade independently, because a banner must never be the reason a
run fails or a terminal wraps into noise.

Width. `select_font` picks the widest wordmark the terminal can fit, and the
mark is added only when the terminal can also hold the mark, the gap, and the
wordmark together. A terminal too narrow for any font gets the plain word.

Encoding. `Theme.encodable` in `cmax/progress.py` exists because one code point
outside the terminal's range raises UnicodeEncodeError on write and takes the
display down. The block wordmark and the mark are offered only when the stream
reports a UTF encoding, and `ASCII_FONT` covers every other terminal.

Color depth. `Ink.codes` in `cmax/logo.py` sends a 24-bit sequence only to a
terminal that advertises truecolor, because a terminal that cannot read one
prints its digits as text across the art.

The mark itself lives in `cmax/logo.py`. This module owns the wordmark fonts
and the composition of the two.

Every letter in a font is a fixed cell of `Font.width` columns and `Font.height`
rows, so the composed word cannot misalign. The alternative is one pasted block
of art, where a single stray space shifts a row and no test can see the shift.
`Font.defects` states the shape rule, and `cmax/test_banner.py` asserts it.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from typing import Sequence, TextIO

from cmax import logo
from cmax.logo import BASIC, PALETTE256, TRUECOLOR, Ink, color_depth
from cmax.progress import Theme, progress_enabled

WORD = "CLUSTERMAX"

# The SemiAnalysis brand gold. `dashboard/STYLING-STACK.md` names it SA Amber,
# and `dashboard/src/app/globals.css` sets the same value as the dashboard
# `--primary` and `--tier-gold` tokens. The wordmark therefore matches the
# product's own color rather than defining a second one.
#
# The 16-color stand-in is bold yellow. The progress display gives yellow the
# warning meaning in `color_status_text`, and that overlap cannot be avoided at
# 16 colors. The banner carries no status, and it sits above the report rather
# than inside it.
GOLD = Ink(
    name="SA Amber",
    hex="#E8A830",
    rgb=(232, 168, 48),
    xterm256=179,
    basic=("33", "1"),
)

# The mark component. The grid, its two colors, and their provenance live in
# `cmax/logo.py`; these aliases keep one import surface for banner callers.
LOGO_BLUE = logo.BLUE
LOGO_ORANGE = logo.ORANGE
LOGO_ROWS = logo.ROWS
LOGO_WIDTH = logo.WIDTH
LOGO_HEIGHT = logo.HEIGHT

# Columns between the mark and the wordmark.
LOGO_GAP = 3


@dataclass(frozen=True)
class Font:
    """One fixed-cell letterform table.

    `width` and `height` describe every cell. `gap` is the blank columns placed
    between two adjacent cells. `ink` is the single character a cell is drawn
    with, and `defects` enforces that a cell contains nothing else.
    """

    name: str
    width: int
    height: int
    gap: int
    ink: str
    glyphs: dict[str, tuple[str, ...]]

    def measure(self, word: str) -> int:
        """Printable columns the composed word occupies in this font."""
        if not word:
            return 0
        return len(word) * self.width + (len(word) - 1) * self.gap

    def covers(self, word: str) -> bool:
        return all(letter in self.glyphs for letter in word)

    def defects(self) -> list[str]:
        """Every letter whose cell is not exactly `height` by `width`.

        Composition trusts each cell to be a rectangle of the declared size. A
        cell that breaks the rule shifts every letter to its right, so the rule
        is checked here and asserted by the tests rather than left to review.
        """
        found: list[str] = []
        for letter, rows in sorted(self.glyphs.items()):
            if len(rows) != self.height:
                found.append(
                    f"{self.name} {letter}: has {len(rows)} rows, "
                    f"needs {self.height}"
                )
            for index, row in enumerate(rows):
                if len(row) != self.width:
                    found.append(
                        f"{self.name} {letter}: row {index} is {len(row)} "
                        f"columns, needs {self.width}"
                    )
                unexpected = set(row) - {self.ink, " "}
                if unexpected:
                    found.append(
                        f"{self.name} {letter}: row {index} has "
                        f"{sorted(unexpected)!r}, needs only {self.ink!r} "
                        f"and a space"
                    )
        return found

    def compose(self, word: str) -> list[str]:
        """The word as `height` lines, with no color and no indent."""
        missing = sorted({letter for letter in word if letter not in self.glyphs})
        if missing:
            raise KeyError(f"{self.name} has no glyph for {missing!r}")
        pad = " " * self.gap
        return [
            pad.join(self.glyphs[letter][row] for letter in word)
            for row in range(self.height)
        ]


# Solid block letterforms, six rows tall. A vertical stroke is two columns and a
# horizontal bar is one row, because a terminal cell is about twice as tall as
# it is wide and those two measures therefore read as the same thickness.
_BLOCK_GLYPHS: dict[str, tuple[str, ...]] = {
    "C": (
        "███████",
        "██     ",
        "██     ",
        "██     ",
        "██     ",
        "███████",
    ),
    "L": (
        "██     ",
        "██     ",
        "██     ",
        "██     ",
        "██     ",
        "███████",
    ),
    "U": (
        "██   ██",
        "██   ██",
        "██   ██",
        "██   ██",
        "██   ██",
        "███████",
    ),
    "S": (
        "███████",
        "██     ",
        "███████",
        "     ██",
        "     ██",
        "███████",
    ),
    "T": (
        "███████",
        "  ███  ",
        "  ███  ",
        "  ███  ",
        "  ███  ",
        "  ███  ",
    ),
    "E": (
        "███████",
        "██     ",
        "██████ ",
        "██     ",
        "██     ",
        "███████",
    ),
    "R": (
        "██████ ",
        "██   ██",
        "██████ ",
        "██  ██ ",
        "██   ██",
        "██   ██",
    ),
    "M": (
        "██   ██",
        "███ ███",
        "███████",
        "██ █ ██",
        "██   ██",
        "██   ██",
    ),
    "A": (
        "███████",
        "██   ██",
        "███████",
        "██   ██",
        "██   ██",
        "██   ██",
    ),
    "X": (
        "██   ██",
        " ██ ██ ",
        "  ███  ",
        "  ███  ",
        " ██ ██ ",
        "██   ██",
    ),
}

# Plain letterforms for a terminal that cannot encode a block, or that is too
# narrow for the block font. A solid fill needs two blank columns between
# letters, because one column lets the upright of L run into the upright of U
# and the word reads as a single wall.
_ASCII_GLYPHS: dict[str, tuple[str, ...]] = {
    "C": (
        "#####",
        "#    ",
        "#    ",
        "#    ",
        "#####",
    ),
    "L": (
        "#    ",
        "#    ",
        "#    ",
        "#    ",
        "#####",
    ),
    "U": (
        "#   #",
        "#   #",
        "#   #",
        "#   #",
        "#####",
    ),
    "S": (
        "#####",
        "#    ",
        "#####",
        "    #",
        "#####",
    ),
    "T": (
        "#####",
        "  #  ",
        "  #  ",
        "  #  ",
        "  #  ",
    ),
    "E": (
        "#####",
        "#    ",
        "#### ",
        "#    ",
        "#####",
    ),
    "R": (
        "#### ",
        "#   #",
        "#### ",
        "#  # ",
        "#   #",
    ),
    "M": (
        "#   #",
        "## ##",
        "# # #",
        "#   #",
        "#   #",
    ),
    "A": (
        "#####",
        "#   #",
        "#####",
        "#   #",
        "#   #",
    ),
    "X": (
        "#   #",
        " # # ",
        "  #  ",
        " # # ",
        "#   #",
    ),
}

BLOCK_FONT = Font(
    name="block",
    width=7,
    height=6,
    gap=1,
    ink=logo.BLOCK,
    glyphs=_BLOCK_GLYPHS,
)

ASCII_FONT = Font(
    name="ascii",
    width=5,
    height=5,
    gap=2,
    ink="#",
    glyphs=_ASCII_GLYPHS,
)

# Widest first. `select_font` walks this order and takes the first font that
# the terminal can encode and fit.
FONTS = (BLOCK_FONT, ASCII_FONT)


def select_font(
    *, width: int, unicode_ok: bool, word: str = WORD
) -> Font | None:
    """The widest font this terminal can both encode and fit, or None.

    None means every font is wider than the terminal, and the caller falls back
    to the plain word. Art wider than the terminal wraps on every row, which
    destroys the shape the banner exists to show.
    """
    for font in FONTS:
        if font.ink.isascii() is False and not unicode_ok:
            continue
        if not font.covers(word):
            continue
        if font.measure(word) <= width:
            return font
    return None


def logo_defects() -> list[str]:
    """The mark's own shape defects plus this module's composition rule.

    The mark is drawn beside the block wordmark, so the two must be the same
    height or the rows cannot be joined. That rule belongs here, because only
    this module knows what the mark is drawn next to.
    """
    found = logo.defects()
    if logo.HEIGHT != BLOCK_FONT.height:
        found.append(
            f"logo is {logo.HEIGHT} rows and the block font is "
            f"{BLOCK_FONT.height}"
        )
    return found


def glyph_defects() -> list[str]:
    """Shape defects across every defined font and the mark."""
    found: list[str] = []
    for font in FONTS:
        found.extend(font.defects())
    found.extend(logo_defects())
    return found


def compose(word: str = WORD, font: Font = BLOCK_FONT) -> list[str]:
    """The word as lines, with no color and no indent."""
    return font.compose(word)


def banner_width(word: str = WORD, font: Font = BLOCK_FONT) -> int:
    """Printable columns the composed word occupies."""
    return font.measure(word)


def full_width(word: str = WORD) -> int:
    """Columns the mark, the gap, and the block wordmark occupy together."""
    return LOGO_WIDTH + LOGO_GAP + BLOCK_FONT.measure(word)


def render(
    *,
    width: int,
    theme: Theme | None = None,
    word: str = WORD,
    depth: str | None = None,
) -> list[str]:
    """Banner lines for a terminal `width` columns wide.

    The mark is drawn beside the block wordmark when the terminal can hold
    both. A terminal that can hold only the wordmark gets the wordmark. A
    narrower or non-UTF terminal steps down to the ASCII font, and a terminal
    too narrow for either font gets the plain word.

    Each line drops its trailing spaces, because a trailing space serves no
    purpose on screen and leaves noise in a captured log.

    `depth` overrides the color depth, which lets a caller and a test state the
    depth instead of reading it from the environment.
    """
    resolved = theme or Theme()
    if not word:
        return []
    shade = depth if depth is not None else color_depth()
    font = select_font(width=width, unicode_ok=resolved.unicode, word=word)
    if font is None:
        return [resolved.paint(word, *GOLD.codes(shade))]

    with_logo = (
        font is BLOCK_FONT
        and resolved.unicode
        and width >= full_width(word)
    )
    art_width = full_width(word) if with_logo else font.measure(word)
    margin = " " * ((width - art_width) // 2)

    lines = []
    for index, row in enumerate(font.compose(word)):
        trimmed = row.rstrip()
        painted = (
            resolved.paint(trimmed, *GOLD.codes(shade)) if trimmed else ""
        )
        if with_logo:
            mark = logo.paint_row(logo.ROWS[index], resolved, shade)
            line = (margin + mark + " " * LOGO_GAP + painted).rstrip()
        else:
            line = (margin + painted).rstrip() if painted else ""
        lines.append(line)
    return lines


def should_show(stream: TextIO) -> bool:
    """Whether `stream` is a place this banner belongs.

    The banner follows the same gates as the progress display, because both are
    decoration that a pipe, a log file, or `CLUSTERMAX_PROGRESS=0` must not
    receive. A parser that reads piped CLI output must see the output it saw
    before this feature existed.
    """
    if not progress_enabled():
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def print_banner(stream: TextIO | None = None, *, word: str = WORD) -> bool:
    """Draw the banner and report whether it was drawn.

    The return value lets a caller decide its own spacing without repeating the
    gate checks that `should_show` performs.
    """
    target = stream if stream is not None else sys.stdout
    if not should_show(target):
        return False
    encoding = (getattr(target, "encoding", "") or "").lower()
    theme = Theme(
        color="NO_COLOR" not in os.environ,
        unicode="utf" in encoding,
    )
    width = shutil.get_terminal_size((100, 30)).columns
    lines: Sequence[str] = render(width=width, theme=theme, word=word)
    if not lines:
        return False
    target.write("\n".join(lines) + "\n\n")
    target.flush()
    return True
