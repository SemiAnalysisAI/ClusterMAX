"""The SemiAnalysis mark as a reusable terminal component.

This module owns one thing: the company mark, reduced to a terminal grid, with
the color model needed to draw it at any terminal depth. `cmax/banner.py`
composes it beside the product wordmark, and any other surface that wants the
mark imports it from here rather than redrawing it.

Provenance. The geometry and both colors were measured from the opaque pixels
of `dashboard/public/semianalysis-logo.png`, where the mark is the four
connected shapes that lie outside the wordmark band. Every bar runs at 45
degrees, each bar is about 14 pixels thick with about 30 pixels between the two
centers of a pair, and the bars sit in two pairs. The upper pair is blue on the
left and orange on the right. The lower pair holds the same two diagonals and
swaps the colors. Do not take the geometry from
`dashboard/public/semianalysis-icon.svg`. That file is a hand-drawn stand-in
whose bar directions and colors both differ from the logo it is named for.

Two reductions were made for the terminal, and both are deliberate. First, the
logo separates the pairs by the width of the word that passes between them.
Nothing passes between them here, so the pairs are joined into one continuous
double diagonal and the color still swaps at the join. Second, each ribbon is
four columns wide against the two-column step per row, so consecutive rows
overlap by two columns and the ribbon stays solid. A ribbon exactly as wide as
the step touches the next row only at a corner, and a terminal that spaces its
cells draws that as a chain of separate squares rather than a bar. A terminal
cell is about twice as tall as it is wide, so the two-column step per row is
what 45 degrees means on this grid.

The grid is drawn with the solid block, so it must go only to a stream whose
encoding can carry one. `Theme.encodable` in `cmax/progress.py` exists because
one code point outside the terminal's range raises UnicodeEncodeError on write
and takes the display down. The caller owns that gate, because the caller owns
the stream.
"""

from __future__ import annotations

import itertools
import os
from dataclasses import dataclass

from cmax.progress import Theme

BLOCK = "█"

TRUECOLOR = "truecolor"
PALETTE256 = "256"
BASIC = "basic"

_TRUECOLOR_VALUES = frozenset({"truecolor", "24bit"})


@dataclass(frozen=True)
class Ink:
    """One color, expressed at each terminal color depth.

    `xterm256` is the nearest entry in the 216-entry color cube, chosen by
    red-mean distance. `basic` is the 16-color stand-in for a terminal that has
    neither of the richer forms.
    """

    name: str
    hex: str
    rgb: tuple[int, int, int]
    xterm256: int
    basic: tuple[str, ...]

    def codes(self, depth: str) -> tuple[str, ...]:
        if depth == TRUECOLOR:
            red, green, blue = self.rgb
            return ("38", "2", str(red), str(green), str(blue))
        if depth == PALETTE256:
            return ("38", "5", str(self.xterm256))
        return self.basic


def color_depth(env: dict[str, str] | None = None) -> str:
    """How much color this terminal accepts.

    A 24-bit sequence sent to a terminal that cannot read it prints the digits
    as text across the art, so the richer forms are used only when the
    environment advertises them.
    """
    source = os.environ if env is None else env
    if (source.get("COLORTERM") or "").strip().lower() in _TRUECOLOR_VALUES:
        return TRUECOLOR
    if "256color" in (source.get("TERM") or "").lower():
        return PALETTE256
    return BASIC


# The two mark colors, sampled from the logo pixels named in the module
# docstring.
BLUE = Ink(
    name="logo blue",
    hex="#0B86D1",
    rgb=(11, 134, 209),
    xterm256=32,
    basic=("34", "1"),
)
ORANGE = Ink(
    name="logo orange",
    hex="#F7B041",
    rgb=(247, 176, 65),
    xterm256=215,
    basic=("33", "1"),
)

ROWS: tuple[str, ...] = (
    "..........BBBB...OOOO",
    "........BBBB...OOOO..",
    "......BBBB...OOOO....",
    "....OOOO...BBBB......",
    "..OOOO...BBBB........",
    "OOOO...BBBB..........",
)

WIDTH = 21
HEIGHT = 6

_INKS = {"B": BLUE, "O": ORANGE}


def defects() -> list[str]:
    """Every way the mark grid breaks its declared shape.

    Composition places the grid beside other art at fixed offsets, so a row of
    the wrong size shifts everything to its right. The rule is checked here and
    asserted by the tests rather than left to review.
    """
    found: list[str] = []
    if len(ROWS) != HEIGHT:
        found.append(f"logo has {len(ROWS)} rows, needs {HEIGHT}")
    for index, row in enumerate(ROWS):
        if len(row) != WIDTH:
            found.append(f"logo row {index} is {len(row)} columns, needs {WIDTH}")
        unexpected = set(row) - {".", *_INKS}
        if unexpected:
            found.append(f"logo row {index} has {sorted(unexpected)!r}")
    return found


def paint_row(row: str, theme: Theme, depth: str) -> str:
    """One mark row, with each run of a color painted as a single sequence.

    Painting per run rather than per cell keeps the line short. A sequence for
    every cell would multiply the row length many times over for no visible
    difference.
    """
    parts: list[str] = []
    for char, group in itertools.groupby(row):
        run = len(list(group))
        if char == ".":
            parts.append(" " * run)
            continue
        parts.append(theme.paint(BLOCK * run, *_INKS[char].codes(depth)))
    return "".join(parts)


def render(*, theme: Theme | None = None, depth: str | None = None) -> list[str]:
    """The mark as `HEIGHT` painted lines with no indent.

    Trailing spaces are kept, so every line is exactly `WIDTH` printable
    columns and a caller can place art directly to the right of any row. A
    caller that ends a line at the mark strips the trail itself.
    """
    resolved = theme or Theme()
    shade = depth if depth is not None else color_depth()
    return [paint_row(row, resolved, shade) for row in ROWS]
