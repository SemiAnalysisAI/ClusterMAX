from __future__ import annotations

import argparse
import io
import os
from unittest import mock

from cmax import banner, cli, logo
from cmax.progress import Theme


class FakeTty(io.StringIO):
    encoding = "utf-8"

    def isatty(self) -> bool:
        return True


def test_master_art_geometry_and_brand_colors_are_preserved() -> None:
    assert banner.glyph_defects() == []
    assert logo.ROWS == (
        "..........BBBB...OOOO",
        "........BBBB...OOOO..",
        "......BBBB...OOOO....",
        "....OOOO...BBBB......",
        "..OOOO...BBBB........",
        "OOOO...BBBB..........",
    )
    assert logo.BLUE.hex == "#0B86D1"
    assert logo.ORANGE.hex == "#F7B041"
    assert banner.GOLD.hex == "#E8A830"


def test_wide_terminal_renders_the_mark_and_clustermax_wordmark() -> None:
    lines = banner.render(
        width=banner.full_width(),
        theme=Theme(color=False, unicode=True),
    )
    assert len(lines) == 6
    assert all("█" in line for line in lines)
    assert lines[0].startswith(" " * 10 + "████")


def test_non_utf_terminal_uses_the_ascii_wordmark() -> None:
    lines = banner.render(width=120, theme=Theme(color=False, unicode=False))
    assert len(lines) == banner.ASCII_FONT.height
    assert all(line.isascii() for line in lines)


def test_banner_prints_only_to_an_interactive_terminal() -> None:
    stream = FakeTty()
    with mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=True), mock.patch(
        "shutil.get_terminal_size", return_value=os.terminal_size((120, 30))
    ):
        assert banner.print_banner(stream)
    assert "█" in stream.getvalue()
    assert stream.getvalue().endswith("\n\n")

    pipe = io.StringIO()
    assert not banner.print_banner(pipe)
    assert pipe.getvalue() == ""


def test_cli_wires_banner_to_live_audits_only() -> None:
    with mock.patch.object(banner, "print_banner") as rendered:
        cli._show_banner(argparse.Namespace(command="audit", show=False))
    rendered.assert_called_once_with()

    for fields in (
        {"command": "audit", "show": True},
        {"command": "audit", "dry_run": True},
        {"command": "audit", "output_format": "yaml"},
    ):
        with mock.patch.object(banner, "print_banner") as rendered:
            cli._show_banner(argparse.Namespace(**fields))
        rendered.assert_not_called()
