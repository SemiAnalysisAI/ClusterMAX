from __future__ import annotations

import argparse
import io
import os
from unittest import mock

import pytest

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
        {"command": "audit", "output_file": "audit.yaml"},
        {"command": "other"},
    ):
        with mock.patch.object(banner, "print_banner") as rendered:
            cli._show_banner(argparse.Namespace(**fields))
        rendered.assert_not_called()


def test_prayer_follows_the_logo_once() -> None:
    stream = FakeTty()
    with mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=True), mock.patch(
        "shutil.get_terminal_size", return_value=os.terminal_size((120, 30))
    ):
        assert banner.print_banner(stream)
    output = stream.getvalue()
    assert output.index("█") < output.index("A prayer for the cluster")
    for line in banner.STARTUP_PRAYER:
        assert output.count(line) == 1
    assert output.count("Blessed be the aligned.") == 1
    assert "Blessed be the aligned.\nAmen.\n\n" in output
    assert output.endswith("Amen.\n\n")
    assert "\x1b" not in output


@pytest.mark.parametrize("width", [1, 20, 40, 80, 120])
def test_prayer_wraps_to_terminal_width(width: int) -> None:
    stream = FakeTty()
    with mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=True), mock.patch(
        "shutil.get_terminal_size", return_value=os.terminal_size((width, 30))
    ):
        banner.print_banner(stream)
    prayer = stream.getvalue().split("\n\n", 1)[1]
    assert all(len(line) <= width for line in prayer.splitlines())
    assert "".join(prayer.split()) == "".join(
        ("A prayer for the cluster" + "".join(banner.STARTUP_PRAYER)).split()
    )


def test_prayer_is_ascii_safe() -> None:
    class AsciiTty(FakeTty):
        encoding = "ascii"

    stream = AsciiTty()
    with mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=True):
        banner.print_banner(stream)
    assert "Amen." in stream.getvalue()
    stream.getvalue().encode("ascii")


def test_progress_opt_out_also_hides_prayer() -> None:
    stream = FakeTty()
    with mock.patch.dict(os.environ, {"CLUSTERMAX_PROGRESS": "0"}, clear=True):
        assert not banner.print_banner(stream)
    assert stream.getvalue() == ""


def test_live_cli_prints_prayer_before_dispatch() -> None:
    stream = FakeTty()

    def run_audit(*_args: object) -> int:
        assert stream.getvalue().endswith("Amen.\n\n")
        return 0

    with mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=True), mock.patch(
        "sys.stdout", stream
    ), mock.patch.object(cli, "_run_audit", side_effect=run_audit) as run:
        assert cli.main(["audit", "--local"]) == 0
    run.assert_called_once()


@pytest.mark.parametrize("args", [["--help"], ["--version"], ["audit", "--help"]])
def test_help_and_version_do_not_print_prayer(args: list[str]) -> None:
    with mock.patch.object(banner, "print_banner") as rendered:
        with pytest.raises(SystemExit) as result:
            cli.main(args)
    assert result.value.code == 0
    rendered.assert_not_called()
