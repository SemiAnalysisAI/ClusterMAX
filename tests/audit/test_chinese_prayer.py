from __future__ import annotations

import io
import os
from pathlib import Path
from unittest import mock

import pytest
from prompt_toolkit.utils import get_cwidth

from cmax import banner, cli
from cmax.audit_profiles import AUDIT_CATEGORY_NAMES


class EncodedTty(io.StringIO):
    def __init__(self, encoding: str = "utf-8") -> None:
        super().__init__()
        self._encoding = encoding

    @property
    def encoding(self) -> str:
        return self._encoding

    def isatty(self) -> bool:
        return True

    def write(self, text: str) -> int:
        text.encode(self.encoding)
        return super().write(text)


@pytest.fixture(autouse=True)
def clean_display_environment():
    with mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=True):
        yield


@pytest.mark.parametrize(
    "command",
    [
        ["audit"],
        ["audit", "security"],
        ["audit", "review"],
        *[["audit", name] for name in AUDIT_CATEGORY_NAMES],
        *[["audit", name] for name in cli.AUDIT_TARGET_NAMES],
    ],
)
def test_flag_works_at_every_command_level(command: list[str]) -> None:
    parser = cli.build_parser()
    assert parser.parse_args(command).chinese is False
    for position in range(len(command) + 1):
        argv = command[:position] + ["--chinese"] + command[position:]
        args = parser.parse_args(argv)
        assert args.chinese is True, argv
        assert args.command == "audit"
        assert args.profile == (command[1] if len(command) > 1 else None)
    assert parser.parse_args(["--chinese", *command, "--chinese"]).chinese


def test_chinese_is_passed_to_live_banner_and_does_not_leak_between_calls() -> None:
    with mock.patch.object(banner, "print_banner") as rendered, mock.patch.object(
        cli, "_run_audit", return_value=0
    ) as run:
        assert cli.main(["audit", "--local", "--chinese"]) == 0
        assert run.call_args.args[0].chinese is True
        assert cli.main(["audit", "--local"]) == 0
    assert rendered.call_args_list == [
        mock.call(chinese=True),
        mock.call(chinese=False),
    ]


@pytest.mark.parametrize("encoding", ["utf-8", "gb18030"])
def test_chinese_prayer_is_complete_and_printed_once(encoding: str) -> None:
    stream = EncodedTty(encoding)
    with mock.patch(
        "shutil.get_terminal_size", return_value=os.terminal_size((120, 30))
    ):
        assert banner.print_banner(stream, chinese=True)
    output = stream.getvalue()
    assert output.count("为集群祈祷") == 1
    for verse in banner.CHINESE_PRAYER:
        assert output.count(verse) == 1
    assert output.endswith("对齐者有福了。\n阿门。\n\n")
    assert "O Lord" not in output
    assert "\x1b" not in output


@pytest.mark.parametrize("width", [2, 3, 10, 20, 40, 80, 120])
def test_chinese_wraps_by_display_cells_without_losing_text(width: int) -> None:
    stream = EncodedTty()
    with mock.patch(
        "shutil.get_terminal_size", return_value=os.terminal_size((width, 30))
    ):
        banner.print_banner(stream, chinese=True)
    prayer = stream.getvalue().split("\n\n", 1)[1]
    assert all(get_cwidth(line) <= width for line in prayer.splitlines())
    assert "".join(prayer.split()) == "".join(
        ("为集群祈祷" + "".join(banner.CHINESE_PRAYER)).split()
    )


@pytest.mark.parametrize("encoding", ["ascii", "latin-1"])
def test_incompatible_encoding_falls_back_to_english(encoding: str) -> None:
    stream = EncodedTty(encoding)
    assert banner.print_banner(stream, chinese=True)
    output = stream.getvalue()
    assert "A prayer for the cluster" in output
    assert "Blessed are the aligned." in output
    assert output.isascii()


def test_one_column_terminal_falls_back_without_overflow() -> None:
    stream = EncodedTty()
    with mock.patch(
        "shutil.get_terminal_size", return_value=os.terminal_size((1, 30))
    ):
        banner.print_banner(stream, chinese=True)
    prayer = stream.getvalue().split("\n\n", 1)[1]
    assert all(get_cwidth(line) <= 1 for line in prayer.splitlines())
    assert "Blessedarethealigned." in "".join(prayer.split())


def test_default_english_output_is_unchanged() -> None:
    implicit, explicit = EncodedTty(), EncodedTty()
    banner.print_banner(implicit)
    banner.print_banner(explicit, chinese=False)
    assert implicit.getvalue() == explicit.getvalue()
    assert "Blessed are the aligned." in implicit.getvalue()


def test_chinese_is_silent_for_pipes_and_disabled_progress() -> None:
    pipe = io.StringIO()
    assert not banner.print_banner(pipe, chinese=True)
    assert pipe.getvalue() == ""
    terminal = EncodedTty()
    with mock.patch.dict(os.environ, {"CLUSTERMAX_PROGRESS": "0"}):
        assert not banner.print_banner(terminal, chinese=True)
    assert terminal.getvalue() == ""


@pytest.mark.parametrize(
    "args",
    [
        ["--help"],
        ["--version"],
        ["audit", "--help"],
        ["audit", "security", "--help"],
    ],
)
def test_chinese_help_and_version_never_print_banner(args: list[str]) -> None:
    with mock.patch.object(banner, "print_banner") as rendered:
        with pytest.raises(SystemExit) as result:
            cli.main(["--chinese", *args])
    assert result.value.code == 0
    rendered.assert_not_called()


@pytest.mark.parametrize(
    "args",
    [
        ["audit", "--local", "--show"],
        ["audit", "security", "--local", "--show"],
        ["audit", "security", "--local", "--dry-run", "-o", "yaml"],
    ],
)
def test_inspection_output_is_identical_in_both_languages(args: list[str]) -> None:
    english, chinese = EncodedTty(), EncodedTty()
    with mock.patch("sys.stdout", english):
        assert cli.main(args) == 0
    with mock.patch("sys.stdout", chinese):
        assert cli.main([*args, "--chinese"]) == 0
    assert english.getvalue()
    assert english.getvalue() == chinese.getvalue()
    assert "阿门" not in chinese.getvalue()


def test_unknown_options_still_fail() -> None:
    with mock.patch("sys.stdout", io.StringIO()), pytest.raises(SystemExit) as result:
        cli.main(["audit", "--chinese", "--not-a-real-option"])
    assert result.value.code == 2


def test_chinese_yaml_file_output_matches_english(tmp_path: Path) -> None:
    outputs = []
    for chinese in (False, True):
        path = tmp_path / f"plan-{chinese}.yaml"
        args = [
            "audit", "security", "--local", "--dry-run", "-o", "yaml",
            "--output-file", str(path),
        ]
        if chinese:
            args.append("--chinese")
        stream = EncodedTty()
        with mock.patch("sys.stdout", stream):
            assert cli.main(args) == 0
        assert stream.getvalue() == ""
        outputs.append(path.read_bytes())
    assert outputs[0] == outputs[1]


def test_live_cli_prints_chinese_before_audit_dispatch() -> None:
    stream = EncodedTty()

    def run_audit(*_args: object) -> int:
        assert stream.getvalue().endswith("对齐者有福了。\n阿门。\n\n")
        assert "Blessed are the aligned." not in stream.getvalue()
        return 0

    with mock.patch("sys.stdout", stream), mock.patch.object(
        cli, "_run_audit", side_effect=run_audit
    ) as run:
        assert cli.main(["--chinese", "audit", "--local"]) == 0
    run.assert_called_once()
