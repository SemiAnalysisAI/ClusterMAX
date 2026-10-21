from __future__ import annotations

import io
import os
from unittest import mock

from cmax import banner


class FakeTty(io.StringIO):
    encoding = "utf-8"

    def isatty(self) -> bool:
        return True


def test_banner_renders_to_a_terminal_but_not_a_pipe() -> None:
    stream = FakeTty()
    with mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=True):
        assert banner.print_banner(stream)
    assert stream.getvalue().strip()

    pipe = io.StringIO()
    assert not banner.print_banner(pipe)
    assert pipe.getvalue() == ""


def test_banner_is_ascii_safe() -> None:
    class AsciiTty(FakeTty):
        encoding = "ascii"

        def write(self, text: str) -> int:
            text.encode(self.encoding)
            return super().write(text)

    stream = AsciiTty()
    with mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=True):
        assert banner.print_banner(stream)
    assert stream.getvalue().strip()


def test_disabled_banner_produces_no_output() -> None:
    stream = FakeTty()
    with mock.patch.dict(os.environ, {"CLUSTERMAX_PROGRESS": "0"}, clear=True):
        assert not banner.print_banner(stream)
    assert stream.getvalue() == ""
