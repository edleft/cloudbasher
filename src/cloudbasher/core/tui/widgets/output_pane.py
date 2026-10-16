"""Output pane widget for displaying ANSI-colored terminal output."""

from rich.text import Text

from .follow_tail import FollowTailLog


class OutputPane(FollowTailLog):
    """Scrollable output pane that accepts ANSI-filtered terminal text."""

    def push_ansi(self, filtered_text: str) -> None:
        """Write ANSI-colored output to the pane."""
        if filtered_text:
            self.write(Text.from_ansi(filtered_text))

    def get_plain_text(self, *, strip_ansi_codes: bool = True) -> str:
        """Extract pane content as plain text, joined with newlines."""
        from ...utils.output import strip_ansi as _strip

        line_strs: list[str] = []
        for strip in self.lines:

            try:
                line_strs.append("".join(seg.text for seg in strip))
            except TypeError:

                line_strs.append(str(strip))
        joined = "\n".join(line_strs)
        return _strip(joined) if strip_ansi_codes else joined
