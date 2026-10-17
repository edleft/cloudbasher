"""Command input widget with history navigation and search."""

from __future__ import annotations

from typing import Optional

from textual.widgets import Input


class CommandInput(Input):
    """Input widget with up/down history, Ctrl-R search, and Ctrl-U clear."""

    def __init__(
        self,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
        disabled: bool = False,
        history: Optional[list[str]] = None,
    ):
        super().__init__(name=name, id=id, classes=classes, disabled=disabled)
        self._history = history or []
        self._history_idx = -1
        self._draft = ""
        self._search_mode = False
        self._search_query = ""

    async def _on_key(self, event):
        """Handle key presses: up/down history, Ctrl-R search, Ctrl-U clear."""
        if self._search_mode:
            if event.key == "escape":
                self._search_mode = False
                self.value = self._draft
                event.stop()
                return
            elif event.key == "enter":

                if self._search_query and self._history:
                    for idx, entry in enumerate(self._history):
                        if entry.startswith(self._search_query):
                            self.value = entry
                            self._history_idx = len(self._history) - 1 - idx
                            self._search_mode = False
                            event.stop()
                            return
            elif event.key == "backspace":
                if self._search_query:
                    self._search_query = self._search_query[:-1]
                event.stop()
                return
            else:

                if (
                    hasattr(event, "character")
                    and event.character
                    and event.character.isprintable()
                ):
                    self._search_query += event.character
                    event.stop()
                    return
        else:

            if event.key == "up":
                self._history_older()
                event.stop()
                return
            elif event.key == "down":
                self._history_newer()
                event.stop()
                return
            elif event.key == "ctrl+r":

                if self._history:
                    self._search_mode = True
                    self._draft = self.value
                    self.value = ""
                    self._search_query = ""
                    event.stop()
                return
            elif event.key == "ctrl+u":

                self.value = ""
                event.stop()
                return
            elif event.key == "enter":


                self._history_idx = -1


        await super()._on_key(event)

    def _history_older(self) -> None:
        """Load previous command from history (up arrow)."""
        if not self._history:
            return

        if self._history_idx == -1:

            self._draft = self.value
            self._history_idx = len(self._history) - 1
        elif self._history_idx > 0:
            self._history_idx -= 1
        else:

            return

        if 0 <= self._history_idx < len(self._history):
            self.value = self._history[self._history_idx]

    def _history_newer(self) -> None:
        """Load next command from history (down arrow)."""
        if not self._history or self._history_idx == -1:
            return

        self._history_idx += 1

        if self._history_idx >= len(self._history):

            self._history_idx = -1
            self.value = self._draft
        else:
            self.value = self._history[self._history_idx]
