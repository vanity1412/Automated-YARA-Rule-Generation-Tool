# -*- coding: utf-8 -*-
"""Reusable scrollable screen container for large Tkinter/ttk forms."""
import tkinter as tk
from tkinter import ttk


class ScrollableScreen(ttk.Frame):
    """A stable scrollable ttk screen.

    Large option panels can be clipped on smaller laptop screens.  This base
    class gives screens a canvas + vertical scrollbar while keeping the app's
    normal ttk styles.  It also supports mouse-wheel scrolling on Windows,
    macOS and Linux.
    """

    def __init__(self, parent, app, *args, **kwargs):
        super().__init__(parent, style="App.TFrame", *args, **kwargs)
        self.app = app
        self.canvas = None
        self.scrollbar = None
        self.scrollable_frame = None
        self._bound_mousewheel = False

    def create_scrollable_content(self, title: str | None = None):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        outer = ttk.Frame(self, style="App.TFrame")
        outer.grid(row=0, column=0, sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)

        self.canvas = tk.Canvas(outer, highlightthickness=0, borderwidth=0, background=self._bg())
        self.scrollbar = ttk.Scrollbar(outer, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.scrollable_frame = ttk.Frame(self.canvas, style="App.TFrame", padding=(2, 2, 10, 12))
        self._window_id = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.scrollable_frame.columnconfigure(0, weight=1)
        self.scrollable_frame.bind("<Configure>", self._on_frame_configure, add="+")
        self.canvas.bind("<Configure>", self._on_canvas_configure, add="+")
        self.canvas.bind("<Enter>", self._bind_mousewheel, add="+")
        self.canvas.bind("<Leave>", self._unbind_mousewheel, add="+")

        if title:
            header = ttk.Frame(self.scrollable_frame, style="App.TFrame")
            header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
            header.columnconfigure(0, weight=1)
            ttk.Label(header, text=title, style="Title.TLabel").grid(row=0, column=0, sticky="w")
            return_frame = ttk.Frame(self.scrollable_frame, style="App.TFrame")
            return_frame.grid(row=1, column=0, sticky="nsew")
            return_frame.columnconfigure(0, weight=1)
            return return_frame
        return self.scrollable_frame

    def _bg(self):
        try:
            return self.app.cget("bg")
        except Exception:
            return "#F8FBFF"

    def _on_frame_configure(self, _event=None):
        if self.canvas is not None:
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        if self.canvas is not None and hasattr(self, "_window_id"):
            self.canvas.itemconfigure(self._window_id, width=max(1, event.width))

    def _bind_mousewheel(self, _event=None):
        if self._bound_mousewheel or self.canvas is None:
            return
        root = self.winfo_toplevel()
        root.bind_all("<MouseWheel>", self._on_mousewheel, add="+")
        root.bind_all("<Button-4>", self._on_mousewheel, add="+")
        root.bind_all("<Button-5>", self._on_mousewheel, add="+")
        self._bound_mousewheel = True

    def _unbind_mousewheel(self, _event=None):
        if not self._bound_mousewheel:
            return
        root = self.winfo_toplevel()
        root.unbind_all("<MouseWheel>")
        root.unbind_all("<Button-4>")
        root.unbind_all("<Button-5>")
        self._bound_mousewheel = False

    def _on_mousewheel(self, event):
        if self.canvas is None:
            return
        if getattr(event, "num", None) == 4:
            delta = -3
        elif getattr(event, "num", None) == 5:
            delta = 3
        else:
            delta = int(-1 * (event.delta / 120))
        self.canvas.yview_scroll(delta, "units")
