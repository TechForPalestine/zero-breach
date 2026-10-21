"""Zero Breach desktop app: a window around the same read-only scan as the CLI.

Packaged with PyInstaller (see zero-breach.spec) into a Windows .exe and a macOS
.app that carry their own Python, so the person running it installs nothing.

The window adds no scanning logic of its own. It loads the bundled indicator
file, runs the exact modules the command line runs - inside the same
no-network guard - and shows the same human report. Anything the report says,
the CLI would have said too.

  zero_breach_gui.py               open the window
  zero_breach_gui.py --self-test   load the indicators, check the optional
                                   pattern engine, exit 0/1 (used by CI on the
                                   packaged app; opens no window)
"""

from __future__ import annotations

import datetime
import importlib.util
import os
import queue
import re
import sys
import threading
import webbrowser


def _resource_root() -> str:
    """Where the bundled files live: the PyInstaller unpack directory when
    frozen, otherwise the repository root (this file sits in <root>/app/)."""
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


ROOT = _resource_root()
if not getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.join(ROOT, "scan"))

from adint_scan import __version__  # noqa: E402
from adint_scan.candiru_rules import CANDIRU_ENGINE_VERSION  # noqa: E402
from adint_scan.cli import _run_modules  # noqa: E402
from adint_scan.context import ScanContext  # noqa: E402
from adint_scan.iocs import IocError, load  # noqa: E402
from adint_scan.localpaths import path_problem  # noqa: E402
from adint_scan.report import (V_HITS, V_NONE, build_document,  # noqa: E402
                               render_human, write_json)

IOC_PATH = os.path.join(ROOT, "iocs", "adfection_iocs.txt")

HELP_LINKS = (
    ("Access Now Digital Security Helpline", "https://www.accessnow.org/help/"),
    ("Amnesty International Security Lab", "https://securitylab.amnesty.org/"),
)


def load_bundled_iocs():
    """Load the indicator file shipped inside the app.

    A frozen app unpacks its files at launch, so the file's mtime is "now" and
    the report would call a months-old indicator set fresh. Report the age of
    the DATA instead - the '# as-of:' header, as the single-file build does."""
    ioc_set = load(IOC_PATH)
    if getattr(sys, "frozen", False):
        with open(IOC_PATH, encoding="utf-8") as fh:
            m = re.search(r"^#\s*as-of:\s*(\d{4})-(\d{2})-(\d{2})\s*$",
                          fh.read(), re.M)
        if m:
            y, mo, d = (int(g) for g in m.groups())
            ioc_set.source_mtime = datetime.datetime(
                y, mo, d, tzinfo=datetime.timezone.utc).timestamp()
        ioc_set.source_path = "(bundled with this app)"
    return ioc_set


def pattern_engine_status():
    """(available, reason). The optional Candiru pattern check needs the pinned
    yara-x; the packaged app ships it when the build had it installed."""
    if importlib.util.find_spec("yara_x") is None:
        return False, "pattern engine (yara-x) is not included in this build"
    try:
        from importlib.metadata import version
        found = version("yara-x")
    except Exception as exc:  # metadata missing from the bundle
        return False, "pattern engine version unreadable: {}".format(exc)
    if found != CANDIRU_ENGINE_VERSION:
        return False, "pattern engine {} found; {} required".format(
            found, CANDIRU_ENGINE_VERSION)
    return True, "yara-x {}".format(found)


def self_test() -> int:
    """Headless check of the packaged app. Writes to a file as well as stdout,
    because a windowed Windows .exe has no console to print to."""
    lines = ["Zero Breach {} self-test".format(__version__)]
    ok = True
    try:
        iocs = load_bundled_iocs()
        lines.append("indicators: {} loaded from {}".format(
            len(iocs.indicators), iocs.source_path))
    except Exception as exc:
        lines.append("indicators: FAILED {}".format(exc))
        ok = False
    try:
        from adint_scan.modules import browser, hashscan, host  # noqa: F401
        lines.append("modules: ok")
    except Exception as exc:
        lines.append("modules: FAILED {}".format(exc))
        ok = False
    avail, why = pattern_engine_status()
    lines.append("patterns: {} ({})".format("available" if avail else "absent", why))
    if os.environ.get("ZB_REQUIRE_PATTERNS") and not avail:
        ok = False
    lines.append("result: {}".format("ok" if ok else "FAILED"))
    text = "\n".join(lines)
    out = os.environ.get("ZB_SELF_TEST_OUT")
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    try:
        print(text)
    except Exception:
        pass
    return 0 if ok else 1


# --- window -------------------------------------------------------------------

def _enable_windows_dpi_awareness() -> None:
    # Without this, Tk renders blurry on scaled Windows displays.
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass


class App:
    def __init__(self, root) -> None:
        import tkinter as tk
        from tkinter import font, ttk
        from tkinter.scrolledtext import ScrolledText

        self.tk = tk
        self.root = root
        self.events: "queue.Queue" = queue.Queue()
        self.document = None
        self.report_text = ""
        self.running = False

        root.title("Zero Breach {}".format(__version__))
        root.minsize(760, 560)
        root.geometry("920x700")

        mono = font.nametofont("TkFixedFont").copy()
        mono.configure(size=max(10, mono.cget("size")))
        bold = font.nametofont("TkDefaultFont").copy()
        bold.configure(weight="bold", size=bold.cget("size") + 4)

        outer = ttk.Frame(root, padding=14)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="Zero Breach — AdFection / Candiru indicator check",
                  font=bold).pack(anchor="w")
        ttk.Label(outer, wraplength=860, justify="left", text=(
            "Looks for published traces of ad-delivered spyware in this "
            "computer's browser data, files and settings. It only reads: it "
            "changes nothing, needs no administrator, and makes no network "
            "connections. Close your web browsers before scanning so their "
            "data is not locked.\n"
            "A clean result is NOT a clean bill of health - the report lists "
            "what could not be checked.")).pack(anchor="w", pady=(6, 10))

        opts = ttk.Frame(outer)
        opts.pack(fill="x")
        self.quick = tk.BooleanVar(value=False)
        self.quick_cb = ttk.Checkbutton(
            opts, variable=self.quick,
            text="Quick scan (skip file fingerprints; roughly halves the time)")
        self.quick_cb.pack(anchor="w")

        avail, why = pattern_engine_status()
        self.patterns = tk.BooleanVar(value=False)
        self.patterns_cb = ttk.Checkbutton(
            opts, variable=self.patterns,
            text="Also run experimental Candiru file patterns"
                 + ("" if avail else "  (unavailable: {})".format(why)))
        if not avail:
            self.patterns_cb.state(["disabled"])
        self.patterns_cb.pack(anchor="w")

        bar = ttk.Frame(outer)
        bar.pack(fill="x", pady=(10, 6))
        self.start_btn = ttk.Button(bar, text="Start scan", command=self.start)
        self.start_btn.pack(side="left")
        self.save_txt_btn = ttk.Button(bar, text="Save report…",
                                       command=self.save_txt, state="disabled")
        self.save_txt_btn.pack(side="left", padx=(8, 0))
        self.save_json_btn = ttk.Button(bar, text="Save JSON…",
                                        command=self.save_json, state="disabled")
        self.save_json_btn.pack(side="left", padx=(8, 0))
        self.copy_btn = ttk.Button(bar, text="Copy report",
                                   command=self.copy, state="disabled")
        self.copy_btn.pack(side="left", padx=(8, 0))
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=180)
        self.progress.pack(side="right")

        self.status = tk.StringVar(value="Ready.")
        self.verdict = tk.Label(outer, textvariable=self.status, anchor="w",
                                justify="left", padx=10, pady=8,
                                bg="#e8e8e8", fg="#000000")
        self.verdict.pack(fill="x", pady=(0, 6))

        self.text = ScrolledText(outer, wrap="none", font=mono, height=20)
        self.text.pack(fill="both", expand=True)
        self.text.configure(state="disabled")

        links = ttk.Frame(outer)
        links.pack(fill="x", pady=(8, 0))
        ttk.Label(links, text="Real reason to worry? Get expert help:").pack(side="left")
        for label, url in HELP_LINKS:
            lk = tk.Label(links, text=label, fg="#1a5fb4", cursor="hand2")
            lk.pack(side="left", padx=(10, 0))
            lk.bind("<Button-1>", lambda _e, u=url: webbrowser.open(u))

        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(100, self.pump)

    # -- text area

    def _set_text(self, text: str) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("end", text)
        self.text.configure(state="disabled")

    def _append(self, line: str) -> None:
        self.text.configure(state="normal")
        self.text.insert("end", line + "\n")
        self.text.see("end")
        self.text.configure(state="disabled")

    def _banner(self, text: str, bg: str, fg: str = "#000000") -> None:
        self.status.set(text)
        self.verdict.configure(bg=bg, fg=fg)

    # -- scan

    def start(self) -> None:
        if self.running:
            return
        try:
            iocs = load_bundled_iocs()
        except IocError as exc:
            self._banner("Could not load the indicator list: {}".format(exc), "#f6d5d5")
            return
        self.running = True
        self.document = None
        self.report_text = ""
        for w in (self.start_btn, self.save_txt_btn, self.save_json_btn, self.copy_btn):
            w.state(["disabled"])
        self.quick_cb.state(["disabled"])
        self.patterns_cb.state(["disabled"])
        self._set_text("")
        self._banner("Scanning… this can take several minutes. You can close "
                     "the window at any time; nothing is being modified.", "#fff4cc")
        self.progress.start(12)
        ctx = ScanContext(iocs=iocs, quick=self.quick.get(),
                          patterns=self.patterns.get(),
                          emit=lambda msg: self.events.put(("log", msg)))
        threading.Thread(target=self._worker, args=(iocs, ctx), daemon=True).start()

    def _worker(self, iocs, ctx) -> None:
        try:
            started = datetime.datetime.now()
            results = _run_modules(ctx)
            document = build_document(iocs, results, started)
            self.events.put(("done", (document, render_human(document))))
        except Exception as exc:  # surface it rather than hang the window
            self.events.put(("error", exc))

    def pump(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._append(payload)
                elif kind == "done":
                    self._finish(*payload)
                elif kind == "error":
                    self._failed(payload)
        except queue.Empty:
            pass
        self.root.after(100, self.pump)

    def _end_run(self) -> None:
        self.running = False
        self.progress.stop()
        self.start_btn.state(["!disabled"])
        self.start_btn.configure(text="Scan again")
        self.quick_cb.state(["!disabled"])
        if pattern_engine_status()[0]:
            self.patterns_cb.state(["!disabled"])

    def _finish(self, document, text: str) -> None:
        self._end_run()
        self.document = document
        self.report_text = text
        self._set_text(text)
        for w in (self.save_txt_btn, self.save_json_btn, self.copy_btn):
            w.state(["!disabled"])
        status = document["verdict"]["status"]
        if status == V_HITS:
            self._banner("RESULT: something matched. This means INVESTIGATE, not "
                         "\"you are infected\". Read the summary at the top of the "
                         "report and follow its next steps.", "#f6d5d5")
        elif status == V_NONE:
            self._banner("RESULT: no known indicators found. This is not a clean "
                         "bill of health - read the report.", "#d9f2d9")
        else:
            self._banner("RESULT: no known indicators found, but some checks could "
                         "not run. Read what was not checked in the report.",
                         "#d9f2d9")

    def _failed(self, exc) -> None:
        self._end_run()
        self._append("\nThe scan could not complete: {}".format(exc))
        self._banner("The scan could not complete: {}".format(exc), "#f6d5d5")

    # -- output

    def _default_name(self, ext: str) -> str:
        return "zero-breach-{}.{}".format(
            datetime.datetime.now().strftime("%Y%m%d-%H%M%S"), ext)

    def _ask_path(self, ext: str, kind: str):
        from tkinter import filedialog, messagebox
        path = filedialog.asksaveasfilename(
            parent=self.root, defaultextension="." + ext,
            initialfile=self._default_name(ext),
            filetypes=[(kind, "*." + ext), ("All files", "*")])
        if not path:
            return None
        # Same rule as the CLI's --json: creating a file on a UNC path or mapped
        # network drive makes Windows open an SMB session and send the report off
        # the machine.
        problem = path_problem(os.path.abspath(path))
        if problem:
            messagebox.showerror("Zero Breach", "Not saved: {}.\nChoose a folder on "
                                 "this computer's own disk.".format(problem),
                                 parent=self.root)
            return None
        return path

    def save_txt(self) -> None:
        from tkinter import messagebox
        path = self._ask_path("txt", "Text report")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(self.report_text + "\n")
        except OSError as exc:
            messagebox.showerror("Zero Breach", "Could not save: {}".format(exc),
                                 parent=self.root)

    def save_json(self) -> None:
        from tkinter import messagebox
        path = self._ask_path("json", "JSON report")
        if not path:
            return
        try:
            write_json(self.document, path)
        except OSError as exc:
            messagebox.showerror("Zero Breach", "Could not save: {}".format(exc),
                                 parent=self.root)

    def copy(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(self.report_text)

    def close(self) -> None:
        if self.running:
            from tkinter import messagebox
            if not messagebox.askyesno(
                    "Zero Breach", "A scan is running. Stop it and close? "
                    "Nothing on this computer has been changed.", parent=self.root):
                return
        self.root.destroy()


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--self-test" in argv:
        return self_test()
    if "--version" in argv:
        print("Zero Breach {}".format(__version__))
        return 0
    _enable_windows_dpi_awareness()
    import tkinter as tk
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
