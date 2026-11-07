"""arcount-popup: the alert card the desktop agent shows (tkinter, standard library).

Run as its own short-lived process by `arcount.notify_agent`, one per alert:
    python3 -m arcount.popup --spec '<json>'
It prints the key of the button the user clicked on stdout and exits 0. An alert with actions stays
on screen until one is clicked (no timeout, no close button, no keyboard shortcuts). Exit status 2
means "no usable display or tkinter"; the agent then falls back to `notify-send`. Wayland sessions
never get a card (an undecorated always-on-top window is not reliable there): they use `notify-send`.

Everything in the spec can contain network-controlled text (SSIDs, hostnames). tkinter labels
show it as plain text, never as markup, and it is length-capped and stripped of control characters.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys

COLORS = {"critical": "#ff5454", "high": "#ff5454", "medium": "#fbbf24", "low": "#60a5fa", "info": "#60a5fa"}
BG, PANEL, INK, DIM, BTN = "#141a24", "#1e252f", "#ecf1f7", "#aab4c2", "#323d4d"
WIDTH = 470
SLOT_PX = 360                 # vertical room per stacked card
ARM_MS = 700                  # buttons ignore clicks this long, so a click aimed at another window cannot answer
KEY_RE = re.compile(r"^[a-z][a-z0-9_-]{0,23}$")
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean(s, limit: int) -> str:
    s = CTRL_RE.sub("?", str(s))
    return s if len(s) <= limit else s[:limit - 1] + "…"


def parse_spec(raw: str) -> dict:
    """Validate and bound the JSON spec. Raises ValueError for anything unusable."""
    d = json.loads(raw)
    if not isinstance(d, dict):
        raise ValueError("spec must be an object")
    actions = []
    for a in d.get("actions") or []:
        if isinstance(a, (list, tuple)) and len(a) == 2 and KEY_RE.match(str(a[0])) and len(actions) < 3:
            actions.append((str(a[0]), clean(a[1], 40)))
    sev = d.get("severity") if d.get("severity") in COLORS else "medium"
    persistent = bool(d.get("persistent")) and bool(actions)
    timeout = 0 if persistent else max(3, min(120, int(d.get("timeout") or 12)))
    return {"title": clean(d.get("title") or "Arcount", 90), "body": clean(d.get("body") or "", 600),
            "severity": sev, "confirmed": bool(d.get("confirmed")), "actions": actions,
            "persistent": persistent, "timeout": timeout, "slot": max(0, min(5, int(d.get("slot") or 0)))}


def header(spec: dict) -> str:
    tag = spec["severity"].upper() + ("  ·  confirmed" if spec["confirmed"] else "")
    return f"Arcount  ·  {tag}"


def unavailable_reason() -> str | None:
    """Why the card cannot be used here, or None. Does not open a window."""
    if os.environ.get("WAYLAND_DISPLAY") or os.environ.get("XDG_SESSION_TYPE", "").lower() == "wayland":
        return "this is a Wayland session"
    if not os.environ.get("DISPLAY"):
        return "no X display"
    try:
        import tkinter  # noqa: F401
    except ImportError:
        return "python3-tk is not installed"
    return None


def available() -> bool:
    return unavailable_reason() is None


def probe(timeout: float = 10.0) -> bool:
    """Open and close an invisible tkinter window in a child process: proves the display works."""
    try:
        return subprocess.run([sys.executable, "-m", "arcount.popup", "--probe"], capture_output=True,
                              timeout=timeout, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def blend(a: str, b: str, t: float) -> str:
    ca, cb = [int(a[i:i + 2], 16) for i in (1, 3, 5)], [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{int(x + (y - x) * t):02x}" for x, y in zip(ca, cb))


def round_button(tk, parent, text, command, fill, fg, hover, font, bg, radius=12, padx=18, pady=10):
    """A flat button with rounded corners (a canvas; tk.Button cannot be rounded)."""
    import tkinter.font as tkfont
    f = tkfont.Font(font=font)
    w, h = f.measure(text) + 2 * padx, f.metrics("linespace") + 2 * pady
    c = tk.Canvas(parent, width=w, height=h, bg=bg, highlightthickness=0, bd=0, takefocus=0)
    r = min(radius, h // 2)
    pts = []
    for cx, cy, a0 in ((w - r, r, -90), (w - r, h - r, 0), (r, h - r, 90), (r, r, 180)):     # four quarter circles
        for k in range(9):
            a = math.radians(a0 + 10 * k)
            pts += [cx + r * math.cos(a), cy + r * math.sin(a)]
    shape = c.create_polygon(pts, fill=fill, outline=fill)
    c.create_text(w / 2, h / 2, text=text, fill=fg, font=font)
    state = {"on": False}

    def paint(color):
        c.itemconfig(shape, fill=color, outline=color)

    def arm():
        state["on"] = True
        c.config(cursor="hand2")

    c.arm = arm
    c.bind("<Enter>", lambda e: state["on"] and paint(hover))
    c.bind("<Leave>", lambda e: paint(fill))
    c.bind("<Button-1>", lambda e: state["on"] and command())
    paint(blend(fill, bg, 0.55))
    c.after(ARM_MS, lambda: (paint(fill), arm()))
    return c


def show(spec: dict) -> str:
    """Build the card, block until a button (or the timeout) ends it, return the clicked key."""
    import tkinter as tk
    root = tk.Tk()
    color = COLORS[spec["severity"]]
    choice = [""]
    root.overrideredirect(True)
    root.attributes("-topmost", True)
    root.configure(bg=color)
    root.title("Arcount")
    card = tk.Frame(root, bg=PANEL)
    card.pack(padx=3, pady=3)
    inner = tk.Frame(card, bg=PANEL)
    inner.pack(padx=26, pady=(22, 22))
    tk.Label(inner, text=header(spec), bg=PANEL, fg=color, font=("Sans", 10, "bold"), anchor="w").pack(fill="x")
    tk.Label(inner, text=spec["title"], bg=PANEL, fg=INK, font=("Sans", 17, "bold"), anchor="w",
             justify="left", wraplength=WIDTH - 52).pack(fill="x", pady=(8, 8))
    if spec["body"]:
        tk.Label(inner, text=spec["body"], bg=PANEL, fg=DIM, font=("Sans", 11), anchor="w", justify="left",
                 wraplength=WIDTH - 52).pack(fill="x", pady=(0, 14))
    row = tk.Frame(inner, bg=PANEL)
    row.pack(fill="x")

    def answer(key):
        choice[0] = key
        root.destroy()
    for i, (key, label) in enumerate(spec["actions"]):
        primary = i == 0
        fill = color if primary else BTN
        round_button(tk, row, label, lambda k=key: answer(k), fill, "#1a0a0a" if primary else INK,
                     blend(fill, "#ffffff", 0.18), ("Sans", 11, "bold"), PANEL).pack(side="left", padx=(0, 10))
    root.update_idletasks()
    x = max(0, root.winfo_screenwidth() - root.winfo_reqwidth() - 24)
    root.geometry(f"+{x}+{24 + spec['slot'] * SLOT_PX}")
    if spec["timeout"]:
        root.after(spec["timeout"] * 1000, root.destroy)
    root.mainloop()
    return choice[0]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="arcount-popup")
    ap.add_argument("--spec", help="JSON: title, body, severity, confirmed, actions, persistent, timeout, slot")
    ap.add_argument("--probe", action="store_true", help="open and close an invisible window; exit 0 if that works")
    args = ap.parse_args(argv)
    if args.probe:
        try:
            import tkinter as tk
            tk.Tk().destroy()
            return 0
        except Exception:
            return 2
    if not args.spec:
        return 2
    try:
        spec = parse_spec(args.spec)
    except (ValueError, TypeError):
        return 2
    try:
        key = show(spec)
    except Exception:       # no display, no tkinter, X refused us: let the agent fall back
        return 2
    sys.stdout.write(key + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
