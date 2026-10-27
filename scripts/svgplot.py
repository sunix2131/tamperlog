"""Минимальный построитель графиков в SVG в духе matplotlib/pgfplots для статей:
рамка вокруг поля, засечки внутрь на всех сторонах, малые засечки на лог-шкале,
шрифт с засечками. Только стандартная библиотека Python."""
import math
from xml.sax.saxutils import escape

FONT = "STIX Two Text, STIXGeneral, Times New Roman, serif"
COLORS = ["#000000", "#1f4e9a", "#b2182b", "#3d7a1f", "#7b3294", "#a6611a"]
DASH = ["", "5,3", "1.5,2.5", "7,2,1.5,2", "3,3", "9,3"]


def _fmt(v):
    if v == 0:
        return "0"
    if abs(v) >= 1 and abs(v - round(v)) < 1e-9:
        return str(int(round(v)))
    s = f"{v:.3g}"
    return s.replace(".", ",").replace("-", "−")


class Axes:
    def __init__(self, fig, x, y, w, h, xlim, ylim, xlog=False, ylog=False):
        self.f, self.x, self.y, self.w, self.h = fig, x, y, w, h
        self.xlim, self.ylim, self.xlog, self.ylog = xlim, ylim, xlog, ylog
        self.legend_items = []

    def _t(self, v, lim, log):
        a, b = lim
        if log:
            v, a, b = math.log10(v), math.log10(a), math.log10(b)
        return (v - a) / (b - a)

    def px(self, v):
        return self.x + self._t(v, self.xlim, self.xlog) * self.w

    def py(self, v):
        return self.y + self.h - self._t(v, self.ylim, self.ylog) * self.h

    def _ticks(self, lim, log, step=None):
        a, b = lim
        major, minor = [], []
        if log:
            for e in range(math.floor(math.log10(a)), math.ceil(math.log10(b)) + 1):
                for m in range(1, 10):
                    v = m * 10 ** e
                    if a * 0.999 <= v <= b * 1.001:
                        (major if m == 1 else minor).append(v)
            if step and step > 1:
                major = [v for v in major if round(math.log10(v)) % step == 0]
        else:
            st = step or (b - a) / 5
            v = math.ceil(a / st - 1e-9) * st
            while v <= b + 1e-9:
                major.append(round(v, 10))
                v += st
        return major, minor

    def frame(self, xlabel="", ylabel="", xstep=None, ystep=None, xticklabel=None, yticklabel=None):
        s = self.f
        s.add(f'<rect x="{self.x}" y="{self.y}" width="{self.w}" height="{self.h}" fill="none" stroke="#000" stroke-width="0.8"/>')
        xm, xn = self._ticks(self.xlim, self.xlog, xstep)
        ym, yn = self._ticks(self.ylim, self.ylog, ystep)
        for v, L in [(v, 5) for v in xm] + [(v, 2.5) for v in xn]:
            X = self.px(v)
            s.add(f'<line x1="{X:.2f}" y1="{self.y + self.h}" x2="{X:.2f}" y2="{self.y + self.h - L}" stroke="#000" stroke-width="0.6"/>')
            s.add(f'<line x1="{X:.2f}" y1="{self.y}" x2="{X:.2f}" y2="{self.y + L}" stroke="#000" stroke-width="0.6"/>')
        for v, L in [(v, 5) for v in ym] + [(v, 2.5) for v in yn]:
            Y = self.py(v)
            s.add(f'<line x1="{self.x}" y1="{Y:.2f}" x2="{self.x + L}" y2="{Y:.2f}" stroke="#000" stroke-width="0.6"/>')
            s.add(f'<line x1="{self.x + self.w}" y1="{Y:.2f}" x2="{self.x + self.w - L}" y2="{Y:.2f}" stroke="#000" stroke-width="0.6"/>')
        for v in xm:
            lab = xticklabel(v) if xticklabel else (self._pow(v) if self.xlog else _fmt(v))
            s.text(self.px(v), self.y + self.h + 14, lab, anchor="middle", size=10.5, raw=True)
        for v in ym:
            lab = yticklabel(v) if yticklabel else (self._pow(v) if self.ylog else _fmt(v))
            s.text(self.x - 5, self.py(v) + 3.6, lab, anchor="end", size=10.5, raw=True)
        if xlabel:
            s.text(self.x + self.w / 2, self.y + self.h + 32, xlabel, anchor="middle", size=11.5, raw=True)
        if ylabel:
            cx, cy = self.x - 44, self.y + self.h / 2
            s.add(f'<text x="{cx}" y="{cy}" transform="rotate(-90 {cx} {cy})" text-anchor="middle" '
                  f'font-family="{FONT}" font-size="11.5">{ylabel}</text>')

    @staticmethod
    def _pow(v):
        e = round(math.log10(v))
        return f'10<tspan dy="-4" font-size="8">{e}</tspan><tspan dy="4"> </tspan>'

    def clip_id(self):
        cid = f"c{id(self)}"
        self.f.add(f'<clipPath id="{cid}"><rect x="{self.x}" y="{self.y}" width="{self.w}" height="{self.h}"/></clipPath>')
        return cid

    def line(self, xs, ys, i=0, label=None, dash=None, width=1.2, marker=None, mfill=True, color=None):
        c = color or COLORS[i % len(COLORS)]
        d = DASH[i % len(DASH)] if dash is None else dash
        pts = " ".join(f"{self.px(x):.2f},{self.py(y):.2f}" for x, y in zip(xs, ys))
        cid = self.clip_id()
        if width > 0:
            self.f.add(f'<polyline points="{pts}" fill="none" stroke="{c}" stroke-width="{width}" '
                       f'stroke-dasharray="{d}" stroke-linejoin="round" clip-path="url(#{cid})"/>')
        if marker:
            for x, y in zip(xs, ys):
                self.f.add(self._marker(self.px(x), self.py(y), marker, c, mfill))
        if label:
            self.legend_items.append((label, c, d if width > 0 else None, marker, mfill, width))

    def errorbars(self, xs, lo, hi, i=0, color=None):
        c = color or COLORS[i % len(COLORS)]
        for x, a, b in zip(xs, lo, hi):
            X = self.px(x)
            self.f.add(f'<line x1="{X:.2f}" y1="{self.py(a):.2f}" x2="{X:.2f}" y2="{self.py(b):.2f}" stroke="{c}" stroke-width="0.7"/>')
            for v in (a, b):
                self.f.add(f'<line x1="{X - 2.5:.2f}" y1="{self.py(v):.2f}" x2="{X + 2.5:.2f}" y2="{self.py(v):.2f}" stroke="{c}" stroke-width="0.7"/>')

    @staticmethod
    def _marker(X, Y, kind, c, fill):
        f = c if fill else "#fff"
        if kind == "o":
            return f'<circle cx="{X:.2f}" cy="{Y:.2f}" r="2.6" fill="{f}" stroke="{c}" stroke-width="0.9"/>'
        if kind == "s":
            return f'<rect x="{X - 2.4:.2f}" y="{Y - 2.4:.2f}" width="4.8" height="4.8" fill="{f}" stroke="{c}" stroke-width="0.9"/>'
        if kind == "^":
            return (f'<polygon points="{X:.2f},{Y - 3.2:.2f} {X - 3:.2f},{Y + 2.3:.2f} {X + 3:.2f},{Y + 2.3:.2f}" '
                    f'fill="{f}" stroke="{c}" stroke-width="0.9"/>')
        if kind == "d":
            return (f'<polygon points="{X:.2f},{Y - 3.3:.2f} {X + 3:.2f},{Y:.2f} {X:.2f},{Y + 3.3:.2f} {X - 3:.2f},{Y:.2f}" '
                    f'fill="{f}" stroke="{c}" stroke-width="0.9"/>')
        return ""

    def text(self, x, y, s, size=10, anchor="start"):
        self.f.text(self.px(x), self.py(y), s, anchor=anchor, size=size, raw=True)

    def legend(self, where="tl", width=None):
        n = len(self.legend_items)
        if not n:
            return
        rowh = 14
        wbox = width or 150
        hbox = n * rowh + 8
        x0 = self.x + 8 if where[1] == "l" else self.x + self.w - wbox - 8
        y0 = self.y + 8 if where[0] == "t" else self.y + self.h - hbox - 8
        self.f.add(f'<rect x="{x0}" y="{y0}" width="{wbox}" height="{hbox}" fill="#fff" stroke="#000" stroke-width="0.5"/>')
        for k, (label, c, d, marker, mfill, width) in enumerate(self.legend_items):
            yy = y0 + 4 + rowh * k + rowh / 2
            if d is not None:
                self.f.add(f'<line x1="{x0 + 6}" y1="{yy}" x2="{x0 + 30}" y2="{yy}" stroke="{c}" stroke-width="{width}" stroke-dasharray="{d}"/>')
            if marker:
                self.f.add(self._marker(x0 + 18, yy, marker, c, mfill))
            self.f.text(x0 + 36, yy + 3.6, label, size=10, raw=True)


class Figure:
    def __init__(self, w, h):
        self.w, self.h, self.parts = w, h, []

    def add(self, s):
        self.parts.append(s)

    def text(self, x, y, s, anchor="start", size=10, raw=False):
        body = s if raw else escape(s)
        self.add(f'<text x="{x:.2f}" y="{y:.2f}" text-anchor="{anchor}" font-family="{FONT}" font-size="{size}">{body}</text>')

    def axes(self, *a, **k):
        return Axes(self, *a, **k)

    def save(self, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" '
                    f'viewBox="0 0 {self.w} {self.h}">\n<rect width="100%" height="100%" fill="#fff"/>\n')
            f.write("\n".join(self.parts))
            f.write("\n</svg>\n")
