"""Рисунки и сводные числа для отчёта из сырых CSV в results/.
Запуск из корня проекта: python3 -I scripts/figures.py"""
import csv
import math
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from svgplot import Figure  # noqa: E402

OUT = "paper/fig"
os.makedirs(OUT, exist_ok=True)


def rows(path):
    with open(path) as f:
        return list(csv.DictReader(f))


I = lambda s: f'<tspan font-style="italic">{s}</tspan>'  # noqa: E731


# Рис. 1. Размер доказательств
def fig_sizes():
    d = rows("results/proof_sizes.csv")
    n = [float(r["n"]) for r in d]
    fig = Figure(640, 270)
    a = fig.axes(66, 14, 230, 200, (1e3, 3e12), (1e2, 1e14), xlog=True, ylog=True)
    a.line(n, [float(r["chain_cons_bytes_mean"]) for r in d], i=2, label="цепочка хешей", dash="5,3")
    a.line(n, [32 * float(r["cons_mean"]) for r in d], i=1, label="дерево, согласованность", marker="s", mfill=False)
    a.line(n, [float(r["tree_incl_bytes_mean"]) for r in d], i=0, label="дерево, включение", marker="o", width=0.9)
    a.frame(xlabel=f"размер журнала {I('n')}, записей", ylabel="средний размер, байт", xstep=3, ystep=2)
    a.legend("tl", width=152)
    fig.text(66 + 115, 262, "(а)", anchor="middle", size=11)

    b = fig.axes(392, 14, 230, 200, (8, 44), (8, 44))
    lg = [math.log2(x) for x in n]
    b.line([8, 44], [8, 44], i=0, dash="1.5,2.5", width=0.8, color="#666", label=f"{I('y')} = log<tspan dy='3' font-size='8'>2</tspan><tspan dy='-3'> </tspan>{I('n')}")
    b.line(lg, [float(r["incl_mean"]) for r in d], i=0, width=0, marker="o", label="включение, среднее")
    b.line(lg, [float(r["incl_max"]) for r in d], i=0, width=0, marker="o", mfill=False, label="включение, максимум")
    b.line(lg, [float(r["cons_max"]) for r in d], i=1, width=0, marker="s", mfill=False, label="согласованность, максимум")
    b.frame(xlabel=f"log<tspan dy='3' font-size='8'>2</tspan><tspan dy='-3'> </tspan>{I('n')}", ylabel="хешей в доказательстве", xstep=8, ystep=8)
    b.legend("br", width=168)
    fig.text(392 + 115, 262, "(б)", anchor="middle", size=11)
    fig.save(f"{OUT}/fig1_sizes.svg")


# Рис. 2. Время проверки, медиана p50 по трём запускам, усы — min..max
def fig_timing():
    runs = [rows(f"results/timing_run{k}.csv") for k in (1, 2, 3)]
    fig = Figure(560, 270)
    a = fig.axes(66, 14, 470, 200, (7e2, 1.5e7), (0, 22), xlog=True)
    series = [("blake2b", "incl_ver_us_p50", 0, "o", True, "BLAKE2b, включение"),
              ("blake2b", "cons_ver_us_p50", 0, "s", False, "BLAKE2b, согласованность"),
              ("sha256", "incl_ver_us_p50", 2, "o", True, "SHA-256, включение"),
              ("sha256", "cons_ver_us_p50", 2, "s", False, "SHA-256, согласованность")]
    for alg, col, ci, mk, fill, label in series:
        idx = [k for k, r in enumerate(runs[0]) if r["alg"] == alg]
        xs = [float(runs[0][k]["n"]) for k in idx]
        vals = [[float(R[k][col]) for R in runs] for k in idx]
        a.errorbars(xs, [min(v) for v in vals], [max(v) for v in vals], i=ci)
        a.line(xs, [statistics.median(v) for v in vals], i=ci, dash="" if fill else "4,2.5", marker=mk, mfill=fill, label=label)
    a.frame(xlabel=f"размер журнала {I('n')}, записей", ylabel="время проверки, мкс", ystep=5)
    a.legend("tl", width=168)
    fig.save(f"{OUT}/fig2_verify_time.svg")


def sim():
    return rows("results/fork_sim.csv")


# Рис. 3. E5: вероятность поймать раздвоение за первый раунд
def fig_e5():
    d = [r for r in sim() if r["scenario"] == "E5_grid" and r["r"] == "1"]
    fig = Figure(560, 270)
    a = fig.axes(66, 14, 470, 200, (0.5, 10.5), (0, 1.02))
    for ci, (e, mk) in enumerate([("0.50", "o"), ("0.70", "s"), ("0.80", "^"), ("0.90", "d")]):
        pts = [r for r in d if r["e"] == e]
        ks = [int(r["k"]) for r in pts]
        a.line(ks, [float(r["p_naive"]) for r in pts], i=ci, dash="", width=0.9)
        a.line(ks, [float(r["p_sim"]) for r in pts], i=ci, width=0, marker=mk, mfill=False, label=f"{I('e')} = {e.replace('.', ',')}")
    a.frame(xlabel=f"свидетелей за раунд {I('k')}", ylabel="P(поймано за 1 раунд)", xstep=1, ystep=0.2)
    a.legend("br", width=84)
    fig.save(f"{OUT}/fig3_e5.svg")


# Рис. 4. E6: режимы перехвата; по оси Y — вероятность НЕ поймать (лог-шкала)
def fig_e6_interception():
    d = [r for r in sim() if r["scenario"] == "E6_interception" and r["e"] == "0.80"]
    fig = Figure(560, 280)
    a = fig.axes(66, 14, 470, 210, (0.5, 10.5), (1e-4, 1), ylog=True)
    rs = list(range(1, 11))
    naive = [r for r in d if r["mode"] == "independent"]
    a.line(rs, [1 - float(r["p_naive"]) for r in naive], i=0, dash="", width=4, color="#d0d0d0",
           label=f"формула {I('e')}<tspan dy='-4' font-size='8'>kr</tspan><tspan dy='4'> </tspan>")
    for ci, (mode, mk, label) in enumerate([("independent", "o", "независимый перехват"),
                                            ("persistent", "s", "постоянный, выбор заново"),
                                            ("fixed_list", "^", "постоянный, список фиксирован")]):
        pts = [r for r in d if r["mode"] == mode]
        a.line(rs, [1 - float(r["p_theory"]) for r in pts], i=ci, dash="4,2.5", width=0.8)
        keep = [(int(r["r"]), 1 - float(r["p_sim"])) for r in pts if float(r["p_sim"]) < 1]
        a.line([k for k, _ in keep], [v for _, v in keep], i=ci, width=0, marker=mk, mfill=mode != "persistent", label=label)
    a.frame(xlabel=f"раунд {I('r')}", ylabel="P(раздвоение не поймано)", xstep=1)
    a.legend("bl", width=196)
    fig.save(f"{OUT}/fig4_e6_interception.svg")


# Рис. 5. E6: сговор свидетелей (а) и офлайн (б)
def fig_e6_other():
    S = sim()
    fig = Figure(640, 280)
    rs = list(range(1, 11))
    panels = [("E6_collusion", "f", ["0", "2", "5", "10"], 66, "(а)"),
              ("E6_offline", "off", ["0.00", "0.20", "0.50"], 392, "(б)")]
    for panel, (scen, key, vals, x0, tag) in enumerate(panels):
        a = fig.axes(x0, 14, 230, 210, (0.5, 10.5), (1e-4, 1), ylog=True)
        for ci, v in enumerate(vals):
            pts = [r for r in S if r["scenario"] == scen and r[key] == v]
            a.line(rs, [max(1 - float(r["p_theory"]), 1e-9) for r in pts], i=ci, dash="", width=0.8)
            keep = [(int(r["r"]), 1 - float(r["p_sim"])) for r in pts if float(r["p_sim"]) < 1]
            lab = f"{I('f')} = {v} из 20" if key == "f" else f"офлайн {round(float(v) * 100)}%"
            a.line([k for k, _ in keep], [x for _, x in keep], i=ci, width=0, marker="osd^"[ci], mfill=False, label=lab)
        a.frame(xlabel=f"раунд {I('r')}", ylabel="P(раздвоение не поймано)" if panel == 0 else "", xstep=3)
        a.legend("tr", width=104)
        fig.text(x0 + 115, 272, tag, anchor="middle", size=11)
    fig.save(f"{OUT}/fig5_e6_collusion_offline.svg")


def summary():
    out = []
    d = [r for r in sim() if r["scenario"] == "E5_grid"]
    dev = max(abs(float(r["p_sim"]) - float(r["p_naive"])) for r in d)
    out.append(f"E5: {len(d)} точек (k x e x r), max |p_sim - p_naive| = {dev:.4f}")
    # Практическая таблица: сколько сверок в сутки нужно для 99% при доле перехвата e
    # и доле сговора phi (большое M, независимая модель, подтверждённая E5/E6).
    sizes = {int(r["n"]): r for r in rows("results/proof_sizes.csv")}
    proof_bytes = 32 * float(sizes[1000000000]["cons_mean"])
    out.append(f"средний размер доказательства согласованности при n=1e9: {proof_bytes:.0f} байт; голова 112 байт")
    out.append("e,phi,contacts_per_day,bytes_per_day")
    for phi in (0.0, 0.25):
        for e in (0.3, 0.5, 0.7, 0.8, 0.9):
            u = phi + (1 - phi) * e
            c = math.ceil(math.log(0.01) / math.log(u))
            out.append(f"{e},{phi},{c},{c * (112 + proof_bytes):.0f}")
    with open("results/summary.txt", "w") as f:
        f.write("\n".join(out) + "\n")
    print("\n".join(out))


if __name__ == "__main__":
    fig_sizes()
    fig_timing()
    fig_e5()
    fig_e6_interception()
    fig_e6_other()
    summary()
