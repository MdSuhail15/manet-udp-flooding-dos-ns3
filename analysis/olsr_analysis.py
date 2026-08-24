#!/usr/bin/env python3
"""
olsr_section.py  —  tables + figures for the OLSR subsection.


Reads olsr-summary.csv and produces:
  TABLES (printed to terminal):
    OLSR Table 1 - baseline vs DoS (speed 10)
    OLSR Table 2 - mobility sweep (2/5/10), no attack and under attack
    OLSR Table 3 - attacker density (1/3/5) with PDR, Throughput, Delay,
                   AND TxPackets/RxPackets so the ratio effect is visible
  FIGURES (PNG, 300 dpi):
    olsr_fig1_pdr_vs_throughput_density.png  - twin-axis: PDR flat vs throughput falling
    olsr_fig2_txrx_vs_density.png            - Tx and Rx both falling (explains the ratio)
    olsr_fig3_metrics_vs_density.png         - PDR, throughput, delay together

Usage:  python3 olsr_section.py [olsr-summary.csv]
Requires: matplotlib
"""
import csv, sys, statistics
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import rcParams

rcParams.update({
    "font.size": 12, "font.family": "DejaVu Sans",
    "axes.titlesize": 14, "axes.titleweight": "bold", "axes.labelsize": 12,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.25, "grid.linewidth": 0.7,
    "legend.frameon": False, "legend.fontsize": 11, "figure.dpi": 300,
})

C_OLSR = "#1a9850"       # OLSR green (consistent with main report)
C_PDR  = "#1a9850"       # PDR line
C_THPT = "#d95f02"       # throughput line (orange, distinct)
C_DELAY= "#7570b3"       # delay (purple)

CSV = sys.argv[1] if len(sys.argv) > 1 else "olsr-summary.csv"
rows = list(csv.DictReader(open(CSV)))
if not rows:
    sys.exit(f"No rows in {CSV}")

G = defaultdict(lambda: defaultdict(list))
for r in rows:
    key = (r["DosEnabled"].strip().lower()=="true", float(r["NodeSpeed"]), int(r["NumAttackers"]))
    G[key]["pdr"].append(float(r["PDR_percent"]))
    G[key]["thpt"].append(float(r["Throughput_kbps"]))
    G[key]["delay"].append(float(r["AvgDelay_ms"]))
    G[key]["tx"].append(float(r["TxPackets"]))
    G[key]["rx"].append(float(r["RxPackets"]))

def ms(key, m):
    if key not in G or not G[key][m]: return None, None
    v = G[key][m]
    return statistics.mean(v), (statistics.stdev(v) if len(v)>1 else 0.0)

speeds = sorted({k[1] for k in G})
top_speed = max(speeds) if speeds else 10.0
n_seeds = max((len(G[k]["pdr"]) for k in G), default=0)

# ---------------- TABLES ----------------
def c(m,s): return "  --  " if m is None else f"{m:7.2f} +/- {s:5.2f}"

print(f"\n### OLSR subsection data — averaged over {n_seeds} seeds ###")

print("\n" + "="*72)
print("OLSR TABLE 1 — Baseline vs DoS at %g m/s" % top_speed)
print("="*72)
print(f"{'Condition':<16}{'PDR (%)':>18}{'Thpt(kbps)':>18}{'Delay(ms)':>18}")
print("-"*72)
for atk,lbl in [(False,"No attack"),(True,"DoS (1 attacker)")]:
    key=(atk,top_speed,1 if atk else 0)
    pm,ps=ms(key,"pdr"); tm,ts=ms(key,"thpt"); dm,ds=ms(key,"delay")
    print(f"{lbl:<16}{c(pm,ps):>18}{c(tm,ts):>18}{c(dm,ds):>18}")

print("\n" + "="*72)
print("OLSR TABLE 2 — Mobility sweep (PDR %, mean +/- sd)")
print("="*72)
print(f"{'Speed (m/s)':<14}{'No attack':>22}{'Under DoS':>22}")
print("-"*72)
for sp in speeds:
    n=ms((False,sp,0),"pdr"); a=ms((True,sp,1),"pdr")
    print(f"{sp:<14.0f}{c(*n):>22}{c(*a):>22}")

print("\n" + "="*84)
print("OLSR TABLE 3 — Attacker density at %g m/s  (KEY TABLE: shows the ratio effect)" % top_speed)
print("="*84)
print(f"{'Attackers':<10}{'PDR (%)':>13}{'Thpt(kbps)':>13}{'Delay(ms)':>13}{'TxPkts':>13}{'RxPkts':>13}")
print("-"*84)
for na in (1,3,5):
    key=(True,top_speed,na)
    pm,_=ms(key,"pdr"); tm,_=ms(key,"thpt"); dm,_=ms(key,"delay")
    tx,_=ms(key,"tx"); rx,_=ms(key,"rx")
    if pm is None: continue
    print(f"{na:<10}{pm:>13.2f}{tm:>13.2f}{dm:>13.2f}{tx:>13.0f}{rx:>13.0f}")


# ---------------- FIGURES ----------------
made=[]
def save(fig,n): fig.tight_layout(); fig.savefig(n,bbox_inches="tight"); plt.close(fig); made.append(n)

densities=[1,3,5]
def series(metric):
    xs,ys,es=[],[],[]
    for na in densities:
        m,s=ms((True,top_speed,na),metric)
        if m is None: continue
        xs.append(na); ys.append(m); es.append(s)
    return xs,ys,es

# Note: fig1: twin-axis PDR (flat) vs throughput (falling)
xs,pdr,pe = series("pdr")
_,thpt,te = series("thpt")
fig,ax1=plt.subplots(figsize=(8,5))
l1=ax1.errorbar(xs,pdr,yerr=pe,capsize=4,marker="o",markersize=7,linewidth=2,
                color=C_PDR,label="PDR (%)")
ax1.set_xlabel("Number of attacking nodes")
ax1.set_ylabel("Packet Delivery Ratio (%)", color=C_PDR)
ax1.tick_params(axis='y', labelcolor=C_PDR)
ax1.set_ylim(0, max(pdr)*1.4)
ax1.set_xticks(xs)
ax2=ax1.twinx()
ax2.spines['top'].set_visible(False)
l2=ax2.errorbar(xs,thpt,yerr=te,capsize=4,marker="s",markersize=7,linewidth=2,
                ls="--",color=C_THPT,label="Throughput (kbps)")
ax2.set_ylabel("Throughput (kbps)", color=C_THPT)
ax2.tick_params(axis='y', labelcolor=C_THPT)
ax2.set_ylim(0, max(thpt)*1.4)
ax2.grid(False)
ax1.set_title("OLSR: PDR stays flat while throughput falls\n(speed %g m/s, under attack)" % top_speed)
lines=[l1,l2]; ax1.legend(lines,[l.get_label() for l in lines],loc="lower left")
save(fig,"olsr_fig1_pdr_vs_throughput_density.png")

# Note: fig2: Tx and Rx both falling (explains why the ratio stays flat)
_,tx,txe=series("tx"); _,rx,rxe=series("rx")
fig,ax=plt.subplots(figsize=(8,5))
ax.errorbar(xs,tx,yerr=txe,capsize=4,marker="o",markersize=7,linewidth=2,color="#1b7837",label="Transmitted packets")
ax.errorbar(xs,rx,yerr=rxe,capsize=4,marker="s",markersize=7,linewidth=2,ls="--",color="#762a83",label="Received packets")
ax.set_xlabel("Number of attacking nodes"); ax.set_ylabel("Packet count")
ax.set_title("OLSR: transmitted and received packets both fall under attack\n(speed %g m/s)" % top_speed)
ax.set_xticks(xs); ax.set_ylim(bottom=0); ax.legend()
save(fig,"olsr_fig2_txrx_vs_density.png")

# Note: fig3: PDR, throughput, delay together (normalised view optional; here raw with 2 axes not needed)
_,delay,de=series("delay")
fig,ax=plt.subplots(figsize=(8,5))
ax.errorbar(xs,pdr,yerr=pe,capsize=4,marker="o",markersize=7,linewidth=2,color=C_PDR,label="PDR (%)")
ax.errorbar(xs,thpt,yerr=te,capsize=4,marker="s",markersize=7,linewidth=2,ls="--",color=C_THPT,label="Throughput (kbps)")
ax.errorbar(xs,delay,yerr=de,capsize=4,marker="^",markersize=7,linewidth=2,ls=":",color=C_DELAY,label="Delay (ms)")
ax.set_xlabel("Number of attacking nodes"); ax.set_ylabel("Value")
ax.set_title("OLSR metrics vs attacker density (speed %g m/s)" % top_speed)
ax.set_xticks(xs); ax.set_ylim(bottom=0); ax.legend()
save(fig,"olsr_fig3_metrics_vs_density.png")

print(f"\nGenerated {len(made)} figures:")
for f in made: print("  "+f)
