#!/usr/bin/env python3
"""
manet_report_2proto.py  —  AODV vs DSDV tables + graphs from two summary CSVs.

Reads two summary files (default: aodv-summary.csv and dsdv-summary.csv),
merges them, averages over seeds, and produces:
  - plain-text tables (printed to terminal; redirect to a file if you want)
  - six PNG graphs (300 dpi, error bars)

Usage:
    python3 manet_report_2proto.py                       # uses default filenames
    python3 manet_report_2proto.py aodv.csv dsdv.csv     # explicit files
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

C_AODV, C_DSDV = "#2166ac", "#b2182b"
PCOL = {"AODV": C_AODV, "DSDV": C_DSDV}
STYLE = {}
for _p, _c in PCOL.items():
    STYLE[(_p, False)] = dict(color=_c, marker="o", ls="-",  label=f"{_p} (no attack)")
    STYLE[(_p, True )] = dict(color=_c, marker="s", ls="--", label=f"{_p} (DoS)")

# ---- inputs ----
files = sys.argv[1:] if len(sys.argv) > 1 else ["aodv-summary.csv", "dsdv-summary.csv"]

rows = []
for f in files:
    try:
        rows.extend(list(csv.DictReader(open(f))))
    except FileNotFoundError:
        sys.exit(f"File not found: {f}")
if not rows:
    sys.exit("No data rows found.")

G = defaultdict(lambda: defaultdict(list))
for r in rows:
    key = (r["Protocol"], r["DosEnabled"].strip().lower()=="true",
           float(r["NodeSpeed"]), int(r["NumAttackers"]))
    G[key]["pdr"].append(float(r["PDR_percent"]))
    G[key]["thpt"].append(float(r["Throughput_kbps"]))
    G[key]["delay"].append(float(r["AvgDelay_ms"]))

def ms(key, m):
    if key not in G or not G[key][m]: return None, None, 0
    v = G[key][m]
    return statistics.mean(v), (statistics.stdev(v) if len(v)>1 else 0.0), len(v)

protos = sorted({k[0] for k in G})
speeds = sorted({k[2] for k in G})
top_speed = max(speeds) if speeds else 10.0
n_seeds = max((len(G[k]["pdr"]) for k in G), default=0)

# ---------------- PLAIN-TEXT TABLES ----------------
def cell(m,s): return "  --  " if m is None else f"{m:6.2f} +/- {s:5.2f}"
def ptable(title, colhdr, spec):
    print("\n"+"="*78); print(title); print("="*78)
    print(f"{colhdr:<22}{'PDR (%)':>16}{'Throughput(kbps)':>18}{'Delay(ms)':>18}")
    print("-"*78)
    for label,key in spec:
        pm,ps,_=ms(key,"pdr"); tm,ts,_=ms(key,"thpt"); dm,ds,_=ms(key,"delay")
        if pm is None: continue
        print(f"{label:<22}{cell(pm,ps):>16}{cell(tm,ts):>18}{cell(dm,ds):>18}")

print(f"\n### AODV vs DSDV — averaged over {n_seeds} seeds ###")

ab=[]
for p in protos:
    ab.append((f"{p} / no attack",(p,False,top_speed,0)))
    ab.append((f"{p} / DoS",(p,True,top_speed,1)))
ptable(f"TABLE A+B — Baseline vs DoS at {top_speed:g} m/s","Protocol / Condition",ab)

if len(speeds)>=2:
    c=[]
    for p in protos:
        for sp in speeds: c.append((f"{p} @ {sp:g} m/s",(p,False,sp,0)))
    ptable("TABLE C — Mobility sweep, NO attack","Protocol @ speed",c)
    d=[]
    for p in protos:
        for sp in speeds: d.append((f"{p} @ {sp:g} m/s",(p,True,sp,1)))
    ptable("TABLE D — Mobility sweep, under DoS","Protocol @ speed",d)

mals=sorted({k[3] for k in G if k[1]})
if len(mals)>=2:
    e=[]
    for p in protos:
        for m in mals: e.append((f"{p} / {m} attacker(s)",(p,True,top_speed,m)))
    ptable(f"TABLE E — Attacker density at {top_speed:g} m/s","Protocol / attackers",e)

# ---------------- GRAPHS ----------------
made=[]
def save(fig,n): fig.tight_layout(); fig.savefig(n,bbox_inches="tight"); plt.close(fig); made.append(n)

# fig1 baseline vs attack bars
clean,ce,atk,ae=[],[],[],[]
for p in protos:
    m,s,_=ms((p,False,top_speed,0),"pdr"); clean.append(m or 0); ce.append(s or 0)
    m,s,_=ms((p,True,top_speed,1),"pdr"); atk.append(m or 0); ae.append(s or 0)
x=range(len(protos)); w=0.35
fig,ax=plt.subplots(figsize=(7,5))
ax.bar([i-w/2 for i in x],clean,w,yerr=ce,capsize=5,color=[PCOL[p] for p in protos],alpha=0.9,edgecolor="black",linewidth=0.6,label="No attack")
ax.bar([i+w/2 for i in x],atk,w,yerr=ae,capsize=5,color=[PCOL[p] for p in protos],alpha=0.5,edgecolor="black",linewidth=0.6,hatch="//",label="DoS attack")
ax.set_xticks(list(x)); ax.set_xticklabels(protos); ax.set_ylabel("Packet Delivery Ratio (%)")
ax.set_title(f"Baseline vs DoS attack (speed {top_speed:g} m/s)"); ax.set_ylim(0,100); ax.legend()
save(fig,"fig1_baseline_vs_attack.png")

def line_speed(metric,ylabel,title,fname):
    if len(speeds)<2: return
    fig,ax=plt.subplots(figsize=(8,5)); drew=False
    for p in protos:
        for atk_ in (False,True):
            xs,ys,es=[],[],[]
            for sp in speeds:
                m,s,_=ms((p,atk_,sp,1 if atk_ else 0),metric)
                if m is None: continue
                xs.append(sp); ys.append(m); es.append(s)
            if len(xs)<2: continue
            drew=True; ax.errorbar(xs,ys,yerr=es,capsize=4,markersize=7,linewidth=2,elinewidth=1,**STYLE[(p,atk_)])
    if not drew: plt.close(fig); return
    ax.set_xlabel("Maximum node speed (m/s)"); ax.set_ylabel(ylabel); ax.set_title(title)
    ax.set_xticks(speeds); ax.set_ylim(bottom=0); ax.legend()
    save(fig,fname)

line_speed("pdr","Packet Delivery Ratio (%)","PDR vs mobility speed","fig2_pdr_vs_speed.png")
line_speed("thpt","Throughput (kbps)","Throughput vs mobility speed","fig3_throughput_vs_speed.png")
line_speed("delay","Average end-to-end delay (ms)","Delay vs mobility speed","fig4_delay_vs_speed.png")

def line_density(metric,ylabel,title,fname):
    mals=sorted({k[3] for k in G if k[1]})
    if len(mals)<2: return
    fig,ax=plt.subplots(figsize=(8,5)); drew=False
    for p in protos:
        xs,ys,es=[],[],[]
        for m in mals:
            mm,s,_=ms((p,True,top_speed,m),metric)
            if mm is None: continue
            xs.append(m); ys.append(mm); es.append(s)
        if len(xs)<2: continue
        drew=True; ax.errorbar(xs,ys,yerr=es,capsize=4,marker="D",markersize=7,linewidth=2,elinewidth=1,color=PCOL[p],label=p)
    if not drew: plt.close(fig); return
    ax.set_xlabel("Number of attacking nodes"); ax.set_ylabel(ylabel); ax.set_title(title)
    ax.set_xticks(mals); ax.set_ylim(bottom=0); ax.legend()
    save(fig,fname)

line_density("pdr","Packet Delivery Ratio (%)","PDR vs attacker density","fig5_pdr_vs_attackers.png")
line_density("thpt","Throughput (kbps)","Throughput vs attacker density","fig6_throughput_vs_attackers.png")

print(f"\n\nGenerated {len(made)} graphs (averaged over {n_seeds} seeds):")
for f in made: print("  "+f)
