"""
gen_charts.py — Generate chart artifacts from metrics.csv and summary.json
Output: artifacts/release/chart_metrics.png
        artifacts/release/chart_confusion.png
        artifacts/release/chart_traffic.png

Usage:
    python3 data/gen_charts.py
    (run after make demo has populated artifacts/release/)
"""

import csv
import json
import os
import sys

try:
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
except ImportError:
    print("ERROR: matplotlib not found. Install with: pip install matplotlib")
    sys.exit(1)

CSV_PATH     = "artifacts/release/metrics.csv"
SUMMARY_PATH = "artifacts/release/summary.json"
OUT_DIR      = "artifacts/release"

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------

def load_summary():
    with open(SUMMARY_PATH) as f:
        return json.load(f)

def load_csv():
    rows = []
    with open(CSV_PATH, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "index":      int(row["index"]),
                "src_port":   int(row["src_port"]),
                "dst_port":   int(row["dst_port"]),
                "predicted":  int(row["predicted_malicious"]),
                "actual":     int(row["actual_malicious"]),
            })
    return rows

# ---------------------------------------------------------------------------
# Chart 1: Detection metrics bar chart
# ---------------------------------------------------------------------------

def chart_metrics(summary):
    labels  = ["Detection Rate", "False Positive Rate", "Accuracy"]
    values  = [
        summary["detection_rate"]      * 100,
        summary["false_positive_rate"] * 100,
        summary["accuracy"]            * 100,
    ]
    colors  = ["#2ecc71", "#e74c3c", "#3498db"]
    targets = [85, 15, None]  # project targets

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(labels, values, color=colors, width=0.5, zorder=3)

    # Annotate bars
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{val:.1f}%", ha="center", va="bottom", fontsize=11, fontweight="bold")

    # Target lines
    ax.axhline(85,  color="#2ecc71", linestyle="--", linewidth=1, label="Target ≥85%")
    ax.axhline(15,  color="#e74c3c", linestyle="--", linewidth=1, label="Target ≤15%")

    ax.set_ylim(0, 115)
    ax.set_ylabel("Percentage (%)")
    ax.set_title("Detection Performance Metrics", fontsize=13, fontweight="bold")
    ax.legend(fontsize=9)
    ax.yaxis.grid(True, zorder=0, alpha=0.4)
    ax.set_axisbelow(True)

    total = summary["total"]
    ms    = summary.get("processing_ms", 0)
    fig.text(0.99, 0.01, f"{total} packets | {ms:.2f} ms",
             ha="right", va="bottom", fontsize=8, color="#666")

    plt.tight_layout()
    path = os.path.join(OUT_DIR, "chart_metrics.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Wrote {path}")

# ---------------------------------------------------------------------------
# Chart 2: Confusion matrix heatmap
# ---------------------------------------------------------------------------

def chart_confusion(summary):
    tp = summary["tp"]
    fp = summary["fp"]
    fn = summary["fn"]
    tn = summary["tn"]

    matrix = np.array([[tp, fn],
                        [fp, tn]])
    labels_row = ["Predicted Malicious", "Predicted Legit"]
    labels_col = ["Actually Malicious",  "Actually Legit"]

    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(matrix, cmap="Blues")

    ax.set_xticks(range(2))
    ax.set_yticks(range(2))
    ax.set_xticklabels(labels_col, fontsize=10)
    ax.set_yticklabels(labels_row, fontsize=10)

    cell_labels = [["TP", "FN"], ["FP", "TN"]]
    for i in range(2):
        for j in range(2):
            count = matrix[i, j]
            ax.text(j, i, f"{cell_labels[i][j]}\n{count}",
                    ha="center", va="center", fontsize=14, fontweight="bold",
                    color="white" if count > matrix.max() * 0.5 else "black")

    ax.set_title("Confusion Matrix", fontsize=13, fontweight="bold")
    plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    plt.tight_layout()
    path = os.path.join(OUT_DIR, "chart_confusion.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Wrote {path}")

# ---------------------------------------------------------------------------
# Chart 3: Per-packet verdict timeline (sampled for readability)
# ---------------------------------------------------------------------------

def chart_traffic(rows, summary):
    indices   = [r["index"]    for r in rows]
    predicted = [r["predicted"] for r in rows]
    actual    = [r["actual"]    for r in rows]

    # Color each packet by outcome
    colors = []
    for p, a in zip(predicted, actual):
        if p == 1 and a == 1:   colors.append("#e74c3c")   # TP — red
        elif p == 0 and a == 0: colors.append("#2ecc71")   # TN — green
        elif p == 1 and a == 0: colors.append("#e67e22")   # FP — orange
        else:                   colors.append("#9b59b6")   # FN — purple

    fig, ax = plt.subplots(figsize=(10, 3))
    ax.scatter(indices, [0] * len(indices), c=colors, s=18, marker="|", linewidths=1.5)

    ax.set_xlim(-1, max(indices) + 1)
    ax.set_ylim(-0.5, 0.5)
    ax.set_yticks([])
    ax.set_xlabel("Packet Index")
    ax.set_title("Per-Packet Verdict Timeline", fontsize=13, fontweight="bold")

    legend_patches = [
        mpatches.Patch(color="#e74c3c", label=f"True Positive ({summary['tp']})"),
        mpatches.Patch(color="#2ecc71", label=f"True Negative ({summary['tn']})"),
        mpatches.Patch(color="#e67e22", label=f"False Positive ({summary['fp']})"),
        mpatches.Patch(color="#9b59b6", label=f"False Negative ({summary['fn']})"),
    ]
    ax.legend(handles=legend_patches, loc="upper right", fontsize=8, ncol=2)
    ax.xaxis.grid(True, alpha=0.3)

    plt.tight_layout()
    path = os.path.join(OUT_DIR, "chart_traffic.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Wrote {path}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    for required in [CSV_PATH, SUMMARY_PATH]:
        if not os.path.exists(required):
            print(f"ERROR: {required} not found. Run 'make demo' first.")
            sys.exit(1)

    summary = load_summary()
    rows    = load_csv()

    chart_metrics(summary)
    chart_confusion(summary)
    chart_traffic(rows, summary)

    print(f"\nDone. Charts written to {OUT_DIR}/")
