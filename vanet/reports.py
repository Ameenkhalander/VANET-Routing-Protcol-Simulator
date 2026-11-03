"""Downloadable report builders (CSV, PNG via Matplotlib, self-contained HTML)."""
import html
import io
import json
import datetime as dt

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from .visual import METRICS


def comparison_png(df):
    fig, axes = plt.subplots(2, 3, figsize=(13, 7))
    for ax, (col, title) in zip(axes.ravel(), METRICS.items()):
        vals = df[col].fillna(0)
        ax.bar(df["protocol"], vals, color="#1d6fd8")
        ax.set_title(title, fontsize=10)
        ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150)
    plt.close(fig)
    return buf.getvalue()


def html_report(cfg, df, figs, extra_notes=""):
    parts = [f"<h1>VANET Routing Protocol Performance Report</h1><p>Generated {dt.datetime.now():%Y-%m-%d %H:%M}</p>",
             "<h2>Configuration</h2><pre>" + html.escape(json.dumps(cfg, indent=2, default=str)) + "</pre>",
             "<h2>Results</h2>" + df.drop(columns=["drops"], errors="ignore").to_html(index=False, border=0)]
    if "drops" in df:
        parts.append("<h2>Packet loss causes</h2><pre>" + html.escape("\n".join(f"{r.protocol}: {r.drops}" for r in df.itertuples())) + "</pre>")
    for i, (title, fig) in enumerate(figs.items()):
        parts.append(f"<h2>{html.escape(title)}</h2>" + fig.to_html(full_html=False, include_plotlyjs=(i == 0)))
    if extra_notes:
        parts.append("<h2>Notes</h2><p>" + html.escape(extra_notes) + "</p>")
    css = "body{font-family:Segoe UI,Arial;max-width:1000px;margin:2rem auto}table{border-collapse:collapse}td,th{padding:4px 10px;border-bottom:1px solid #ddd}"
    return f"<html><head><meta charset='utf-8'><title>VANET Report</title><style>{css}</style></head><body>{''.join(parts)}</body></html>"
