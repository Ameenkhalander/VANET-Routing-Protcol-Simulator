"""Plotly figure builders: animated network view and analysis charts."""
import math
import plotly.graph_objects as go

KIND_COLOR = {"DATA": "#e63946", "RREQ": "#f4a261", "RREP": "#2a9d8f", "RERR": "#7b2cbf"}


def _lines(pairs, pos):
    xs, ys = [], []
    for a, b in pairs:
        xs += [pos[a][0], pos[b][0], None]
        ys += [pos[a][1], pos[b][1], None]
    return xs, ys


def build_animation(sim, max_frames=120, show_links=True, max_tx=500):
    road, hist, ids = sim.world.road, sim.history, sim.ids
    vids = [i for i in ids if i < 1000]
    rsus = [i for i in ids if i >= 1000]
    step = max(1, math.ceil(len(hist) / max_frames))
    idx = {i: k for k, i in enumerate(ids)}
    rx, ry = _lines(road.g.edges, road.pos)
    kinds = list(KIND_COLOR) + ["OTHER"]

    def dyn(k0):
        group = hist[k0:k0 + step]
        snap = group[0]
        P = {i: snap["pos"][idx[i]] for i in ids}
        lx, ly = _lines(snap["links"], P) if show_links else ([], [])
        data = [go.Scatter(x=lx, y=ly, mode="lines", line=dict(color="rgba(120,120,120,0.35)", width=1),
                           hoverinfo="skip", name="links")]
        mal = sim.malicious
        data.append(go.Scatter(
            x=[P[i][0] for i in vids], y=[P[i][1] for i in vids], mode="markers+text" if len(vids) <= 60 else "markers",
            text=[str(i) for i in vids], textposition="top center", textfont=dict(size=9),
            marker=dict(size=9, color=["#d00000" if i in mal else "#1d6fd8" for i in vids],
                        line=dict(width=1, color="white")),
            hovertext=[f"V{i}{' (ATTACKER)' if i in mal else ''}<br>{sim.nodes[i].speed:.1f} m/s" for i in vids],
            hoverinfo="text", name="vehicles"))
        bucket = {k: [] for k in kinds}
        for g in group:
            for (a, b, kd) in g["tx"]:
                bucket[kd if kd in KIND_COLOR else "OTHER"].append((a, b))
        for kd in kinds:
            xs, ys = _lines(bucket[kd][:max_tx], P)
            data.append(go.Scatter(x=xs, y=ys, mode="lines", name=kd, hoverinfo="skip",
                                   line=dict(color=KIND_COLOR.get(kd, "#888"), width=3 if kd == "DATA" else 2)))
        return data, snap["t"]

    first, _ = dyn(0)
    static = [go.Scatter(x=rx, y=ry, mode="lines", line=dict(color="#555", width=4), name="roads", hoverinfo="skip")]
    if rsus:
        static.append(go.Scatter(x=[sim.nodes[i].x for i in rsus], y=[sim.nodes[i].y for i in rsus],
                                 mode="markers+text", text=[f"RSU{i-999}" for i in rsus], textposition="bottom center",
                                 marker=dict(symbol="square", size=14, color="#2b9348"), name="RSU"))
    n_static = len(static)
    dyn_ids = list(range(n_static, n_static + len(first)))
    frames, steps = [], []
    for k0 in range(0, len(hist), step):
        d, t = dyn(k0)
        frames.append(go.Frame(data=d, traces=dyn_ids, name=str(k0)))
        steps.append(dict(method="animate", label=f"{t:.0f}s",
                          args=[[str(k0)], dict(mode="immediate", frame=dict(duration=0, redraw=True), transition=dict(duration=0))]))
    x0, y0, x1, y1 = road.bounds
    padx, pady = 60, max(60, (y1 - y0) * 0.08) if y1 - y0 > 100 else 120
    shapes = [dict(type="rect", x0=a, y0=b, x1=c, y1=d_, fillcolor="rgba(160,160,160,0.35)", line=dict(width=0), layer="below")
              for (a, b, c, d_) in road.buildings]
    fig = go.Figure(data=static + first, frames=frames)
    fig.update_layout(
        height=560, margin=dict(l=10, r=10, t=30, b=10), shapes=shapes, template="plotly_white",
        xaxis=dict(range=[x0 - padx, x1 + padx], showgrid=False, zeroline=False),
        yaxis=dict(range=[y0 - pady, y1 + pady], showgrid=False, zeroline=False,
                   **({"scaleanchor": "x"} if sim.cfg.scenario == "Urban City" else {})),
        legend=dict(orientation="h", y=1.07),
        updatemenus=[dict(type="buttons", x=0.0, y=-0.02, direction="left", buttons=[
            dict(label="▶ Play", method="animate", args=[None, dict(frame=dict(duration=180, redraw=True), fromcurrent=True, transition=dict(duration=0))]),
            dict(label="⏸ Pause", method="animate", args=[[None], dict(mode="immediate", frame=dict(duration=0, redraw=False))])])],
        sliders=[dict(active=0, x=0.15, len=0.85, y=-0.02, steps=steps, currentvalue=dict(prefix="t = "))])
    return fig


def series_figure(series_df):
    fig = go.Figure()
    fig.add_scatter(x=series_df.t, y=series_df.connectivity, name="Connectivity (largest component)")
    fig.add_scatter(x=series_df.t, y=series_df.avg_neighbors, name="Avg neighbours", yaxis="y2")
    fig.add_bar(x=series_df.t, y=series_df.link_changes, name="Link changes / tick", opacity=0.3, yaxis="y2")
    fig.update_layout(height=320, template="plotly_white", margin=dict(l=10, r=10, t=30, b=10),
                      xaxis_title="time (s)", yaxis=dict(title="connectivity", range=[0, 1.05]),
                      yaxis2=dict(title="neighbours / changes", overlaying="y", side="right"), legend=dict(orientation="h", y=1.15))
    return fig


METRICS = {"pdr": "Packet delivery ratio", "avg_delay_ms": "Avg end-to-end delay (ms)", "avg_hops": "Avg hop count",
           "routing_overhead": "Control tx per delivered packet", "tx_per_delivered": "Data tx per delivered packet",
           "throughput_kbps": "Throughput (kbps)"}


def comparison_figures(df):
    figs = {}
    for col, title in METRICS.items():
        figs[title] = go.Figure(go.Bar(x=df["protocol"], y=df[col], text=df[col], textposition="outside",
                                       marker_color="#1d6fd8")).update_layout(
            title=title, height=330, template="plotly_white", margin=dict(l=10, r=10, t=50, b=10))
    return figs
