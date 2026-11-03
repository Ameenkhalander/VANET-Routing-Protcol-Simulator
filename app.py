"""Streamlit front-end:  streamlit run app.py"""
import json

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from vanet import SimConfig, Simulation, SCENARIOS, PROTOCOLS, ATTACKS
from vanet.visual import build_animation, series_figure, comparison_figures
from vanet import reports

st.set_page_config(page_title="VANET Routing Simulator", page_icon="🚗", layout="wide")
st.title("🚗 VANET Routing Protocol Simulator")
st.caption("Performance analysis and simulation of AODV · DSR · GPSR · GPCR · DTN · VADD (+ OLSR baseline)")

# ------------------------------------------------------------------ sidebar
sb = st.sidebar
sb.header("Scenario")
scn = sb.selectbox("Predefined scenario", list(SCENARIOS))
if st.session_state.get("_scn") != scn:
    p = SCENARIOS[scn]
    st.session_state.update(_scn=scn, n_vehicles=p["n_vehicles"], speed=(p["vmin"], p["vmax"]), comm_range=p["comm_range"],
                            duration=p["duration"], n_rsu=p["n_rsu"], n_flows=p["n_flows"], packet_interval=p["packet_interval"],
                            msg_ttl=p["msg_ttl"])
proto = sb.selectbox("Routing protocol (live run)", PROTOCOLS)
sb.slider("Vehicles", 5, 150, key="n_vehicles")
sb.slider("Speed range (m/s)", 1.0, 45.0, key="speed")
sb.slider("Communication range (m)", 50.0, 600.0, key="comm_range", step=10.0)
sb.slider("Simulation duration (s)", 30.0, 600.0, key="duration", step=10.0)
sb.slider("Roadside units", 0, 6, key="n_rsu")
sb.header("Traffic")
sb.slider("Message flows", 1, 12, key="n_flows")
sb.slider("Packet interval (s)", 0.5, 20.0, key="packet_interval", step=0.5)
sb.slider("DTN/VADD message lifetime (s)", 10.0, 600.0, key="msg_ttl", step=10.0)
sb.header("Security")
attack = sb.selectbox("Routing attack", ATTACKS)
n_mal = sb.slider("Malicious vehicles", 0, 20, 3 if attack != "none" else 0)
sb.header("Manual messages")
manual_txt = sb.text_area("time,src,dst (one per line)", "5,0,1\n20,2,3",
                          help="Send a message from vehicle src to vehicle dst at the given time.")
seed = sb.number_input("Random seed", 0, 10_000, 1)


def parse_manual(txt):
    out = []
    for line in txt.splitlines():
        try:
            t, s, d = [x.strip() for x in line.split(",")]
            out.append((float(t), int(s), int(d)))
        except ValueError:
            pass
    return out


def current_cfg(**over):
    ss = st.session_state
    d = dict(n_vehicles=ss.n_vehicles, vmin=ss.speed[0], vmax=ss.speed[1], comm_range=ss.comm_range, duration=ss.duration,
             n_rsu=ss.n_rsu, n_flows=ss.n_flows, packet_interval=ss.packet_interval, msg_ttl=ss.msg_ttl, seed=int(seed),
             attack=attack, n_malicious=n_mal, manual_messages=parse_manual(manual_txt))
    d.update(over)
    return SimConfig.preset(scn, **d)


@st.cache_data(show_spinner=False)
def run_cached(cfg_json, protocol):
    cfg = SimConfig(**json.loads(cfg_json))
    sim = Simulation(cfg, protocol).run()
    return sim.summary(), pd.DataFrame(sim.series)


tab_live, tab_cmp, tab_rep, tab_doc = st.tabs(["🎬 Live simulation", "📊 Protocol comparison", "📄 Reports", "ℹ️ About"])

# ------------------------------------------------------------------ live tab
with tab_live:
    c1, c2 = st.columns([1, 1])
    show_links = c1.checkbox("Show wireless links", True)
    run = c2.button("▶ Run simulation", type="primary")
    if run:
        cfg = current_cfg()
        bar = st.progress(0.0, "Simulating…")
        sim = Simulation(cfg, proto).run(progress=lambda x: bar.progress(x))
        bar.empty()
        st.session_state["sim"] = sim
    sim = st.session_state.get("sim")
    if sim is None:
        st.info("Choose a scenario and protocol in the sidebar, then press **Run simulation**.")
    else:
        s = sim.summary()
        st.subheader(f"{s['protocol']} · {s['scenario']} · {s['vehicles']} vehicles")
        m = st.columns(6)
        m[0].metric("Sent", s["sent"]); m[1].metric("Delivered", s["delivered"]); m[2].metric("PDR", f"{s['pdr']*100:.1f}%")
        m[3].metric("Avg delay", f"{s['avg_delay_ms']:.0f} ms" if s["avg_delay_ms"] else "–")
        m[4].metric("Avg hops", s["avg_hops"] or "–"); m[5].metric("Link changes", s["link_changes"])
        st.caption("Legend: blue = vehicle, red = attacker, green square = RSU, red line = DATA, orange = RREQ, teal = RREP, purple = RERR.")
        st.plotly_chart(build_animation(sim, show_links=show_links), width="stretch")
        st.markdown("**Connectivity, disconnections and link churn over time**")
        sdf = pd.DataFrame(sim.series)
        st.plotly_chart(series_figure(sdf), width="stretch")
        a, b = st.columns(2)
        with a:
            st.markdown("**Packet forwarding trace**")
            opts = {f"msg #{u}  {v[0]}→{v[1]}  @{v[2]:.0f}s  [{'delivered' if u in sim.delivered else 'not delivered'}]": u
                    for u, v in sim.msg_info.items()}
            if opts:
                pick = st.selectbox("Message", list(opts))
                st.dataframe(pd.DataFrame(sim.trace[opts[pick]]), width="stretch", hide_index=True)
        with b:
            st.markdown("**Event log** (RREQ/RREP/RERR show route discovery)")
            log = pd.DataFrame(sim.log).astype({"to": str, "frm": str})
            kinds = st.multiselect("Event types", sorted(log.event.unique()), default=[k for k in ["SEND", "RREQ", "RREP", "RERR", "DELIVER", "DROP"] if k in set(log.event)])
            st.dataframe(log[log.event.isin(kinds)].head(1500), width="stretch", hide_index=True, height=300)
        st.markdown("**Vehicles at end of simulation**")
        st.dataframe(pd.DataFrame([dict(id=n.id, x=round(n.x), y=round(n.y), speed=round(n.speed, 1), direction_deg=round(n.direction_deg),
                                        range=n.range, neighbors=sorted(n.neighbors), connected=n.connected,
                                        buffered=len(n.buffer), last_route=n.route[-8:], attacker=n.malicious)
                                   for n in sim.nodes.values() if not n.is_rsu]), width="stretch", hide_index=True)
        st.markdown("**Packet loss causes**")
        st.json(s["drops"])

# ------------------------------------------------------------------ comparison tab
with tab_cmp:
    chosen = st.multiselect("Protocols to compare", PROTOCOLS, default=["AODV", "DSR", "GPSR", "GPCR", "DTN", "VADD"])
    if st.button("Run comparison (same mobility & traffic for every protocol)") and chosen:
        cfg = current_cfg()
        bar, rows, curves = st.progress(0.0), [], {}
        for k, p in enumerate(chosen):
            summ, ser = run_cached(json.dumps(cfg.to_dict()), p)
            rows.append(summ); curves[p] = ser
            bar.progress((k + 1) / len(chosen))
        st.session_state["cmp"] = (cfg.to_dict(), pd.DataFrame(rows), curves)
    if "cmp" in st.session_state:
        cfg_d, df, curves = st.session_state["cmp"]
        st.dataframe(df.drop(columns=["drops"]), width="stretch", hide_index=True)
        figs = comparison_figures(df)
        cols = st.columns(3)
        for i, f in enumerate(figs.values()):
            cols[i % 3].plotly_chart(f, width="stretch")
        fig = go.Figure()
        for p, ser in curves.items():
            fig.add_scatter(x=ser.t, y=(ser.delivered / ser.sent.clip(lower=1)), name=p)
        fig.update_layout(title="Cumulative delivery ratio over time", template="plotly_white", height=360, xaxis_title="time (s)")
        st.plotly_chart(fig, width="stretch")
        st.session_state["cmp_figs"] = {**figs, "Cumulative delivery ratio over time": fig}
    st.divider()
    st.subheader("Parameter sweep")
    sweep = st.selectbox("Vary", ["Vehicle density (n_vehicles)", "Vehicle speed (m/s)", "Communication range (m)"])
    vals = st.text_input("Values (comma separated)", {"V": "20,40,60,80", "e": "10,20,30,40", "C": "100,150,250,350"}[sweep[1]])
    sp = st.multiselect("Protocols", PROTOCOLS, default=["AODV", "GPSR", "DTN"], key="sp")
    if st.button("Run sweep") and sp:
        try:
            values = [float(v) for v in vals.split(",")]
        except ValueError:
            st.error("Enter numbers separated by commas."); values = []
        rows, bar = [], st.progress(0.0)
        total = max(len(values) * len(sp), 1)
        for i, v in enumerate(values):
            over = {"V": dict(n_vehicles=int(v)), "e": dict(vmin=v * 0.8, vmax=v * 1.2), "C": dict(comm_range=v)}[sweep[1]]
            for j, p in enumerate(sp):
                summ, _ = run_cached(json.dumps(current_cfg(**over).to_dict()), p)
                rows.append(dict(x=v, protocol=p, pdr=summ["pdr"], delay=summ["avg_delay_ms"], overhead=summ["routing_overhead"]))
                bar.progress((i * len(sp) + j + 1) / total)
        if rows:
            sdf = pd.DataFrame(rows)
            st.session_state["sweep"] = sdf
    if "sweep" in st.session_state:
        sdf = st.session_state["sweep"]
        for col, title in [("pdr", "PDR"), ("delay", "Avg delay (ms)"), ("overhead", "Control tx / delivered")]:
            f = go.Figure()
            for p, g in sdf.groupby("protocol"):
                f.add_scatter(x=g.x, y=g[col], mode="lines+markers", name=p)
            f.update_layout(title=f"{title} vs sweep value", template="plotly_white", height=320)
            st.plotly_chart(f, width="stretch")

# ------------------------------------------------------------------ reports tab
with tab_rep:
    if "cmp" not in st.session_state:
        st.info("Run a protocol comparison first; reports are generated from its results.")
    else:
        cfg_d, df, _ = st.session_state["cmp"]
        st.download_button("⬇ Results (CSV)", df.drop(columns=["drops"]).to_csv(index=False), "vanet_results.csv", "text/csv")
        st.download_button("⬇ Charts (PNG, Matplotlib)", reports.comparison_png(df), "vanet_charts.png", "image/png")
        st.download_button("⬇ Full report (HTML)", reports.html_report(cfg_d, df, st.session_state.get("cmp_figs", {})),
                           "vanet_report.html", "text/html")
        st.download_button("⬇ Configuration (JSON)", json.dumps(cfg_d, indent=2, default=str), "vanet_config.json", "application/json")
    if st.session_state.get("sim") is not None:
        st.download_button("⬇ Event log of live run (CSV)", pd.DataFrame(st.session_state["sim"].log).to_csv(index=False), "vanet_events.csv", "text/csv")

# ------------------------------------------------------------------ about tab
with tab_doc:
    st.markdown(open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "See README.md")
