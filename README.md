# VANET Routing Protocol Simulator

Interactive simulation of **AODV, DSR, GPSR, GPCR, DTN, VADD** (plus an OLSR-style baseline) on
**Highway, Urban City and Rural/Sparse** road networks. Pure Python, free libraries only, no internet needed.

## Run on Windows 11
1. Install Python 3.11+ (tick *Add python.exe to PATH*).
2. Double-click **`run.bat`** (creates a virtual environment, installs requirements, starts the app at http://localhost:8501).
3. Tests: double-click **`run_tests.bat`** (or `python -m pytest -q`).

Manual: `pip install -r requirements.txt` then `streamlit run app.py`.
CLI: `python -m vanet.cli --scenario "Urban City" --protocol all`

## Using the app
* **Live simulation** – pick scenario + protocol, tune vehicles / speed / range / duration / RSUs / flows / attack,
  press *Run*. Animated map (▶ Play or drag the slider): blue vehicles, red attackers, green RSUs, grey wireless links
  (watch links appear and vanish as vehicles enter/leave range), coloured packets (DATA red, RREQ orange, RREP teal, RERR purple).
  Below: connectivity/disconnection chart, per-message hop-by-hop trace (next hop chosen at each step, AODV next-hop,
  DSR full source route, GPSR greedy/perimeter choice), event log, vehicle table (ID, x/y, speed, direction, range, neighbours,
  buffer, last route, connection status), and packet-loss causes.
* **Manual messages** (sidebar): `time,src,dst` lines inject extra messages.
* **Protocol comparison** – runs the chosen protocols on identical mobility and traffic (same seed); tables and charts for
  PDR, delay, hops, control overhead, transmissions/delivery, throughput; plus parameter sweeps (density, speed, range).
* **Reports** – CSV, PNG (Matplotlib), self-contained HTML (Plotly), JSON config, event-log CSV.

## Architecture
| File | Purpose |
|---|---|
| `vanet/simulator.py` | Discrete-event engine (heap of timed events), topology, beacons, attacks, metrics |
| `vanet/world.py` | Road graphs (NetworkX), buildings, vehicles/RSUs, road-constrained mobility, line-of-sight |
| `vanet/protocols.py` | One class per protocol |
| `vanet/visual.py`, `vanet/reports.py` | Plotly figures; CSV/PNG/HTML reports |
| `app.py` | Streamlit UI |

## Modelling notes and honest limitations
* Mobility: vehicles follow road-graph edges at random speeds in [vmin, vmax], pick a random road at junctions, U-turn at dead ends.
  No lane changing/overtaking/traffic lights. Highway is a two-carriageway ring. Topology updates every 0.5 s; beacons every 1 s.
* Radio: unit-disc range (min of both nodes' ranges) + building line-of-sight in the urban map; no fading, collisions or MAC contention.
  Hop delay ≈ 2–7 ms (+ up to 15 ms jitter on broadcasts).
* **AODV**: RREQ flood with duplicate suppression, reverse routes, RREP (destination or intermediate), destination sequence numbers,
  route lifetime, RERR upstream, rediscovery at source, discovery retries.
* **DSR**: source route in header, route cache with expiry, caching from overheard routes at intermediate nodes, intermediate cache replies,
  RERR + purge of stale links, one-shot packet salvaging.
* **GPSR**: greedy on beaconed (slightly stale) neighbour positions; perimeter mode = right-hand rule on a Gabriel graph with loop detection
  (simplified). Destination position comes from an idealised location service.
* **GPCR (simplified, GPCR-inspired)**: junction sequence from shortest road path; coordinator vehicles at junctions preferred; recovery is
  bounded backtracking, *not* planar-graph perimeter routing. Not standard-compliant.
* **DTN**: binary spray-and-wait store-carry-forward, buffers with eviction, contact detection via beacons, message expiry, RSU relays.
* **VADD (simplified, VADD-inspired)**: road-density-weighted min-delay junction path, single-copy carrier selection by predicted position, RSU support.
* **OLSR-style baseline**: link-state shortest path over last beaconed graph; its HELLO/TC overhead is modelled analytically, not packet by packet.
* **Attacks**: *blackhole* (drops all data; forges AODV/DSR replies), *grayhole* (drops 50 %), *wormhole* (out-of-range tunnel between attacker pairs + 30 % drops).
* Metrics: PDR, average delay, hops, control transmissions per delivered packet, data transmissions per delivered packet, throughput,
  connectivity, link changes. Control overhead counts each broadcast once; beacons are charged to protocols that need them.
* Results are simulation outputs of this simplified model, not NS-3/SUMO/OMNeT++ measurements.
