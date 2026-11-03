"""Discrete-event VANET simulation engine.

Events (mobility ticks, packet transmissions/receptions, protocol timers, traffic generation)
are kept in a priority queue ordered by time.  Mobility is advanced every `dt` seconds; between
ticks the topology is constant, so a transmission succeeds iff the receiver is a current
neighbour of the sender (range + building line-of-sight).
"""
import heapq
import itertools
import random
from collections import Counter

import networkx as nx
import numpy as np

from .world import World, los_clear
from .protocols import make_protocol

DROP_PROB = {"blackhole": 1.0, "grayhole": 0.5, "wormhole": 0.3}


class Packet:
    def __init__(self, uid, kind, src, dst, created, size=64, ttl=32, **data):
        self.uid, self.kind, self.src, self.dst = uid, kind, src, dst
        self.created, self.size, self.ttl = created, size, ttl
        self.hops, self.path, self.data = 0, [src], dict(data)

    def clone(self):
        p = Packet(self.uid, self.kind, self.src, self.dst, self.created, self.size, self.ttl)
        p.hops, p.path, p.data = self.hops, list(self.path), dict(self.data)
        return p


class Simulation:
    def __init__(self, cfg, protocol):
        self.cfg, self.protocol_name = cfg, protocol
        self.rng = random.Random(cfg.seed)            # mobility only -> identical across protocols
        self.trng = random.Random(cfg.seed + 777)     # traffic + attacker selection
        self.prng = random.Random(cfg.seed + 12345)   # MAC jitter / protocol randomness
        self.world = World(cfg, self.rng)
        self.nodes = self.world.nodes
        self.ids = list(self.nodes)
        self.vids = [i for i in self.ids if i < 1000]
        self.t, self.heap, self._seq, self._uid = 0.0, [], itertools.count(), itertools.count(1)
        self.adj = {i: set() for i in self.ids}
        self.beacon, self.beacon_epoch, self.links = {}, 0, set()
        self.history, self.frame_tx, self.log, self.trace, self.series = [], [], [], {}, []
        self.sent, self.delivered, self.msg_info = 0, {}, {}
        self.drops, self.tx = Counter(), Counter()
        self.malicious, self.tunnels = set(), []
        self.link_changes = 0
        self._tick_i = 0
        self._plan_traffic()
        self._setup_attack()
        self.update_topology()
        self.refresh_beacons()
        self.proto = make_protocol(protocol, self)

    # ---------------------------------------------------------------- scheduling
    def schedule(self, delay, fn, *args):
        heapq.heappush(self.heap, (self.t + delay, next(self._seq), fn, args))

    def _at(self, t, fn, *args):
        heapq.heappush(self.heap, (t, next(self._seq), fn, args))

    def run(self, progress=None):
        cfg = self.cfg
        self._at(0.0, self._tick)
        for (t, s, d) in self.flow_events:
            self._at(t, self.send_data, s, d)
        for (t, s, d) in cfg.manual_messages:
            if s in self.nodes and d in self.nodes and s != d:
                self._at(float(t), self.send_data, int(s), int(d))
        end = cfg.duration + 10.0
        while self.heap:
            t, _, fn, args = heapq.heappop(self.heap)
            if t > end:
                break
            self.t = t
            fn(*args)
            if progress and self._tick_i % 10 == 0:
                progress(min(t / cfg.duration, 1.0))
        return self

    # ---------------------------------------------------------------- setup
    def _plan_traffic(self):
        cfg, r = self.cfg, self.trng
        v = self.vids
        self.flow_events, self.flow_endpoints = [], set()
        for _ in range(cfg.n_flows):
            if len(v) < 2:
                break
            s, d = r.sample(v, 2)
            self.flow_endpoints |= {s, d}
            t = r.uniform(1, 5)
            while t < cfg.duration * 0.8:
                self.flow_events.append((t, s, d))
                t += cfg.packet_interval

    def _setup_attack(self):
        cfg = self.cfg
        if cfg.attack == "none" or cfg.n_malicious <= 0:
            return
        pool = [i for i in self.vids if i not in self.flow_endpoints] or self.vids
        k = min(cfg.n_malicious, len(pool))
        self.malicious = set(self.trng.sample(pool, k))
        for i in self.malicious:
            self.nodes[i].malicious = True
        if cfg.attack == "wormhole":
            m = sorted(self.malicious)
            self.tunnels = [(m[i], m[i + 1]) for i in range(0, len(m) - 1, 2)]

    def is_malicious(self, n):
        return n in self.malicious

    # ---------------------------------------------------------------- topology
    def update_topology(self):
        ids, N = self.ids, len(self.ids)
        P = np.array([[self.nodes[i].x, self.nodes[i].y] for i in ids])
        R = np.array([self.nodes[i].range for i in ids])
        D = np.hypot(P[:, 0][:, None] - P[:, 0][None, :], P[:, 1][:, None] - P[:, 1][None, :])
        iu = np.triu_indices(N, 1)
        m = D[iu] <= np.minimum(R[:, None], R[None, :])[iu]
        I, J = iu[0][m], iu[1][m]
        rects = self.world.road.buildings
        if rects and len(I):
            ok = los_clear(P[I], P[J], rects)
            I, J = I[ok], J[ok]
        adj = {i: set() for i in ids}
        links = set()
        for a, b in zip(I.tolist(), J.tolist()):
            A, B = ids[a], ids[b]
            adj[A].add(B); adj[B].add(A)
            links.add((min(A, B), max(A, B)))
        for a, b in self.tunnels:          # wormhole tunnel
            adj[a].add(b); adj[b].add(a)
            links.add((min(a, b), max(a, b)))
        if self.links or self._tick_i:
            up, down = links - self.links, self.links - links
            self.link_changes += len(up) + len(down)
            self._cur_changes = len(up) + len(down)
            for (a, b) in list(up)[:3]:
                self._log("LINK_UP", a, b, note="entered range")
            for (a, b) in list(down)[:3]:
                self._log("LINK_DOWN", a, b, note="left range")
        else:
            self._cur_changes = 0
        self.adj, self.links = adj, links
        for i in ids:
            self.nodes[i].neighbors = adj[i]
            self.nodes[i].connected = bool(adj[i])

    def refresh_beacons(self):
        n = self.nodes
        self.beacon = {i: {j: (n[j].x, n[j].y, n[j].vx, n[j].vy) for j in self.adj[i]} for i in self.ids}
        self.beacon_epoch += 1

    # ---------------------------------------------------------------- tick
    def _tick(self):
        cfg = self.cfg
        if self._tick_i > 0:
            self.world.step(cfg.dt)
        self.update_topology()
        every = max(1, round(cfg.beacon_interval / cfg.dt))
        if self._tick_i % every == 0:
            self.refresh_beacons()
            if self.proto.uses_beacons:
                self.tx["BEACON"] += len(self.ids)
        self.proto.on_tick()
        G = nx.Graph()
        G.add_nodes_from(self.ids)
        G.add_edges_from(self.links)
        comp = max((len(c) for c in nx.connected_components(G)), default=0)
        deg = [len(self.adj[i]) for i in self.ids]
        self.history.append(dict(
            t=self.t, ids=self.ids,
            pos=np.array([[self.nodes[i].x, self.nodes[i].y] for i in self.ids]),
            links=list(self.links), tx=self.frame_tx))
        self.frame_tx = []
        self.series.append(dict(t=self.t, sent=self.sent, delivered=len(self.delivered),
                                connectivity=comp / len(self.ids), avg_neighbors=float(np.mean(deg)),
                                isolated=sum(1 for d in deg if d == 0), link_changes=self._cur_changes))
        self._tick_i += 1
        if self.t + cfg.dt <= cfg.duration + 1e-9:
            self.schedule(cfg.dt, self._tick)

    # ---------------------------------------------------------------- packets
    def new_packet(self, kind, src, dst, size=64, ttl=32, **data):
        return Packet(next(self._uid), kind, src, dst, self.t, size, ttl, **data)

    def send_data(self, src, dst):
        pkt = self.new_packet("DATA", src, dst, size=self.cfg.packet_size, ttl=32)
        self.sent += 1
        self.msg_info[pkt.uid] = (src, dst, self.t)
        self.trace[pkt.uid] = []
        self._log("SEND", src, dst, pkt.uid, f"message {src}→{dst}")
        self.proto.send(pkt)

    def _delay(self, pkt, broadcast=False):
        return 0.002 + pkt.size * 8 / 6e6 + self.prng.random() * (0.012 if broadcast else 0.003)

    def transmit(self, pkt, frm, to, note=""):
        if to not in self.adj[frm]:
            return False
        self._record_tx(pkt, frm, to, note)
        self.schedule(self._delay(pkt), self._rx, pkt, to, frm)
        return True

    def broadcast(self, pkt, frm, note=""):
        self.tx[pkt.kind] += 1
        for to in self.adj[frm]:
            self.frame_tx.append((frm, to, pkt.kind))
            self.schedule(self._delay(pkt, True), self._rx, pkt.clone(), to, frm)
        self._log(pkt.kind, frm, "*", pkt.uid, note or "broadcast")

    def _record_tx(self, pkt, frm, to, note):
        self.tx[pkt.kind] += 1
        self.frame_tx.append((frm, to, pkt.kind))
        self._log(pkt.kind, frm, to, pkt.uid, note)
        if pkt.kind == "DATA":
            self.trace[pkt.uid].append(dict(t=round(self.t, 3), event="FORWARD", frm=frm, to=to, note=note))

    def _rx(self, pkt, node, frm):
        pkt.hops += 1
        if pkt.kind == "DATA":
            pkt.path.append(node)
            if node in self.malicious and node != pkt.dst:
                if self.prng.random() < DROP_PROB.get(self.cfg.attack, 0):
                    self.drop(pkt, f"{self.cfg.attack}_drop", node)
                    return
        self.proto.on_receive(pkt, node, frm)

    def deliver(self, pkt):
        if pkt.uid in self.delivered:
            return
        self.delivered[pkt.uid] = (self.t - pkt.created, pkt.hops)
        self.trace[pkt.uid].append(dict(t=round(self.t, 3), event="DELIVERED", frm=pkt.dst, to=pkt.dst,
                                        note=f"hops={pkt.hops} delay={(self.t - pkt.created) * 1000:.0f} ms"))
        self._log("DELIVER", pkt.src, pkt.dst, pkt.uid, f"hops={pkt.hops}")

    def drop(self, pkt, reason, node):
        if pkt.kind != "DATA":
            return
        self.drops[reason] += 1
        self.trace[pkt.uid].append(dict(t=round(self.t, 3), event="DROP", frm=node, to=node, note=reason))
        self._log("DROP", node, pkt.dst, pkt.uid, reason)

    def _log(self, kind, a, b, uid=None, note=""):
        if len(self.log) < 40000:
            self.log.append(dict(t=round(self.t, 3), event=kind, frm=a, to=b, msg=uid, note=note))

    # ---------------------------------------------------------------- results
    def summary(self):
        cfg = self.cfg
        d = len(self.delivered)
        delays = [v[0] for v in self.delivered.values()]
        hops = [v[1] for v in self.delivered.values()]
        data_tx = self.tx["DATA"]
        ctrl = sum(c for k, c in self.tx.items() if k != "DATA")
        accounted = sum(self.drops.values()) + d
        drops = dict(self.drops)
        if self.sent - accounted > 0:
            drops["undelivered/expired"] = self.sent - accounted
        ser = self.series
        return dict(
            protocol=self.protocol_name, scenario=cfg.scenario, vehicles=cfg.n_vehicles,
            sent=self.sent, delivered=d, pdr=round(d / self.sent, 4) if self.sent else 0.0,
            avg_delay_ms=round(1000 * float(np.mean(delays)), 2) if delays else None,
            avg_hops=round(float(np.mean(hops)), 2) if hops else None,
            control_tx=ctrl, data_tx=data_tx,
            routing_overhead=round(ctrl / d, 2) if d else None,
            tx_per_delivered=round(data_tx / d, 2) if d else None,
            throughput_kbps=round(d * cfg.packet_size * 8 / 1000 / cfg.duration, 3),
            avg_connectivity=round(float(np.mean([s["connectivity"] for s in ser])), 3),
            avg_neighbors=round(float(np.mean([s["avg_neighbors"] for s in ser])), 2),
            link_changes=self.link_changes, attack=cfg.attack, malicious=len(self.malicious),
            drops=drops)
