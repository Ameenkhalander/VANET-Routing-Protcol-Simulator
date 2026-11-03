"""Routing protocol models: AODV, DSR, GPSR, GPCR (simplified), DTN, VADD (simplified), OLSR (baseline).

Every protocol implements:  send(pkt) · on_receive(pkt,node,frm) · on_tick() · on_link_fail(pkt,frm,to)
and talks to the simulator only through sim.transmit / sim.broadcast / sim.schedule / sim.deliver / sim.drop.
"""
import math
from collections import Counter

import networkx as nx

from .world import JUNCTION_RADIUS, dist


class Protocol:
    name = "base"
    uses_beacons = False   # True -> periodic HELLO/beacon overhead is charged to the protocol

    def __init__(self, sim):
        self.sim = sim

    def send(self, pkt):
        raise NotImplementedError

    def on_receive(self, pkt, node, frm):
        pass

    def on_tick(self):
        pass

    def on_link_fail(self, pkt, frm, to):
        if pkt.kind == "DATA":
            self.sim.drop(pkt, "link_break", frm)

    def fwd(self, pkt, frm, to, note=""):
        if self.sim.transmit(pkt, frm, to, note):
            return True
        self.on_link_fail(pkt, frm, to)
        return False

    def blackhole(self, n):
        return n in self.sim.malicious and self.sim.cfg.attack == "blackhole"


# =============================================================================== AODV
class AODV(Protocol):
    """Reactive distance-vector routing: RREQ flood, RREP unicast, RERR on link break,
    destination sequence numbers, hop-by-hop forwarding and re-discovery."""
    name = "AODV"
    LIFETIME, TIMEOUT, RETRIES, NET_TTL = 12.0, 1.5, 2, 16

    def __init__(self, sim):
        super().__init__(sim)
        ids = sim.ids
        self.rt = {i: {} for i in ids}      # dst -> {next,hops,seq,exp,valid}
        self.seq = {i: 1 for i in ids}
        self.rid = {i: 0 for i in ids}
        self.seen = {i: set() for i in ids}
        self.pending = {i: {} for i in ids}

    def valid(self, n, dst):
        r = self.rt[n].get(dst)
        return r if r and r["valid"] and r["exp"] > self.sim.t else None

    def update(self, n, dst, nxt, hops, seq):
        r, now = self.rt[n].get(dst), self.sim.t
        if (r is None or not r["valid"] or r["exp"] <= now or seq > r["seq"] or (seq == r["seq"] and hops < r["hops"])):
            self.rt[n][dst] = dict(next=nxt, hops=hops, seq=seq, exp=now + self.LIFETIME, valid=True)
        else:
            r["exp"] = max(r["exp"], now + self.LIFETIME)

    # ---- data plane
    def send(self, pkt):
        self._data(pkt, pkt.src)

    def _data(self, pkt, node):
        sim = self.sim
        if node == pkt.dst:
            return sim.deliver(pkt)
        if pkt.ttl <= 0:
            return sim.drop(pkt, "ttl", node)
        r = self.valid(node, pkt.dst)
        if r:
            r["exp"] = sim.t + self.LIFETIME
            pkt.ttl -= 1
            sim.nodes[pkt.src].route = [pkt.src] + [x for x in pkt.path[1:]]
            self.fwd(pkt, node, r["next"], f"AODV next hop {r['next']} (dst_seq={r['seq']}, hops={r['hops']})")
        elif node == pkt.src:
            q = self.pending[node].setdefault(pkt.dst, [])
            q.append(pkt)
            if len(q) == 1:
                self._discover(node, pkt.dst, 0)
        else:
            sim.drop(pkt, "no_route", node)

    # ---- route discovery
    def _discover(self, src, dst, attempt):
        self.seq[src] += 1
        self.rid[src] += 1
        known = self.rt[src].get(dst)
        rid = self.rid[src]
        pkt = self.sim.new_packet("RREQ", src, dst, size=24, ttl=self.NET_TTL, origin=src, rid=rid,
                                  origin_seq=self.seq[src], dest_seq=known["seq"] if known else 0, hop=0)
        self.seen[src].add((src, rid))
        self.sim.broadcast(pkt, src, f"RREQ {src}→{dst} id={rid}")
        self.sim.schedule(self.TIMEOUT, self._timeout, src, dst, attempt)

    def _timeout(self, src, dst, attempt):
        q = self.pending[src].get(dst)
        if not q:
            return
        if attempt < self.RETRIES:
            self._discover(src, dst, attempt + 1)
        else:
            for p in self.pending[src].pop(dst):
                self.sim.drop(p, "discovery_failed", src)

    def _rrep(self, node, origin, dest, seq, hops):
        rrep = self.sim.new_packet("RREP", node, origin, size=20, dest=dest, dest_seq=seq, hop=hops)
        r = self.valid(node, origin)
        if r:
            self.sim.transmit(rrep, node, r["next"], f"RREP for {dest}")

    def on_receive(self, pkt, node, frm):
        sim, k, d = self.sim, pkt.kind, pkt.data
        if k == "DATA":
            return self._data(pkt, node)
        if k == "RREQ":
            key = (d["origin"], d["rid"])
            if key in self.seen[node]:
                return
            self.seen[node].add(key)
            self.update(node, d["origin"], frm, d["hop"] + 1, d["origin_seq"])      # reverse route
            if self.blackhole(node):                                                  # forged RREP
                return self._rrep(node, d["origin"], pkt.dst, 10 ** 6, 1)
            if node == pkt.dst:
                self.seq[node] = max(self.seq[node], d["dest_seq"]) + 1
                return self._rrep(node, d["origin"], node, self.seq[node], 0)
            r = self.valid(node, pkt.dst)
            if r and r["seq"] >= d["dest_seq"] > 0:                                  # intermediate reply
                return self._rrep(node, d["origin"], pkt.dst, r["seq"], r["hops"])
            if pkt.ttl > 1:
                fw = pkt.clone()
                fw.ttl -= 1
                fw.data["hop"] = d["hop"] + 1
                sim.broadcast(fw, node, f"RREQ rebroadcast (origin {d['origin']}, hop {d['hop'] + 1})")
        elif k == "RREP":
            dest = d["dest"]
            self.update(node, dest, frm, d["hop"] + 1, d["dest_seq"])
            if node == pkt.dst:                                                        # route discovered at origin
                for p in self.pending[node].pop(dest, []):
                    self._data(p, node)
            else:
                r = self.valid(node, pkt.dst)
                if r:
                    fw = pkt.clone()
                    fw.data["hop"] = d["hop"] + 1
                    sim.transmit(fw, node, r["next"], f"RREP → {pkt.dst}")
        elif k == "RERR":
            for dst, r in self.rt[node].items():
                if dst == d["unreach"] and r["valid"] and r["next"] == frm:
                    r["valid"] = False
                    r["seq"] += 1
            if d["back"]:
                fw = pkt.clone()
                fw.data["back"] = d["back"][1:]
                sim.transmit(fw, node, d["back"][0], "RERR upstream")

    # ---- route maintenance
    def on_link_fail(self, pkt, frm, to):
        if pkt.kind != "DATA":
            return
        for dst, r in self.rt[frm].items():
            if r["valid"] and r["next"] == to:
                r["valid"] = False
                r["seq"] += 1
        if frm == pkt.src:
            return self._data(pkt, frm)          # re-buffer and rediscover
        back = list(reversed(pkt.path[:-1]))
        if back:
            rerr = self.sim.new_packet("RERR", frm, back[-1], size=16, unreach=pkt.dst, back=back[1:])
            self.sim.transmit(rerr, frm, back[0], f"RERR dst {pkt.dst}")
        self.sim.drop(pkt, "link_break", frm)


# =============================================================================== DSR
class DSR(Protocol):
    """Dynamic Source Routing: full source route in packet header, route cache with expiry,
    intermediate-node caching/replies, RERR + stale-route removal, simple packet salvaging."""
    name = "DSR"
    CACHE_TTL, TIMEOUT, RETRIES, NET_TTL = 20.0, 1.5, 2, 16

    def __init__(self, sim):
        super().__init__(sim)
        ids = sim.ids
        self.cache = {i: {} for i in ids}   # dst -> (route list starting at i, timestamp)
        self.rid = {i: 0 for i in ids}
        self.seen = {i: set() for i in ids}
        self.pending = {i: {} for i in ids}

    def get(self, n, dst):
        e = self.cache[n].get(dst)
        if e and self.sim.t - e[1] <= self.CACHE_TTL:
            return e[0]
        if e:
            del self.cache[n][dst]          # expired
        return None

    def learn(self, n, route):
        if n not in route:
            return
        i = route.index(n)
        for j in range(i + 1, len(route)):
            sub, dst = route[i:j + 1], route[j]
            old = self.get(n, dst)
            if old is None or len(sub) <= len(old):
                self.cache[n][dst] = (sub, self.sim.t)

    def send(self, pkt):
        self._source(pkt)

    def _source(self, pkt):
        node = pkt.src
        route = self.get(node, pkt.dst)
        if route:
            pkt.data["route"] = route
            self._data(pkt, node)
        else:
            q = self.pending[node].setdefault(pkt.dst, [])
            q.append(pkt)
            if len(q) == 1:
                self._discover(node, pkt.dst, 0)

    def _discover(self, src, dst, attempt):
        self.rid[src] += 1
        pkt = self.sim.new_packet("RREQ", src, dst, size=24, ttl=self.NET_TTL, origin=src, rid=self.rid[src], record=[src])
        self.seen[src].add((src, self.rid[src]))
        self.sim.broadcast(pkt, src, f"RREQ {src}→{dst}")
        self.sim.schedule(self.TIMEOUT, self._timeout, src, dst, attempt)

    def _timeout(self, src, dst, attempt):
        if not self.pending[src].get(dst):
            return
        if attempt < self.RETRIES:
            self._discover(src, dst, attempt + 1)
        else:
            for p in self.pending[src].pop(dst):
                self.sim.drop(p, "discovery_failed", src)

    def _reply(self, node, record, full):
        back = list(reversed(record))                     # replier ... origin
        rrep = self.sim.new_packet("RREP", node, record[0], size=20 + 4 * len(full), route=full, back=back)
        self.learn(node, full)
        if len(back) > 1:
            self.sim.transmit(rrep, node, back[1], f"RREP route={full}")

    def on_receive(self, pkt, node, frm):
        sim, k, d = self.sim, pkt.kind, pkt.data
        if k == "DATA":
            return self._data(pkt, node)
        if k == "RREQ":
            key = (d["origin"], d["rid"])
            if key in self.seen[node]:
                return
            self.seen[node].add(key)
            rec = d["record"] + [node]
            if self.blackhole(node):
                return self._reply(node, rec, rec + [pkt.dst])      # forged route
            if node == pkt.dst:
                return self._reply(node, rec, rec)
            cached = self.get(node, pkt.dst)
            if cached and not (set(cached[1:]) & set(rec)):          # intermediate-node reply
                return self._reply(node, rec, rec + cached[1:])
            if pkt.ttl > 1:
                fw = pkt.clone()
                fw.ttl -= 1
                fw.data["record"] = rec
                sim.broadcast(fw, node, f"RREQ record={rec}")
        elif k == "RREP":
            self.learn(node, d["route"])
            back = d["back"]
            if node == pkt.dst:
                for p in self.pending[node].pop(d["route"][-1], []):
                    p.data["route"] = self.get(node, p.dst) or d["route"]
                    self._data(p, node)
            else:
                i = back.index(node)
                sim.transmit(pkt.clone(), node, back[i + 1], "RREP (source-routed back)")
        elif k == "RERR":
            self._purge(node, d["link"])
            back = d["back"]
            if back and node in back:
                i = back.index(node)
                if i + 1 < len(back):
                    sim.transmit(pkt.clone(), node, back[i + 1], "RERR upstream")

    def _purge(self, node, link):
        a, b = link
        for dst in list(self.cache[node]):
            r = self.cache[node][dst][0]
            if any(r[i] == a and r[i + 1] == b for i in range(len(r) - 1)):
                del self.cache[node][dst]

    def _data(self, pkt, node):
        sim = self.sim
        if node == pkt.dst:
            return sim.deliver(pkt)
        route = pkt.data["route"]
        self.learn(node, route)
        sim.nodes[pkt.src].route = route
        nxt = route[route.index(node) + 1]
        self.fwd(pkt, node, nxt, f"source route {route} → next {nxt}")

    def on_link_fail(self, pkt, frm, to):
        if pkt.kind != "DATA":
            return
        self._purge(frm, (frm, to))
        route = pkt.data["route"]
        if frm == pkt.src:
            return self._source(pkt)
        i = route.index(frm)
        back = route[:i + 1][::-1]
        rerr = self.sim.new_packet("RERR", frm, pkt.src, size=16, link=(frm, to), back=back)
        if len(back) > 1:
            self.sim.transmit(rerr, frm, back[1], f"RERR link {frm}-{to}")
        alt = self.get(frm, pkt.dst)                                  # salvage with own cache
        if alt and not pkt.data.get("salvaged") and alt[1] in self.sim.adj[frm]:
            pkt.data["route"], pkt.data["salvaged"] = route[:i] + alt, True
            return self._data(pkt, frm)
        self.sim.drop(pkt, "link_break", frm)


# =============================================================================== GPSR
def planar_neighbors(me, tbl):
    """Gabriel-graph planarisation using only local neighbour positions."""
    keep = []
    for w, pw in tbl.items():
        r = dist(me, pw[:2]) / 2
        mid = ((me[0] + pw[0]) / 2, (me[1] + pw[1]) / 2)
        if all(z == w or dist(mid, pz[:2]) >= r for z, pz in tbl.items()):
            keep.append(w)
    return keep


class GPSR(Protocol):
    """Greedy forwarding on beaconed neighbour positions; simplified perimeter mode
    (right-hand rule on a Gabriel graph) at local maxima.  Destination position comes from an
    idealised location service (documented assumption)."""
    name = "GPSR"
    uses_beacons = True

    def send(self, pkt):
        pkt.data.update(mode="greedy", prev=None)
        self._route(pkt, pkt.src)

    def on_receive(self, pkt, node, frm):
        if pkt.kind == "DATA":
            self._route(pkt, node)

    def on_link_fail(self, pkt, frm, to):
        if pkt.kind == "DATA":                         # MAC feedback: drop stale neighbour, re-route
            self.sim.beacon[frm].pop(to, None)
            self._route(pkt, frm)

    def _peri_next(self, pkt, node, tbl):
        me, nodes = self.sim.nodes[node].xy, self.sim.nodes
        cand = planar_neighbors(me, tbl)
        if not cand:
            return None
        prev = pkt.data.get("prev")
        ref_pt = tbl[prev][:2] if prev in tbl else nodes[pkt.dst].xy
        ref = math.atan2(ref_pt[1] - me[1], ref_pt[0] - me[0])
        best, ba = None, 10.0
        for w in cand:
            a = (math.atan2(tbl[w][1] - me[1], tbl[w][0] - me[0]) - ref) % (2 * math.pi)
            if a < 1e-9:
                a = 2 * math.pi
            if a < ba:
                best, ba = w, a
        return best

    def _route(self, pkt, node):
        sim, d = self.sim, pkt.data
        if node == pkt.dst:
            return sim.deliver(pkt)
        if pkt.ttl <= 0:
            return sim.drop(pkt, "ttl", node)
        tbl = sim.beacon[node]
        if not tbl:
            return sim.drop(pkt, "no_neighbor", node)
        me, dpos = sim.nodes[node].xy, sim.nodes[pkt.dst].xy
        myd = dist(me, dpos)
        if d["mode"] == "peri" and myd < d["lp"]:
            d["mode"] = "greedy"
        nxt, note = None, ""
        if d["mode"] == "greedy":
            best = min(tbl, key=lambda n: dist(tbl[n][:2], dpos))
            bd = dist(tbl[best][:2], dpos)
            if bd < myd:
                nxt, note = best, f"greedy → {best} (closest to dst, {bd:.0f} m left)"
            else:
                d.update(mode="peri", lp=myd, edges=set(), prev=None)
        if nxt is None:
            nxt = self._peri_next(pkt, node, tbl)
            if nxt is None:
                return sim.drop(pkt, "local_maximum", node)
            if (node, nxt) in d["edges"]:
                return sim.drop(pkt, "perimeter_loop", node)
            d["edges"].add((node, nxt))
            note = f"PERIMETER (local max at {node}) → {nxt}"
        d["prev"] = node
        pkt.ttl -= 1
        sim.nodes[pkt.src].route = pkt.path + [nxt]
        self.fwd(pkt, node, nxt, note)


# =============================================================================== GPCR (simplified)
def next_target(road, me, dpos, jpath):
    """Pop junctions already reached/passed; return (target position, remaining junction path)."""
    jp = list(jpath)
    while len(jp) >= 2 and dist(me, road.pos[jp[1]]) < dist(road.pos[jp[0]], road.pos[jp[1]]):
        jp.pop(0)
    if jp and dist(me, road.pos[jp[0]]) < JUNCTION_RADIUS:
        jp.pop(0)
    return (road.pos[jp[0]] if jp else dpos), jp


class GPCR(GPSR):
    """GPCR-inspired: the packet follows the junction sequence of the shortest road path to the
    destination; on each street it is relayed greedily, preferring *coordinator* vehicles
    (those standing at a junction).  Recovery = bounded backtracking over non-visited
    neighbours instead of planar-graph perimeter traversal."""
    name = "GPCR"

    def send(self, pkt):
        road = self.sim.world.road
        a, b = road.nearest_junction(self.sim.nodes[pkt.src].xy), road.nearest_junction(self.sim.nodes[pkt.dst].xy)
        try:
            path = nx.shortest_path(road.g, a, b, weight="length")
        except nx.NetworkXNoPath:
            path = [a]
        pkt.data.update(jpath=path, visited=frozenset(), mode="greedy", prev=None)
        self._route(pkt, pkt.src)

    def _is_coord(self, p):
        return any(dist(p[:2], jp) < JUNCTION_RADIUS for jp in self.sim.world.road.pos.values())

    def _route(self, pkt, node):
        sim, d, road = self.sim, pkt.data, self.sim.world.road
        if node == pkt.dst:
            return sim.deliver(pkt)
        if pkt.ttl <= 0:
            return sim.drop(pkt, "ttl", node)
        tbl = sim.beacon[node]
        me, dpos = sim.nodes[node].xy, sim.nodes[pkt.dst].xy
        tgt, jp = next_target(road, me, dpos, d["jpath"])
        d["jpath"] = jp
        d["visited"] = d["visited"] | {node}
        if pkt.dst in tbl:
            nxt, note = pkt.dst, "destination in range"
        else:
            myd = dist(me, tgt)
            cands = [(n, dist(p[:2], tgt)) for n, p in tbl.items() if dist(p[:2], tgt) < myd - 1 and n not in d["visited"]]
            if cands:
                coord = [c for c in cands if self._is_coord(tbl[c[0]])]
                nxt, bd = min(coord or cands, key=lambda c: c[1])
                note = f"{'coordinator at junction' if coord else 'street greedy'} → {nxt} (target {'junction' if jp else 'dst'}, {bd:.0f} m)"
            else:
                rec = [(n, dist(p[:2], tgt)) for n, p in tbl.items() if n not in d["visited"]]
                if not rec:
                    return sim.drop(pkt, "dead_end", node)
                nxt = min(rec, key=lambda c: c[1])[0]
                note = f"RECOVERY (no progress) → {nxt}"
        pkt.ttl -= 1
        sim.nodes[pkt.src].route = pkt.path + [nxt]
        self.fwd(pkt, node, nxt, note)


# =============================================================================== OLSR-style baseline
class OLSR(Protocol):
    """Proactive link-state baseline: each beacon period every node refreshes a topology map
    (modelled analytically: N HELLO + ~35 % of nodes as MPR TC floods) and forwards along the
    shortest path of the *last beaconed* graph."""
    name = "OLSR"
    uses_beacons = True

    def __init__(self, sim):
        super().__init__(sim)
        self.epoch, self.G = -1, nx.Graph()

    def on_tick(self):
        s = self.sim
        if self.epoch != s.beacon_epoch:
            self.epoch = s.beacon_epoch
            self.G = nx.Graph()
            self.G.add_nodes_from(s.ids)
            for i in s.ids:
                for j in s.beacon[i]:
                    if i in s.beacon[j]:
                        self.G.add_edge(i, j)
            s.tx["TC"] += int(0.35 * len(s.ids))

    def send(self, pkt):
        self._route(pkt, pkt.src)

    def on_receive(self, pkt, node, frm):
        if pkt.kind == "DATA":
            self._route(pkt, node)

    def _route(self, pkt, node):
        sim = self.sim
        if node == pkt.dst:
            return sim.deliver(pkt)
        if pkt.ttl <= 0:
            return sim.drop(pkt, "ttl", node)
        try:
            path = nx.shortest_path(self.G, node, pkt.dst)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return sim.drop(pkt, "no_route", node)
        pkt.ttl -= 1
        sim.nodes[pkt.src].route = pkt.path[:-1] + path
        self.fwd(pkt, node, path[1], f"link-state path {path}")


# =============================================================================== DTN
class DTN(Protocol):
    """Store-carry-forward with binary spray-and-wait.  Contacts are detected from beacons each tick;
    RSUs also store and relay.  Messages expire after msg_ttl; delivery is tracked in the simulator."""
    name = "DTN"
    uses_beacons = True
    BUF = 25

    def __init__(self, sim):
        super().__init__(sim)
        self.buf = {i: {} for i in sim.ids}

    def send(self, pkt):
        pkt.data.update(copies=self.sim.cfg.dtn_copies, exp=self.sim.t + self.sim.cfg.msg_ttl)
        self._store(pkt, pkt.src)

    def on_receive(self, pkt, node, frm):
        if pkt.kind == "DATA":
            self._store(pkt, node)

    def _store(self, pkt, node):
        if node == pkt.dst:
            return self.sim.deliver(pkt)
        b = self.buf[node]
        if pkt.uid in b or pkt.uid in self.sim.delivered:
            return
        if len(b) >= self.BUF:
            oldest = min(b, key=lambda u: b[u].created)
            del b[oldest]
        b[pkt.uid] = pkt

    def on_tick(self):
        sim = self.sim
        for node in sim.ids:
            b = self.buf[node]
            for uid in list(b):
                pkt = b.get(uid)
                if pkt is None:
                    continue
                if pkt.data["exp"] < sim.t or uid in sim.delivered:
                    del b[uid]
                    continue
                nb = sim.adj[node]
                if pkt.dst in nb:                                   # contact with destination
                    if sim.transmit(pkt.clone(), node, pkt.dst, "DTN contact with destination"):
                        del b[uid]
                    continue
                c = pkt.data["copies"]
                for m in sorted(nb):
                    if c > 1 and uid not in self.buf[m]:             # spray half of the copies
                        give = c // 2
                        cp = pkt.clone()
                        cp.data["copies"] = give
                        if sim.transmit(cp, node, m, f"store-carry-forward: hand {give} copies to {m}"):
                            c -= give
                pkt.data["copies"] = c
            node_obj = sim.nodes[node]
            node_obj.buffer = list(b)


# =============================================================================== VADD (simplified)
class VADD(Protocol):
    """VADD-inspired: single-copy store-carry-forward.  Road-graph edges get an expected delay
    (fast if the street is densely populated, slow = carried at vehicle speed otherwise); the
    packet steers toward the next junction of the min-delay path and is handed to the neighbour
    (vehicle or RSU) whose *predicted* position (pos + velocity*H) gets closest to that target."""
    name = "VADD"
    uses_beacons = True
    H = 10.0

    def __init__(self, sim):
        super().__init__(sim)
        self.buf = {i: {} for i in sim.ids}
        self.cache, self.cache_t = {}, -1.0

    def send(self, pkt):
        pkt.data.update(exp=self.sim.t + self.sim.cfg.msg_ttl)
        self._store(pkt, pkt.src)

    def on_receive(self, pkt, node, frm):
        if pkt.kind == "DATA":
            self._store(pkt, node)

    def _store(self, pkt, node):
        if node == pkt.dst:
            return self.sim.deliver(pkt)
        self.buf[node][pkt.uid] = pkt

    def _weights(self):
        sim, g = self.sim, self.sim.world.road.g
        cnt = Counter(frozenset(sim.nodes[i].edge) for i in sim.vids)
        vs = [sim.nodes[i].speed for i in sim.vids] or [10.0]
        carry = max(sum(vs) / len(vs) * 0.6, 1.0)
        for u, v, e in g.edges(data=True):
            dense = cnt.get(frozenset((u, v)), 0) * 2 * sim.cfg.comm_range >= e["length"]
            e["delay"] = e["length"] / (120.0 if dense else carry)
        self.cache.clear()

    def _target(self, node, pkt):
        sim, road = self.sim, self.sim.world.road
        me, dpos = sim.nodes[node].xy, sim.nodes[pkt.dst].xy
        a, b = road.nearest_junction(me), road.nearest_junction(dpos)
        if (a, b) not in self.cache:
            try:
                self.cache[(a, b)] = nx.shortest_path(road.g, a, b, weight="delay")
            except nx.NetworkXNoPath:
                self.cache[(a, b)] = [a]
        return next_target(road, me, dpos, self.cache[(a, b)])[0]

    def _pred(self, x, y, vx, vy, tgt):
        return dist((x + vx * self.H, y + vy * self.H), tgt)

    def on_tick(self):
        sim = self.sim
        self._weights()
        for node in sim.ids:
            b, me = self.buf[node], sim.nodes[node]
            for uid in list(b):
                pkt = b.get(uid)
                if pkt is None:
                    continue
                if pkt.data["exp"] < sim.t or uid in sim.delivered:
                    del b[uid]
                    continue
                if pkt.dst in sim.adj[node]:
                    if sim.transmit(pkt, node, pkt.dst, "VADD: destination in range"):
                        del b[uid]
                    continue
                tgt = self._target(node, pkt)
                mine = self._pred(me.x, me.y, me.vx, me.vy, tgt)
                best, bp = None, mine - 0.1 * sim.cfg.comm_range
                for m, (x, y, vx, vy) in sim.beacon[node].items():
                    p = self._pred(x, y, vx, vy, tgt)
                    if p < bp:
                        best, bp = m, p
                if best is not None and sim.transmit(pkt, node, best, f"VADD next carrier {best}{' (RSU)' if best >= 1000 else ''}"):
                    del b[uid]
            me.buffer = list(b)


PROTOCOL_CLASSES = {c.name: c for c in (AODV, DSR, GPSR, GPCR, DTN, VADD, OLSR)}


def make_protocol(name, sim):
    return PROTOCOL_CLASSES[name](sim)
