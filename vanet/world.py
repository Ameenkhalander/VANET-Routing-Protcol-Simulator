"""Road maps, vehicles, RSUs and road-constrained mobility."""
import math
import numpy as np
import networkx as nx

JUNCTION_RADIUS = 45.0


def dist(a, b):
    return math.hypot(a[0] - b[0], a[1] - b[1])


class Node:
    """A vehicle (id < 1000) or a Roadside Unit (id >= 1000)."""

    def __init__(self, nid, comm_range, is_rsu=False):
        self.id, self.range, self.is_rsu = nid, comm_range, is_rsu
        self.x = self.y = self.vx = self.vy = self.speed = self.desired = 0.0
        self.edge, self.s = None, 0.0
        self.route = []          # last route used by this node (set by protocols)
        self.neighbors = set()
        self.buffer = []         # message uids buffered (DTN / VADD)
        self.connected = False
        self.malicious = False

    @property
    def xy(self):
        return (self.x, self.y)

    @property
    def direction_deg(self):
        return math.degrees(math.atan2(self.vy, self.vx)) % 360 if (self.vx or self.vy) else 0.0


class RoadMap:
    def __init__(self, scenario):
        self.g = nx.Graph()
        self.pos = {}
        self.buildings = []  # (xmin, ymin, xmax, ymax)
        {"Highway": self._highway, "Urban City": self._urban, "Rural / Sparse": self._rural}[scenario]()
        for u, v in self.g.edges:
            self.g.edges[u, v]["length"] = dist(self.pos[u], self.pos[v])
        xs = [p[0] for p in self.pos.values()]
        ys = [p[1] for p in self.pos.values()]
        self.bounds = (min(xs), min(ys), max(xs), max(ys))

    def _node(self, n, x, y):
        self.g.add_node(n)
        self.pos[n] = (x, y)

    def _highway(self):
        # Two parallel carriageways joined at both ends -> vehicles circulate in both directions.
        k = 7
        for i in range(k):
            self._node(f"A{i}", i * 500.0, 0.0)
            self._node(f"B{i}", i * 500.0, 14.0)
        for i in range(k - 1):
            self.g.add_edge(f"A{i}", f"A{i+1}")
            self.g.add_edge(f"B{i}", f"B{i+1}")
        self.g.add_edge("A0", "B0")
        self.g.add_edge(f"A{k-1}", f"B{k-1}")

    def _urban(self):
        n, sp = 5, 250.0
        for r in range(n):
            for c in range(n):
                self._node(f"J{r}{c}", c * sp, r * sp)
        for r in range(n):
            for c in range(n):
                if c + 1 < n: self.g.add_edge(f"J{r}{c}", f"J{r}{c+1}")
                if r + 1 < n: self.g.add_edge(f"J{r}{c}", f"J{r+1}{c}")
        m = 14.0  # building set-back from the road centre line
        for r in range(n - 1):
            for c in range(n - 1):
                self.buildings.append((c * sp + m, r * sp + m, (c + 1) * sp - m, (r + 1) * sp - m))

    def _rural(self):
        for n, xy in {"R0": (0, 0), "R1": (1000, 60), "R2": (2000, -40), "R3": (3000, 0),
                      "R4": (1100, 800), "R5": (2500, -650)}.items():
            self._node(n, *xy)
        self.g.add_edges_from([("R0", "R1"), ("R1", "R2"), ("R2", "R3"), ("R1", "R4"), ("R2", "R5")])

    def nearest_junction(self, xy):
        return min(self.pos, key=lambda n: dist(self.pos[n], xy))


def los_clear(p0, p1, rects):
    """Vectorised line-of-sight test: True where segment p0->p1 crosses no building."""
    d = p1 - p0
    clear = np.ones(len(p0), dtype=bool)
    for (x0, y0, x1, y1) in rects:
        tmin, tmax = np.zeros(len(p0)), np.ones(len(p0))
        for ax, lo, hi in ((0, x0, x1), (1, y0, y1)):
            da, oa = d[:, ax], p0[:, ax]
            par = np.abs(da) < 1e-9
            with np.errstate(divide="ignore", invalid="ignore"):
                t1, t2 = (lo - oa) / da, (hi - oa) / da
            inside = (oa > lo) & (oa < hi)
            tl = np.where(par, np.where(inside, -np.inf, np.inf), np.minimum(t1, t2))
            th = np.where(par, np.where(inside, np.inf, -np.inf), np.maximum(t1, t2))
            tmin, tmax = np.maximum(tmin, tl), np.minimum(tmax, th)
        clear &= ~(tmin < tmax)
    return clear


class World:
    def __init__(self, cfg, rng):
        self.cfg, self.rng = cfg, rng
        self.road = RoadMap(cfg.scenario)
        self.nodes = {}
        edges = list(self.road.g.edges)
        weights = [self.road.g.edges[e]["length"] for e in edges]
        for i in range(cfg.n_vehicles):
            n = Node(i, cfg.comm_range)
            u, v = rng.choices(edges, weights)[0]
            if rng.random() < 0.5:
                u, v = v, u
            n.edge = (u, v)
            n.s = rng.uniform(0, self.road.g.edges[u, v]["length"])
            n.desired = n.speed = rng.uniform(cfg.vmin, cfg.vmax)
            self.nodes[i] = n
            self._place(n)
        # Roadside units on junctions
        junctions = list(self.road.g.nodes)
        pref = ["R1", "R2", "R3", "R0", "R4", "R5"] if cfg.scenario.startswith("Rural") else None
        for k in range(cfg.n_rsu):
            j = pref[k % len(pref)] if pref else junctions[(k * len(junctions)) // max(cfg.n_rsu, 1)]
            r = Node(1000 + k, cfg.rsu_range, is_rsu=True)
            r.x, r.y = self.road.pos[j]
            self.nodes[r.id] = r

    def _place(self, n):
        u, v = n.edge
        (x0, y0), (x1, y1) = self.road.pos[u], self.road.pos[v]
        L = self.road.g.edges[u, v]["length"]
        f = n.s / L
        n.x, n.y = x0 + (x1 - x0) * f, y0 + (y1 - y0) * f
        n.vx, n.vy = (x1 - x0) / L * n.speed, (y1 - y0) / L * n.speed

    def step(self, dt):
        g, rng, cfg = self.road.g, self.rng, self.cfg
        for n in self.nodes.values():
            if n.is_rsu:
                continue
            n.speed = min(max(n.speed + rng.gauss(0, 0.4), cfg.vmin), cfg.vmax)
            move = n.speed * dt
            u, v = n.edge
            L = g.edges[u, v]["length"]
            while n.s + move >= L:          # reached a junction: choose next road
                move -= (L - n.s)
                options = [w for w in g.neighbors(v) if w != u] or [u]   # U-turn at dead ends
                u, v = v, rng.choice(options)
                n.s, L = 0.0, g.edges[u, v]["length"]
            n.edge, n.s = (u, v), n.s + move
            self._place(n)
