import numpy as np
import pytest

from vanet import SimConfig, Simulation, SCENARIOS, PROTOCOLS
from vanet.protocols import planar_neighbors
from vanet.world import los_clear


def quick(scn, proto, **over):
    over.setdefault("duration", 40.0)
    return Simulation(SimConfig.preset(scn, **over), proto).run()


@pytest.mark.parametrize("scn", list(SCENARIOS))
@pytest.mark.parametrize("proto", PROTOCOLS)
def test_every_protocol_runs_in_every_scenario(scn, proto):
    s = quick(scn, proto).summary()
    assert s["sent"] > 0
    assert 0 <= s["delivered"] <= s["sent"]
    assert 0.0 <= s["pdr"] <= 1.0


def test_deterministic_for_same_seed():
    assert quick("Highway", "AODV").summary() == quick("Highway", "AODV").summary()


def test_vehicles_stay_on_roads_and_neighbours_are_symmetric():
    sim = quick("Urban City", "GPSR", duration=20.0)
    road = sim.world.road
    for n in sim.nodes.values():
        u, v = n.edge
        assert 0 <= n.s <= road.g.edges[u, v]["length"] + 1e-6
    for a, nb in sim.adj.items():
        for b in nb:
            assert a in sim.adj[b]


def test_range_changes_connectivity():
    small = quick("Highway", "AODV", comm_range=60.0, duration=20.0).summary()["avg_neighbors"]
    large = quick("Highway", "AODV", comm_range=400.0, duration=20.0).summary()["avg_neighbors"]
    assert large > small


def test_buildings_block_line_of_sight():
    rects = [(10, 10, 20, 20)]
    p0 = np.array([[0.0, 15.0], [0.0, 0.0]])
    p1 = np.array([[30.0, 15.0], [30.0, 0.0]])
    assert list(los_clear(p0, p1, rects)) == [False, True]


def test_gabriel_planarisation_removes_witnessed_edge():
    tbl = {1: (100, 0, 0, 0), 2: (50, 1, 0, 0)}       # node 2 lies inside circle on edge me-1
    assert planar_neighbors((0, 0), tbl) == [2]


def test_aodv_discovers_and_delivers_on_dense_highway():
    s = quick("Highway", "AODV", n_vehicles=60, comm_range=400.0).summary()
    assert s["pdr"] > 0.4 and s["control_tx"] > 0


def test_dtn_beats_aodv_in_sparse_network():
    d = quick("Rural / Sparse", "DTN", duration=300.0).summary()["pdr"]
    a = quick("Rural / Sparse", "AODV", duration=300.0).summary()["pdr"]
    assert d > a


def test_blackhole_hurts_aodv():
    clean = quick("Highway", "AODV", n_vehicles=60, comm_range=400.0).summary()["pdr"]
    bad = quick("Highway", "AODV", n_vehicles=60, comm_range=400.0, attack="blackhole", n_malicious=8).summary()["pdr"]
    assert bad < clean


def test_manual_message_is_traced():
    sim = quick("Highway", "GPSR", n_vehicles=50, comm_range=400.0, n_flows=1, manual_messages=[(3.0, 0, 1)])
    assert any(v[:2] == (0, 1) for v in sim.msg_info.values())
