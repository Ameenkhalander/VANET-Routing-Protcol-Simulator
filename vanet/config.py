"""Configuration dataclass and the three predefined scenario presets."""
from dataclasses import dataclass, field, asdict

PROTOCOLS = ["AODV", "DSR", "GPSR", "GPCR", "DTN", "VADD", "OLSR"]
ATTACKS = ["none", "blackhole", "grayhole", "wormhole"]

# Every value below is user-editable in the UI.
SCENARIOS = {
    "Highway": dict(n_vehicles=40, vmin=25.0, vmax=35.0, comm_range=300.0, duration=120.0,
                    n_rsu=0, n_flows=4, packet_interval=2.0, msg_ttl=60.0),
    "Urban City": dict(n_vehicles=80, vmin=6.0, vmax=14.0, comm_range=250.0, duration=120.0,
                       n_rsu=0, n_flows=6, packet_interval=2.0, msg_ttl=60.0),
    "Rural / Sparse": dict(n_vehicles=10, vmin=12.0, vmax=22.0, comm_range=250.0, duration=300.0,
                           n_rsu=3, n_flows=3, packet_interval=10.0, msg_ttl=250.0),
}


@dataclass
class SimConfig:
    scenario: str = "Highway"
    n_vehicles: int = 40
    vmin: float = 25.0           # m/s
    vmax: float = 35.0           # m/s
    comm_range: float = 300.0    # m (vehicle radio range)
    rsu_range: float = 300.0     # m
    n_rsu: int = 0
    duration: float = 120.0      # s
    dt: float = 0.5              # mobility / topology tick (s)
    beacon_interval: float = 1.0 # neighbour beacon period (s)
    seed: int = 1
    n_flows: int = 4             # constant-bit-rate flows between random vehicle pairs
    packet_interval: float = 2.0 # s between packets of a flow
    packet_size: int = 512       # bytes
    msg_ttl: float = 60.0        # DTN / VADD message lifetime (s)
    dtn_copies: int = 8          # spray-and-wait copy budget for DTN
    attack: str = "none"
    n_malicious: int = 0
    manual_messages: list = field(default_factory=list)  # [(time, src, dst), ...]

    @classmethod
    def preset(cls, scenario, **over):
        d = dict(SCENARIOS[scenario])
        d.update(over)
        return cls(scenario=scenario, **d)

    def to_dict(self):
        return asdict(self)
