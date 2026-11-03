"""Command-line runner:  python -m vanet.cli --scenario Highway --protocol AODV"""
import argparse, json
from . import SimConfig, Simulation, SCENARIOS, PROTOCOLS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="Highway", choices=list(SCENARIOS))
    ap.add_argument("--protocol", default="all", choices=PROTOCOLS + ["all"])
    ap.add_argument("--duration", type=float)
    ap.add_argument("--vehicles", type=int)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    over = {k: v for k, v in dict(duration=a.duration, n_vehicles=a.vehicles).items() if v is not None}
    for p in (PROTOCOLS if a.protocol == "all" else [a.protocol]):
        s = Simulation(SimConfig.preset(a.scenario, seed=a.seed, **over), p).run().summary()
        print(json.dumps(s))


if __name__ == "__main__":
    main()
