#!/usr/bin/env python3

# pip3 install --user msgpack

import msgpack
import argparse
from collections import defaultdict

parser = argparse.ArgumentParser()
parser.add_argument("input")
args = parser.parse_args()

all_stats = defaultdict(int)

with open(args.input, "rb") as f:
    unpacker = msgpack.Unpacker(f, raw=False)
    for unpacked in unpacker:
        segment_id, stats, injection_attempts, successful_injections = unpacked

        for k, v in stats.items():
            all_stats[k] += v
        
        all_stats["Total"] += injection_attempts
        all_stats["Injected"] += successful_injections

for k, v in all_stats.items():
    print(f"{k}: {v}")
