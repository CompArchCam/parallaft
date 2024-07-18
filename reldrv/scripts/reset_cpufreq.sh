#!/bin/bash

set -e

for policy in /sys/devices/system/cpu/cpufreq/policy*; do
	max_freq=`cat $policy/cpuinfo_max_freq`
	echo $max_freq > "$policy/scaling_max_freq"
done
