#!/bin/sh

sudo find /sys/devices/system/cpu/cpufreq -regextype posix-egrep -regex '/sys/devices/system/cpu/cpufreq/policy[0-9]*/(scaling_setspeed|scaling_governor)' -exec chmod 666 '{}' +
