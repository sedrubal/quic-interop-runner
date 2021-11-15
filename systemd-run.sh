#!/usr/bin/env sh
set -eu

#
# Wrapper script to run scripts while telling systemd / linux through cgroups to controll memory and CPU usage.
#

SLICE=user.slice
# --slice="${SLICE}" \
# --user \
# --uid="$(id -u)" \
# --gid="$(id -g)" \
CPUQUOTA=$((($(nproc --all) - 1) * 100))

exec systemd-run \
    --quiet \
    --pty \
    --collect \
    --same-dir \
    --wait \
    --slice="${SLICE}" \
    --description="QUIC Interop Runner with constrained CPU and Memory usage" \
    --property=CPUQuota="${CPUQUOTA}%" \
    --property=MemoryLimit=95% \
    --property=OOMPolicy=kill \
    poetry run $@
