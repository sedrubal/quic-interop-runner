#!/usr/bin/env sh
set -eu

#
# Script to run interop runner while telling systemd / linux through cgroups to controll memory and CPU usage.
#

# SLICE=user.slice
# --slice="${SLICE}" \
# --user \
# --uid="$(id -u)" \
# --gid="$(id -g)" \

exec systemd-run \
    --quiet \
    --pty \
    --collect \
    --same-dir \
    --wait \
    --slice-inherit \
    --description="QUIC Interop Runner with constrained CPU and Memory usage" \
    --property=CPUQuota=95% \
    --property=MemoryLimit=95% \
    poetry run ./run.py $@
