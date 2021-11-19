#!/bin/bash
set -eu

RESULT=https://interop.sedrubal.de/logs/logs_sat_2021-11-07/result.json
MEASUREMENTS=(G SAT SATL)
IMG_PATH=../../img/plots/

function run {
    echo "$@"
    poetry run $@
}

for extra_arg in "" "--efficiency"; do
    run ./plot_stats.py --no-interactive "${extra_arg}" "--img-path=${IMG_PATH}" --plot-type=boxplot ${MEASUREMENTS[@]} "${RESULT}"
    run ./plot_stats.py --no-interactive "${extra_arg}" "--img-path=${IMG_PATH}" --plot-type=kdes ${MEASUREMENTS[@]} "${RESULT}"

    for measurement in "${MEASUREMENTS[@]}"; do
        run ./plot_stats.py --no-interactive "${extra_arg}" "--img-path=${IMG_PATH}" --plot-type=heatmap "${measurement}" "${RESULT}"
        run ./plot_stats.py --no-interactive "${extra_arg}" "--img-path=${IMG_PATH}" --plot-type=ridgeline "${measurement}" "${RESULT}"
    done
done
