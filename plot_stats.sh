#!/bin/bash
set -eu

RESULT_SIM=https://interop.sedrubal.de/logs/logs_sat_2021-11-07/result.json
RESULT_REAL=https://interop.sedrubal.de/logs/logs_real_2021-11-15/result.json
RESULT_ORIG=https://interop.seemann.io/logs/latest/result.json
MEASUREMENTS=(G SAT SATL)
IMG_PATH=../../img/plots/
FORMAT=png

function run {
    echo "$@"
    poetry run $@
}

for extra_arg in "" "--efficiency"; do
    run ./plot_stats.py --no-interactive "${extra_arg}" "--img-path=${IMG_PATH}" "--img-format=${FORMAT}" --plot-type=boxplot ${MEASUREMENTS[@]} "${RESULT_SIM}"
    run ./plot_stats.py --no-interactive "${extra_arg}" "--img-path=${IMG_PATH}" "--img-format=${FORMAT}" --plot-type=kdes ${MEASUREMENTS[@]} "${RESULT_SIM}"

    for measurement in "${MEASUREMENTS[@]}"; do
        run ./plot_stats.py --no-interactive "${extra_arg}" "--img-path=${IMG_PATH}" "--img-format=${FORMAT}" --plot-type=heatmap "${measurement}" "${RESULT_SIM}"
        run ./plot_stats.py --no-interactive "${extra_arg}" "--img-path=${IMG_PATH}" "--img-format=${FORMAT}" --plot-type=ridgeline "${measurement}" "${RESULT_SIM}"
    done
done

run ./plot_pairplot.py --no-interactive "--img-path=${IMG_PATH}" "--img-format=${FORMAT}" "${RESULT_SIM}" "${RESULT_REAL}"

run ./long_term_evaluation.py --testcase=G -o "${IMG_PATH}/long_term_evaluation_G.${FORMAT}" ../../spielwiese/quic-interop-runner-results/logs

run ./compare_results.py "--output=${IMG_PATH}/compare_G_orig_own.${FORMAT}" --label1="Marten Seemann" --label2="Local" --plot "${RESULT_ORIG}" "${RESULT_SIM}" G > /dev/null

echo "Don't forget to plot using ./plot_real_experiments.py!"
