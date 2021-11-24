#!/bin/bash
set -eu

source .env.sh

function run_muted {
    echo "$@"
    poetry run "$@" >/dev/null
}

function run {
    echo "$@"
    poetry run "$@"
}

run ./plot_pairplot.py \
    --no-interactive \
    "--img-path=${IMG_PATH}" \
    "--img-format=${FORMAT}" \
    "${RESULT_SIM}" \
    "${RESULT_REAL}"

run_muted ./long_term_evaluation.py \
    --testcase=G \
    "--output=${IMG_PATH}/long_term_evaluation_G.${FORMAT}" \
    "${QIR_RESULTS}/logs"

run_muted ./compare_results.py \
    --plot \
    "--output=${IMG_PATH}/compare_G_orig_own.${FORMAT}" \
    "--label1=Marten Seemann" \
    "--label2=Local" \
    "${RESULT_ORIG}" \
    "${RESULT_SIM}" \
    G

for extra_arg in "" "--efficiency"; do
    # TODO measurements argument breaks
    run ./plot_stats.py \
        --no-interactive \
        "${extra_arg}" \
        "--img-path=${IMG_PATH}" \
        "--img-format=${FORMAT}" \
        --plot-type=boxplot \
        "${MEASUREMENTS[@]}" \
        "${RESULT_SIM}"
    run ./plot_stats.py \
        --no-interactive \
        "${extra_arg}" \
        "--img-path=${IMG_PATH}" \
        "--img-format=${FORMAT}" \
        --plot-type=kdes \
        "${MEASUREMENTS[@]}" \
        "${RESULT_SIM}"

    for measurement in "${MEASUREMENTS[@]}"; do
        run ./plot_stats.py \
            --no-interactive \
            "${extra_arg}" \
            "--img-path=${IMG_PATH}" \
            "--img-format=${FORMAT}" \
            --plot-type=heatmap \
            "${measurement}" \
            "${RESULT_SIM}"
        run ./plot_stats.py \
            --no-interactive \
            "${extra_arg}" \
            "--img-path=${IMG_PATH}" \
            "--img-format=${FORMAT}" \
            --plot-type=ridgeline \
            "${measurement}" \
            "${RESULT_SIM}"
    done
done

echo "Don't forget to plot using ./plot_real_experiments.py!"
