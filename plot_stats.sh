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

run ./plot_stats.py \
    --no-interactive \
    "--img-path=${IMG_PATH}" \
    "--img-format=${FORMAT}" \
    --plot-type=boxplot \
    "${RESULT_SIM}" \
    "${RESULT_REAL}"

for prop in "goodput" "efficiency"; do
    run ./plot_stats.py \
        --no-interactive \
        "--img-path=${IMG_PATH}" \
        "--img-format=${FORMAT}" \
        --plot-type=swarm \
        --measurement "${NEW_MEASUREMENTS[@]}" \
        "--prop=${prop}" \
        "${RESULT_SIM}" \
        "${RESULT_REAL}"

    run ./plot_stats.py \
        --no-interactive \
        "--prop=${prop}" \
        "--img-path=${IMG_PATH}" \
        "--img-format=${FORMAT}" \
        --plot-type=kdes \
        "${RESULT_SIM}" \
        "${RESULT_REAL}"

    for measurement in "${MEASUREMENTS[@]}"; do
        run ./plot_stats.py \
            --no-interactive \
            "--prop=${prop}" \
            "--measurement=${measurement}" \
            "--img-path=${IMG_PATH}" \
            "--img-format=${FORMAT}" \
            --plot-type=heatmap \
            "${RESULT_SIM}" \
            "${RESULT_REAL}"
        run ./plot_stats.py \
            --no-interactive \
            "--prop=${prop}" \
            "--measurement=${measurement}" \
            "--img-path=${IMG_PATH}" \
            "--img-format=${FORMAT}" \
            --plot-type=ridgeline \
            "${RESULT_SIM}" \
            "${RESULT_REAL}"
    done
done

echo "Don't forget to plot using ./plot_real_experiments.py!"
