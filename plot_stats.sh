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

FORMAT="pgf"

run ./plot_pairplot.py \
    --no-interactive \
    "--img-path=${IMG_PATH}" \
    "--img-format=${FORMAT}" \
    "${RESULT}"

# run_muted ./long_term_evaluation.py \
#     --testcase=G \
#     "--output=${IMG_PATH}/long_term_evaluation_G.${FORMAT}" \
#     "${QIR_RESULTS}/logs"

# run_muted ./compare_results.py \
#     --plot \
#     "--output=${IMG_PATH}/compare_G_orig_own.${FORMAT}" \
#     "--label1=Marten Seemann" \
#     "--label2=Local" \
#     "${RESULT}" \
#     "${RESULT_ORIG}" \
#     G

run ./plot_stats.py \
    --no-interactive \
    "--img-path=${IMG_PATH}" \
    "--img-format=${FORMAT}" \
    --plot-type=boxplot \
    "${RESULT}"

run ./plot_stats.py \
    --no-interactive \
    "--img-path=${IMG_PATH}" \
    "--img-format=${FORMAT}" \
    --plot-type ccas \
    --measurement SAT SATL \
    -- \
    "${RESULT}"
run ./plot_stats.py \
    --no-interactive \
    "--img-path=${IMG_PATH}" \
    "--img-format=${FORMAT}" \
    --plot-type ccas \
    --measurement T SAT \
    -- \
    "${RESULT}"

run ./plot_stats.py \
    --no-interactive \
    "--img-path=${IMG_PATH}" \
    "--img-format=${FORMAT}" \
    --plot-type violins \
    --measurement "${MEASUREMENTS[@]}" \
    -- \
    "${RESULT}"

for prop in "goodput" "efficiency"; do

    run ./plot_stats.py \
        --no-interactive \
        "--img-path=${IMG_PATH}" \
        "--img-format=${FORMAT}" \
        --plot-type=swarm \
        "--prop=${prop}" \
        --measurement "${MEASUREMENTS[@]}" \
        -- \
        "${RESULT}"

    run ./plot_stats.py \
        --no-interactive \
        "--prop=${prop}" \
        "--img-path=${IMG_PATH}" \
        "--img-format=${FORMAT}" \
        --plot-type=kdes \
        "${RESULT}"

    for include_failed in "true" "false"; do
        run ./plot_stats.py \
            --no-interactive \
            "--prop=${prop}" \
            "--img-path=${IMG_PATH}" \
            "--img-format=${FORMAT}" \
            "--include-failed=${include_failed}" \
            --plot-type=cdf \
            "${RESULT}"
    done

    for measurement in "${MEASUREMENTS[@]}"; do
        run ./plot_stats.py \
            --no-interactive \
            "--prop=${prop}" \
            "--measurement=${measurement}" \
            "--img-path=${IMG_PATH}" \
            "--img-format=${FORMAT}" \
            --plot-type=heatmap \
            "${RESULT}"
        # run ./plot_stats.py \
        #     --no-interactive \
        #     "--prop=${prop}" \
        #     "--measurement=${measurement}" \
        #     "--img-path=${IMG_PATH}" \
        #     "--img-format=${FORMAT}" \
        #     --plot-type=ridgeline \
        #     "${RESULT}"
    done
done

echo "Don't forget to plot using ./plot_real_experiments.py!"
