#!/usr/bin/env python3

import argparse
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from termcolor import colored, cprint

from enums import CacheMode, PlotMode, Side
from plot_diagram import DEFAULT_TITLES, PlotCli
from result_parser import MeasurementResultInfo, Result
from trace_analyzer2 import ParsingError
from utils import TraceTriple, create_relpath, existing_file_path

DEFAULT_TITLE = "{mode_default_title} ({test_abbr}, server: {server}, client: {client})"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "results",
        nargs="+",
        type=existing_file_path,
        help="quic-interop-runner result.json files.",
    )
    parser.add_argument(
        "--only-sat",
        action="store_true",
        help="Plot only for for SAT testcase.",
    )
    parser.add_argument(
        "--include-failed",
        action="store_true",
        help="Plot also failed test cases.",
    )
    parser.add_argument(
        "-t",
        "--title",
        action="store",
        default=DEFAULT_TITLE,
        help=(
            f"The title for the diagram (default='{DEFAULT_TITLE}'). "
            "WATCH OUT! THIS TTILE WILL BE FORMATTED → WE TRUST THE FORMAT STRING!"
        ),
    )
    parser.add_argument(
        "--no-annotation",
        action="store_true",
        help="Hide TTFB, PLT, ... markers.",
    )
    parser.add_argument(
        "--format",
        action="store",
        default="png",
        choices=("svg", "png", "pdf"),
        help="The file format to plot.",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Force overwriting existing plot.",
    )
    parser.add_argument(
        "--mode",
        action="store",
        choices=PlotMode,
        nargs="+",
        type=PlotMode,
        default=[mode for mode in PlotMode],
        help="The mode of plotting (time vs. packet-number or time vs. file-size or both)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode.",
    )
    parser.add_argument(
        "-j",
        "--workers",
        action="store",
        type=int,
        default=1,
        help="Number of workers for plotting. NOTE: >1 breaks output",
    )

    return parser.parse_args()


class PlotAllCli:
    def __init__(
        self,
        #  log_dirs: list[Path],
        result_files: list[Path],
        title: str,
        annotate: bool,
        format: str,
        force=False,
        only_sat=False,
        include_failed=False,
        modes: list[PlotMode] = list(PlotMode),
        debug=False,
        max_workers: int = 1,
    ):
        #  self.log_dirs = log_dirs
        self.result_files = result_files
        self.only_sat = only_sat
        self.title = title
        self.annotate = annotate
        self.format = format
        self.force = force
        self.include_failed = include_failed
        self.modes = modes
        self._current_log_dir: Optional[Path] = None
        self.debug = debug
        self.max_workers = max_workers
        if max_workers > 1 and debug:
            sys.exit("Debug and max_workers > 1 is not advised")

    def plot_in_meas_run_dir(
        self,
        measurement_result: MeasurementResultInfo,
        modes: list[PlotMode],
    ) -> list[str]:
        """Generate plot for for this test case."""
        assert self._current_log_dir
        test_case_dir = measurement_result.log_dir_for_test.path

        if not measurement_result.succeeded and not self.include_failed:
            cprint(
                (
                    "✔ Measurement "
                    f"{measurement_result.log_dir_for_test.path.relative_to(self._current_log_dir)} "
                    "Failed. Skipping. Use --include-failed to include it anyway."
                ),
                file=sys.stderr,
                color="cyan",
            )

            return ["testcase failed"]

        trace_triples = list[TraceTriple]()

        for repetition_dir in measurement_result.repetition_log_dirs:
            base_sim_path = repetition_dir / "sim"
            trace_triple = TraceTriple(
                left_pcap_path=(
                    base_sim_path / f"trace_node_{Side.LEFT.value}_with_secrets.pcapng"
                ).resolve(),
                right_pcap_path=(
                    base_sim_path / f"trace_node_{Side.RIGHT.value}_with_secrets.pcapng"
                ).resolve(),
            )

            if not trace_triple.left_pcap_path.is_file():
                cprint(
                    f"⨯ {trace_triple.left_pcap_path} does not exist",
                    color="red",
                    file=sys.stderr,
                )

                continue

            if not trace_triple.right_pcap_path.is_file():
                cprint(
                    f"⨯ {trace_triple.right_pcap_path} does not exist",
                    color="red",
                    file=sys.stderr,
                )

                continue

            trace_triples.append(trace_triple)

        if not trace_triples:
            cprint(
                f"⨯ no pcapng files found for {test_case_dir}. Skipping...",
                file=sys.stderr,
                color="red",
            )

            return ["no traces files found"]

        cli = PlotCli(
            trace_triples=trace_triples,
            annotate=self.annotate,
            cache=CacheMode.LOAD,
            # enable debug mode with interruptable terminal logging when we use more than 1 worker
            debug=self.debug or self.max_workers > 1,
        )

        rets = list[str]()

        for mode in modes:
            output_file = test_case_dir / f"time_{mode.value}_plot.{self.format}"
            err_output_file = test_case_dir / f".time_{mode.value}_plot_error.txt"

            if not self.force:
                if output_file.is_file():
                    cprint(
                        (
                            f"✔ {output_file.relative_to(self._current_log_dir)} already exists. "
                            "Skipping. Use --force to overwrite."
                        ),
                        file=sys.stderr,
                        color="cyan",
                    )

                    rets.append("already exists")

                    continue
                elif err_output_file.is_file():
                    with err_output_file.open("r") as file:
                        err_msg = file.read().strip()

                    try:
                        broken_pcap, err_msg = err_msg.splitlines()
                    except ValueError:
                        cprint(
                            f"Error message {err_output_file} has invalid format.",
                            file=sys.stderr,
                        )
                        broken_pcap = None

                    cprint(
                        (
                            "⨯ Trace could not be plotted in previous run. "
                            f"{err_output_file.relative_to(self._current_log_dir)} exists: "
                        ),
                        file=sys.stderr,
                        color="red",
                    )
                    if broken_pcap:
                        cprint(broken_pcap, file=sys.stderr, color="red")
                    cprint(err_msg, file=sys.stderr, color="red")
                    cprint(
                        "Skipping. Use --force to overwrite.",
                        file=sys.stderr,
                        color="red",
                    )

                    rets.append(err_msg)

                    continue

            cprint(
                (
                    f"⚒ Plotting in {create_relpath(test_case_dir)} "
                    f"({len(trace_triples)} trace pairs) → {create_relpath(output_file)}"
                ),
                attrs=["bold"],
            )
            cli.set_params(
                title=self.title.format(
                    combination=measurement_result.combination,
                    client=measurement_result.client.name,
                    server=measurement_result.server.name,
                    mode_default_title=DEFAULT_TITLES[mode],
                    test_abbr=measurement_result.test.abbr,
                    test_name=measurement_result.test.name,
                    test_desc=measurement_result.test.desc,
                ),
                mode=mode,
                output_file=output_file,
            )
            try:
                cli.run()
            except ParsingError as err:
                cprint(
                    (
                        f"⨯ Could not parse {err.trace} in "
                        f"{test_case_dir}. "
                        "Skipping..."
                    ),
                    file=sys.stderr,
                    color="red",
                )
                cprint(f"⨯ {err}", file=sys.stderr, color="red")

                with err_output_file.open("w") as file:
                    print(
                        f"{err.trace.input_file}:\n",
                        err.msg,
                        file=file,
                    )

                rets.append(err.msg)

                continue

        return rets

    def plot_in_log_dir(self, result: Result):
        """Generate plots for result file."""
        cprint(
            f"⚒ Plotting results {result} (log dir: {result.log_dir})",
            attrs=["bold"],
        )

        self._current_log_dir = result.log_dir.path

        plot_results = defaultdict[str, set[str]](set[str])

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for tmp1 in result.measurement_results.values():
                for tmp2 in tmp1.values():
                    measurement_results = list[MeasurementResultInfo]()

                    if self.only_sat:
                        measurement_results = [tmp2["SAT"]]
                    else:
                        measurement_results = list(tmp2.values())

                    def job(measurement_result, modes):
                        plot_results = self.plot_in_meas_run_dir(
                            measurement_result, modes
                        )
                        return (
                            measurement_result.combination,
                            measurement_result.test.abbr,
                            plot_results,
                        )

                    for measurement_result in measurement_results:
                        future = executor.submit(
                            job,
                            measurement_result,
                            self.modes,
                        )
                        futures.append(future)

            for future in futures:
                combi, test_abbr, results = future.result()

                for plot_result in results:
                    if plot_result == "already_exists":
                        plot_result = colored(plot_result, color="green")
                    plot_results[plot_result].add(f"{combi}-{test_abbr}")

                if not results:
                    plot_results[colored("success", color="green")].add(
                        f"{combi}-{test_abbr}"
                    )

        # Print a summary.
        print()
        print("#### Results:")
        print()

        for msg, combinations in plot_results.items():
            print(f"- {msg}: {len(combinations)}")

            for combination in combinations:
                print(f"  - `{combination}`")

        print()

    def run(self):
        for result_file in self.result_files:
            result = Result(result_file)
            result.load_from_json()
            self.plot_in_log_dir(result)


def main():
    args = parse_args()
    cli = PlotAllCli(
        #  log_dirs=args.log_dirs,
        result_files=args.results,
        only_sat=args.only_sat,
        title=args.title,
        annotate=not args.no_annotation,
        format=args.format,
        force=args.force,
        include_failed=args.include_failed,
        modes=args.mode,
        debug=args.debug,
        max_workers=args.workers,
    )
    try:
        cli.run()
    except KeyboardInterrupt:
        sys.exit("\nQuit")

    cprint("✔ Done", color="green", attrs=["bold"])


if __name__ == "__main__":
    main()
