#!/usr/bin/env python3

"""Run sat test for all implementation combinations that support it (that succeeded in a previous run)."""

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from implementations import IMPLEMENTATIONS, Role
from interop import InteropRunner
from run import implementations
from testcases import MeasurementSatellite

TEST_ABBR = MeasurementSatellite.abbreviation()
AVAILABLE_COMBINATIONS = {
    f"{client_name}_{server_name}"
    for client_name, client in IMPLEMENTATIONS.items()
    if client["role"] in (Role.BOTH, Role.CLIENT)
    for server_name, server in IMPLEMENTATIONS.items()
    if server["role"] in (Role.BOTH, Role.SERVER)
}


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="turn on debug logs",
    )
    parser.add_argument(
        "-a",
        "--additional-combinations",
        metavar="COMBI",
        default=set(),
        nargs="+",
        choices=AVAILABLE_COMBINATIONS,
        help="run these implementation combinations in addition to the succeeding",
    )
    parser.add_argument(
        "-l",
        "--log-dir",
        type=Path,
        help="log directory",
        default="",
    )
    parser.add_argument(
        "-f",
        "--save-files",
        action="store_true",
        help="save downloaded files if a test fails",
    )
    parser.add_argument(
        "--skip-compliance-check",
        action="store_true",
        help="Skip compliance check.",
    )
    parser.add_argument(
        "-j",
        "--json",
        type=Path,
        help="output the matrix to file in json format",
    )
    parser.add_argument(
        "last_results",
        type=Path,
        help="output the matrix to file in json format",
    )

    return parser.parse_args()


def find_succeeding(results_file_path: Path) -> set[tuple[str, str]]:
    """Find implementation combinations that succeeded before."""
    print(f"Loading results from {results_file_path}")

    combinations_succeeded = set[tuple[str, str]]()

    with results_file_path.open("r") as results_file:
        previous_results = json.load(results_file)

    servers = previous_results["servers"]
    clients = previous_results["clients"]
    tests = previous_results["tests"].keys()

    if TEST_ABBR not in tests:
        sys.exit("`SAT` testcase was not executed in this run")

    print(f"This combinations succeeded for test case {TEST_ABBR}")

    for i, tests in enumerate(previous_results["measurements"]):
        sat_tests = [test for test in tests if test["abbr"] == TEST_ABBR]
        assert len(sat_tests) == 1
        sat_test = sat_tests[0]
        succeeded = sat_test["result"] == "succeeded"

        if succeeded:
            client_index, server_index = divmod(i, len(servers))
            client = clients[client_index]
            server = servers[server_index]
            print(f"- {client}_{server}")
            combinations_succeeded.add((client, server))

    return combinations_succeeded


def merge_results(result1: dict, result2: dict, log_dir: str) -> dict:
    """Merge two result files."""
    assert result1["quic_draft"] == result2["quic_draft"]
    assert result1["quic_version"] == result2["quic_version"]
    tests1 = dict[str, dict[str, dict[str, Any]]]()
    meass1 = dict[str, dict[str, dict[str, Any]]]()
    tests2 = dict[str, dict[str, dict[str, Any]]]()
    meass2 = dict[str, dict[str, dict[str, Any]]]()
    servers1: list[str] = result1["servers"]
    servers2: list[str] = result2["servers"]
    clients1: list[str] = result1["clients"]
    clients2: list[str] = result2["clients"]

    clients_merged = sorted(frozenset(clients1) | frozenset(clients2))
    servers_merged = sorted(frozenset(servers1) | frozenset(servers2))

    for client_index, client in enumerate(clients1):
        tests1[client] = {}
        meass1[client] = {}

        for server_index, server in enumerate(servers1):
            tests1[client][server] = {}
            meass1[client][server] = {}

            for test in result1["results"][client_index * len(clients1) + server_index]:
                tests1[client][server][test["abbr"]] = test

            for meas in result1["measurements"][
                client_index * len(clients1) + server_index
            ]:
                meass1[client][server][meas["abbr"]] = meas

    for client_index, client in enumerate(clients2):
        tests2[client] = {}
        meass2[client] = {}

        for server_index, server in enumerate(servers2):
            tests2[client][server] = {}
            meass2[client][server] = {}

            for test in result2["results"][client_index * len(clients2) + server_index]:
                tests2[client][server][test["abbr"]] = test

            for meas in result2["measurements"][
                client_index * len(clients2) + server_index
            ]:
                meass2[client][server][meas["abbr"]] = meas

    # check and merge test and measurements
    tests_merged = dict[str, dict[str, dict[str, Any]]]()
    meass_merged = dict[str, dict[str, dict[str, Any]]]()

    for client in clients_merged:
        tests_merged[client] = {}
        meass_merged[client] = {}

        for server in servers_merged:
            # merge tests
            tests_for_combi1 = tests1.get(client, {}).get(server, {})
            tests_for_combi2 = tests2.get(client, {}).get(server, {})
            test_abbrs1 = frozenset(tests_for_combi1.keys())
            test_abbrs2 = frozenset(tests_for_combi2.keys())
            common_tests = test_abbrs1 & test_abbrs2

            if common_tests:
                breakpoint()
                sys.exit(
                    f"Both results have same test results for {client}_{server}: {', '.join(common_tests)}"
                )

            tests_merged[client][server] = {**tests_for_combi1, **tests_for_combi2}

            # merge measurements
            meass_for_combi1 = meass1.get(client, {}).get(server, {})
            meass_for_combi2 = meass2.get(client, {}).get(server, {})
            meas_abbrs1 = frozenset(meass_for_combi1.keys())
            meas_abbrs2 = frozenset(meass_for_combi2.keys())
            common_meass = meas_abbrs1 & meas_abbrs2

            if common_meass:
                breakpoint()
                sys.exit(
                    f"Both results have same measurement results for {client}_{server}: {', '.join(common_meass)}"
                )

            meass_merged[client][server] = {**meass_for_combi1, **meass_for_combi2}

    # linearize tests and measurements
    tests_lin = list[list[Any]]()
    meass_lin = list[list[Any]]()

    for client in clients_merged:
        for server in servers_merged:
            tests_lin.append(list(tests_merged[client][server].values()))
            meass_lin.append(list(meass_merged[client][server].values()))

    output = {
        "start_time": min(result1["start_time"], result2["start_time"]),
        "end_time": min(result1["end_time"], result2["end_time"]),
        "log_dir": log_dir,
        "servers": servers_merged,
        "clients": clients_merged,
        "urls": {**result1.get("urls", {}), **result2.get("urls", {})},
        "tests": {**result1.get("tests", {}), **result2.get("tests", {})},
        "quic_draft": result1["quic_draft"],
        "quic_version": result1["quic_version"],
        "results": tests_lin,
        "measurements": meass_lin,
    }

    return output


def run_single(
    server: str,
    client: str,
    output: Path,
    log_dir: Path,
    debug=False,
    save_files=False,
    skip_compliance_check=False,
) -> int:
    """docstring for run_single"""

    combination = f"{client}_{server}"

    with tempfile.TemporaryDirectory(
        prefix=f"log_dir_{combination}_"
    ) as tmp_log_dir_base:
        with tempfile.NamedTemporaryFile(
            prefix=f"results_{combination}_",
            suffix=".json",
            mode="r",
        ) as tmp_results_file:
            tmp_log_dir_path = Path(tmp_log_dir_base) / "logs"

            ret = InteropRunner(
                implementations=implementations,
                servers=[server],
                clients=[client],
                tests=[],
                measurements=[MeasurementSatellite],
                output=tmp_results_file.name,
                debug=debug,
                log_dir=str(tmp_log_dir_path),
                save_files=save_files,
                skip_compliance_check=skip_compliance_check,
            ).run()

            print("copy result files to final destination")
            # 1. merge results json files
            tmp_result = json.load(tmp_results_file)

            if output.is_file():
                with output.open("r") as final_result_file:
                    final_result = json.load(final_result_file)

                final_result = merge_results(
                    final_result,
                    tmp_result,
                    log_dir=str(log_dir.absolute()),
                )
            else:
                final_result = tmp_result
                final_result["log_dir"] = str(output.absolute())

            with output.open("w") as final_result_file:
                json.dump(final_result, fp=final_result_file)

            # 2. move files from log dir
            combination_log_dir_path = tmp_log_dir_path / combination

            if combination_log_dir_path.is_dir():
                combination_log_dir_path.rename(log_dir / combination)
            else:
                print(
                    f"Log dir {combination_log_dir_path} does not exist",
                    file=sys.stderr,
                )

    return ret


def main():
    args = get_args()
    combinations_succeeded = find_succeeding(args.last_results)
    combinations_to_run = combinations_succeeded | frozenset(
        args.additional_combinations
    )
    print(f"Will run {len(combinations_to_run)} combinations")

    if args.log_dir.is_dir():
        print(f"WARNING: Log dir {args.log_dir} exists!", file=sys.stderr)
    args.log_dir.mkdir(parents=True, exist_ok=True)

    if args.json.is_file():
        sys.exit(f"Output file {args.json} exists!")

    for client, server in combinations_to_run:
        ret = run_single(
            server=server,
            client=client,
            output=args.json,
            log_dir=args.log_dir,
            debug=args.debug,
            save_files=args.save_files,
            skip_compliance_check=args.skip_compliance_check,
        )

        if ret:
            sys.exit(ret)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(0)
