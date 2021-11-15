#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path
from typing import List, Tuple, Type

import testcases
from implementations import IMPLEMENTATIONS
from interop import InteropRunner
from testcases import MEASUREMENTS, TESTCASES
from utils import time_range

client_implementations = [
    name for name, value in IMPLEMENTATIONS.items() if value.role.is_client
]
server_implementations = [
    name for name, value in IMPLEMENTATIONS.items() if value.role.is_server
]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="turn on debug logs",
    )
    parser.add_argument(
        "-s",
        "--server",
        nargs="+",
        action="extend",
        choices=server_implementations,
        help="server implementation",
    )
    parser.add_argument(
        "-c",
        "--client",
        nargs="+",
        action="extend",
        choices=client_implementations,
        help="client implementation",
    )
    parser.add_argument(
        "-t",
        "--test",
        nargs="+",
        action="extend",
        default=None,
        choices=[
            "onlyTests",
            "onlyMeasurements",
            *(x.name for x in TESTCASES),
            *(x.name for x in MEASUREMENTS),
        ],
        help="test cases.",
    )
    parser.add_argument(
        "-r",
        "--replace",
        nargs="*",
        default=[],
        help="replace path of implementation. Example: -r myquicimpl=dockertagname",
    )
    parser.add_argument(
        "-l",
        "--log-dir",
        help="log directory",
        default="",
        type=Path,
    )
    parser.add_argument(
        "-f",
        "--save-files",
        action="store_true",
        help="save downloaded files if a test fails",
    )
    parser.add_argument(
        "-j",
        "--json",
        help="output the matrix to file in json format",
        type=Path,
    )
    parser.add_argument(
        "--skip-compliance-check",
        action="store_true",
        help="Skip compliance check.",
    )
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="Retry failed tests and measurements when resuming a run.",
    )
    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Scramble the order of the test cases.",
    )
    parser.add_argument(
        "--pause-between",
        action="store",
        type=time_range,
        help="Pause between a specific time of the day (for real links). Format: HH:MM-HH:MM.",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    for replace in args.replace:
        try:
            name, image = replace.split("=")
        except ValueError:
            sys.exit("Invalid format for replace")

        if name not in IMPLEMENTATIONS:
            sys.exit(f"Implementation {name} not found.")

        print(
            f"Using image {image} for {name} instead of {IMPLEMENTATIONS[name].image}"
        )
        IMPLEMENTATIONS[name].image = image

    def get_tests_and_measurements(
        arg,
    ) -> Tuple[List[Type[testcases.TestCase]], List[Type[testcases.Measurement]]]:
        if arg is None:
            return TESTCASES, MEASUREMENTS
        elif not arg:
            return [], []
        elif len(arg) == 1:
            if arg[0] == "onlyTests":
                return TESTCASES, []
            elif arg[0] == "onlyMeasurements":
                return [], MEASUREMENTS

        tests: List[Type[testcases.TestCase]] = []
        measurements: List[Type[testcases.Measurement]] = []

        for test_case_name in arg:
            test_case_lookup = {tc.name: tc for tc in TESTCASES}
            measurement_lookup = {m.name: m for m in MEASUREMENTS}

            if test_case_name in test_case_lookup.keys():
                tests.append(test_case_lookup[test_case_name])
            elif test_case_name in measurement_lookup.keys():
                measurements.append(measurement_lookup[test_case_name])
            else:
                print(f"Test case {test_case_name} not found.", file=sys.stderr)
                print(
                    f"Available testcases: {', '.join(sorted(test_case_lookup.keys()))}",
                    file=sys.stderr,
                )
                print(
                    f"Available measurements: {', '.join(sorted(measurement_lookup.keys()))}",
                    file=sys.stderr,
                )
                sys.exit()

        return tests, measurements

    tests, measurements = get_tests_and_measurements(args.test)

    return InteropRunner(
        servers=args.server or server_implementations,
        clients=args.client or client_implementations,
        tests=tests,
        measurements=measurements,
        output=args.json,
        debug=args.debug,
        log_dir=args.log_dir,
        save_files=args.save_files,
        skip_compliance_check=args.skip_compliance_check,
        retry_failed=args.retry_failed,
        shuffle=args.shuffle,
        pause_between=args.pause_between,
    ).run()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(0)
