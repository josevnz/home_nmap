#!/usr/bin/env python
"""
# home_scan.py - A simple host discovery script
This script can scan your home network to show information from all the connected devices.

## References:
* [NMAP reference](https://nmap.org/book/man.html)

# Author
Jose Vicente Nunez Zuleta (kodegeek.com@protonmail.com)
"""
import json
import logging
import sys

from rich.layout import Layout
from rich.live import Live
from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text
from rich.traceback import install
from rich.progress import TimeElapsedColumn, Progress, TextColumn
from typing import List
import argparse

from home_nmap.query import target_validator
from home_nmap.system import HostIface, NMapRunner
from home_nmap.ui import create_scan_table, update_scan_table


def get_targets(target_list: List[str], cli_args: argparse.Namespace) -> str:
    if cli_args.target:
        return ','.join(target_list)
    return ','.join(HostIface().get_prefixed_local_networks())


if __name__ == '__main__':

    install()
    logging.basicConfig(
        level="NOTSET",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )

    console = Console()
    arg_parser = argparse.ArgumentParser(
        description="Identify my local networked devices, with open ports",
        prog=__file__
    )
    arg_parser.add_argument(
        '--debug',
        action='store_true',
        default=False,
        help="Enable debug mode"
    )
    arg_parser.add_argument(
        '--full',
        action='store_true',
        default=False,
        help="Show full description for advisories. May be too long for the screen. Default is false"
    )
    arg_parser.add_argument(
        '--results',
        '-xO',
        action='store',
        help=f"If defined, save scan results into this file."
    )
    arg_parser.add_argument(
        'target',
        action='store',
        nargs='*',
        type=target_validator,  # Custom validator for min, max size and to ensure no overrides are passed
        help=(f"One or more targets, in NMAP format (scanme.homenmap.org, microsoft.com/24, 192.168.0.1; "
              f"10.0.0-255.1-254). If not provided, then scan local networks")
    )
    args = arg_parser.parse_args()

    current_app_progress = Progress(
        TimeElapsedColumn(),
        TextColumn("{task.description}"),
    )
    scanning_task = current_app_progress.add_task("[yellow]Waiting[/yellow] for scan results... :hourglass:")

    try:
        scanner = NMapRunner()
        scan_targets = get_targets(args.target, args)
        if args.results:
            table_title = f"Targets: {scan_targets}, results file={args.results}"
        else:
            table_title = f"Targets: {scan_targets}"
        results_table = create_scan_table(cli=f"Targets: {table_title}")
        layout = Layout()
        layout.split(
            Layout(name="Scan status", size=1),
            Layout(name="Scan results"),
        )
        with Live(
                layout,
                console=console,
                screen=False,
                redirect_stderr=False,
        ) as live:
            layout['Scan results'].update(Text(
                text=f"No results yet ({scan_targets})", style="green", justify="center")),
            layout['Scan status'].update(current_app_progress)
            nmap_args, data, stderr = scanner.scan(hosts=scan_targets)
            update_scan_table(scan_result=data,
                              results_table=results_table,
                              main_layout=layout,
                              progress=current_app_progress,
                              task_id=scanning_task,
                              full_advisory=args.full
                              )
        if args.results:
            report_data = {
                'args': nmap_args,
                'scan': data
            }
            with open(args.results, 'w') as report_file:
                json.dump(report_data, report_file, indent=True)

    except ValueError:
        logging.exception("There was an error")
        sys.exit(100)
    except KeyboardInterrupt:
        console.log("Scan interrupted, exiting...")
        pass
    sys.exit(0)
