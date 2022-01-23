#!/usr/bin/env python
"""
Generate network diagrams for this tutorial
Author Jose Vicente Nunez (kodegeek.com@protonmail.com)
"""
import argparse
from diagrams import Cluster, Diagram
from diagrams.aws.general import TraditionalServer


def generate_pivot_diagram(diagram_name: str):
    with Diagram("Example of a network requiring Pivoting for reconnaissance", filename=diagram_name, show=False):
        with Cluster("Nmap + Proxy-chains"):
            proxy_chains = TraditionalServer("External Linux")

        with Cluster("Behind the firewall"):
            with Cluster("SOCKS-5"):
                socks5 = TraditionalServer("Multihomed Linux")

            behind_firewall = socks5
            behind_firewall - [
                TraditionalServer("Internal Linux1"),
                TraditionalServer("Internal Linux2"),
                TraditionalServer("Internal Linux3")
            ]

        proxy_chains >> socks5 >> behind_firewall


if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(
        description="Generate network diagrams for examples used on this tutorial",
        prog=__file__
    )
    DIAGRAMS_TYPES = PARSER.add_mutually_exclusive_group(required=True)
    DIAGRAMS_TYPES.add_argument(
        '--pivot',
        action='store_true',
        default=False,
        help="Generate PIVOT network diagram"
    )
    PARSER.add_argument(
        'diagram',
        action='store',
        help="Name odf the network diagram to generate"
    )
    ARGS = PARSER.parse_args()

    if ARGS.pivot:
        generate_pivot_diagram(ARGS.diagram)
