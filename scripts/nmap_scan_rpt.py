#!/usr/bin/env python3
"""
Take Nmap XML results and show hosts that are up with opened ports
Author Jose Vicente Nunez (kodegeek.com@protonmail.com)
"""
import sys
from rich.console import Console
from home_nmap.query import OutputParser
from home_nmap.ui import fill_simple_table


if __name__ == "__main__":
    console = Console()
    for nmap_xml in sys.argv[1:]:
        with open(nmap_xml, 'r') as xml:
            xml_data = xml.read()
            rundata, parsed = OutputParser.parse_nmap_xml(xml_data)
            nmap_table = fill_simple_table(exec_data=rundata, parsed_xml=parsed)
            console.print(nmap_table)
