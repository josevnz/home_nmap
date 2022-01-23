import re
import shlex
from dataclasses import dataclass
from typing import List, Any, Dict, Optional

import requests
from lxml import html
from xml.etree import ElementTree
from cpe import CPE

from home_nmap import IGNORED_CPES


@dataclass
class NIDS:
    summary: str
    link: str
    score: str


class NDISHtml:

    def __init__(self):
        """
        Some CPE return too many false positives,
        so they are ignored right out the bat
        """
        self.raw_html = None
        self.parsed_results = []
        self.url = "https://nvd.nist.gov/vuln/search/results"
        self.ignored_cpes = IGNORED_CPES

    def get(self, cpe: str) -> str:
        """
        Run a CPE search on the NDIS website. If the CPE has no version then skip the search
        as it will return too many false positives
        @param cpe: CPE identifier coming from NMAP, like cpe:/a:openbsd:openssh:8.0
        @return:
        """
        params = {
            'form_type': 'Basic',
            'results_type': 'overview',
            'search_type': 'all',
            'isCpeNameSearch': 'false',
            'query': cpe
        }
        if cpe in self.ignored_cpes:
            return ""
        valid_cpe = CPE(cpe)
        if not valid_cpe.get_version()[0]:
            return ""
        response = requests.get(
            url=self.url,
            params=params
        )
        response.raise_for_status()
        return response.text

    def parse(self, html_data: str) -> List[NIDS]:
        """
        Parse NDIS web search. Not aware they offer an REST API that doesn't require parsing.
        It is assumed than this method is never called directly by end users, so no further checks are done on the
        HTML file contents.
        @param html_data: RAW HTML used for scrapping
        @return: List of NDIS, if any
        """
        self.parsed_results = []
        if html_data:
            ndis_html = html.fromstring(html_data)
            # 1:1 match between 3 elements, use parallel array
            summary = ndis_html.xpath("//*[contains(@data-testid, 'vuln-summary')]")
            cve = ndis_html.xpath("//*[contains(@data-testid, 'vuln-detail-link')]")
            score = ndis_html.xpath("//*[contains(@data-testid, 'vuln-cvss2-link')]")
            for i in range(len(summary)):
                ndis = NIDS(
                    summary=summary[i].text,
                    link="https://nvd.nist.gov/vuln/detail/" + cve[i].text,
                    score=score[i].text
                )
                self.parsed_results.append(ndis)
        return self.parsed_results

    def correlate_nmap_with_nids(self, parsed_xml: List[Dict[str, Any]]) -> Dict[str, List[NIDS]]:
        correlated_cpe = {}
        for row_data in parsed_xml:
            ports = row_data['ports']
            for port_data in ports:
                for cpe in port_data['cpes']:
                    raw_ndis = self.get(cpe)
                    cpes = self.parse(raw_ndis)
                    correlated_cpe[cpe] = cpes
        return correlated_cpe


class OutputParser:
    """
    Parse Nmap raw XML output
    """

    @staticmethod
    def parse_nmap_xml(xml: str) -> (str, Any):
        """
        Parse XML and return details for the scanned ports.
        It is assumed this method is never called directly by the user, so no special sanity checks are done in the XML
        @param xml: NMAP results in XML file
        @return: tuple NMAP arguments, port details
        """
        parsed_data = []
        root = ElementTree.fromstring(xml)
        nmap_args = root.attrib['args']
        for host in root.findall('host'):
            for address in host.findall('address'):
                curr_address = address.attrib['addr']
                data = {
                    'address': curr_address,
                    'ports': []
                }
                states = host.findall('ports/port/state')
                ports = host.findall('ports/port')
                for i in range(len(ports)):
                    if states[i].attrib['state'] == 'closed':
                        continue  # Skip closed ports
                    port_id = ports[i].attrib['portid']
                    protocol = ports[i].attrib['protocol']
                    services = ports[i].findall('service')
                    cpe_list = []
                    service_name = ""
                    service_product = ""
                    service_version = ""
                    for service in services:
                        for key in ['name', 'product', 'version']:
                            if key in service.attrib:
                                if key == 'name':
                                    service_name = service.attrib['name']
                                elif key == 'product':
                                    service_product = service.attrib['product']
                                elif key == 'version':
                                    service_version = service.attrib['version']
                        cpes = service.findall('cpe')
                        for cpe in cpes:
                            if cpe.text in IGNORED_CPES:
                                continue
                            cpe_list.append(cpe.text)
                        data['ports'].append({
                            'port_id': port_id,
                            'protocol': protocol,
                            'service_name': service_name,
                            'service_product': service_product,
                            'service_version': service_version,
                            'cpes': cpe_list
                        })
                parsed_data.append(data)
        return nmap_args, parsed_data


MIN_LEN_TARGET = 9
MAX_LEN_TARGET = 50


def target_validator(target: Optional[str]) -> str:
    """
    Simple validator for NMAP target expressions
    @param target: (scanme.homenmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254). None or empty are valid
    @return:
    """
    if target:
        regexp_list = [
            '-[a-z-A-Z][A-Z]*',
            '-[a-zA-Z]\\d*',
            '--[a-z-]+'
        ]
        if len(target) < MIN_LEN_TARGET:
            raise ValueError(f"Provided length for target is too small < {MIN_LEN_TARGET}")
        if len(target) > MAX_LEN_TARGET:
            raise ValueError(f"Provided length for target is too big < {MAX_LEN_TARGET}")
        for arg in shlex.split(target):
            for regexp in regexp_list:
                if re.search(regexp, arg):
                    raise ValueError(f"You cannot override NMAP arguments: {arg}")
    return target
