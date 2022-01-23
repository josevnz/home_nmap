"""
# Nmap helper code
## Performance:
The NMAP default are tailored for a home network (wired/ wireless). To understand the impact, you must read:
* [Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html)
* [Timing and Performance](https://nmap.org/book/man-performance.html).
* [Timing Templates (-T)](https://nmap.org/book/performance-timing-templates.html)
# Author
Jose Vicente Nunez Zuleta (kodegeek.com@protonmail.com)
"""

import os
import re
import shlex
import shutil
import socket
import fcntl
import struct
import ipaddress
import subprocess
from typing import Set, List, Any

from home_nmap.query import OutputParser

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B


class HostIface:
    """
    Get network interface details for a given Linux server
    """

    def __init__(self):
        self.interfaces = set([])
        self.__refresh_interfaces__()

    def __refresh_interfaces__(self, *, skip_loopback: bool = True, only_alive: bool = True) -> Set[str]:
        """
        Alive means an interface that has shown any byte activity since the server is up
        Skips the loopback interface by default
        :param only_alive: Skip interfaces with zero bytes activity
        :param skip_loopback
        :return: Set with interface names
        """
        with open('/proc/net/dev', 'r') as dev:
            for line in dev:
                tokens = line.split()
                if tokens[0].find(":") != -1:
                    name = tokens[0].split(':')[0]
                    if re.search('virbr\\d+|docker', name):
                        continue  # Skip virtual interfaces
                    if only_alive and int(tokens[1].strip()) == 0:
                        continue
                    if skip_loopback and name == 'lo':
                        continue
                    self.interfaces.add(name)
        return self.interfaces

    def get_alive_interfaces(self, *, skip_loopback: bool = True, refresh: bool = False) -> Set[str]:
        """
        Get the list of the active interfaces
        :param skip_loopback: If true ignore loopback
        :param refresh: If true re-read proc, otherwise use first scan results
        :return:  Set with interface names
        """
        if refresh:
            return self.__refresh_interfaces__(skip_loopback=skip_loopback)
        return self.interfaces

    def get_details_all_interfaces(self, *, skip_loopback: bool = True, refresh: bool = False) -> List[Any]:
        """
        Convenience method to get the details of all interfaces on the current host, per get_alive_interfaces
        :param skip_loopback: Skip loopback interface
        :param refresh: Re-read interface information available from /proc
        :return: List of triplet iface, ip, netmask
        """
        details = []
        ifaces = self.get_alive_interfaces(skip_loopback=skip_loopback, refresh=refresh)
        for iface in ifaces:
            ip, netmask = self.get_iface_details(iface)
            details.append((iface, ip, netmask))
        return details

    @staticmethod
    def get_iface_details(iface: str):
        """
        Get network interface IP using the network interface name
        :return: iface, ip, network mask
        :param iface: Interface name (like eth0, enp2s0, etc.)
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            iface_pack = struct.pack('256s', bytes(iface, 'ascii'))
            packed_ip = fcntl.ioctl(s.fileno(), SIOCGIFADDR, iface_pack)[20:24]
            packed_netmask = fcntl.ioctl(s.fileno(), SIOCGIFNETMASK, iface_pack)[20:24]
        return socket.inet_ntoa(packed_ip), socket.inet_ntoa(packed_netmask)

    def get_local_networks(self, *, refresh: bool = False) -> List[ipaddress.IPv4Network]:
        """
        Get the list of local networks, using all the local IP addresses. Skips loopback!
        :param refresh: If true, re-read /proc to get list of interfaces
        :return: List of IPv4Network addresses
        """
        local_networks: List[ipaddress.IPv4Network] = []
        for iface in self.get_alive_interfaces(refresh=refresh, skip_loopback=True):
            ip, netmask = self.get_iface_details(iface)
            network: ipaddress.IPv4Network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
            if network not in local_networks:
                local_networks.append(network)
        return local_networks

    def get_prefixed_local_networks(self) -> List[str]:
        """
        Convenience method that returns networks as strings with prefix appended
        :return: List of networks
        """
        return [f"{ln.network_address}/{ln.prefixlen}" for ln in self.get_local_networks()]


class NMapRunner:

    def __init__(self):
        """
        Create a Nmap executor
        """
        self.nmap_report_file = None
        found_sudo = shutil.which('sudo', mode=os.F_OK | os.X_OK)
        if not found_sudo:
            raise ValueError(f"SUDO is missing")
        self.sudo = found_sudo
        found_nmap = shutil.which('nmap', mode=os.F_OK | os.X_OK)
        if not found_nmap:
            raise ValueError(f"NMAP is missing")
        self.nmap = found_nmap

    def scan(
            self,
            *,
            hosts: str,
            sudo: bool = True
    ):
        command = []
        if sudo:
            command.append(self.sudo)
        command.append(self.nmap)
        command.extend(__NMAP__FLAGS__)
        command.append(hosts)
        completed = subprocess.run(
            command,
            capture_output=True,
            shell=False,
            check=True
        )
        completed.check_returncode()
        args, data = OutputParser.parse_nmap_xml(completed.stdout.decode('utf-8'))
        return args, data, completed.stderr


# Convert the args for proper usage on the CLI
NMAP_HOME_NETWORK_DEFAULT_FLAGS = {
    '-n': 'Never do DNS resolution',
    '-sS': 'TCP SYN scan, recommended',
    '-p-': 'All ports',
    '-sV': 'Probe open ports to determine service/version info',
    '-O': 'OS Probe. Requires sudo/ root',
    '-T4': 'Aggressive timing template',
    '-PE': 'Enable this echo request behavior. Good for internal networks',
    '--version-intensity 5': 'Set version scan intensity. Default is 7',
    '--disable-arp-ping': 'No ARP or ND Ping',
    '--max-hostgroup 20': 'Hostgroup (batch of hosts scanned concurrently) size',
    '--min-parallelism 10': 'Number of probes that may be outstanding for a host group',
    '--osscan-limit': 'Limit OS detection to promising targets',
    '--max-os-tries 1': 'Maximum number of OS detection tries against a target',
    '-oX -': 'Send XML output to STDOUT, avoid creating a temp file'
}
__NMAP__FLAGS__ = shlex.split(" ".join(NMAP_HOME_NETWORK_DEFAULT_FLAGS.keys()))
