"""
Unit tests for code used on this tutorial.
Author Jose Vicente Nunez (kodegeek.com@protonmail.com)
"""
import pprint
import unittest

from home_nmap.system import HostIface

DEBUG = True


class TestSysten(unittest.TestCase):
    """
    Unit tests for HostIface
    """

    def setUp(self) -> None:
        self.hostiface = HostIface()

    def test_iface_details(self):
        (lo_ip, lo_net) = self.hostiface.get_iface_details('lo')
        self.assertIsNotNone(lo_ip)
        self.assertEqual(lo_ip, '127.0.0.1')
        self.assertEqual(lo_net, '255.0.0.0')
        if DEBUG:
            print(f"lo ip={lo_ip}")
            print(f"lo net={lo_net}")

    def test_get_details_all_interfaces(self):
        all_ifaces = self.hostiface.get_details_all_interfaces(skip_loopback=False, refresh=True)
        self.assertIsNotNone(all_ifaces)
        for iface, ip, netmask in all_ifaces:
            self.assertIsNotNone(iface)
            self.assertIsNotNone(ip)
            self.assertIsNotNone(netmask)
            if DEBUG:
                print(f"iface={iface}, ip={ip}, netmask={netmask}")

    def test_get_alive_interfaces(self):
        interfaces = self.hostiface.get_alive_interfaces(skip_loopback=False, refresh=True)
        self.assertIsNotNone(interfaces)
        self.assertIn('lo', interfaces)
        if DEBUG:
            pprint.pprint(interfaces)

    def test_get_local_networks(self):
        local_networks = self.hostiface.get_local_networks()
        self.assertIsNotNone(local_networks)
        self.assertTrue(local_networks, "Empty list of local networks received!")
        if DEBUG:
            pprint.pprint(local_networks)

    def test_get_prefixed_local_networks(self):
        local_networks = self.hostiface.get_prefixed_local_networks()
        self.assertIsNotNone(local_networks)
        self.assertTrue(local_networks, "Empty list of local networks received!")
        if DEBUG:
            pprint.pprint(local_networks)


if __name__ == '__main__':
    unittest.main()
