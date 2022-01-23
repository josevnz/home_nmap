import os.path
import pprint
import unittest
from pathlib import Path

from home_nmap.system import NMapRunner
from home_nmap.query import OutputParser

DEBUG = True


class NMapRunnerTest(unittest.TestCase):

    def test_scan(self):
        sc = NMapRunner()
        self.assertIsNotNone(sc)
        args, xml_data, stderr = sc.scan(hosts="127.0.0.1")
        self.assertIsNotNone(args)
        self.assertIsNotNone(xml_data)
        if DEBUG:
            pprint.pprint(xml_data)


class OutputParserTest(unittest.TestCase):

    def setUp(self) -> None:
        self.xml_data_file = os.path.join(str(Path(__file__).parent), "linux_host_scan.xml")

    def test_parse_nmap_xml(self):
        with open(self.xml_data_file, 'r') as xml:
            xml_data = xml.read()
        runargs, parsed_xml = OutputParser.parse_nmap_xml(xml_data)
        self.assertIsNotNone(runargs)
        self.assertIsNotNone(parsed_xml)
        for row_data in parsed_xml:
            self.assertIn('address', row_data)
            address = row_data['address']
            self.assertIsNotNone(address)
            self.assertIn('ports', row_data)
            ports = row_data['ports']
            for port_data in ports:
                self.assertIn('protocol', port_data)
                self.assertIn('port_id', port_data)
                self.assertIn('cpes', port_data)
                self.assertIn('service_name', port_data)
                self.assertIn('service_product', port_data)
                self.assertIn('service_version', port_data)


if __name__ == '__main__':
    unittest.main()
