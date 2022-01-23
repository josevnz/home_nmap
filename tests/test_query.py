import os
import unittest
from pathlib import Path

from home_nmap.query import NDISHtml


class NDISHtmlTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self.ndishtml = NDISHtml()

    def test_get(self):
        raw_html = self.ndishtml.get('cpe:/a:openbsd:openssh:8.0')
        self.assertIsNotNone(raw_html)

    def test_parse(self):
        html_data_file = os.path.join(str(Path(__file__).parent), "NVD - Results.html")
        with open(html_data_file, 'r') as html_data:
            html = html_data.read()
        ndis_list = self.ndishtml.parse(html)
        self.assertIsNotNone(ndis_list)
        for ndis in ndis_list:
            self.assertTrue(ndis.summary)
            self.assertTrue(ndis.score)
            self.assertTrue(ndis.link)


if __name__ == '__main__':
    unittest.main()
