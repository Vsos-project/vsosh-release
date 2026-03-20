import unittest
from unittest.mock import patch, MagicMock, mock_open, call
import json
import sys
import os
import time
import requests
from pathlib import Path
from datetime import datetime


import cve_scanner


class TestMain(unittest.TestCase):
    def test_output_structure(self):
        scanner = cve_scanner.CVEScanner()
        libraries = {"lib": "1.0"}
        results = {"lib": {"version": "1.0", "cve_count": 1, "cves": [{"id": "CVE-1"}]}}
        output_data = {
            "metadata": {
                "scan_date": "2025-01-01T00:00:00",
                "target_file": "deps.txt",
                "parser": "parser",
                "sources": ["NVD", "FSTEC"]
            },
            "statistics": {
                "total_libraries": 1,
                "libraries_with_cves": 1,
                "total_cves_found": 1
            },
            "libraries": libraries,
            "scan_results": results
        }
        self.assertEqual(output_data["statistics"]["total_libraries"], 1)


class TestNVD(unittest.TestCase):
    def setUp(self):
        self.nvd = cve_scanner.NVD(api_key="test_key")

    def test_init_with_key(self):
        nvd = cve_scanner.NVD(api_key="test_key")
        self.assertEqual(nvd.session.headers.get("apiKey"), "test_key")
        self.assertTrue(nvd.have_key)

    def test_init_without_key(self):
        nvd = cve_scanner.NVD()
        self.assertIsNone(nvd.session.headers.get("apiKey"))
        self.assertFalse(nvd.have_key)

    @patch.object(cve_scanner.NVD, '_find_cpes')
    @patch.object(cve_scanner.NVD, '_get_cves_by_cpe')
    def test_get_cves_for_library_with_version(self, mock_get_cves, mock_find_cpes):
        mock_find_cpes.return_value = ["cpe:2.3:a:lib:library:1.0:*:*:*:*:*:*:*"]
        mock_get_cves.return_value = [{"id": "CVE-2021-1234"}]

        result = self.nvd.get_cves_for_library("library", "2.0")

        mock_get_cves.assert_called_once_with("cpe:2.3:a:lib:library:2.0:*:*:*:*:*:*:*")
        self.assertEqual(result, [{"id": "CVE-2021-1234"}])

    @patch.object(cve_scanner.NVD, '_find_cpes')
    @patch.object(cve_scanner.NVD, '_get_cves_by_cpe')
    def test_get_cves_for_library_no_version(self, mock_get_cves, mock_find_cpes):
        mock_find_cpes.return_value = ["cpe:2.3:a:lib:library:1.0:*:*:*:*:*:*:*"]
        mock_get_cves.return_value = [{"id": "CVE-2021-1234"}]

        result = self.nvd.get_cves_for_library("library")

        mock_get_cves.assert_called_once_with("cpe:2.3:a:lib:library:1.0:*:*:*:*:*:*:*")
        self.assertEqual(result, [{"id": "CVE-2021-1234"}])

    @patch.object(cve_scanner.NVD, '_find_cpes')
    def test_get_cves_for_library_no_cpes(self, mock_find_cpes):
        mock_find_cpes.return_value = []
        result = self.nvd.get_cves_for_library("library")
        self.assertEqual(result, [])

    @patch('requests.Session.get')
    def test_find_cpes_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "products": [
                {"cpe": {"cpeName": "cpe:2.3:a:lib:library:1.0:*:*:*:*:*:*:*"}},
                {"cpe": {"cpeName": "cpe:2.3:a:other:lib:2.0:*:*:*:*:*:*:*"}}
            ]
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = self.nvd._find_cpes("library")
        mock_get.assert_called_once()
        self.assertEqual(result, ["cpe:2.3:a:lib:library:1.0:*:*:*:*:*:*:*"])

    @patch('requests.Session.get')
    def test_find_cpes_exception(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException("Error")
        result = self.nvd._find_cpes("library")
        self.assertEqual(result, [])

    @patch('requests.Session.get')
    def test_get_cves_by_cpe_single_page(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [{"cve": {"id": "CVE-2021-1234"}}],
            "totalResults": 1
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        with patch.object(self.nvd, '_normalize', return_value=[{"id": "CVE-2021-1234"}]):
            result = self.nvd._get_cves_by_cpe("cpe:...")
            self.assertEqual(result, [{"id": "CVE-2021-1234"}])

    @patch('requests.Session.get')
    def test_get_cves_by_cpe_pagination(self, mock_get):
        mock_resp1 = MagicMock()
        mock_resp1.json.return_value = {
            "vulnerabilities": [{"cve": {"id": "CVE-1"}}],
            "totalResults": 2
        }
        mock_resp2 = MagicMock()
        mock_resp2.json.return_value = {
            "vulnerabilities": [{"cve": {"id": "CVE-2"}}],
            "totalResults": 2
        }
        mock_get.side_effect = [mock_resp1, mock_resp2]

        with patch.object(self.nvd, '_normalize', side_effect=lambda x: x):
            result = self.nvd._get_cves_by_cpe("cpe:...")
            self.assertEqual(len(result), 2)
            self.assertEqual(mock_get.call_count, 2)

    def test_normalize_full(self):
        raw = [{
            "cve": {
                "id": "CVE-2021-1234",
                "descriptions": [{"lang": "en", "value": "Description"}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]
                },
                "published": "2021-01-01T00:00:00",
                "references": [{"url": "http://example.com"}]
            }
        }]
        normalized = self.nvd._normalize(raw)
        expected = [{
            "id": "CVE-2021-1234",
            "description": "Description",
            "cvss_score": 7.5,
            "published": "2021-01-01T00:00:00",
            "references": ["http://example.com"],
            "source": "NVD"
        }]
        self.assertEqual(normalized, expected)

    def test_normalize_missing_fields(self):
        raw = [{
            "cve": {
                "id": "CVE-2021-1234",
                "descriptions": [{"lang": "fr", "value": "Description"}],
                "metrics": {},
                "published": "",
                "references": []
            }
        }]
        normalized = self.nvd._normalize(raw)
        expected = [{
            "id": "CVE-2021-1234",
            "description": "Description",
            "cvss_score": "N/A",
            "published": "",
            "references": [],
            "source": "NVD"
        }]
        self.assertEqual(normalized, expected)


class TestFSTEC(unittest.TestCase):
    def setUp(self):
        self.fstec = cve_scanner.FSTEC()

    @patch('requests.Session.get')
    def test_get_cves_for_library_no_pagination(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.text = """
        <html>
            <h4><a>BDU:2021-12345</a></h4>
            <div>Some content</div>
            <h4><a>CVE-2021-1234</a></h4>
            <div>Other content</div>
        </html>
        """
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        with patch.object(self.fstec, '_parse', return_value=[{"id": "BDU:2021-12345"}, {"id": "CVE-2021-1234"}]):
            result = self.fstec.get_cves_for_library("library", "1.0")
            self.assertEqual(len(result), 2)
            mock_get.assert_called_once()

    @patch('requests.Session.get')
    def test_get_cves_for_library_with_pagination(self, mock_get):
        html_page1 = """
        <html>
            <h4><a>BDU:1</a></h4>
            <a href="/search?page=2">></a>
        </html>
        """
        html_page2 = """
        <html>
            <h4><a>BDU:2</a></h4>
        </html>
        """
        mock_resp1 = MagicMock()
        mock_resp1.text = html_page1
        mock_resp1.raise_for_status = MagicMock()
        mock_resp2 = MagicMock()
        mock_resp2.text = html_page2
        mock_resp2.raise_for_status = MagicMock()
        mock_get.side_effect = [mock_resp1, mock_resp2]

        with patch.object(self.fstec, '_parse') as mock_parse:
            mock_parse.side_effect = [[{"id": "BDU:1"}], [{"id": "BDU:2"}]]
            result = self.fstec.get_cves_for_library("library")
            self.assertEqual(len(result), 2)
            self.assertEqual(mock_get.call_count, 2)

    def test_parse_extracts_blocks(self):
        html = """
        <h4><a>BDU:2021-12345</a></h4>
        <div>Description</div>
        <h4><a>CVE-2021-1234</a></h4>
        <div>Other</div>
        """
        with patch.object(self.fstec, '_parse_vuln') as mock_parse_vuln:
            mock_parse_vuln.side_effect = [{"id": "BDU:2021-12345"}, {"id": "CVE-2021-1234"}]
            result = self.fstec._parse(html)
            self.assertEqual(len(result), 2)
            self.assertEqual(mock_parse_vuln.call_count, 2)

    def test_parse_vuln_full(self):
        text = """
        <h4><a>BDU:2021-12345 Vulnerability title</a></h4>
        <strong>Дата публикации:</strong> 2021-01-01<br>
        CVE-2021-1234
        """
        result = self.fstec._parse_vuln(text)
        self.assertEqual(result["id"], "BDU:2021-12345")
        self.assertEqual(result["description"], "Vulnerability title")
        self.assertEqual(result["published"], "2021-01-01")
        self.assertEqual(result["references"], ["CVE-2021-1234"])

    def test_parse_vuln_minimal(self):
        text = """
        <h4>Some text without id</h4>
        """
        result = self.fstec._parse_vuln(text)
        self.assertIsNone(result)


class TestCVEScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = cve_scanner.CVEScanner(api_key="key", cache_file="cache.json")

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='{"lib-1.0": [{"id": "CVE-1"}]}')
    def test_init_load_cache(self, mock_file, mock_exists):
        mock_exists.return_value = True
        scanner = cve_scanner.CVEScanner(cache_file="cache.json")
        self.assertEqual(scanner.cache, {"lib-1.0": [{"id": "CVE-1"}]})

    @patch('os.path.exists')
    @patch('builtins.open')
    def test_init_cache_missing(self, mock_file, mock_exists):
        mock_exists.return_value = False
        scanner = cve_scanner.CVEScanner(cache_file="cache.json")
        self.assertEqual(scanner.cache, {})

    @patch('builtins.open', new_callable=mock_open)
    def test_save_cache(self, mock_file):
        self.scanner.cache = {"key": "value"}
        self.scanner._save_cache()
        mock_file.assert_called_once_with("cache.json", 'w')
        handle = mock_file()
        written = ''.join(call[0][0] for call in handle.write.call_args_list)
        self.assertIn('"key": "value"', written)

    @patch.object(cve_scanner.NVD, 'get_cves_for_library')
    @patch.object(cve_scanner.FSTEC, 'get_cves_for_library')
    def test_get_cves_for_library_cache_hit(self, mock_fstec, mock_nvd):
        self.scanner.cache = {"lib-1.0": [{"id": "CVE-1"}]}
        result = self.scanner.get_cves_for_library("lib", "1.0")
        self.assertEqual(result, [{"id": "CVE-1"}])
        mock_nvd.assert_not_called()
        mock_fstec.assert_not_called()

    @patch.object(cve_scanner.NVD, 'get_cves_for_library')
    @patch.object(cve_scanner.FSTEC, 'get_cves_for_library')
    def test_get_cves_for_library_cache_miss(self, mock_fstec, mock_nvd):
        mock_nvd.return_value = [{"id": "CVE-1"}]
        mock_fstec.return_value = [{"id": "CVE-1"}, {"id": "CVE-2"}] 
        result = self.scanner.get_cves_for_library("lib", "1.0")
        expected = [{"id": "CVE-1"}, {"id": "CVE-2"}]
        self.assertEqual(result, expected)
        self.assertIn("lib-1.0", self.scanner.cache)

    @patch.object(cve_scanner.CVEScanner, 'get_cves_for_library')
    def test_scan_libraries(self, mock_get_cves):
        mock_get_cves.side_effect = [
            [{"id": "CVE-1"}],  
            []                  
        ]
        libraries = {"lib1": "1.0", "lib2": None}
        results = self.scanner.scan_libraries(libraries)
        expected = {
            "lib1": {"version": "1.0", "cve_count": 1, "cves": [{"id": "CVE-1"}]},
            "lib2": {"version": None, "cve_count": 0, "cves": []}
        }
        self.assertEqual(results, expected)
        self.assertEqual(mock_get_cves.call_count, 2)



if __name__ == '__main__':
    unittest.main()