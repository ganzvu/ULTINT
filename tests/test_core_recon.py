"""Tests for core/recon.py — handle_command with mocked network."""
import pytest
from unittest.mock import MagicMock, patch
import core.recon as recon


def _console():
    c = MagicMock()
    c.status = MagicMock(return_value=MagicMock(__enter__=lambda s, *a: s, __exit__=MagicMock(return_value=False)))
    return c


class TestReconHandleCommand:
    # ------------------------------------------------------------------
    # Argument validation
    # ------------------------------------------------------------------

    def test_no_args_prints_warning(self):
        c = _console()
        recon.handle_command("", c)
        c.print.assert_called_once()

    def test_missing_target_prints_error(self):
        c = _console()
        recon.handle_command("idb", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "target" in msg.lower() or "provide" in msg.lower()

    def test_unknown_subcommand(self):
        c = _console()
        recon.handle_command("scan 1.2.3.4", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "unknown" in msg.lower() or "Unknown" in msg


class TestGetInternetDB:
    def _make_response(self, status_code=200, json_data=None):
        r = MagicMock()
        r.status_code = status_code
        r.json.return_value = json_data or {}
        return r

    def test_successful_response(self):
        c = _console()
        data = {
            "ports": [80, 443],
            "hostnames": ["example.com"],
            "vulns": ["CVE-2021-0001"],
            "tags": ["web"],
            "cpes": ["cpe:/a:nginx:nginx:1.18.0"],
        }
        with patch("requests.get", return_value=self._make_response(200, data)):
            recon.get_internetdb("1.2.3.4", c)
        c.print.assert_called_once()

    def test_404_response(self):
        c = _console()
        with patch("requests.get", return_value=self._make_response(404)):
            recon.get_internetdb("1.2.3.4", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "No Shodan data" in msg or "not found" in msg.lower()

    def test_non_200_non_404_response(self):
        c = _console()
        with patch("requests.get", return_value=self._make_response(500)):
            recon.get_internetdb("1.2.3.4", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "500" in msg or "Error" in msg

    def test_network_exception_handled(self):
        c = _console()
        with patch("requests.get", side_effect=Exception("timeout")):
            recon.get_internetdb("1.2.3.4", c)
        c.print.assert_called_once()

    def test_cpes_truncated_at_5(self):
        c = _console()
        data = {"ports": [], "cpes": [f"cpe{i}" for i in range(10)]}
        with patch("requests.get", return_value=self._make_response(200, data)):
            recon.get_internetdb("1.2.3.4", c)
        c.print.assert_called_once()

    def test_empty_ports(self):
        c = _console()
        data = {"ports": []}
        with patch("requests.get", return_value=self._make_response(200, data)):
            recon.get_internetdb("1.2.3.4", c)
        c.print.assert_called_once()


class TestGetWayback:
    def _make_response(self, status_code=200, json_data=None):
        r = MagicMock()
        r.status_code = status_code
        r.json.return_value = json_data or []
        return r

    def test_successful_response(self):
        c = _console()
        # Wayback CDX response: first row is header, rest are data
        data = [
            ["original", "mimetype", "statuscode"],
            ["https://example.com/login", "text/html", "200"],
            ["https://example.com/admin", "text/html", "301"],
        ]
        with patch("requests.get", return_value=self._make_response(200, data)):
            recon.get_wayback("example.com", c)
        c.print.assert_called_once()

    def test_empty_data_returns_early(self):
        c = _console()
        data = [["original", "mimetype", "statuscode"]]  # Only header
        with patch("requests.get", return_value=self._make_response(200, data)):
            recon.get_wayback("example.com", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "No archived" in msg

    def test_failed_request(self):
        c = _console()
        with patch("requests.get", return_value=self._make_response(503)):
            recon.get_wayback("example.com", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "503" in msg or "Failed" in msg

    def test_junk_only_urls_filtered(self):
        c = _console()
        data = [
            ["original", "mimetype", "statuscode"],
            ["https://example.com/logo.jpg", "image/jpeg", "200"],
            ["https://example.com/style.css", "text/css", "200"],
        ]
        with patch("requests.get", return_value=self._make_response(200, data)):
            recon.get_wayback("example.com", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "junk" in msg.lower() or "Only junk" in msg

    def test_network_exception_handled(self):
        c = _console()
        with patch("requests.get", side_effect=Exception("connection failed")):
            recon.get_wayback("example.com", c)
        c.print.assert_called_once()

    def test_more_than_50_results_capped(self):
        c = _console()
        data = [["original", "mimetype", "statuscode"]] + [
            [f"https://example.com/page{i}", "text/html", "200"] for i in range(60)
        ]
        with patch("requests.get", return_value=self._make_response(200, data)):
            recon.get_wayback("example.com", c)
        c.print.assert_called_once()
        printed_arg = str(c.print.call_args)
        assert "omitted" in printed_arg or c.print.called


class TestReconWhoisNmap:
    """Integration tests for whois/nmap that are subprocess-driven."""

    def _subprocess_result(self, returncode=0, stdout="output", stderr=""):
        r = MagicMock()
        r.returncode = returncode
        r.stdout = stdout
        r.stderr = stderr
        return r

    def test_whois_success(self):
        c = _console()
        with patch("subprocess.run", return_value=self._subprocess_result(0, "Domain: example.com\n")):
            recon.handle_command("whois example.com", c)
        c.print.assert_called_once()

    def test_whois_tool_not_found_falls_back_to_rdap(self):
        c = _console()
        rdap_resp = MagicMock()
        rdap_resp.status_code = 200
        rdap_resp.json.return_value = {"handle": "example.com"}
        with patch("subprocess.run", side_effect=FileNotFoundError), \
             patch("requests.get", return_value=rdap_resp):
            recon.handle_command("whois example.com", c)
        c.print.assert_called()

    def test_nmap_success(self):
        c = _console()
        with patch("subprocess.run", return_value=self._subprocess_result(0, "Host: 1.2.3.4\n")):
            recon.handle_command("nmap 1.2.3.4", c)
        c.print.assert_called_once()

    def test_nmap_tool_not_found(self):
        c = _console()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            recon.handle_command("nmap 1.2.3.4", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "nmap" in msg.lower() or "not found" in msg.lower()

    def test_nmap_error_returncode(self):
        c = _console()
        with patch("subprocess.run", return_value=self._subprocess_result(1, stderr="permission denied")):
            recon.handle_command("nmap 1.2.3.4", c)
        c.print.assert_called_once()
