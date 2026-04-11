"""Tests for core/social.py — check_site logic and handle_command with mocked HTTP."""
import asyncio
import pytest
import pytest_asyncio
from unittest.mock import MagicMock, patch, AsyncMock
import core.social as social


# ---------------------------------------------------------------------------
# check_site — async helper
# ---------------------------------------------------------------------------

def _make_site_info(
    url="https://example.com/{}",
    error_type="status_code",
    error_msgs=None,
    error_url=None,
    url_probe=None,
    method="GET",
    request_payload=None,
    headers=None,
):
    info = {
        "url": url,
        "errorType": error_type,
    }
    if error_msgs:
        info["errorMsg"] = error_msgs
    if error_url:
        info["errorUrl"] = error_url
    if url_probe:
        info["urlProbe"] = url_probe
    if method != "GET":
        info["request_method"] = method
    if request_payload:
        info["request_payload"] = request_payload
    if headers:
        info["headers"] = headers
    return info


def _make_httpx_response(status_code=200, text="<html>User Profile</html>", url=None):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.url = url or "https://example.com/testuser"
    return r


class TestCheckSite:
    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_status_code_found(self):
        client = MagicMock()
        client.get = AsyncMock(return_value=_make_httpx_response(200, "User Profile Page"))
        site_info = _make_site_info(error_type="status_code")
        result = self._run(social.check_site(client, "TestSite", site_info, "testuser"))
        assert result is not None
        assert result[0] == "TestSite"
        assert "Found" in result[2]

    def test_status_code_404_returns_none(self):
        client = MagicMock()
        client.get = AsyncMock(return_value=_make_httpx_response(404))
        site_info = _make_site_info(error_type="status_code")
        result = self._run(social.check_site(client, "TestSite", site_info, "testuser"))
        assert result is None

    def test_soft_404_returns_none(self):
        client = MagicMock()
        # Response is 200 but content says "Page not found"
        client.get = AsyncMock(return_value=_make_httpx_response(200, "<html>Page not found</html>"))
        site_info = _make_site_info(error_type="status_code")
        result = self._run(social.check_site(client, "TestSite", site_info, "testuser"))
        assert result is None

    def test_cloudflare_captcha_returns_none(self):
        client = MagicMock()
        client.get = AsyncMock(return_value=_make_httpx_response(200, "Attention Required! Cloudflare"))
        site_info = _make_site_info(error_type="status_code")
        result = self._run(social.check_site(client, "TestSite", site_info, "testuser"))
        assert result is None

    def test_message_error_type_found_when_no_error_msg(self):
        client = MagicMock()
        client.get = AsyncMock(return_value=_make_httpx_response(200, "User Profile Page"))
        site_info = _make_site_info(error_type="message", error_msgs=["User not found"])
        result = self._run(social.check_site(client, "TestSite", site_info, "testuser"))
        assert result is not None

    def test_message_error_type_not_found_when_error_msg_present(self):
        client = MagicMock()
        client.get = AsyncMock(return_value=_make_httpx_response(200, "User not found on this platform"))
        site_info = _make_site_info(error_type="message", error_msgs=["User not found"])
        result = self._run(social.check_site(client, "TestSite", site_info, "testuser"))
        assert result is None

    def test_empty_url_returns_none(self):
        client = MagicMock()
        client.get = AsyncMock(return_value=_make_httpx_response(200))
        site_info = {"url": "", "errorType": "status_code"}
        result = self._run(social.check_site(client, "EmptySite", site_info, "testuser"))
        assert result is None

    def test_exception_returns_none(self):
        client = MagicMock()
        client.get = AsyncMock(side_effect=Exception("network error"))
        site_info = _make_site_info(error_type="status_code")
        result = self._run(social.check_site(client, "TestSite", site_info, "testuser"))
        assert result is None

    def test_response_url_error_type_found(self):
        client = MagicMock()
        r = _make_httpx_response(200, "User Profile")
        r.url = "https://example.com/testuser"
        client.get = AsyncMock(return_value=r)
        site_info = _make_site_info(
            error_type="response_url",
            error_url="https://example.com/notfound",
        )
        result = self._run(social.check_site(client, "TestSite", site_info, "testuser"))
        assert result is not None

    def test_response_url_error_type_redirected_to_error_url(self):
        client = MagicMock()
        r = _make_httpx_response(200, "Not Found Page")
        r.url = "https://example.com/notfound/testuser"
        client.get = AsyncMock(return_value=r)
        site_info = _make_site_info(
            error_type="response_url",
            error_url="https://example.com/notfound",
        )
        result = self._run(social.check_site(client, "TestSite", site_info, "testuser"))
        assert result is None

    def test_post_method_used_correctly(self):
        client = MagicMock()
        client.post = AsyncMock(return_value=_make_httpx_response(200, "Registered User"))
        site_info = _make_site_info(error_type="status_code", method="POST")
        result = self._run(social.check_site(client, "TestSite", site_info, "testuser"))
        assert client.post.called

    def test_error_msg_as_string_normalised_to_list(self):
        """error_msgs as a bare string should still work (normalised to list internally)."""
        client = MagicMock()
        client.get = AsyncMock(return_value=_make_httpx_response(200, "User Profile Page"))
        site_info = _make_site_info(error_type="message")
        # Set errorMsg as a plain string, not a list
        site_info["errorMsg"] = "User not found"
        result = self._run(social.check_site(client, "TestSite", site_info, "testuser"))
        # "User not found" NOT in the page text → Found
        assert result is not None


# ---------------------------------------------------------------------------
# handle_command
# ---------------------------------------------------------------------------

class TestSocialHandleCommand:
    def _console(self):
        c = MagicMock()
        return c

    def test_no_args_prints_usage(self):
        c = self._console()
        social.handle_command("", c)
        c.print.assert_called_once()

    def test_missing_target_prints_error(self):
        c = self._console()
        social.handle_command("username", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "target" in msg.lower() or "provide" in msg.lower()

    def test_unknown_subcommand_prints_error(self):
        c = self._console()
        social.handle_command("twitter alice", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "unknown" in msg.lower() or "Unknown" in msg

    def test_username_subcommand_runs_sherlock(self):
        c = self._console()
        with patch("core.social.asyncio.run") as mock_run:
            social.handle_command("username alice", c)
        mock_run.assert_called_once()

    def test_email_subcommand_runs_holehe(self):
        c = self._console()
        with patch("core.social.asyncio.run") as mock_run:
            social.handle_command("email alice@example.com", c)
        mock_run.assert_called_once()

    def test_keyboard_interrupt_handled_for_username(self):
        c = self._console()
        with patch("core.social.asyncio.run", side_effect=KeyboardInterrupt):
            social.handle_command("username alice", c)
        c.print.assert_called()

    def test_keyboard_interrupt_handled_for_email(self):
        c = self._console()
        with patch("core.social.asyncio.run", side_effect=KeyboardInterrupt):
            social.handle_command("email test@example.com", c)
        c.print.assert_called()
