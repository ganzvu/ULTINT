"""Tests for src/api/auth.py — SessionManager (mocked filesystem/pickle)."""
import os
import pickle
import pytest
from unittest.mock import MagicMock, patch, mock_open
from src.api.auth import SessionManager
from src.core.exceptions import AuthenticationError


# Must be at module level so pickle can serialise it
class _FakeCookie:
    name = "sessionid"
    value = "tok123"
    domain = ".instagram.com"
    path = "/"


class TestGetSessionFile:
    def test_returns_path_when_local_session_exists(self):
        with patch("os.path.exists", side_effect=lambda p: "session-alice" in p):
            result = SessionManager.get_session_file("alice")
        assert result is not None
        assert "alice" in result

    def test_returns_none_when_no_session_exists(self):
        with patch("os.path.exists", return_value=False):
            result = SessionManager.get_session_file("alice")
        assert result is None

    def test_checks_multiple_candidate_paths(self):
        calls = []
        def spy(path):
            calls.append(path)
            return False
        with patch("os.path.exists", side_effect=spy):
            SessionManager.get_session_file("alice")
        assert len(calls) >= 2


class TestDeleteSession:
    def test_deletes_existing_session(self):
        with patch.object(SessionManager, "get_session_file", return_value="/tmp/session-alice"), \
             patch("os.remove") as mock_remove:
            SessionManager.delete_session("alice")
        mock_remove.assert_called_once_with("/tmp/session-alice")

    def test_no_error_when_session_not_found(self):
        with patch.object(SessionManager, "get_session_file", return_value=None):
            SessionManager.delete_session("nonexistent")  # should not raise

    def test_os_error_silently_ignored(self):
        with patch.object(SessionManager, "get_session_file", return_value="/tmp/session-alice"), \
             patch("os.remove", side_effect=OSError("permission denied")):
            SessionManager.delete_session("alice")  # should not raise


class TestLoadCookies:
    def test_no_session_file_raises_auth_error(self):
        with patch.object(SessionManager, "get_session_file", return_value=None):
            with pytest.raises(AuthenticationError, match="No saved session"):
                SessionManager.load_cookies("alice")

    def test_loads_modern_dict_format(self):
        cookie_dict = {"sessionid": "abc123", "csrftoken": "xyz"}
        pickled = pickle.dumps(cookie_dict)
        with patch.object(SessionManager, "get_session_file", return_value="/tmp/session-alice"), \
             patch("builtins.open", mock_open(read_data=pickled)):
            cookies = SessionManager.load_cookies("alice")
        assert isinstance(cookies, list)
        names = [c["name"] for c in cookies]
        assert "sessionid" in names
        assert "csrftoken" in names

    def test_cookie_domain_hardcoded_to_instagram(self):
        cookie_dict = {"sessionid": "abc123"}
        pickled = pickle.dumps(cookie_dict)
        with patch.object(SessionManager, "get_session_file", return_value="/tmp/session-alice"), \
             patch("builtins.open", mock_open(read_data=pickled)):
            cookies = SessionManager.load_cookies("alice")
        for c in cookies:
            assert c["domain"] == ".instagram.com"
            assert c["path"] == "/"

    def test_cookie_values_are_strings(self):
        cookie_dict = {"uid": 12345}  # integer value
        pickled = pickle.dumps(cookie_dict)
        with patch.object(SessionManager, "get_session_file", return_value="/tmp/session-alice"), \
             patch("builtins.open", mock_open(read_data=pickled)):
            cookies = SessionManager.load_cookies("alice")
        for c in cookies:
            assert isinstance(c["value"], str)

    def test_corrupt_file_raises_auth_error(self):
        with patch.object(SessionManager, "get_session_file", return_value="/tmp/session-alice"), \
             patch("builtins.open", mock_open(read_data=b"not valid pickle data")):
            with pytest.raises(AuthenticationError, match="Failed to parse"):
                SessionManager.load_cookies("alice")

    def test_unexpected_structure_raises_auth_error(self):
        """If pickle returns neither dict nor expected tuple, raises AuthenticationError."""
        pickled = pickle.dumps("just a string")
        with patch.object(SessionManager, "get_session_file", return_value="/tmp/session-alice"), \
             patch("builtins.open", mock_open(read_data=pickled)):
            with pytest.raises(AuthenticationError):
                SessionManager.load_cookies("alice")

    def test_loads_legacy_tuple_format(self):
        """Test the fallback path for older instaloader tuple format."""
        cookie_jar = [_FakeCookie()]
        legacy_tuple = ("version", "ua", cookie_jar)
        pickled = pickle.dumps(legacy_tuple)

        with patch.object(SessionManager, "get_session_file", return_value="/tmp/session-alice"), \
             patch("builtins.open", mock_open(read_data=pickled)):
            cookies = SessionManager.load_cookies("alice")
        names = [c["name"] for c in cookies]
        assert "sessionid" in names
