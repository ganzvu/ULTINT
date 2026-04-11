"""Tests for core/forensics.py — handle_command with mocked subprocess."""
import pytest
from unittest.mock import MagicMock, patch
import subprocess
import core.forensics as forensics


def _console():
    c = MagicMock()
    c.status = MagicMock(return_value=MagicMock(__enter__=lambda s, *a: s, __exit__=MagicMock(return_value=False)))
    return c


class TestForensicsHandleCommand:
    # ------------------------------------------------------------------
    # Argument validation
    # ------------------------------------------------------------------

    def test_no_args_prints_warning(self):
        c = _console()
        forensics.handle_command("", c)
        c.print.assert_called_once()

    def test_missing_file_arg_prints_error(self):
        c = _console()
        forensics.handle_command("exif", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "file" in msg.lower() or "provide" in msg.lower()

    def test_unknown_subcommand_prints_error(self):
        c = _console()
        forensics.handle_command("unknown /tmp/file.bin", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "unknown" in msg.lower() or "Unknown" in msg

    # ------------------------------------------------------------------
    # exif subcommand
    # ------------------------------------------------------------------

    def test_exif_success(self):
        c = _console()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "ExifTool Version Number: 12.0\nFile Type: JPEG\n"
        with patch("subprocess.run", return_value=mock_result):
            forensics.handle_command("exif /tmp/photo.jpg", c)
        c.print.assert_called_once()

    def test_exif_non_zero_returncode(self):
        c = _console()
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Error: File not found"
        with patch("subprocess.run", return_value=mock_result):
            forensics.handle_command("exif /tmp/missing.jpg", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "error" in msg.lower() or "Error" in msg

    def test_exif_tool_not_found(self):
        c = _console()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            forensics.handle_command("exif /tmp/photo.jpg", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "exiftool" in msg.lower() or "not found" in msg.lower()

    def test_exif_generic_exception_handled(self):
        c = _console()
        with patch("subprocess.run", side_effect=Exception("timeout")):
            forensics.handle_command("exif /tmp/photo.jpg", c)
        c.print.assert_called_once()

    # ------------------------------------------------------------------
    # strings subcommand
    # ------------------------------------------------------------------

    def test_strings_success(self):
        c = _console()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "\n".join([f"string{i}" for i in range(25)])
        with patch("subprocess.run", return_value=mock_result):
            forensics.handle_command("strings /tmp/binary", c)
        c.print.assert_called_once()

    def test_strings_non_zero_returncode(self):
        c = _console()
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "binary: permission denied"
        with patch("subprocess.run", return_value=mock_result):
            forensics.handle_command("strings /tmp/binary", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "error" in msg.lower() or "Error" in msg

    def test_strings_tool_not_found(self):
        c = _console()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            forensics.handle_command("strings /tmp/binary", c)
        c.print.assert_called_once()
        msg = c.print.call_args[0][0]
        assert "strings" in msg.lower() or "not found" in msg.lower()

    def test_strings_generic_exception_handled(self):
        c = _console()
        with patch("subprocess.run", side_effect=Exception("boom")):
            forensics.handle_command("strings /tmp/binary", c)
        c.print.assert_called_once()

    def test_strings_output_capped_at_20_lines(self):
        """The panel should show only first 20 lines."""
        c = _console()
        mock_result = MagicMock()
        mock_result.returncode = 0
        # Provide 30 lines
        lines = [f"line{i}" for i in range(30)]
        mock_result.stdout = "\n".join(lines)
        with patch("subprocess.run", return_value=mock_result):
            forensics.handle_command("strings /tmp/binary", c)
        # Panel content should mention "more lines"
        panel_content = str(c.print.call_args)
        assert "more" in panel_content.lower() or c.print.called

    # ------------------------------------------------------------------
    # File path with spaces
    # ------------------------------------------------------------------

    def test_file_path_with_spaces(self):
        c = _console()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Key: Value\n"
        with patch("subprocess.run", return_value=mock_result):
            forensics.handle_command("exif /tmp/my file with spaces.jpg", c)
        c.print.assert_called_once()
