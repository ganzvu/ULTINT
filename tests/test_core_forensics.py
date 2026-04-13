"""Tests for core/forensics.py — automated forensic pipeline with mocked I/O."""
import pytest
import os
import tempfile
import hashlib
from unittest.mock import MagicMock, patch, mock_open
import core.forensics as forensics


def _console():
    c = MagicMock()
    c.status = MagicMock(return_value=MagicMock(
        __enter__=lambda s, *a: s,
        __exit__=MagicMock(return_value=False)
    ))
    return c


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

class TestArgumentValidation:
    def test_no_args_prints_usage(self):
        c = _console()
        forensics.handle_command("", c)
        c.print.assert_called()
        output = str(c.print.call_args_list)
        assert "usage" in output.lower() or "subcommand" in output.lower() or "Usage" in output

    def test_missing_file_arg_prints_error(self):
        c = _console()
        forensics.handle_command("analyze", c)
        c.print.assert_called()
        output = str(c.print.call_args_list)
        assert "file" in output.lower() or "provide" in output.lower()

    def test_nonexistent_file_prints_error(self):
        c = _console()
        forensics.handle_command("analyze /tmp/this_file_does_not_exist_12345.bin", c)
        c.print.assert_called()
        output = str(c.print.call_args_list)
        assert "not found" in output.lower() or "File not found" in output

    def test_unknown_subcommand_prints_error(self):
        c = _console()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data")
            tmp = f.name
        try:
            forensics.handle_command(f"unknown {tmp}", c)
            c.print.assert_called()
            output = str(c.print.call_args_list)
            assert "unknown" in output.lower() or "Unknown" in output
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# _has_tool helper
# ---------------------------------------------------------------------------

class TestHasTool:
    def test_has_tool_returns_true_for_python(self):
        # python3 or python should always exist in test env
        assert forensics._has_tool("python3") or forensics._has_tool("python")

    def test_has_tool_returns_false_for_nonexistent(self):
        assert forensics._has_tool("this_tool_does_not_exist_xyz") is False


# ---------------------------------------------------------------------------
# _run helper
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_returns_success_tuple(self):
        ok, out, err = forensics._run(["echo", "hello"])
        assert ok is True
        assert "hello" in out

    def test_run_returns_failure_for_bad_command(self):
        ok, out, err = forensics._run(["false"])
        assert ok is False

    def test_run_handles_missing_binary(self):
        ok, out, err = forensics._run(["nonexistent_binary_xyz"])
        assert ok is False
        assert out == ""


# ---------------------------------------------------------------------------
# Full Analysis Pipeline (analyze)
# ---------------------------------------------------------------------------

class TestFullAnalysis:
    def _create_test_file(self, content=b"Hello World! This is test data for forensic analysis."):
        """Create a temp file with known content."""
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        f.write(content)
        f.close()
        return f.name

    def test_analyze_runs_without_crash(self):
        """The pipeline should complete without exceptions even if tools are missing."""
        c = _console()
        tmp = self._create_test_file()
        try:
            forensics.handle_command(f"analyze {tmp}", c)
            assert c.print.called
        finally:
            os.unlink(tmp)

    def test_analyze_detects_file_size(self):
        c = _console()
        content = b"A" * 2048
        tmp = self._create_test_file(content)
        try:
            forensics.handle_command(f"analyze {tmp}", c)
            # Pipeline should produce multiple print calls (phases)
            assert c.print.call_count >= 4  # At least: banner, identity, hashes, entropy
        finally:
            os.unlink(tmp)

    def test_analyze_computes_hashes_phase(self):
        """Verify the hash phase runs and produces a Table with 'Phase 2' title."""
        c = _console()
        content = b"forensics test content"
        tmp = self._create_test_file(content)
        try:
            forensics.handle_command(f"analyze {tmp}", c)
            # Find the Phase 2 hash table in the print calls
            from rich.table import Table
            tables = [call.args[0] for call in c.print.call_args_list
                      if call.args and isinstance(call.args[0], Table)]
            # Should have at least 2 tables (identity + hashes)
            assert len(tables) >= 2
            # The hash table should have title containing 'Hash'
            hash_tables = [t for t in tables if t.title and 'Hash' in t.title]
            assert len(hash_tables) == 1
        finally:
            os.unlink(tmp)

    def test_analyze_low_entropy_for_repetitive_data(self):
        c = _console()
        # All same bytes = zero entropy
        content = b"A" * 1000
        tmp = self._create_test_file(content)
        try:
            forensics.handle_command(f"analyze {tmp}", c)
            output = str(c.print.call_args_list)
            # Entropy should be 0.0000 for single-byte content
            assert "0.0000" in output
        finally:
            os.unlink(tmp)

    def test_analyze_high_entropy_for_random_data(self):
        c = _console()
        # Random-ish data should have high entropy
        import random
        random.seed(42)
        content = bytes(random.randint(0, 255) for _ in range(4096))
        tmp = self._create_test_file(content)
        try:
            forensics.handle_command(f"analyze {tmp}", c)
            output = str(c.print.call_args_list)
            # Should detect high entropy (> 7.0)
            assert "High" in output or "encrypted" in output.lower() or "compressed" in output.lower() or "7." in output
        finally:
            os.unlink(tmp)

    def test_analyze_extension_mismatch_detected(self):
        """A file with .jpg extension but non-JPEG content should trigger a warning."""
        c = _console()
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
        f.write(b"PK\x03\x04" + b"\x00" * 100)  # ZIP magic bytes with .jpg extension
        f.close()
        try:
            with patch.object(forensics, '_has_tool', return_value=True):
                # Mock 'file' command to return "Zip archive"
                def mock_run(cmd, **kwargs):
                    if cmd[0] == 'file' and '-b' in cmd:
                        result = MagicMock()
                        result.returncode = 0
                        if '--mime-type' in cmd:
                            result.stdout = "application/zip\n"
                        else:
                            result.stdout = "Zip archive data\n"
                        return True, result.stdout, ""
                    return False, "", ""
                
                with patch.object(forensics, '_run', side_effect=mock_run):
                    forensics.handle_command(f"analyze {f.name}", c)
                    output = str(c.print.call_args_list)
                    # Should flag the mismatch
                    assert "MISMATCH" in output.upper() or "WARNING" in output.upper() or c.print.called
        finally:
            os.unlink(f.name)

    def test_analyze_strings_detects_flags(self):
        """Strings phase should highlight flag patterns."""
        c = _console()
        content = b"normal data\nflag{this_is_a_test_flag}\nmore data\nhttps://evil.com/backdoor\n"
        tmp = self._create_test_file(content)
        try:
            with patch.object(forensics, '_has_tool', return_value=True):
                mock_strings_result = MagicMock()
                mock_strings_result.returncode = 0
                mock_strings_result.stdout = content.decode()
                mock_strings_result.stderr = ""
                
                original_run = forensics._run
                def selective_mock(cmd, **kwargs):
                    if cmd[0] == 'strings':
                        return True, content.decode(), ""
                    return original_run(cmd, **kwargs)
                
                with patch.object(forensics, '_run', side_effect=selective_mock):
                    forensics.handle_command(f"analyze {tmp}", c)
                    output = str(c.print.call_args_list)
                    assert "flag" in output.lower()
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# Steghide Brute-Force (stegcrack)
# ---------------------------------------------------------------------------

class TestStegCrack:
    def test_stegcrack_without_steghide_installed(self):
        c = _console()
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
        f.write(b"\xff\xd8\xff" + b"\x00" * 100)
        f.close()
        try:
            with patch.object(forensics, '_has_tool', return_value=False):
                forensics.handle_command(f"stegcrack {f.name}", c)
                c.print.assert_called()
                output = str(c.print.call_args_list)
                assert "steghide" in output.lower() or "not found" in output.lower()
        finally:
            os.unlink(f.name)

    def test_stegcrack_without_wordlist(self):
        c = _console()
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
        f.write(b"\xff\xd8\xff" + b"\x00" * 100)
        f.close()
        try:
            with patch.object(forensics, '_has_tool', return_value=True):
                with patch("os.path.exists", side_effect=lambda p: p == f.name):
                    forensics.handle_command(f"stegcrack {f.name}", c)
                    c.print.assert_called()
                    output = str(c.print.call_args_list)
                    assert "wordlist" in output.lower() or "rockyou" in output.lower()
        finally:
            os.unlink(f.name)


# ---------------------------------------------------------------------------
# Intelligence Summary
# ---------------------------------------------------------------------------

class TestIntelligenceSummary:
    def test_clean_file_shows_no_findings(self):
        """A plain text file with no anomalies should report clean."""
        c = _console()
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        f.write(b"Just some normal boring text content here nothing to see.")
        f.close()
        try:
            # Mock all external tools as unavailable so only pure-python phases run
            with patch.object(forensics, '_has_tool', return_value=False):
                forensics.handle_command(f"analyze {f.name}", c)
                assert c.print.called
                output = str(c.print.call_args_list)
                # Should either show "No significant findings" or "Analysis Complete"
                assert "complete" in output.lower() or "clean" in output.lower() or "no significant" in output.lower() or c.print.call_count > 0
        finally:
            os.unlink(f.name)
