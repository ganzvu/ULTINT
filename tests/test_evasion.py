"""Tests for src/modules/evasion.py — jitter functions."""
import pytest
from unittest.mock import patch
import numpy as np
from src.modules.evasion import poisson_jitter, apply_jitter
from src.core.config import settings


class TestPoissonJitter:
    def test_returns_float(self):
        delay = poisson_jitter(5.0)
        assert isinstance(delay, float)

    def test_minimum_is_1(self):
        # Force numpy to return 0 to verify the max(1.0, ...) floor
        with patch("numpy.random.poisson", return_value=0):
            delay = poisson_jitter(5.0)
        assert delay == 1.0

    def test_non_negative(self):
        for _ in range(20):
            assert poisson_jitter(3.0) >= 0

    def test_returns_at_least_one_second(self):
        for _ in range(20):
            assert poisson_jitter(3.0) >= 1.0

    def test_roughly_correct_scale(self):
        # With mean=10 and many samples the average should be near 10
        delays = [poisson_jitter(10.0) for _ in range(200)]
        avg = sum(delays) / len(delays)
        assert 5.0 < avg < 20.0  # generous range


class TestApplyJitter:
    """apply_jitter calls time.sleep — we mock it so tests run instantly."""

    def _run(self, speed):
        with patch("src.modules.evasion.time.sleep") as mock_sleep, \
             patch("src.modules.evasion.poisson_jitter", return_value=5.0) as mock_jitter:
            apply_jitter(speed)
            return mock_sleep, mock_jitter

    def test_fast_speed_uses_fast_mean(self):
        mock_sleep, mock_jitter = self._run("fast")
        mock_jitter.assert_called_once_with(settings.JITTER_MEAN_FAST)
        mock_sleep.assert_called_once_with(5.0)

    def test_slow_speed_uses_slow_mean(self):
        mock_sleep, mock_jitter = self._run("slow")
        mock_jitter.assert_called_once_with(settings.JITTER_MEAN_SLOW)

    def test_normal_speed_uses_normal_mean(self):
        mock_sleep, mock_jitter = self._run("normal")
        mock_jitter.assert_called_once_with(settings.JITTER_MEAN_NORMAL)

    def test_default_speed_is_normal(self):
        with patch("src.modules.evasion.time.sleep"), \
             patch("src.modules.evasion.poisson_jitter", return_value=5.0) as mock_jitter:
            apply_jitter()  # no argument → defaults to "normal"
        mock_jitter.assert_called_once_with(settings.JITTER_MEAN_NORMAL)

    def test_unknown_speed_falls_back_to_normal(self):
        with patch("src.modules.evasion.time.sleep"), \
             patch("src.modules.evasion.poisson_jitter", return_value=5.0) as mock_jitter:
            apply_jitter("turbo")  # unknown string → else branch
        mock_jitter.assert_called_once_with(settings.JITTER_MEAN_NORMAL)
