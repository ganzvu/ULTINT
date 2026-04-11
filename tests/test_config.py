"""Tests for src/core/config.py — Config dataclass defaults."""
from src.core.config import Config, settings


class TestConfigDefaults:
    def test_data_dir_default(self):
        assert Config().DATA_DIR == "data"

    def test_session_dir_contains_ig_detective(self):
        assert "ig-detective" in Config().SESSION_DIR

    def test_jitter_fast(self):
        assert Config().JITTER_MEAN_FAST == 3.0

    def test_jitter_normal(self):
        assert Config().JITTER_MEAN_NORMAL == 8.0

    def test_jitter_slow(self):
        assert Config().JITTER_MEAN_SLOW == 25.0

    def test_user_agent_is_string(self):
        assert isinstance(Config().USER_AGENT, str)
        assert len(Config().USER_AGENT) > 0

    def test_timeout_default(self):
        assert Config().TIMEOUT == 15

    def test_max_retries_default(self):
        assert Config().MAX_RETRIES == 3

    def test_cache_ttl_default(self):
        assert Config().CACHE_DEFAULT_TTL == 3600


class TestSettingsSingleton:
    def test_settings_is_config_instance(self):
        assert isinstance(settings, Config)

    def test_settings_uses_defaults(self):
        assert settings.TIMEOUT == 15
        assert settings.MAX_RETRIES == 3
