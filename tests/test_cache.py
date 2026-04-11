"""Tests for src/core/cache.py — CacheManager TTL behaviour."""
import time
import pytest
from src.core.cache import CacheManager


class TestCacheManager:
    def setup_method(self):
        self.cache = CacheManager()

    # ------------------------------------------------------------------
    # get / set basics
    # ------------------------------------------------------------------

    def test_get_returns_none_for_missing_key(self):
        assert self.cache.get("missing") is None

    def test_set_and_get(self):
        self.cache.set("key", "value")
        assert self.cache.get("key") == "value"

    def test_set_and_get_non_string_value(self):
        self.cache.set("num", 42)
        assert self.cache.get("num") == 42

    def test_set_and_get_dict_value(self):
        d = {"a": 1, "b": [1, 2, 3]}
        self.cache.set("dict_key", d)
        assert self.cache.get("dict_key") == d

    def test_set_overwrites_existing_key(self):
        self.cache.set("k", "first")
        self.cache.set("k", "second")
        assert self.cache.get("k") == "second"

    # ------------------------------------------------------------------
    # TTL expiry
    # ------------------------------------------------------------------

    def test_expired_entry_returns_none(self):
        self.cache.set("ttl_key", "val", ttl_seconds=1)
        time.sleep(1.05)
        assert self.cache.get("ttl_key") is None

    def test_non_expired_entry_still_accessible(self):
        self.cache.set("live_key", "val", ttl_seconds=60)
        assert self.cache.get("live_key") == "val"

    def test_expired_entry_removed_from_internal_dict(self):
        self.cache.set("gone", "val", ttl_seconds=1)
        time.sleep(1.05)
        self.cache.get("gone")  # triggers deletion
        assert "gone" not in self.cache._cache

    # ------------------------------------------------------------------
    # clear
    # ------------------------------------------------------------------

    def test_clear_removes_all_entries(self):
        self.cache.set("a", 1)
        self.cache.set("b", 2)
        self.cache.clear()
        assert self.cache.get("a") is None
        assert self.cache.get("b") is None

    def test_clear_on_empty_cache_does_not_raise(self):
        self.cache.clear()  # should not raise

    def test_get_after_clear_returns_none(self):
        self.cache.set("x", "y")
        self.cache.clear()
        assert self.cache.get("x") is None

    # ------------------------------------------------------------------
    # default TTL
    # ------------------------------------------------------------------

    def test_default_ttl_is_3600(self):
        self.cache.set("default", "v")
        entry = self.cache._cache["default"]
        # expires_at should be approximately now + 3600
        assert abs(entry["expires_at"] - (time.time() + 3600)) < 5

    # ------------------------------------------------------------------
    # None value stored explicitly
    # ------------------------------------------------------------------

    def test_store_none_value(self):
        # None values can legitimately be cached
        self.cache.set("none_val", None)
        # CacheManager treats a missing entry (None) the same as a stored None,
        # so the returned value is None either way — just verify no exception.
        result = self.cache.get("none_val")
        assert result is None
