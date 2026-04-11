"""Tests for src/modules/recon.py — ReconEngine with mocked API client."""
import sys
import types
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

# Stub out playwright before importing anything that depends on it
for _mod in (
    "playwright",
    "playwright.sync_api",
    "playwright_stealth",
):
    if _mod not in sys.modules:
        sys.modules[_mod] = types.ModuleType(_mod)

# Provide the symbols playwright-dependent code needs
_pw_mod = sys.modules["playwright.sync_api"]
_pw_mod.sync_playwright = MagicMock()
_pw_mod.TimeoutError = type("TimeoutError", (Exception,), {})

_stealth_mod = sys.modules["playwright_stealth"]
_stealth_mod.Stealth = MagicMock()

from src.modules.recon import ReconEngine  # noqa: E402  (import after stubs)
from src.core.models import User, Post
from src.core.cache import CacheManager


def _make_api_client():
    client = MagicMock()
    return client


def _make_engine(api_client=None):
    if api_client is None:
        api_client = _make_api_client()
    engine = ReconEngine.__new__(ReconEngine)
    engine.api = api_client
    engine._geolocator = None
    return engine


def _profile_data(username="alice", user_id="1234"):
    return {
        "id": user_id,
        "username": username,
        "full_name": "Alice Example",
        "biography": "Contact: alice@example.com | +1-800-555-0101",
        "edge_followed_by": {"count": 500},
        "edge_follow": {"count": 100},
        "is_private": False,
        "is_verified": True,
        "profile_pic_url_hd": "https://cdn.instagram.com/alice.jpg",
        "external_url": "https://alice.example.com",
        "business_category_name": "Media",
        "business_email": "biz@alice.example.com",
        "business_phone_number": "+18005550101",
        "obfuscated_email": "a***@example.com",
        "obfuscated_phone": "+1***0101",
        "edge_owner_to_timeline_media": {"edges": []},
    }


def _timeline_edge(i=0, is_video=False, caption="", location=None, tagged=None, ts=None):
    if ts is None:
        ts = int(datetime(2024, 1, i + 1, 12, 0, 0, tzinfo=timezone.utc).timestamp())
    node = {
        "id": str(1000 + i),
        "shortcode": f"sc{i}",
        "owner": {"id": "1234"},
        "taken_at_timestamp": ts,
        "is_video": is_video,
        "edge_media_to_caption": {"edges": [{"node": {"text": caption}}] if caption else []},
        "edge_media_preview_like": {"count": i * 10},
        "edge_media_to_comment": {"count": i * 2},
        "location": location,
        "edge_media_to_tagged_user": {"edges": [{"node": {"user": {"username": u}}} for u in (tagged or [])]},
        "video_view_count": 500 if is_video else None,
    }
    return {"node": node}


class TestGetUserProfile:
    def test_basic_profile_fields(self):
        client = _make_api_client()
        client.fetch_user_info.return_value = _profile_data("alice")
        engine = _make_engine(client)

        # Bypass cache
        with patch("src.modules.recon.global_cache", CacheManager()), \
             patch("src.modules.recon.apply_jitter"):
            user = engine.get_user_profile("alice")

        assert user.username == "alice"
        assert user.id == "1234"
        assert user.full_name == "Alice Example"
        assert user.follower_count == 500
        assert user.following_count == 100
        assert user.is_private is False
        assert user.is_verified is True

    def test_email_extracted_from_bio(self):
        data = _profile_data()
        data["business_email"] = None
        data["biography"] = "Contact me at hidden@example.com for work"
        client = _make_api_client()
        client.fetch_user_info.return_value = data
        engine = _make_engine(client)

        with patch("src.modules.recon.global_cache", CacheManager()), \
             patch("src.modules.recon.apply_jitter"):
            user = engine.get_user_profile("alice")
        assert user.business_email == "hidden@example.com"

    def test_phone_extracted_from_bio(self):
        data = _profile_data()
        data["business_phone_number"] = None
        data["biography"] = "Call +1-800-555-9999 for info"
        client = _make_api_client()
        client.fetch_user_info.return_value = data
        engine = _make_engine(client)

        with patch("src.modules.recon.global_cache", CacheManager()), \
             patch("src.modules.recon.apply_jitter"):
            user = engine.get_user_profile("alice")
        assert user.business_phone is not None

    def test_result_cached(self):
        client = _make_api_client()
        client.fetch_user_info.return_value = _profile_data("alice")
        engine = _make_engine(client)
        fresh_cache = CacheManager()

        with patch("src.modules.recon.global_cache", fresh_cache), \
             patch("src.modules.recon.apply_jitter"):
            engine.get_user_profile("alice")
            engine.get_user_profile("alice")

        # fetch_user_info should only be called once
        assert client.fetch_user_info.call_count == 1

    def test_returns_user_instance(self):
        client = _make_api_client()
        client.fetch_user_info.return_value = _profile_data("alice")
        engine = _make_engine(client)
        with patch("src.modules.recon.global_cache", CacheManager()), \
             patch("src.modules.recon.apply_jitter"):
            result = engine.get_user_profile("alice")
        assert isinstance(result, User)


class TestGetRecentPosts:
    def _run(self, edges, count=12):
        data = _profile_data()
        data["edge_owner_to_timeline_media"] = {"edges": edges}
        client = _make_api_client()
        client.fetch_user_info.return_value = data
        engine = _make_engine(client)
        with patch("src.modules.recon.global_cache", CacheManager()), \
             patch("src.modules.recon.apply_jitter"):
            return engine.get_recent_posts("alice", count=count)

    def test_empty_timeline(self):
        posts = self._run([])
        assert posts == []

    def test_posts_count_respected(self):
        edges = [_timeline_edge(i) for i in range(10)]
        posts = self._run(edges, count=5)
        assert len(posts) == 5

    def test_post_fields_populated(self):
        edges = [_timeline_edge(0, caption="Hello #world", tagged=["bob"])]
        posts = self._run(edges)
        assert len(posts) == 1
        p = posts[0]
        assert isinstance(p, Post)
        assert p.caption == "Hello #world"
        assert "bob" in p.tagged_users

    def test_video_post(self):
        edges = [_timeline_edge(0, is_video=True)]
        posts = self._run(edges)
        assert posts[0].is_video is True
        assert posts[0].video_view_count == 500

    def test_location_extracted(self):
        loc = {"name": "New York", "lat": 40.71, "lng": -74.00}
        edges = [_timeline_edge(0, location=loc)]
        posts = self._run(edges)
        assert posts[0].location_name == "New York"
        assert posts[0].location_lat == 40.71

    def test_result_cached(self):
        edges = [_timeline_edge(0)]
        data = _profile_data()
        data["edge_owner_to_timeline_media"] = {"edges": edges}
        client = _make_api_client()
        client.fetch_user_info.return_value = data
        engine = _make_engine(client)
        fresh_cache = CacheManager()

        with patch("src.modules.recon.global_cache", fresh_cache), \
             patch("src.modules.recon.apply_jitter"):
            engine.get_recent_posts("alice", 12)
            engine.get_recent_posts("alice", 12)

        assert client.fetch_user_info.call_count == 1


class TestParseTimelineEdges:
    def test_no_caption_defaults_empty_string(self):
        engine = _make_engine()
        edge = _timeline_edge(0, caption="")
        posts = engine._parse_timeline_edges([edge])
        assert posts[0].caption == ""

    def test_missing_location_fields_none(self):
        engine = _make_engine()
        edge = _timeline_edge(0)
        posts = engine._parse_timeline_edges([edge])
        assert posts[0].location_name is None
        assert posts[0].location_lat is None
        assert posts[0].location_lng is None

    def test_multiple_tagged_users(self):
        engine = _make_engine()
        edge = _timeline_edge(0, tagged=["user1", "user2", "user3"])
        posts = engine._parse_timeline_edges([edge])
        assert set(posts[0].tagged_users) == {"user1", "user2", "user3"}


class TestGetLocations:
    def test_no_location_posts_returns_empty(self):
        data = _profile_data()
        data["edge_owner_to_timeline_media"] = {"edges": [_timeline_edge(0)]}
        client = _make_api_client()
        client.fetch_user_info.return_value = data
        engine = _make_engine(client)

        with patch("src.modules.recon.global_cache", CacheManager()), \
             patch("src.modules.recon.apply_jitter"):
            locations = engine.get_locations("alice", limit=5)
        assert locations == []

    def test_location_post_included(self):
        loc = {"name": "Paris", "lat": 48.85, "lng": 2.35}
        data = _profile_data()
        data["edge_owner_to_timeline_media"] = {"edges": [_timeline_edge(0, location=loc)]}
        client = _make_api_client()
        client.fetch_user_info.return_value = data
        engine = _make_engine(client)

        with patch("src.modules.recon.global_cache", CacheManager()), \
             patch("src.modules.recon.apply_jitter"):
            locations = engine.get_locations("alice", limit=5)
        assert len(locations) == 1
        assert locations[0]["name"] == "Paris"
