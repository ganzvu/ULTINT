"""Tests for src/core/models.py — User, Post, Comment dataclasses."""
import pytest
from datetime import datetime, timezone
from src.core.models import User, Post, Comment


class TestUserModel:
    def test_minimal_construction(self):
        u = User(id="1", username="alice", full_name="Alice Smith")
        assert u.id == "1"
        assert u.username == "alice"
        assert u.full_name == "Alice Smith"

    def test_default_values(self):
        u = User(id="1", username="alice", full_name="Alice")
        assert u.biography == ""
        assert u.follower_count == 0
        assert u.following_count == 0
        assert u.is_private is False
        assert u.is_verified is False
        assert u.profile_pic_url is None
        assert u.external_url is None
        assert u.business_category is None
        assert u.business_email is None
        assert u.business_phone is None
        assert u.obfuscated_email is None
        assert u.obfuscated_phone is None

    def test_full_construction(self):
        u = User(
            id="42",
            username="bob",
            full_name="Bob Jones",
            biography="My bio",
            follower_count=1000,
            following_count=200,
            is_private=True,
            is_verified=True,
            profile_pic_url="https://example.com/pic.jpg",
            external_url="https://example.com",
            business_category="Media",
            business_email="bob@example.com",
            business_phone="+1234567890",
            obfuscated_email="b***@example.com",
            obfuscated_phone="+1***7890",
        )
        assert u.is_private is True
        assert u.follower_count == 1000
        assert u.business_email == "bob@example.com"


class TestPostModel:
    def _ts(self):
        return datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_minimal_construction(self):
        p = Post(
            id="100",
            shortcode="abc123",
            owner_id="1",
            timestamp=self._ts(),
        )
        assert p.id == "100"
        assert p.shortcode == "abc123"
        assert p.caption == ""
        assert p.likes_count == 0
        assert p.comments_count == 0
        assert p.is_video is False
        assert p.video_view_count is None
        assert p.location_name is None
        assert p.location_lat is None
        assert p.location_lng is None
        assert p.tagged_users == []
        assert p.raw_node == {}

    def test_full_construction(self):
        ts = self._ts()
        p = Post(
            id="200",
            shortcode="xyz",
            owner_id="9",
            timestamp=ts,
            caption="#travel loving it!!",
            likes_count=500,
            comments_count=20,
            is_video=True,
            video_view_count=1500,
            location_name="New York",
            location_lat=40.7128,
            location_lng=-74.0060,
            tagged_users=["carol", "dave"],
            raw_node={"key": "value"},
        )
        assert p.caption == "#travel loving it!!"
        assert p.likes_count == 500
        assert p.tagged_users == ["carol", "dave"]
        assert p.raw_node == {"key": "value"}

    def test_tagged_users_default_independent_per_instance(self):
        p1 = Post(id="1", shortcode="a", owner_id="x", timestamp=self._ts())
        p2 = Post(id="2", shortcode="b", owner_id="y", timestamp=self._ts())
        p1.tagged_users.append("user1")
        assert p2.tagged_users == []  # field(default_factory=list) ensures independence

    def test_raw_node_default_independent_per_instance(self):
        p1 = Post(id="1", shortcode="a", owner_id="x", timestamp=self._ts())
        p2 = Post(id="2", shortcode="b", owner_id="y", timestamp=self._ts())
        p1.raw_node["k"] = "v"
        assert p2.raw_node == {}


class TestCommentModel:
    def test_construction(self):
        ts = datetime(2024, 3, 1, 8, 0, 0, tzinfo=timezone.utc)
        c = Comment(
            id="55",
            post_id="100",
            owner_username="eve",
            text="Great post!",
            created_at=ts,
        )
        assert c.id == "55"
        assert c.post_id == "100"
        assert c.owner_username == "eve"
        assert c.text == "Great post!"
        assert c.created_at == ts
