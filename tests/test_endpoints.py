"""Tests for src/api/endpoints.py — URL generation helpers."""
import urllib.parse
import pytest
from src.api.endpoints import Endpoints


class TestEndpointConstants:
    def test_base_url(self):
        assert Endpoints.BASE_URL == "https://www.instagram.com"

    def test_graphql_url(self):
        assert "graphql" in Endpoints.GRAPHQL_URL

    def test_i_api_base(self):
        assert "i.instagram.com" in Endpoints.I_API_BASE

    def test_login_url(self):
        assert "/accounts/login/" in Endpoints.LOGIN

    def test_two_factor_url(self):
        assert "two_factor" in Endpoints.TWO_FACTOR_LOGIN


class TestUserInfoEndpoint:
    def test_user_info_contains_username(self):
        url = Endpoints.user_info("testuser")
        assert "testuser" in url

    def test_user_info_is_https(self):
        url = Endpoints.user_info("testuser")
        assert url.startswith("https://")

    def test_user_info_different_users(self):
        url1 = Endpoints.user_info("alice")
        url2 = Endpoints.user_info("bob")
        assert url1 != url2
        assert "alice" in url1
        assert "bob" in url2


class TestMediaInfoEndpoint:
    def test_media_info_contains_shortcode(self):
        url = Endpoints.media_info("ABC123")
        assert "ABC123" in url

    def test_media_info_is_graphql(self):
        url = Endpoints.media_info("ABC123")
        assert "graphql" in url or "query" in url

    def test_media_info_different_shortcodes(self):
        url1 = Endpoints.media_info("code1")
        url2 = Endpoints.media_info("code2")
        assert url1 != url2


class TestFollowersEndpoint:
    def test_followers_url_contains_hash(self):
        url = Endpoints.followers("12345", 50)
        assert Endpoints.HASH_FOLLOWERS in url

    def test_followers_url_contains_user_id(self):
        url = Endpoints.followers("99999", 50)
        decoded = urllib.parse.unquote(url)
        assert "99999" in decoded

    def test_followers_url_with_cursor(self):
        url = Endpoints.followers("12345", 50, "cursor123")
        decoded = urllib.parse.unquote(url)
        assert "cursor123" in decoded

    def test_followers_url_empty_cursor(self):
        url = Endpoints.followers("12345", 50, "")
        assert url  # just check not empty

    def test_followers_count_in_url(self):
        url = Endpoints.followers("12345", 25)
        decoded = urllib.parse.unquote(url)
        assert "25" in decoded


class TestFollowingsEndpoint:
    def test_followings_url_contains_hash(self):
        url = Endpoints.followings("12345", 50)
        assert Endpoints.HASH_FOLLOWINGS in url

    def test_followings_url_contains_user_id(self):
        url = Endpoints.followings("77777", 50)
        decoded = urllib.parse.unquote(url)
        assert "77777" in decoded

    def test_followings_url_with_cursor(self):
        url = Endpoints.followings("12345", 50, "cursor_abc")
        decoded = urllib.parse.unquote(url)
        assert "cursor_abc" in decoded

    def test_followers_and_followings_differ(self):
        followers_url = Endpoints.followers("123", 50)
        followings_url = Endpoints.followings("123", 50)
        assert followers_url != followings_url
