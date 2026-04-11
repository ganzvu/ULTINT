"""Tests for src/modules/analytics.py — AnalyticsEngine."""
import pytest
from datetime import datetime, timezone, timedelta
from src.core.models import Post
from src.modules.analytics import AnalyticsEngine


def _make_post(
    id="1",
    caption="",
    likes=0,
    comments=0,
    is_video=False,
    ts=None,
    tagged=None,
    location_name=None,
):
    if ts is None:
        ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return Post(
        id=id,
        shortcode=f"sc_{id}",
        owner_id="owner",
        timestamp=ts,
        caption=caption,
        likes_count=likes,
        comments_count=comments,
        is_video=is_video,
        tagged_users=tagged or [],
        location_name=location_name,
    )


# ---------------------------------------------------------------------------
# get_most_used_hashtags
# ---------------------------------------------------------------------------

class TestGetMostUsedHashtags:
    def test_empty_posts_returns_empty(self):
        result = AnalyticsEngine.get_most_used_hashtags([])
        assert result == []

    def test_single_hashtag(self):
        p = _make_post(caption="#travel vibes")
        result = AnalyticsEngine.get_most_used_hashtags([p])
        assert result[0][0] == "travel"
        assert result[0][1] == 1

    def test_multiple_hashtags_counted(self):
        posts = [
            _make_post(id="1", caption="#travel #food"),
            _make_post(id="2", caption="#travel #travel"),
        ]
        result = AnalyticsEngine.get_most_used_hashtags(posts)
        counts = dict(result)
        assert counts["travel"] == 3
        assert counts["food"] == 1

    def test_top_n_limits_results(self):
        posts = [_make_post(caption=f"#{i}") for i in range(20)]
        result = AnalyticsEngine.get_most_used_hashtags(posts, top_n=5)
        assert len(result) <= 5

    def test_no_hashtags_returns_empty(self):
        p = _make_post(caption="Just a regular caption")
        result = AnalyticsEngine.get_most_used_hashtags([p])
        assert result == []

    def test_post_without_caption(self):
        p = _make_post(caption="")
        result = AnalyticsEngine.get_most_used_hashtags([p])
        assert result == []

    def test_case_sensitivity(self):
        posts = [
            _make_post(id="1", caption="#Travel"),
            _make_post(id="2", caption="#travel"),
        ]
        result = AnalyticsEngine.get_most_used_hashtags(posts)
        counts = dict(result)
        # re.findall(r"#(\w+)") preserves original case
        assert counts.get("Travel", 0) + counts.get("travel", 0) == 2


# ---------------------------------------------------------------------------
# get_aggregate_stats
# ---------------------------------------------------------------------------

class TestGetAggregateStats:
    def test_empty_posts_returns_empty_dict(self):
        assert AnalyticsEngine.get_aggregate_stats([]) == {}

    def test_single_photo_post(self):
        p = _make_post(likes=100, comments=5, is_video=False)
        stats = AnalyticsEngine.get_aggregate_stats([p])
        assert stats["total_posts"] == 1
        assert stats["total_likes"] == 100
        assert stats["total_comments"] == 5
        assert stats["avg_likes"] == 100.0
        assert stats["avg_comments"] == 5.0
        assert stats["photo_count"] == 1
        assert stats["video_count"] == 0

    def test_mixed_posts(self):
        posts = [
            _make_post(id="1", likes=100, comments=10, is_video=False),
            _make_post(id="2", likes=200, comments=20, is_video=True),
            _make_post(id="3", likes=300, comments=30, is_video=False),
        ]
        stats = AnalyticsEngine.get_aggregate_stats(posts)
        assert stats["total_posts"] == 3
        assert stats["total_likes"] == 600
        assert stats["total_comments"] == 60
        assert abs(stats["avg_likes"] - 200.0) < 0.01
        assert stats["photo_count"] == 2
        assert stats["video_count"] == 1

    def test_all_videos(self):
        posts = [_make_post(id=str(i), is_video=True) for i in range(3)]
        stats = AnalyticsEngine.get_aggregate_stats(posts)
        assert stats["video_count"] == 3
        assert stats["photo_count"] == 0

    def test_avg_zero_when_no_likes(self):
        posts = [_make_post(id=str(i), likes=0) for i in range(5)]
        stats = AnalyticsEngine.get_aggregate_stats(posts)
        assert stats["avg_likes"] == 0.0


# ---------------------------------------------------------------------------
# perform_sna
# ---------------------------------------------------------------------------

class TestPerformSNA:
    def test_no_tagged_users_returns_empty(self):
        result = AnalyticsEngine.perform_sna("target", [])
        assert result == []

    def test_single_tagged_user(self):
        result = AnalyticsEngine.perform_sna("target", [["alice"]])
        names = [r[0] for r in result]
        assert "alice" in names

    def test_target_excluded_from_results(self):
        result = AnalyticsEngine.perform_sna("target", [["target", "alice"]])
        names = [r[0] for r in result]
        assert "target" not in names

    def test_frequently_tagged_user_ranked_higher(self):
        # "alice" tagged 5 times, "bob" once
        tags = [["alice"]] * 5 + [["bob"]]
        result = AnalyticsEngine.perform_sna("target", tags)
        names = [r[0] for r in result]
        assert names.index("alice") < names.index("bob")

    def test_result_limited_to_10(self):
        tags = [[f"user{i}"] for i in range(20)]
        result = AnalyticsEngine.perform_sna("target", tags)
        assert len(result) <= 10

    def test_centrality_scores_are_floats(self):
        result = AnalyticsEngine.perform_sna("target", [["alice", "bob"]])
        for _, score in result:
            assert isinstance(score, float)


# ---------------------------------------------------------------------------
# analyze_temporal_behavior
# ---------------------------------------------------------------------------

class TestAnalyzeTemporalBehavior:
    def test_empty_posts_returns_empty(self):
        assert AnalyticsEngine.analyze_temporal_behavior([]) == {}

    def test_keys_present(self):
        posts = [_make_post(ts=datetime(2024, 1, 1, i, 0, 0, tzinfo=timezone.utc)) for i in range(12)]
        result = AnalyticsEngine.analyze_temporal_behavior(posts)
        for key in ("sleep_start_hour", "sleep_gap_duration", "predicted_timezone", "hourly_distribution"):
            assert key in result

    def test_hourly_distribution_has_24_entries(self):
        posts = [_make_post(ts=datetime(2024, 1, 1, i, 0, 0, tzinfo=timezone.utc)) for i in range(12)]
        result = AnalyticsEngine.analyze_temporal_behavior(posts)
        assert len(result["hourly_distribution"]) == 24

    def test_sleep_gap_non_negative(self):
        posts = [_make_post(ts=datetime(2024, 1, 1, i, 0, 0, tzinfo=timezone.utc)) for i in range(10)]
        result = AnalyticsEngine.analyze_temporal_behavior(posts)
        assert result["sleep_gap_duration"] >= 0

    def test_predicted_timezone_is_string(self):
        posts = [_make_post(ts=datetime(2024, 1, 1, i, 0, 0, tzinfo=timezone.utc)) for i in range(10)]
        result = AnalyticsEngine.analyze_temporal_behavior(posts)
        assert isinstance(result["predicted_timezone"], str)


# ---------------------------------------------------------------------------
# get_linguistic_signature
# ---------------------------------------------------------------------------

class TestGetLinguisticSignature:
    def test_empty_posts_returns_empty(self):
        result = AnalyticsEngine.get_linguistic_signature([])
        assert result == {}

    def test_posts_with_only_empty_captions(self):
        posts = [_make_post(caption="") for _ in range(3)]
        result = AnalyticsEngine.get_linguistic_signature(posts)
        assert result == {}

    def test_basic_keys_present(self):
        posts = [_make_post(caption="Hello world this is a test caption for analysis")]
        result = AnalyticsEngine.get_linguistic_signature(posts)
        for key in ("top_emojis", "punctuation_habits", "top_bigrams", "lexical_diversity"):
            assert key in result

    def test_lexical_diversity_between_0_and_1(self):
        posts = [_make_post(caption="word word word different")]
        result = AnalyticsEngine.get_linguistic_signature(posts)
        ld = result.get("lexical_diversity", -1)
        assert 0.0 <= ld <= 1.0

    def test_punctuation_habits_keys(self):
        posts = [_make_post(caption="Wow!! Really?? Let me think... OK")]
        result = AnalyticsEngine.get_linguistic_signature(posts)
        habits = result.get("punctuation_habits", {})
        assert "multiple_excl" in habits
        assert "multiple_qmark" in habits
        assert "ellipsis" in habits
        assert "all_caps_words" in habits

    def test_exclamation_count(self):
        posts = [_make_post(caption="Yes!! No!! Maybe!!")]
        result = AnalyticsEngine.get_linguistic_signature(posts)
        assert result["punctuation_habits"]["multiple_excl"] == 3

    def test_ellipsis_count(self):
        posts = [_make_post(caption="Hmm... wait... really...")]
        result = AnalyticsEngine.get_linguistic_signature(posts)
        assert result["punctuation_habits"]["ellipsis"] == 3

    def test_all_caps_detection(self):
        posts = [_make_post(caption="This is LOUD and VERY BOLD")]
        result = AnalyticsEngine.get_linguistic_signature(posts)
        assert result["punctuation_habits"]["all_caps_words"] >= 3

    def test_top_bigrams_are_strings(self):
        posts = [_make_post(caption="hello world hello world once upon a time")]
        result = AnalyticsEngine.get_linguistic_signature(posts)
        for b in result.get("top_bigrams", []):
            assert isinstance(b, str)
            assert " " in b  # bigram should have a space between words
