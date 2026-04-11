"""Tests for src/core/exceptions.py — exception hierarchy."""
import pytest
from src.core.exceptions import (
    IGDetectiveError,
    RateLimitError,
    AuthenticationError,
    UserNotFoundError,
    NetworkError,
)


class TestExceptionHierarchy:
    def test_base_exception_is_exception(self):
        assert issubclass(IGDetectiveError, Exception)

    def test_rate_limit_is_ig_detective_error(self):
        assert issubclass(RateLimitError, IGDetectiveError)

    def test_authentication_is_ig_detective_error(self):
        assert issubclass(AuthenticationError, IGDetectiveError)

    def test_user_not_found_is_ig_detective_error(self):
        assert issubclass(UserNotFoundError, IGDetectiveError)

    def test_network_error_is_ig_detective_error(self):
        assert issubclass(NetworkError, IGDetectiveError)


class TestExceptionMessages:
    def test_ig_detective_error_message(self):
        e = IGDetectiveError("something went wrong")
        assert str(e) == "something went wrong"

    def test_rate_limit_error_message(self):
        e = RateLimitError("Too many requests")
        assert str(e) == "Too many requests"

    def test_authentication_error_message(self):
        e = AuthenticationError("Invalid credentials")
        assert str(e) == "Invalid credentials"

    def test_user_not_found_error_message(self):
        e = UserNotFoundError("User does not exist")
        assert str(e) == "User does not exist"

    def test_network_error_message(self):
        e = NetworkError("Connection refused")
        assert str(e) == "Connection refused"


class TestExceptionRaiseAndCatch:
    def test_raise_and_catch_base(self):
        with pytest.raises(IGDetectiveError):
            raise IGDetectiveError("base")

    def test_subclass_caught_by_base(self):
        with pytest.raises(IGDetectiveError):
            raise RateLimitError("429")

    def test_rate_limit_not_caught_as_auth_error(self):
        with pytest.raises(RateLimitError):
            try:
                raise RateLimitError("rate")
            except AuthenticationError:
                pass  # should not reach here
            except RateLimitError:
                raise

    def test_user_not_found_caught_specifically(self):
        caught = False
        try:
            raise UserNotFoundError("not found")
        except UserNotFoundError:
            caught = True
        assert caught

    def test_network_error_caught_specifically(self):
        caught = False
        try:
            raise NetworkError("net")
        except NetworkError:
            caught = True
        assert caught
