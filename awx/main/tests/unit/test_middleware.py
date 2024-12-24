import pytest
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser
from django.http import JsonResponse, HttpResponse
from rest_framework.test import APIRequestFactory

from awx.main.middleware import AnonymousAccessRestrictionMiddleware


@pytest.fixture
def access_restriction_middleware():
    return AnonymousAccessRestrictionMiddleware(lambda request: HttpResponse())


@pytest.fixture
def mock_user(is_authenticated):
    return type("User", (), {"is_authenticated": is_authenticated})()


class TestAnonymousAccessRestrictionMiddleware:
    @pytest.mark.parametrize(
        "is_authenticated,expected_response",
        [
            (False, JsonResponse),  # Anonymous user, restricted path
            (True, None),  # Authenticated user, not restricted
        ],
    )
    @patch("django.conf.settings.RESTRICT_API_ANONYMOUS_ACCESS", True)
    @patch("django.conf.settings.ANONYMOUS_ACCESS_API_ALLOWED_PATHS", ["/api/public"])
    def test_restricted_access_to_authenticated_only_path(self, access_restriction_middleware, mock_user, is_authenticated, expected_response):
        request = APIRequestFactory().get("/api/secure-data")
        request.user = mock_user
        response = access_restriction_middleware.process_request(request)

        if expected_response:
            assert isinstance(response, expected_response)
            assert response.status_code == 401
        else:
            assert response is None

    @patch("django.conf.settings.RESTRICT_API_ANONYMOUS_ACCESS", True)
    @patch("django.conf.settings.ANONYMOUS_ACCESS_API_ALLOWED_PATHS", ["/api/public"])
    def test_allowed_path_for_anonymous_user(self, access_restriction_middleware):
        """Test that anonymous users can access paths in the allowed list."""
        request = APIRequestFactory().get("/api/public")
        request.user = AnonymousUser()

        response = access_restriction_middleware.process_request(request)
        assert response is None

    @patch("django.conf.settings.RESTRICT_API_ANONYMOUS_ACCESS", False)
    def test_anonymous_access_when_restriction_disabled(self, access_restriction_middleware):
        """Test that anonymous access is allowed when the restriction is disabled."""
        request = APIRequestFactory().get("/api/secure-data")
        request.user = AnonymousUser()  # Anonymous user

        response = access_restriction_middleware.process_request(request)
        assert response is None

    def test_non_api_path_is_skipped(self, access_restriction_middleware):
        """Test that non-API paths are skipped by the middleware."""
        request = APIRequestFactory().get("/")
        request.user = AnonymousUser()

        response = access_restriction_middleware.process_request(request)
        assert response is None
