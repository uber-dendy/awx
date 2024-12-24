import pytest
from rest_framework import serializers

from awx.api.conf import allowed_urls_validate
from awx.settings.defaults import ANONYMOUS_ACCESS_API_ALLOWED_PATHS as DEFAULT_ALLOWED_PATHS


class TestAllowedUrlsValidator:

    def test_ok_validator(self):
        attrs = {'ANONYMOUS_ACCESS_API_ALLOWED_PATHS': DEFAULT_ALLOWED_PATHS}
        allowed_urls_validate(None, attrs)

    def test_all_validator(self):
        attrs = {'ANONYMOUS_ACCESS_API_ALLOWED_PATHS': []}
        allowed_urls_validate(None, attrs)
        assert attrs.get('ANONYMOUS_ACCESS_API_ALLOWED_PATHS') == DEFAULT_ALLOWED_PATHS

    def test_wrong_path_validator(self):
        attrs = {'ANONYMOUS_ACCESS_API_ALLOWED_PATHS': DEFAULT_ALLOWED_PATHS + ['not_a_path']}

        with pytest.raises(serializers.ValidationError):
            allowed_urls_validate(None, attrs)
