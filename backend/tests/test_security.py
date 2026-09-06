import pytest

from app.utils.validators import (
    validate_eml_filename,
    validate_upload_size,
)
from app.utils.security import safe_filename


def test_valid_eml_filename():
    validate_eml_filename("sample.eml")


def test_invalid_filename():
    with pytest.raises(Exception):
        validate_eml_filename("sample.txt")


def test_missing_filename():
    with pytest.raises(Exception):
        validate_eml_filename(None)


def test_upload_size_within_limit():
    content = b"test email content"

    validate_upload_size(
        content,
        10,
    )


def test_upload_size_exceeded():
    content = b"x" * (11 * 1024 * 1024)

    with pytest.raises(Exception):
        validate_upload_size(
            content,
            10,
        )


def test_safe_filename():
    result = safe_filename(
        "../../malicious.eml"
    )

    assert result == "malicious.eml"