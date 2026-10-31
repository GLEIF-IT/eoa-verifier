"""runtime/test_config.py."""

from dataclasses import replace

import pytest


@pytest.mark.parametrize(
    "relative_uri",
    [
        "",
        "/hook?memo=a%20b",
        "/hook?tag=a&tag=b",
        "/hook?debug",
        "/ho%6Fk",
        "//hook",
    ],
)
def test_webhook_url_must_survive_hio_rendering(config, relative_uri):
    """Reject rewritten path/query spellings before stores or delivery obligations exist."""
    with pytest.raises(ValueError, match="HIO.*path/query"):
        replace(
            config,
            webhook_url="http://127.0.0.1:9999" + relative_uri,
            webhook_aid=config.trusted_geda_aid,
        )
