"""F-1: scrub_secrets_for_fts must remove common credential formats.

The scrubber previously covered only sk- keys, GitHub tokens, Bearer tokens and
raw hex. It missed AWS access keys, Slack tokens, credential-bearing URIs and
JWTs, while its docstring claimed the FTS index would contain "zero
credentials". These tests pin the expanded pattern set and the honest
best-effort framing.

The sample secrets below are deliberately constructed from parts (rather than
written as continuous literals) so the file itself does not trip the pre-push
gitleaks secret scanner while still exercising the scrubber with realistic
values.
"""

from __future__ import annotations

from floorvault.vaultkit.session_crypto import scrub_secrets_for_fts


def _aws_access_key() -> str:
    return "AKIA" + "IOSFODNN7EXAMPLE"


def _slack_token() -> str:
    prefix = "xox" + "b-"
    body = "123456789012" + "-" + "1234567890123" + "-" + "abcdefghijklmnopqrstuvwx"
    return prefix + body


def _jwt() -> str:
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    return f"{header}.{payload}.{signature}"


def test_scrub_removes_aws_access_key():
    key = _aws_access_key()
    out = scrub_secrets_for_fts("aws_access_key_id=" + key)
    assert key not in out
    assert "[REDACTED_SECRET]" in out


def test_scrub_removes_slack_token():
    token = _slack_token()
    out = scrub_secrets_for_fts("slack token " + token)
    assert "xoxb-" not in out
    assert "[REDACTED_SECRET]" in out


def test_scrub_removes_uri_credentials():
    out = scrub_secrets_for_fts("connect to https://user:supersecret@example.com/db")
    assert "supersecret" not in out
    assert "[REDACTED_SECRET]" in out


def test_scrub_removes_jwt():
    jwt = _jwt()
    out = scrub_secrets_for_fts(f"token {jwt}")
    assert jwt not in out
    assert "[REDACTED_SECRET]" in out


def test_scrub_keeps_ordinary_text():
    text = "The quick brown fox jumps over the lazy dog."
    assert scrub_secrets_for_fts(text) == text


def test_a_hex_secret_longer_than_64_digits_is_removed_whole():
    """The pattern stopped at 64 digits and left the rest of a longer key behind."""
    long_key = "ab12" * 20  # 80 hex digits: a 40-byte key
    scrubbed = scrub_secrets_for_fts(f"key {long_key} end")
    assert "ab12" not in scrubbed and scrubbed.endswith(" end")


def test_a_value_that_starts_another_does_not_leave_the_others_tail():
    from floorvault.vaultkit.vault import scrub_secret_from_text

    short, long = "hunter2", "hunter2" + "-EXTRA-TAIL-9f3a"
    for secret in ({"password": short, "api_key": long}, {"api_key": long, "password": short}):
        scrubbed = scrub_secret_from_text(f"auth failed for {long}", secret)
        assert scrubbed == "auth failed for [REDACTED]"


def test_a_secret_stored_as_a_number_is_scrubbed_too():
    from floorvault.vaultkit.vault import scrub_secret_from_text

    assert scrub_secret_from_text("pin 4821 rejected", {"pin": 4821, "on": True}) == (
        "pin [REDACTED] rejected"
    )
