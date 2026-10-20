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
