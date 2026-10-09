"""Regression tests for the inspector CLI (H1: raw SQL identifier interpolation).

The old code built queries via f-string interpolation of table/column names
(``f"SELECT {args.column} FROM {args.table} WHERE id = ?"``), which is a SQL
injection sink: an attacker-controlled column/table value could graft arbitrary
SQL. The fix must refuse non-identifier names (deny-first) so no untrusted
value ever reaches the SQL text.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INSPECTOR = REPO_ROOT / "src" / "floorvault" / "inspector.py"


def _write_sample_db(path: Path) -> dict[str, str]:
    """Build a tiny encrypted store (plaintext SQLite is enough for the CLI
    inspect path to reach the column/table construction), returning the
    AAD-coordinate strings the CLI needs."""
    import os

    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE vault_items (id TEXT, payload_cipher BLOB, label TEXT)")
    conn.execute(
        "INSERT INTO vault_items (id, payload_cipher, label) VALUES (?, ?, ?)",
        ("r1", os.urandom(32), "secret-label"),
    )
    conn.commit()
    conn.close()
    return {"table": "vault_items", "record_id": "r1", "column": "label"}


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    import os

    env = {
        **os.environ,
        "APPSTATE_KEY": "a" * 64,
        "PYTHONPATH": str(REPO_ROOT / "src"),
    }
    return subprocess.run(
        [sys.executable, "-m", "floorvault.inspector", *argv],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )


def test_good_identifier_inspected(tmp_path):
    from floorvault.core import FloorVault
    from floorvault.memory import HardenedMemoryKey

    db = tmp_path / "v.db"
    coords = _write_sample_db(db)
    # Encrypt a value and store it in the payload_cipher column so the CLI
    # inspect path finds real ciphertext to decrypt.
    fv = FloorVault(HardenedMemoryKey(bytes.fromhex("a" * 64)))
    plaintext = "encrypted-value"
    blob = fv.encrypt(
        plaintext, table=coords["table"], record_id=coords["record_id"], column="payload_cipher"
    )
    conn = sqlite3.connect(db)
    conn.execute("UPDATE vault_items SET payload_cipher=? WHERE id=?", (blob, coords["record_id"]))
    conn.commit()
    conn.close()
    result = _run(["inspect", str(db), coords["table"], coords["record_id"], "payload_cipher"])
    assert result.returncode == 0
    assert plaintext in result.stdout


def test_sql_injection_column_name_refused(tmp_path):
    db = tmp_path / "v.db"
    coords = _write_sample_db(db)
    evil = "label FROM vault_items --"
    result = _run(["inspect", str(db), coords["table"], "r1", evil])
    # Deny-first: the hostile identifier must NOT execute; it must be rejected
    # as a non-identifier before reaching SQL text.
    assert result.returncode != 0
    assert "not a valid" in (result.stderr + result.stdout) or "denied" in (
        result.stderr + result.stdout
    )


def test_sql_injection_table_name_refused(tmp_path):
    db = tmp_path / "v.db"
    coords = _write_sample_db(db)
    evil = "vault_items; DROP TABLE vault_items; --"
    result = _run(["inspect", str(db), evil, coords["record_id"], coords["column"]])
    assert result.returncode != 0
    # Table still intact.
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    conn.close()
    assert ("vault_items",) in rows


def test_inspect_never_creates_a_key_for_unknown_service(tmp_path):
    """A typo'd --service-name must error, not mint custody (read-only path).

    Before the fix, ``resolve_key()`` ran with the default
    ``allow_create=True``: an absent service name produced a fresh
    Keychain/Secret-Service/file key seconds before decryption failed.
    Resolution now runs ``allow_create=False`` and only after ciphertext
    exists, so the failure is a clean ``Error:`` with nothing created.
    """
    import os

    db = tmp_path / "v.db"
    coords = _write_sample_db(db)
    fake_home = tmp_path / "isolated-home"
    fake_home.mkdir()
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src"), "HOME": str(fake_home)}
    for var in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        env.pop(var, None)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "floorvault.inspector",
            "inspect",
            str(db),
            coords["table"],
            coords["record_id"],
            "payload_cipher",
            "--service-name",
            f"fv-inspect-test-absent-{os.getpid()}",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )

    assert result.returncode == 1
    assert "Error:" in result.stderr
    assert "Traceback" not in result.stderr
    assert not list(fake_home.rglob("*.key"))


def test_plaintext_value_is_not_echoed(tmp_path):
    """A non-ciphertext cell must be reported by shape, never by content.

    The inspector previously printed ``Plaintext: {value}`` for cells that
    were not binary ciphertext — a diagnostic that exfiltrates stored secrets
    to the terminal. The safe behavior is to report the type only.
    """
    db = tmp_path / "v.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE vault_items (id TEXT, payload_cipher BLOB, label TEXT)")
    conn.execute(
        "INSERT INTO vault_items (id, payload_cipher, label) VALUES (?, ?, ?)",
        ("r1", b"x" * 40, "SECRET-VALUE-9f3b"),
    )
    conn.commit()
    conn.close()

    result = _run(["inspect", str(db), "vault_items", "r1", "label"])
    assert result.returncode == 0
    assert "SECRET-VALUE-9f3b" not in result.stdout
    assert "not binary ciphertext" in result.stdout
