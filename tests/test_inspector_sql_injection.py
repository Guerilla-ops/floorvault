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
        capture_output=True, text=True,
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
    blob = fv.encrypt(plaintext, table=coords["table"], record_id=coords["record_id"], column="payload_cipher")
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
    assert "not a valid" in (result.stderr + result.stdout) or "denied" in (result.stderr + result.stdout)


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
