"""End-to-end integration tests for SQLite with contextual encryption and blind indexing."""

import sqlite3

import pytest

from floorvault import ContextualSQLite, DecryptionVerificationError, FloorVault


@pytest.fixture
def memory_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE credentials (
            id TEXT PRIMARY KEY,
            secret_cipher BLOB NOT NULL,
            account_idx BLOB NOT NULL
        )
    """)
    conn.execute("CREATE INDEX idx_account ON credentials(account_idx)")
    yield conn
    conn.close()


def test_sqlite_contextual_encryption_and_blind_search(memory_db):
    master_key = b"\xaa" * 32
    crypto = FloorVault(master_key, app_instance_id="inst-sql-1", memory_mode="disabled")
    db = ContextualSQLite(memory_db, crypto)

    cred_table = db.table("credentials")

    # Insert 3 records
    accounts = [
        ("user-1", "user1@company.com", "topsecret-token-1"),
        ("user-2", "user2@company.com", "topsecret-token-2"),
        ("admin-1", "admin@company.com", "master-admin-token"),
    ]

    for rec_id, email, secret in accounts:
        cipher = cred_table.encrypt(rec_id, "secret", secret)
        idx = cred_table.blind_index("account", email)
        memory_db.execute(
            "INSERT INTO credentials (id, secret_cipher, account_idx) VALUES (?, ?, ?)",
            (rec_id, cipher, idx),
        )

    # 1. Blind index exact-match query (simulates zero-leakage search)
    search_email = "admin@company.com"
    search_idx = cred_table.blind_index("account", search_email)

    cursor = memory_db.execute(
        "SELECT id, secret_cipher FROM credentials WHERE account_idx = ?", (search_idx,)
    )
    row = cursor.fetchone()
    assert row is not None
    assert row[0] == "admin-1"

    # Decrypt recovered secret
    decrypted_secret = cred_table.decrypt(row[0], "secret", row[1])
    assert decrypted_secret == "master-admin-token"


def test_sqlite_tamper_detection(memory_db):
    crypto = FloorVault(b"\xbb" * 32, memory_mode="disabled")
    db = ContextualSQLite(memory_db, crypto)
    table = db.table("credentials")

    # Store user1 and user2
    c1 = table.encrypt("user-1", "secret", "user1-secret")
    c2 = table.encrypt("user-2", "secret", "user2-secret")

    memory_db.execute("INSERT INTO credentials VALUES ('user-1', ?, X'00')", (c1,))
    memory_db.execute("INSERT INTO credentials VALUES ('user-2', ?, X'01')", (c2,))

    # Malicious tamper: attacker copies user1's ciphertext into user2's row
    memory_db.execute("UPDATE credentials SET secret_cipher = ? WHERE id = 'user-2'", (c1,))

    # Reading user2 must now fail verification
    row = memory_db.execute(
        "SELECT id, secret_cipher FROM credentials WHERE id = 'user-2'"
    ).fetchone()
    with pytest.raises(DecryptionVerificationError, match="Data was tampered with"):
        table.decrypt(row[0], "secret", row[1])
