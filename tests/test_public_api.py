"""Public-API snapshot (roadmap 0e).

Before 1.0 the package surface is the compatibility contract. This test pins
it in both directions: a change that ADDS an export and a change that removes
or re-signs one both fail, so neither can slip through a green suite the way
``LegacyRetiredError`` once sat unexported while SECURITY.md named it.

The snapshot is structural, not textual prose: ``inspect.signature`` renders
string annotations verbatim, so the same source produces the same text on every
supported interpreter. Exception classes record no signature - theirs comes
from ``BaseException`` and is CPython's contract, not ours.
"""

from __future__ import annotations

import inspect

import hermes_vault
from hermes_vault import beacons, vaultkit

EXPECTED_ALL = {
    "AdaptiveKeyProvider",
    "AppStateCrypto",
    "AppStateCryptoError",
    "ContextualSQLite",
    "ContextualTable",
    "DecryptionVerificationError",
    "EncryptedField",
    "EncryptedLibSqlTable",
    "EncryptedMySQLTable",
    "EncryptedPostgresTable",
    "EncryptedSQLiteTable",
    "EncryptedWriteError",
    "FloorVault",
    "FloorVaultError",
    "HardenedMemoryKey",
    "HermesVault",
    "HermesVaultError",
    "HermesVaultStore",
    "KeyProvider",
    "KeyProviderError",
    "KeyRing",
    "LegacyRetiredError",
    "LegacyVaultError",
    "MigratingVaultStore",
    "MissingKeyError",
    "NonceReuseError",
    "RecordBinding",
    "SecurityHardeningError",
    "SqlAlchemyEncryption",
    "UnknownKeyIdError",
    "UnsupportedWriteError",
    "VaultError",
    "VaultItemMeta",
    "VaultStore",
    "associated_data",
    "disable_core_dumps",
    "drop_plaintext_column",
    "get_vault_store",
    "migrate_plaintext_column",
    "recover_master_key",
    "rotate_vault_store",
    "verify_encrypted_column",
    "wrap_master_key",
}

FV_INIT = "(master_key: 'Union[bytes, HardenedMemoryKey]', app_instance_id: 'str' = 'hermes-agent', *, maximum_tracked_nonces: 'int' = 10000, memory_mode: 'str' = 'opportunistic', wipe_source_key: 'bool' = False, hkdf_info: 'bytes' = b'hermes-v1-aes-siv') -> 'None'"
VAULT_STORE_INIT = "(base_dir: 'Path | str', *, crypto: 'Optional[FloorVault]' = None, migrate_legacy_metadata: 'bool' = False)"
VAULT_STORE_METHODS = {
    "add_item": "(self, kind: 'str', label: 'str', secret: 'dict[str, Any]', origin: 'Optional[str]' = None, *, item_id: 'Optional[str]' = None) -> 'VaultItemMeta'",
    "begin_rotation": "(self, target_key_id: 'int', *, target_vault: 'FloorVault') -> 'None'",
    "clear_rotation_journal": "(self) -> 'None'",
    "delete_item": "(self, item_id: 'str') -> 'bool'",
    "get_meta": "(self, item_id: 'str') -> 'Optional[VaultItemMeta]'",
    "get_secret": "(self, item_id: 'str') -> 'dict[str, Any]'",
    "has_items": "(self) -> 'bool'",
    "list_items": "(self) -> 'list[VaultItemMeta]'",
    "list_legacy_retirements": "(self) -> 'dict[str, str]'",
    "mark_rotation_done": "(self, rows: 'Iterable[tuple[str, str, str]]', *, target_key_id: 'int') -> 'None'",
    "read_sealed_item": "(self, item_id: 'str', ring: 'KeyRing') -> 'dict[str, Any]'",
    "remove_item": "(self, item_id: 'str') -> 'bool'",
    "reseal_retirements": "(self, ring: 'KeyRing', *, new_vault: 'FloorVault', key_id: 'int' = 0) -> 'int'",
    "resolve_secret": "(self, item_id: 'str') -> 'dict[str, Any]'",
    "retire_legacy_id": "(self, legacy_id: 'str', modern_id: 'str') -> 'None'",
    "retired_modern_id": "(self, legacy_id: 'str') -> 'Optional[str]'",
    "rotation_journal": "(self) -> 'dict[tuple[str, str, str], tuple[int, str]]'",
    "write_sealed_item": "(self, item_id: 'str', sealed: 'Mapping[str, Any]', *, new_vault: 'FloorVault', key_id: 'int' = 0, journal_rows: 'Optional[Iterable[tuple[str, str, str]]]' = None) -> 'None'",
}
FV_CRYPTO_METHODS = {
    "decrypt": "(self, ciphertext: 'bytes', *, table: 'str', record_id: 'str', column: 'str', schema_id: 'str' = 'hermes.vault.v1', schema_version: 'int' = 1, revision: 'int | None' = None, key_id: 'int | None' = None) -> 'str'",
    "decrypt_bytes": "(self, ciphertext: 'bytes', *, table: 'str', record_id: 'str', column: 'str', schema_id: 'str' = 'hermes.vault.v1', schema_version: 'int' = 1, revision: 'int | None' = None, key_id: 'int | None' = None) -> 'bytes'",
    "decrypt_fields": "(self, fields: 'Mapping[str, bytes]', *, table: 'str', record_id: 'str', schema_id: 'str' = 'hermes.vault.v1', schema_version: 'int' = 1, revision: 'int | None' = None, key_id: 'int | None' = None) -> 'dict[str, bytes]'",
    "encrypt": "(self, plaintext: 'Union[str, bytes, bytearray, memoryview]', *, table: 'str', record_id: 'str', column: 'str', schema_id: 'str' = 'hermes.vault.v1', schema_version: 'int' = 1, revision: 'int | None' = None, key_id: 'int' = 0) -> 'bytes'",
    "encrypt_fields": "(self, fields: 'Mapping[str, Union[str, bytes]]', *, table: 'str', record_id: 'str', schema_id: 'str' = 'hermes.vault.v1', schema_version: 'int' = 1, revision: 'int | None' = None, key_id: 'int' = 0) -> 'dict[str, bytes]'",
    "wipe": "(self) -> 'None'",
}

EXPECTED_SIGNATURES = {
    "AdaptiveKeyProvider": {
        "signature": "(service_name: 'str' = 'hermes-vault', account_name: 'str' = 'default-v1', *, fallback_dir: 'Optional[Path | str]' = None, strict: 'bool' = False, allow_disk_fallback: 'bool' = False, dpapi_entropy: 'Optional[bytes]' = None, allow_legacy_env_vars: 'bool' = False, allow_legacy_adoption: 'bool' = False) -> 'None'",
        "methods": {
            "resolve_key": "(self, *, allow_create: 'bool' = True) -> 'HardenedMemoryKey'",
        },
    },
    "AppStateCrypto": {"signature": FV_INIT, "methods": FV_CRYPTO_METHODS},
    "AppStateCryptoError": {"signature": None, "methods": {}},
    "ContextualSQLite": {
        "signature": "(connection: 'sqlite3.Connection', crypto: 'FloorVault') -> 'None'",
        "methods": {
            "table": "(self, table_name: 'str', *, schema_id: 'str' = 'hermes.vault.v1') -> 'ContextualTable'",
        },
    },
    "ContextualTable": {
        "signature": "(crypto: 'FloorVault', table_name: 'str', *, schema_id: 'str' = 'hermes.vault.v1') -> 'None'",
        "methods": {
            "decrypt": "(self, record_id: 'str', column: 'str', ciphertext: 'bytes', *, schema_version: 'int' = 1) -> 'str'",
            "encrypt": "(self, record_id: 'str', column: 'str', value: 'Union[str, bytes]', *, schema_version: 'int' = 1) -> 'bytes'",
        },
    },
    "DecryptionVerificationError": {"signature": None, "methods": {}},
    "EncryptedField": {
        "signature": "(column_attr: 'str', *, binary: 'bool' = False) -> 'None'",
        "methods": {},
    },
    "EncryptedLibSqlTable": {
        "signature": "(connection: '_LibSqlConnection', crypto: 'FloorVault', table_name: 'str', *, id_column: 'str' = 'id', schema_id: 'str' = 'hermes.vault.v1') -> 'None'",
        "methods": {
            "load": "(self, record_id: 'str', encrypted_column: 'str', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'str'",
            "load_bytes": "(self, record_id: 'str', encrypted_column: 'str', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'bytes'",
            "load_fields": "(self, record_id: 'str', encrypted_columns: 'list[str] | tuple[str, ...]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'dict[str, str]'",
            "load_fields_bytes": "(self, record_id: 'str', encrypted_columns: 'list[str] | tuple[str, ...]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'dict[str, bytes]'",
            "store": "(self, record_id: 'str', encrypted_column: 'str', value: 'Union[str, bytes]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'None'",
            "store_fields": "(self, record_id: 'str', fields: 'Mapping[str, Union[str, bytes]]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'None'",
        },
    },
    "EncryptedMySQLTable": {
        "signature": "(connection: 'DBAPIConnection', crypto: 'FloorVault', table_name: 'str', *, id_column: 'str' = 'id', schema_id: 'str' = 'hermes.vault.v1') -> 'None'",
        "methods": {
            "load": "(self, record_id: 'str', encrypted_column: 'str', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'str'",
            "load_bytes": "(self, record_id: 'str', encrypted_column: 'str', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'bytes'",
            "load_fields": "(self, record_id: 'str', encrypted_columns: 'list[str] | tuple[str, ...]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'dict[str, str]'",
            "load_fields_bytes": "(self, record_id: 'str', encrypted_columns: 'list[str] | tuple[str, ...]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'dict[str, bytes]'",
            "store": "(self, record_id: 'str', encrypted_column: 'str', value: 'Union[str, bytes]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'None'",
            "store_fields": "(self, record_id: 'str', fields: 'Mapping[str, Union[str, bytes]]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'None'",
        },
    },
    "EncryptedPostgresTable": {
        "signature": "(connection: 'DBAPIConnection', crypto: 'FloorVault', table_name: 'str', *, id_column: 'str' = 'id', schema_id: 'str' = 'hermes.vault.v1') -> 'None'",
        "methods": {
            "load": "(self, record_id: 'str', encrypted_column: 'str', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'str'",
            "load_bytes": "(self, record_id: 'str', encrypted_column: 'str', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'bytes'",
            "load_fields": "(self, record_id: 'str', encrypted_columns: 'list[str] | tuple[str, ...]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'dict[str, str]'",
            "load_fields_bytes": "(self, record_id: 'str', encrypted_columns: 'list[str] | tuple[str, ...]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'dict[str, bytes]'",
            "store": "(self, record_id: 'str', encrypted_column: 'str', value: 'Union[str, bytes]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'None'",
            "store_fields": "(self, record_id: 'str', fields: 'Mapping[str, Union[str, bytes]]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'None'",
        },
    },
    "EncryptedSQLiteTable": {
        "signature": "(connection: 'sqlite3.Connection', crypto: 'FloorVault', table_name: 'str', *, id_column: 'str' = 'id', schema_id: 'str' = 'hermes.vault.v1') -> 'None'",
        "methods": {
            "load": "(self, record_id: 'str', encrypted_column: 'str', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'str'",
            "load_bytes": "(self, record_id: 'str', encrypted_column: 'str', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'bytes'",
            "load_fields": "(self, record_id: 'str', encrypted_columns: 'list[str] | tuple[str, ...]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'dict[str, str]'",
            "load_fields_bytes": "(self, record_id: 'str', encrypted_columns: 'list[str] | tuple[str, ...]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'dict[str, bytes]'",
            "store": "(self, record_id: 'str', encrypted_column: 'str', value: 'Union[str, bytes]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'None'",
            "store_fields": "(self, record_id: 'str', fields: 'Mapping[str, Union[str, bytes]]', *, schema_version: 'int' = 1, revision: 'int | None' = None) -> 'None'",
        },
    },
    "EncryptedWriteError": {"signature": None, "methods": {}},
    "FloorVault": {"signature": FV_INIT, "methods": FV_CRYPTO_METHODS},
    "FloorVaultError": {"signature": None, "methods": {}},
    "HermesVault": {"signature": FV_INIT, "methods": FV_CRYPTO_METHODS},
    "HermesVaultError": {"signature": None, "methods": {}},
    "HermesVaultStore": {
        "signature": VAULT_STORE_INIT,
        "methods": VAULT_STORE_METHODS,
    },
    "HardenedMemoryKey": {
        "signature": "(key_bytes: 'bytes', *, mode: 'str' = 'opportunistic') -> 'None'",
        "methods": {
            "from_hex": "(hex_str: 'str', *, mode: 'str' = 'opportunistic') -> 'HardenedMemoryKey'",
            "get_buffer": "(self) -> 'memoryview'",
            "get_bytes": "(self) -> 'bytes'",
            "wipe": "(self) -> 'None'",
        },
    },
    "KeyProvider": {
        "signature": "()",
        "methods": {
            "resolve_key": "(self, *, allow_create: 'bool' = True) -> 'HardenedMemoryKey'",
        },
    },
    "KeyProviderError": {"signature": None, "methods": {}},
    "KeyRing": {
        "signature": "(keys: 'Mapping[int, FloorVault]', *, default_key_id: 'Optional[int]' = None) -> 'None'",
        "methods": {
            "decrypt": "(self, ciphertext: 'bytes', *, table: 'str', record_id: 'str', column: 'str', schema_id: 'str' = 'hermes.vault.v1', schema_version: 'int' = 1, revision: 'Optional[int]' = None) -> 'str'",
            "decrypt_bytes": "(self, ciphertext: 'bytes', *, table: 'str', record_id: 'str', column: 'str', schema_id: 'str' = 'hermes.vault.v1', schema_version: 'int' = 1, revision: 'Optional[int]' = None) -> 'bytes'",
            "key_ids": "(self) -> 'tuple[int, ...]'",
        },
    },
    "LegacyRetiredError": {"signature": None, "methods": {}},
    "LegacyVaultError": {"signature": None, "methods": {}},
    "MigratingVaultStore": {
        "signature": "(*, modern_store: 'VaultStore', legacy_base_dir: 'Path | str', legacy_vault_name: 'str' = 'vault.json.enc', legacy_key_name: 'str' = 'vault.key', backup_suffix: 'str' = '.pre-migration.bak') -> 'None'",
        "methods": {
            "get_meta": "(self, item_id: 'str') -> 'Optional[Any]'",
            "has_items": "(self) -> 'bool'",
            "list_item_ids": "(self) -> 'list[str]'",
            "list_items": "(self) -> 'list[Any]'",
            "migrate_all": "(self) -> 'dict[str, Any]'",
            "resolve_secret": "(self, item_id: 'str') -> 'dict[str, Any]'",
            "verify": "(self) -> 'bool'",
        },
    },
    "MissingKeyError": {"signature": None, "methods": {}},
    "NonceReuseError": {"signature": None, "methods": {}},
    "RecordBinding": {
        "signature": "(crypto: 'FloorVault', table: 'str', schema_id: 'str' = 'hermes.vault.v1', schema_version: 'int' = 1) -> None",
        "methods": {
            "decrypt_field": "(self, record_id: 'str', column: 'str', ciphertext: 'bytes', *, schema_version: 'int | None' = None, revision: 'int | None' = None, key_id: 'int | None' = None) -> 'str'",
            "decrypt_field_bytes": "(self, record_id: 'str', column: 'str', ciphertext: 'bytes', *, schema_version: 'int | None' = None, revision: 'int | None' = None, key_id: 'int | None' = None) -> 'bytes'",
            "decrypt_fields": "(self, record_id: 'str', envelopes: 'Mapping[str, bytes]', *, schema_version: 'int | None' = None, revision: 'int | None' = None, key_id: 'int | None' = None) -> 'dict[str, bytes]'",
            "encrypt_field": "(self, record_id: 'str', column: 'str', value: 'Union[str, bytes]', *, schema_version: 'int | None' = None, revision: 'int | None' = None, key_id: 'int' = 0) -> 'bytes'",
            "encrypt_fields": "(self, record_id: 'str', fields: 'Mapping[str, Union[str, bytes]]', *, schema_version: 'int | None' = None, revision: 'int | None' = None, key_id: 'int' = 0) -> 'dict[str, bytes]'",
        },
    },
    "SecurityHardeningError": {"signature": None, "methods": {}},
    "SqlAlchemyEncryption": {
        "signature": "(crypto: 'FloorVault', *, schema_id: 'str' = 'hermes.vault.v1', schema_version: 'int' = 1) -> 'None'",
        "methods": {
            "is_protected": "(self, model: 'type') -> 'bool'",
            "protect": "(self, model: 'type', *, id_attr: 'str', fields: 'dict[str, EncryptedField | str]', tenant_attr: 'str | None' = None, revision_attr: 'str | None' = None) -> 'type'",
            "session_factory": "(self, **kwargs) -> 'sessionmaker'",
        },
    },
    "UnknownKeyIdError": {"signature": None, "methods": {}},
    "UnsupportedWriteError": {"signature": None, "methods": {}},
    "VaultError": {"signature": None, "methods": {}},
    "VaultItemMeta": {
        "signature": "(id: 'str', kind: 'str', label: 'str', origin: 'Optional[str]', created_at: 'str', identifier_type: 'Optional[str]' = None, identifier: 'Optional[str]' = None, has_otp: 'bool' = False) -> None",
        "methods": {
            "to_dict": "(self) -> 'dict[str, Any]'",
        },
    },
    "VaultStore": {
        "signature": VAULT_STORE_INIT,
        "methods": VAULT_STORE_METHODS,
    },
    "associated_data": {
        "signature": "(*, table: 'str', record_id: 'str', column: 'str', schema_id: 'str' = 'hermes.vault.v1', schema_version: 'int' = 1, app_instance_id: 'str' = 'hermes-agent', revision: 'int | None' = None) -> 'bytes'"
    },
    "disable_core_dumps": {"signature": "() -> 'bool'"},
    "drop_plaintext_column": {
        "signature": "(connection: 'sqlite3.Connection', *, table: 'str', column: 'str', vacuum: 'bool' = False) -> 'dict[str, Any]'"
    },
    "get_vault_store": {
        "signature": "(base_dir: 'Optional[Path | str]' = None, *, auto_migrate: 'bool' = True)"
    },
    "migrate_plaintext_column": {
        "signature": "(connection: 'sqlite3.Connection', crypto: 'FloorVault', *, table: 'str', id_column: 'str', source_column: 'str', destination_column: 'str') -> 'dict[str, int]'"
    },
    "recover_master_key": {
        "signature": "(bundle: 'bytes | bytearray', recovery_key: 'bytes | bytearray', *, memory_mode: 'str' = 'opportunistic') -> 'HardenedMemoryKey'"
    },
    "rotate_vault_store": {
        "signature": "(store: 'VaultStore', *, source_ring: 'KeyRing', new_vault: 'FloorVault', new_key_id: 'int') -> 'dict[str, int]'"
    },
    "verify_encrypted_column": {
        "signature": "(connection: 'sqlite3.Connection', crypto: 'FloorVault', *, table: 'str', id_column: 'str', source_column: 'str', destination_column: 'str') -> 'int'"
    },
    "wrap_master_key": {
        "signature": "(master_key: 'bytes | bytearray', recovery_key: 'bytes | bytearray') -> 'bytes'"
    },
}

SUBMODULE_ALL = {
    "hermes_vault.beacons": {
        "MAX_BEACON_BITS",
        "MIN_BEACON_BITS",
        "BeaconIndexer",
        "beacon_bucket_bytes",
        "beacon_matches",
        "compute_beacon",
        "derive_beacon_key",
        "suggest_beacon_bits",
    },
    "hermes_vault.vaultkit": {
        "SessionCrypto",
        "VaultError",
        "VaultItemMeta",
        "VaultStore",
        "get_vault_store",
        "normalize_origin",
        "normalize_otp_secret",
        "scrub_secret_from_text",
        "scrub_secrets_for_fts",
        "totp_now",
    },
}


def _sig(callable_obj) -> str | None:
    try:
        return str(inspect.signature(callable_obj))
    except (ValueError, TypeError):
        return None


def _collect():
    snapshot = {}
    for name in sorted(hermes_vault.__all__):
        obj = getattr(hermes_vault, name)
        if inspect.isclass(obj):
            if issubclass(obj, BaseException):
                snapshot[name] = {"signature": None, "methods": {}}
                continue
            methods = sorted(
                n for n, _ in inspect.getmembers(obj, callable) if not n.startswith("_")
            )
            snapshot[name] = {
                "signature": _sig(obj),
                "methods": {m: _sig(getattr(obj, m)) for m in methods},
            }
        elif callable(obj):
            snapshot[name] = {"signature": _sig(obj)}
    return snapshot


def test_top_level_exports_match_the_snapshot():
    assert set(hermes_vault.__all__) == EXPECTED_ALL


def test_public_signatures_match_the_snapshot():
    assert _collect() == EXPECTED_SIGNATURES


def test_submodule_exports_match_the_snapshot():
    assert set(beacons.__all__) == SUBMODULE_ALL["hermes_vault.beacons"]
    assert set(vaultkit.__all__) == SUBMODULE_ALL["hermes_vault.vaultkit"]
