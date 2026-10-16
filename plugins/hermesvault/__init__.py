"""hermesvault plugin: local AES-256-SIV agent-secret store as a Hermes secret source.

Registers the ``hermesvault`` secret source (``secrets.hermesvault.env`` maps
env-var names to ``hv:<item_id>[:<field>]`` refs) and the ``hermes hvault``
operator CLI for adding/removing items. The browser-fill login vault at
``<home>/vault`` is never touched — this store lives at
``<home>/agent-vault`` (or ``secrets.hermesvault.dir``) by design.
"""

from __future__ import annotations


def register(ctx) -> None:
    from .source import HermesVaultSource

    ctx.register_secret_source(HermesVaultSource())

    from .cli import hvault_command, register_cli

    ctx.register_cli_command(
        name="hvault",
        help="Manage the hermes-vault agent secret store",
        setup_fn=register_cli,
        handler_fn=hvault_command,
        description=(
            "Operator CLI for the hermesvault secret source. Adds, lists, shows "
            "and removes generic secret items in the local AES-256-SIV vault "
            "that backs secrets.hermesvault.env refs."
        ),
    )
