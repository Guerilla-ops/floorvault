# HermesVault reliability

Approved scope: reliability improvements and a PR for Guerilla-ops/floorvault.

Validate parsed config.yaml before plaintext removal: require an enabled source,
correct nested references, matching store directory, and successful decryption
using the plugin's prospective environment/key route. Reject ambiguous duplicate
YAML keys and the known Hermes max_turns/agent fallback combination. Preserve existing atomic .env replacement and non-removal import behavior.
Add `hermes hvault doctor` to report configuration, missing stores, unresolved
mappings and existing-environment precedence without printing credentials.
Validate CLI identifiers and safely serialize mapping output; stop masking config
load errors and avoid exposing exception payloads or malformed secret input.

Approaches: targeted reliability work is selected by the user; custody extensions
and backup/restore are deferred. Retain the Hermes secret-source contract and
partial mapping success. Keep YAML optional for core users, with an explicit
Hermes extra and actionable failure when unavailable. Native key-store and live
provider verification remain outside automated tests; use temporary stores/keys.

The migration guard validates the raw profile file and the HermesVault-specific section. It does not run Hermes' full version-specific normalization or managed overlay, so other unrelated host configuration errors can still make Hermes fall back. State this limit in operator guidance.
