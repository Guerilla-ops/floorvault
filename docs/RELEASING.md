# Release policy and process

This document defines FloorVault's versioning contract and how a release is
produced. It is the policy; `.github/workflows/release.yml` is the machinery.

## Versioning

FloorVault follows Semantic Versioning.

- **Before 1.0 (`0.x`)**: the wire format is frozen per `docs/SPEC.md`, but the
  Python API may change in minor releases. Breaking API changes are announced
  in the release notes. The public surface is pinned by
  `tests/test_public_api.py` — a change to it is deliberate and reviewable,
  never incidental.
- **From 1.0**: breaking API changes require a major version bump. Additive
  changes (new exports, new optional parameters) are minor; fixes are patch.
- **Deprecations**: a public name scheduled for removal emits
  `DeprecationWarning` for at least one full minor series before removal.
- **Wire format**: envelope versions are versioned independently of the Python
  version. New envelope versions are additive on write; readers must keep
  accepting every previously published version (v1 and v2 today).

## Release process

1. Land all intended changes on `main` with the full gate green.
2. Update `version` in `pyproject.toml` (release PR, reviewed normally).
3. Create a GitHub release with tag `vX.Y.Z`. Publishing the release triggers
   `release.yml`, which:
   - builds the wheel and sdist **twice** and requires byte-identical digests
     (same-runner reproducibility check);
   - verifies the universal-wheel shape (`scripts/verify_wheel.py`);
   - generates a CycloneDX SBOM of the runtime dependency set;
   - attests build provenance via GitHub artifact attestation (Sigstore);
   - publishes to PyPI via Trusted Publishing with PEP 740 attestations.
4. The release notes MUST carry the SHA-256 digests printed by the workflow.

## Verifying a download

- `pip download floorvault==X.Y.Z` and compare the wheel's SHA-256 against the
  digest in the release notes (the ubuntu CI leg's `floorvault-dist` artifact
  is the release identity — see the artifact-identity note in `SECURITY.md`).
- `gh attestation verify <wheel> --repo Guerilla-ops/floorvault` verifies the
  build-provenance attestation.
- PyPI PEP 740 attestations verify against Sigstore via `pypi.org` integrity
  endpoints or `pip audit`.

## Owner-side prerequisites (one-time, inert until done)

Publishing is disabled by construction until all of these exist:

1. PyPI project/name registration for `floorvault`.
2. A PyPI **Trusted Publisher** entry: repo `Guerilla-ops/floorvault`,
   workflow `release.yml`, environment `pypi`.
3. A GitHub environment named `pypi` (optionally with required reviewers).
4. The maintainer's PyPI account as the only publisher.

Until (1)–(3) exist, a real `release: published` run fails at the publish
step; `workflow_dispatch` rehearsals exercise everything except publishing.
