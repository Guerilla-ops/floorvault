"""Strict, optional YAML parsing for the destructive Hermes migration check."""

from __future__ import annotations


def load_hermes_config(text: str) -> dict:
    """Return the enabled plugin section; errors never include YAML input values."""
    try:
        import yaml
    except ImportError:
        raise ValueError(
            "YAML validation requires PyYAML; install floorvault[hermes] before removing .env entries"
        ) from None

    class UniqueSafeLoader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            # Reject ambiguous mappings, including overlapping YAML merges, rather
            # than guessing which configuration the host will use.
            self.flatten_mapping(node)
            seen = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=deep)
                try:
                    if key in seen:
                        raise ValueError("config.yaml contains duplicate mapping keys")
                    seen.add(key)
                except TypeError:
                    raise ValueError("config.yaml contains an invalid mapping key") from None
            return super().construct_mapping(node, deep=deep)

    loader = UniqueSafeLoader(text)
    try:
        data = loader.get_single_data()
    except (yaml.YAMLError, RecursionError):
        raise ValueError("config.yaml is not valid, unambiguous YAML") from None
    finally:
        loader.dispose()
    if not isinstance(data, dict):
        raise ValueError("config.yaml must contain a secrets.hermesvault mapping")
    if (
        "max_turns" in data
        and data.get("agent") is not None
        and not isinstance(data.get("agent"), dict)
    ):
        # Hermes relocates root max_turns by converting agent to a dict. Its
        # loader falls back to defaults if this known combination is malformed.
        raise ValueError("config.yaml has root max_turns but agent must be a mapping")
    for name in ("secrets", "hermesvault"):
        if not isinstance(data, dict):
            raise ValueError("config.yaml must contain a secrets.hermesvault mapping")
        data = data.get(name)
    if not isinstance(data, dict) or data.get("enabled") is not True:
        raise ValueError("secrets.hermesvault.enabled must be true")
    if not isinstance(data.get("env"), dict):
        raise ValueError("secrets.hermesvault.env must be a mapping")
    return data
