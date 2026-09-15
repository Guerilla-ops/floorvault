"""Release-artifact invariants.

The wheel and sdist are the things a user downloads, so what they contain and
whether they can be identified matter as much as what the source does.

Measured fact this file exists to protect (see Appendix B of the review report):
the built artifact is a function of the *checkout*, not only of the source. Three
different digests were produced from the same commit - a POSIX checkout with LF,
the same checkout with CRLF (what a Windows runner gets with git's default
``core.autocrlf=true``), and a checkout whose source files carry the executable
bit - plus a fourth on real Windows, which cannot represent POSIX modes at all.

Line endings are the part that can be pinned from inside the repository, so they
are pinned here. File modes cannot be: the build backend records the mode it sees
on the filesystem, and Windows has no POSIX mode bits, so byte-identity across
operating systems is not claimed anywhere.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GITATTRIBUTES = ROOT / ".gitattributes"


def test_line_endings_are_pinned_to_lf():
    """Without this, a Windows checkout rewrites every text file to CRLF.

    Git's Windows default (``core.autocrlf=true``, also the GitHub runner default)
    converts text files on checkout. The build then packs those CRLF bytes, so the
    artifact changes with the checkout: two digests for one commit, and no way to
    compare a download against a build from source. Pinning ``eol=lf`` makes the
    checkout content identical everywhere.
    """
    assert GITATTRIBUTES.exists(), (
        "no .gitattributes: line endings are left to the checkout, so a Windows "
        "build produces different bytes from a POSIX build of the same commit"
    )
    text = GITATTRIBUTES.read_text(encoding="utf-8")
    assert "text=auto" in text.replace(" ", ""), "no text=auto rule"
    assert "eol=lf" in text.replace(" ", ""), (
        ".gitattributes does not force LF; a CRLF checkout would still change the artifact"
    )


def test_no_tracked_file_is_left_to_the_platform_default():
    """A per-extension exclusion could reintroduce the problem silently.

    Any tracked file whose line endings are not pinned is a candidate for a
    platform-dependent artifact, so the policy is checked to cover the files that
    actually ship.
    """
    text = GITATTRIBUTES.read_text(encoding="utf-8") if GITATTRIBUTES.exists() else ""
    for shipped in ("*.py", "*.md", "*.toml", "*.yml", "*.sh"):
        assert not any(
            line.split()[0] == shipped and "eol=lf" not in line
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ), f"{shipped} is exempted from the LF policy"
