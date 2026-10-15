"""Local-data scan for a built bundle (used by verify_build.py). Standard library only.

Goal: the bundle must contain nothing from the machine that built it: no source-tree path, no
build user name, no computer name. Matching is byte-level, case-insensitive, in UTF-8 and UTF-16LE.

Attribution rule (M1.5 CI finding, 2026-10-15). Third-party binaries can contain THEIR OWN
upstream build paths. pydantic-core's Windows wheel embeds 133 Rust source paths of the form
``C:\\Users\\runneradmin\\.cargo\\registry\\...``, written by its upstream GitHub Actions build.
On a GitHub-hosted Windows runner our build user is also ``runneradmin``, so a bare user-name
match is a false positive there. Therefore:

- Source-path needles fail in EVERY file. No exception.
- Identity needles (user name, computer name) fail in every file EXCEPT a file whose bytes are
  verifiably identical (SHA-256) to the file recorded in the RECORD of an installed, locked
  runtime distribution. Such a file is published upstream content (the wheel is hash-locked in
  uv.lock) and cannot contain data from this build. Every such match is still reported.
- Files that differ from their RECORD hash, files not in any RECORD (our executables, the archive,
  generated files), and files of non-runtime distributions get no exception.
"""

import base64
import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

INTERNAL = "_internal/"
# Written by PyInstaller during OUR build; never upstream wheel content.
BUILD_GENERATED = frozenset({"base_library.zip"})


@dataclass(frozen=True, slots=True)
class WheelFile:
    sha256: str  # hex
    distribution: str


@dataclass
class ScanResult:
    source_path_hits: list[str] = field(default_factory=list)
    identity_hits: list[str] = field(default_factory=list)
    attributed_upstream: list[tuple[str, str]] = field(default_factory=list)  # (file, dist)

    @property
    def ok(self) -> bool:
        return not self.source_path_hits and not self.identity_hits


def _patterns(needles: Iterable[str]) -> list[bytes]:
    out: list[bytes] = []
    for n in needles:
        if not n:
            continue
        for enc in ("utf-8", "utf-16-le"):
            raw = n.encode(enc)
            out += [raw, n.lower().encode(enc)]
    return out


def _matches(data: bytes, patterns: list[bytes]) -> bool:
    low = data.lower()
    return any(p in data or p in low for p in patterns)


def parse_record(text: str) -> dict[str, str]:
    """RECORD lines ``path,sha256=<urlsafe b64>,size`` -> {path: hex digest}. Unhashed: skipped."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.rsplit(",", 2)
        if len(parts) != 3 or not parts[1].startswith("sha256="):
            continue
        b64 = parts[1][len("sha256=") :]
        try:
            raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), altchars=b"-_", validate=True)
        except ValueError:
            continue
        if len(raw) != 32:  # a SHA-256 digest; anything else is malformed and never trusted
            continue
        out[parts[0].replace("\\", "/")] = raw.hex()
    return out


def normalize_distribution(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(".", "-")


def wheel_index(records: Mapping[str, str], allowed: Iterable[str]) -> dict[str, WheelFile]:
    """{distribution: RECORD text} -> {site-packages relative path: WheelFile}.

    Only ``allowed`` distributions (the locked runtime set) contribute. Each entry binds ONE path to
    ONE hash: a bundled file is matched by its own path, so a hash recorded for another file can
    never authorize it. A path recorded by two distributions with different hashes is ambiguous and
    is dropped (no exemption).
    """
    permitted = {normalize_distribution(a) for a in allowed}
    index: dict[str, WheelFile] = {}
    ambiguous: set[str] = set()
    for dist, text in records.items():
        name = normalize_distribution(dist)
        if name not in permitted:
            continue
        for path, digest in parse_record(text).items():
            known = index.get(path)
            if known is not None and known.sha256 != digest:
                ambiguous.add(path)
            index[path] = WheelFile(digest, name)
    for path in ambiguous:
        del index[path]
    return index


def upstream_identical(relpath: str, data: bytes, index: Mapping[str, WheelFile]) -> str | None:
    """Distribution name if ``relpath`` (bundle-relative) is byte-identical to its wheel file."""
    if not relpath.startswith(INTERNAL):
        return None  # our executables and generated top-level files are never upstream content
    inner = relpath[len(INTERNAL) :]
    # Wheel files always live inside a package directory. Top-level _internal files (the Python
    # runtime, base_library.zip, ...) come from the build, not from a wheel: never exempt.
    if "/" not in inner or inner.lower() in BUILD_GENERATED:
        return None
    entry = index.get(inner)
    if entry is None or hashlib.sha256(data).hexdigest() != entry.sha256:
        return None
    return entry.distribution


def scan(
    files: Iterable[tuple[str, bytes]],
    *,
    source_needles: Iterable[str],
    identity_needles: Iterable[str],
    index: Mapping[str, WheelFile],
) -> ScanResult:
    source = _patterns(source_needles)
    identity = _patterns(n for n in identity_needles if len(n) >= 4)
    result = ScanResult()
    for relpath, data in files:
        if _matches(data, source):
            result.source_path_hits.append(relpath)
        if identity and _matches(data, identity):
            dist = upstream_identical(relpath, data, index)
            if dist is None:
                result.identity_hits.append(relpath)
            else:
                result.attributed_upstream.append((relpath, dist))
    return result


def bundle_files(bundle: Path) -> Iterable[tuple[str, bytes]]:
    for path in sorted(bundle.rglob("*")):
        if path.is_file():
            yield path.relative_to(bundle).as_posix(), path.read_bytes()
