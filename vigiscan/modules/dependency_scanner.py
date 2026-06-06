"""Local dependency manifest scanner."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any


SUPPORTED_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "composer.json",
    "package-lock.json",
}


def scan_dependency_file(path: str | Path, *, cve_index: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Extract dependencies from a supported manifest and match local CVE data."""
    file_path = Path(path)
    dependencies = extract_dependencies(file_path)
    return {
        "module": "dependency_scanner",
        "ok": True,
        "source": str(file_path),
        "dependencies": dependencies,
        "cve_matches": match_local_cves(dependencies, cve_index or []),
    }


def extract_dependencies(path: Path) -> list[dict[str, str | None]]:
    """Extract dependency names and pinned versions when present."""
    if path.name == "requirements.txt":
        return _requirements(path.read_text(encoding="utf-8", errors="ignore"))
    if path.name == "pyproject.toml":
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
        values = data.get("project", {}).get("dependencies", [])
        return [_split_requirement(str(item)) for item in values]
    if path.name in {"package.json", "package-lock.json"}:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        deps = data.get("dependencies", {})
        deps.update(data.get("devDependencies", {}))
        return [{"name": name, "version": str(version)} for name, version in deps.items()]
    if path.name == "composer.json":
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        deps = data.get("require", {})
        return [{"name": name, "version": str(version)} for name, version in deps.items()]
    return []


def discover_manifests(root: str | Path) -> list[Path]:
    """Find supported dependency manifests below a root directory."""
    root_path = Path(root)
    return [path for path in root_path.rglob("*") if path.name in SUPPORTED_FILES]


def match_local_cves(
    dependencies: list[dict[str, str | None]],
    cve_index: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Relate dependencies to a provided local CVE index."""
    matches = []
    for dependency in dependencies:
        name = str(dependency.get("name", "")).lower()
        version = str(dependency.get("version") or "")
        for cve in cve_index:
            product = str(cve.get("product", "")).lower()
            affected = str(cve.get("affected_version", cve.get("version", "")))
            if product and product in name and (not affected or affected in version):
                matches.append({"dependency": dependency, "cve": cve})
    return matches


def _requirements(content: str) -> list[dict[str, str | None]]:
    return [
        _split_requirement(line.strip())
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _split_requirement(value: str) -> dict[str, str | None]:
    parts = re.split(r"==|>=|<=|~=|>|<", value, maxsplit=1)
    return {
        "name": parts[0].strip(),
        "version": parts[1].strip() if len(parts) > 1 else None,
    }
