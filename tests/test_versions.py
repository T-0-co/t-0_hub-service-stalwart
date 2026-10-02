"""The version stamps must match (the hub shows the manifest version, humans read the changelog)."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

from stalwart_mcp import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_all_version_stamps_match():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    changelog = re.search(r"^## \[(\d+\.\d+\.\d+)\]", (ROOT / "CHANGELOG.md").read_text(), re.M).group(1)
    manifests = [
        yaml.safe_load((ROOT / "service.yaml").read_text())["version"],
        yaml.safe_load((ROOT / "manifests" / "stalwart-admin" / "service.yaml").read_text())["version"],
    ]
    assert {__version__, pyproject, changelog, *manifests} == {__version__}
