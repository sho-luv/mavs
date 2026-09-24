"""Analyzer registry. Each analyzer maps a context to a list of findings."""

from __future__ import annotations

from collections.abc import Callable

from mavs_scan.analyzers import (
    binary,
    certificate,
    code,
    framework,
    managed_keys,
    manifest,
    network,
    permissions,
    secrets,
    trackers,
)
from mavs_scan.context import ScanContext
from mavs_scan.model import Finding

Analyzer = Callable[[ScanContext], list[Finding]]

ANALYZERS: tuple[Analyzer, ...] = (
    manifest.analyze,
    permissions.analyze,
    certificate.analyze,
    code.analyze,
    network.analyze,
    binary.analyze,
    trackers.analyze,
    secrets.analyze,
    framework.analyze,
    managed_keys.analyze,
)
