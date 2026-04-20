"""Reporter base class."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pqc_lint.findings import ScanReport


class Reporter(ABC):
    format_name: str = ""

    @abstractmethod
    def render(self, report: ScanReport) -> str:
        ...
