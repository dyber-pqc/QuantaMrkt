"""Assertion: permitted usage of this content (c2pa.usage)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from pqc_content_provenance.assertions.base import Assertion


@dataclass
class UsageAssertion(Assertion):
    """How this generated content may be used."""

    label: ClassVar[str] = "c2pa.usage"

    license: str = "all-rights-reserved"        # spdx identifier or custom string
    commercial_use: bool = False
    attribution_required: bool = True
    attribution_text: str = ""                  # what credit must say
    jurisdictions: list[str] = field(default_factory=list)    # countries where valid
    expiry: str = ""                            # ISO-8601 or empty
