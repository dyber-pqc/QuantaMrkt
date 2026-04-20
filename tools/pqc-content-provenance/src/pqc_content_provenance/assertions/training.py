"""Assertion: training data summary (c2pa.training)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from pqc_content_provenance.assertions.base import Assertion


@dataclass
class TrainingAssertion(Assertion):
    """What training data produced the model that generated this output."""

    label: ClassVar[str] = "c2pa.training"

    dataset_name: str = ""                      # e.g. "common-crawl-2024"
    dataset_root_hash: str = ""                 # Merkle root over training data
    fine_tune_dataset: str = ""                 # optional, e.g. "internal-medical-1k"
    fine_tune_root_hash: str = ""
    pii_filtered: bool = True
    copyright_cleared: bool = False
    licenses: list[str] = field(default_factory=list)  # e.g. ["cc-by-4.0", "apache-2.0"]
