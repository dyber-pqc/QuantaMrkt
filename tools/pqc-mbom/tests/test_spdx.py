"""Tests for SPDX 2.3 import/export."""

from __future__ import annotations

import json

import pytest

from pqc_mbom import MBOM, from_spdx_json, to_spdx_json
from pqc_mbom.errors import SPDXConversionError


def test_to_spdx_has_packages(sample_mbom: MBOM) -> None:
    blob = to_spdx_json(sample_mbom)
    doc = json.loads(blob)
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert len(doc["packages"]) == len(sample_mbom.components)
    # each package has a checksum
    for pkg in doc["packages"]:
        assert pkg["checksums"][0]["algorithm"] == "SHA3-256"


def test_roundtrip_preserves_component_names(sample_mbom: MBOM) -> None:
    blob = to_spdx_json(sample_mbom)
    restored = from_spdx_json(blob)
    assert restored.model_name == sample_mbom.model_name
    assert restored.model_version == sample_mbom.model_version
    assert len(restored.components) == len(sample_mbom.components)
    names_before = sorted(c.name for c in sample_mbom.components)
    names_after = sorted(c.name for c in restored.components)
    assert names_before == names_after
    # Content hashes preserved
    hashes_before = sorted(c.content_hash for c in sample_mbom.components)
    hashes_after = sorted(c.content_hash for c in restored.components)
    assert hashes_before == hashes_after


def test_invalid_spdx_raises() -> None:
    with pytest.raises(SPDXConversionError):
        from_spdx_json("{not valid json")
    with pytest.raises(SPDXConversionError):
        from_spdx_json(json.dumps({"spdxVersion": "SPDX-1.0"}))
    with pytest.raises(SPDXConversionError):
        from_spdx_json(json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "wrong"}))
    with pytest.raises(SPDXConversionError):
        # Valid doc shell but no packages
        from_spdx_json(json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}))
