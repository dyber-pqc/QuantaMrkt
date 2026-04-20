"""SPDX 2.3 JSON interoperability for MBOMs.

SPDX doesn't natively model AI-specific component types (training data,
RLHF data, quantization methods, etc.), so we map our MBOM to a superset
of SPDX that:

- Emits each ModelComponent as an SPDX Package.
- Records the pqc-mbom ComponentType in `annotations` and in the Package's
  `externalRefs` as a purl-like identifier.
- Stores the SHA3-256 content hash under `checksums`.

The roundtrip is lossy for fields SPDX doesn't model (commercial_use flag,
arbitrary `properties`, ML-DSA signature) - those live in annotations.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pqc_mbom.component import (
    ComponentReference,
    ComponentType,
    LicenseInfo,
    ModelComponent,
)
from pqc_mbom.errors import SPDXConversionError
from pqc_mbom.mbom import MBOM, SCHEMA_VERSION


SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
_CREATOR = "Tool: pqc-mbom"
_COMPONENT_TYPE_ANNOTATION = "pqc-mbom:component_type"
_MBOM_ROOT_ANNOTATION = "pqc-mbom:root_hash"
_MBOM_SIGNATURE_ANNOTATION = "pqc-mbom:signature"
_MBOM_SIGNER_ANNOTATION = "pqc-mbom:signer_did"
_MBOM_ALGORITHM_ANNOTATION = "pqc-mbom:algorithm"
_MBOM_PUBKEY_ANNOTATION = "pqc-mbom:public_key"
_MBOM_SIGNED_AT_ANNOTATION = "pqc-mbom:signed_at"
_MBOM_SUPPLIER_ANNOTATION = "pqc-mbom:supplier"
_MBOM_PROPERTIES_ANNOTATION = "pqc-mbom:properties"
_MBOM_REFERENCES_ANNOTATION = "pqc-mbom:references"
_MBOM_LICENSE_EXTRA_ANNOTATION = "pqc-mbom:license_extra"


def _spdx_id(raw: str) -> str:
    """Produce a valid SPDXID (alnum, `.`, `-`)."""
    sanitized = "".join(ch if (ch.isalnum() or ch in ".-") else "-" for ch in raw)
    return f"SPDXRef-{sanitized or 'UNKNOWN'}"


def _annotation(comment: str) -> dict[str, Any]:
    return {
        "annotationDate": datetime.now(timezone.utc).isoformat(),
        "annotationType": "OTHER",
        "annotator": _CREATOR,
        "comment": comment,
    }


def _component_to_package(component: ModelComponent) -> dict[str, Any]:
    pkg: dict[str, Any] = {
        "SPDXID": _spdx_id(component.component_id),
        "name": component.name,
        "versionInfo": component.version or "NOASSERTION",
        "downloadLocation": component.external_url or "NOASSERTION",
        "filesAnalyzed": False,
        "supplier": f"Organization: {component.supplier}" if component.supplier else "NOASSERTION",
        "originator": f"Person: {component.author}" if component.author else "NOASSERTION",
        "licenseConcluded": component.license.spdx_id or "NOASSERTION",
        "licenseDeclared": component.license.spdx_id or "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    if component.content_hash:
        pkg["checksums"] = [{"algorithm": "SHA3-256", "checksumValue": component.content_hash}]
    if component.content_size:
        pkg["packageVerificationCode"] = {"packageVerificationCodeValue": str(component.content_size)}

    annotations: list[dict[str, Any]] = [
        _annotation(f"{_COMPONENT_TYPE_ANNOTATION}={component.component_type.value}")
    ]
    if component.properties:
        annotations.append(
            _annotation(f"{_MBOM_PROPERTIES_ANNOTATION}={json.dumps(component.properties, sort_keys=True)}")
        )
    if component.references:
        annotations.append(
            _annotation(
                f"{_MBOM_REFERENCES_ANNOTATION}="
                f"{json.dumps([r.to_dict() for r in component.references], sort_keys=True)}"
            )
        )
    license_extra = {
        "name": component.license.name,
        "url": component.license.url,
        "commercial_use": component.license.commercial_use,
        "attribution_required": component.license.attribution_required,
    }
    annotations.append(
        _annotation(f"{_MBOM_LICENSE_EXTRA_ANNOTATION}={json.dumps(license_extra, sort_keys=True)}")
    )
    pkg["annotations"] = annotations
    return pkg


def _extract_annotation(pkg: dict[str, Any], prefix: str) -> str | None:
    for ann in pkg.get("annotations", []):
        comment = ann.get("comment", "")
        if comment.startswith(f"{prefix}="):
            return comment.split("=", 1)[1]
    return None


def _package_to_component(pkg: dict[str, Any]) -> ModelComponent:
    spdx_id = pkg.get("SPDXID", "")
    if not spdx_id.startswith("SPDXRef-"):
        raise SPDXConversionError(f"invalid SPDXID: {spdx_id!r}")
    component_id = spdx_id[len("SPDXRef-"):]

    ctype_raw = _extract_annotation(pkg, _COMPONENT_TYPE_ANNOTATION) or ComponentType.OTHER.value
    try:
        ctype = ComponentType(ctype_raw)
    except ValueError:
        ctype = ComponentType.OTHER

    content_hash = ""
    for cs in pkg.get("checksums", []):
        if cs.get("algorithm") == "SHA3-256":
            content_hash = cs.get("checksumValue", "")
            break

    content_size = 0
    pvc = pkg.get("packageVerificationCode", {}).get("packageVerificationCodeValue", "")
    if pvc.isdigit():
        content_size = int(pvc)

    supplier_raw = pkg.get("supplier", "")
    supplier = supplier_raw.split(":", 1)[1].strip() if supplier_raw.startswith("Organization:") else ""

    author_raw = pkg.get("originator", "")
    author = author_raw.split(":", 1)[1].strip() if author_raw.startswith("Person:") else ""

    license_extra_raw = _extract_annotation(pkg, _MBOM_LICENSE_EXTRA_ANNOTATION)
    lic_extra: dict[str, Any] = {}
    if license_extra_raw:
        try:
            lic_extra = json.loads(license_extra_raw)
        except json.JSONDecodeError as e:
            raise SPDXConversionError(f"malformed license_extra annotation: {e}") from e

    spdx_id_val = pkg.get("licenseDeclared", "") or pkg.get("licenseConcluded", "")
    if spdx_id_val in ("NOASSERTION", ""):
        spdx_id_val = ""
    license_info = LicenseInfo(
        spdx_id=spdx_id_val,
        name=lic_extra.get("name", ""),
        url=lic_extra.get("url", ""),
        commercial_use=bool(lic_extra.get("commercial_use", False)),
        attribution_required=bool(lic_extra.get("attribution_required", True)),
    )

    properties_raw = _extract_annotation(pkg, _MBOM_PROPERTIES_ANNOTATION)
    properties: dict[str, str] = {}
    if properties_raw:
        try:
            properties = {str(k): str(v) for k, v in json.loads(properties_raw).items()}
        except json.JSONDecodeError as e:
            raise SPDXConversionError(f"malformed properties annotation: {e}") from e

    references_raw = _extract_annotation(pkg, _MBOM_REFERENCES_ANNOTATION)
    references: list[ComponentReference] = []
    if references_raw:
        try:
            for r in json.loads(references_raw):
                references.append(ComponentReference(**r))
        except (json.JSONDecodeError, TypeError) as e:
            raise SPDXConversionError(f"malformed references annotation: {e}") from e

    download = pkg.get("downloadLocation", "")
    external_url = "" if download == "NOASSERTION" else download
    version = pkg.get("versionInfo", "")
    if version == "NOASSERTION":
        version = ""

    return ModelComponent(
        component_id=component_id,
        component_type=ctype,
        name=pkg.get("name", ""),
        version=version,
        content_hash=content_hash,
        content_size=content_size,
        supplier=supplier,
        author=author,
        external_url=external_url,
        license=license_info,
        references=references,
        properties=properties,
    )


def to_spdx_json(mbom: MBOM, *, indent: int = 2) -> str:
    """Serialize an MBOM as an SPDX 2.3 JSON document."""
    document_namespace = f"https://pqc-mbom.dyber.io/{mbom.mbom_id}"
    creation_info = {
        "created": mbom.created_at or datetime.now(timezone.utc).isoformat(),
        "creators": [_CREATOR, f"Tool: pqc-mbom-schema-{SCHEMA_VERSION}"],
    }

    doc: dict[str, Any] = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{mbom.model_name}-{mbom.model_version}-mbom",
        "documentNamespace": document_namespace,
        "creationInfo": creation_info,
        "packages": [_component_to_package(c) for c in mbom.components],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": _spdx_id(c.component_id),
                "relationshipType": "DESCRIBES",
            }
            for c in mbom.components
        ],
    }

    doc_annotations: list[dict[str, Any]] = [
        _annotation(f"pqc-mbom:mbom_id={mbom.mbom_id}"),
        _annotation(f"pqc-mbom:model_name={mbom.model_name}"),
        _annotation(f"pqc-mbom:model_version={mbom.model_version}"),
        _annotation(f"pqc-mbom:schema_version={mbom.schema_version}"),
        _annotation(f"pqc-mbom:description={mbom.description}"),
        _annotation(f"{_MBOM_SUPPLIER_ANNOTATION}={mbom.supplier}"),
        _annotation(f"{_MBOM_ROOT_ANNOTATION}={mbom.components_root_hash}"),
    ]
    if mbom.signature:
        doc_annotations.extend([
            _annotation(f"{_MBOM_SIGNER_ANNOTATION}={mbom.signer_did}"),
            _annotation(f"{_MBOM_ALGORITHM_ANNOTATION}={mbom.algorithm}"),
            _annotation(f"{_MBOM_SIGNATURE_ANNOTATION}={mbom.signature}"),
            _annotation(f"{_MBOM_PUBKEY_ANNOTATION}={mbom.public_key}"),
            _annotation(f"{_MBOM_SIGNED_AT_ANNOTATION}={mbom.signed_at}"),
        ])
    doc["annotations"] = doc_annotations

    return json.dumps(doc, indent=indent, ensure_ascii=False)


def from_spdx_json(blob: str) -> MBOM:
    """Parse an SPDX JSON document produced by `to_spdx_json` back into an MBOM.

    Lossy for non-pqc-mbom SPDX docs - components without the
    `pqc-mbom:component_type` annotation are mapped to ComponentType.OTHER.
    """
    try:
        doc = json.loads(blob)
    except json.JSONDecodeError as e:
        raise SPDXConversionError(f"invalid SPDX JSON: {e}") from e

    if doc.get("spdxVersion") != SPDX_VERSION:
        raise SPDXConversionError(
            f"unsupported spdxVersion: {doc.get('spdxVersion')!r} (expected {SPDX_VERSION!r})"
        )
    if doc.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise SPDXConversionError(f"missing or wrong document SPDXID: {doc.get('SPDXID')!r}")
    if "packages" not in doc:
        raise SPDXConversionError("SPDX document has no packages")

    components = [_package_to_component(p) for p in doc["packages"]]

    def _doc_ann(prefix: str, default: str = "") -> str:
        for ann in doc.get("annotations", []):
            comment = ann.get("comment", "")
            if comment.startswith(f"{prefix}="):
                return comment.split("=", 1)[1]
        return default

    mbom_id = _doc_ann("pqc-mbom:mbom_id") or doc.get("documentNamespace", "")
    model_name = _doc_ann("pqc-mbom:model_name")
    model_version = _doc_ann("pqc-mbom:model_version")
    if not model_name or not model_version:
        name = doc.get("name", "")
        if "-" in name and name.endswith("-mbom"):
            stripped = name[: -len("-mbom")]
            parts = stripped.rsplit("-", 1)
            if len(parts) == 2:
                model_name = model_name or parts[0]
                model_version = model_version or parts[1]

    created_at = doc.get("creationInfo", {}).get("created", "")
    mbom = MBOM(
        mbom_id=mbom_id or "urn:pqc-mbom:spdx-import",
        schema_version=_doc_ann("pqc-mbom:schema_version", SCHEMA_VERSION),
        model_name=model_name or "unknown",
        model_version=model_version or "0",
        supplier=_doc_ann(_MBOM_SUPPLIER_ANNOTATION),
        description=_doc_ann("pqc-mbom:description"),
        components=components,
        created_at=created_at,
        components_root_hash=_doc_ann(_MBOM_ROOT_ANNOTATION),
        signer_did=_doc_ann(_MBOM_SIGNER_ANNOTATION),
        algorithm=_doc_ann(_MBOM_ALGORITHM_ANNOTATION),
        signature=_doc_ann(_MBOM_SIGNATURE_ANNOTATION),
        public_key=_doc_ann(_MBOM_PUBKEY_ANNOTATION),
        signed_at=_doc_ann(_MBOM_SIGNED_AT_ANNOTATION),
    )
    if not mbom.components_root_hash:
        mbom.recompute_root()
    return mbom
