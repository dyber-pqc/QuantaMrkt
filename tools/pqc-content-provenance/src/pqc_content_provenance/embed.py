"""Embed/extract manifests in/from content.

Two embedding modes:
  1. Sidecar: manifest is stored next to content as a separate .c2pa.json file.
  2. Inline header: for text, we can prepend a <!--PQC-PROV--> JSON block.

For images/video, real C2PA stores inside metadata (XMP, EXIF). Here we keep it
simple: we provide sidecar packaging helpers. Callers can embed the bytes
however they want for their own file format.
"""

from __future__ import annotations

import base64
import json

from pqc_content_provenance.errors import InvalidManifestError
from pqc_content_provenance.manifest import ContentManifest


SIDECAR_EXTENSION = ".c2pa.json"
TEXT_MARKER_BEGIN = "<!--PQC-PROV-BEGIN-->"
TEXT_MARKER_END = "<!--PQC-PROV-END-->"


def embed_manifest(content: bytes, manifest: ContentManifest, mode: str = "sidecar") -> bytes:
    """Produce an embedded form of (content, manifest).

    mode='sidecar': returns a JSON blob containing both; save to .c2pa.json.
    mode='text-header': prepends a marker-bracketed JSON to text content.
    """
    if mode == "sidecar":
        envelope = {
            "manifest": manifest.to_dict(),
            "content_base64": _to_base64(content),
        }
        return json.dumps(envelope, indent=2).encode("utf-8")

    if mode == "text-header":
        header = f"{TEXT_MARKER_BEGIN}{manifest.to_json()}{TEXT_MARKER_END}"
        return header.encode("utf-8") + b"\n" + content

    raise ValueError(f"unknown embed mode: {mode}")


def extract_manifest(blob: bytes, mode: str = "sidecar") -> tuple[ContentManifest, bytes]:
    """Extract (manifest, content) from an embedded blob. Inverse of embed_manifest."""
    if mode == "sidecar":
        try:
            envelope = json.loads(blob.decode("utf-8"))
            manifest = ContentManifest.from_dict(envelope["manifest"])
            content = _from_base64(envelope["content_base64"])
            return manifest, content
        except (ValueError, KeyError) as e:
            raise InvalidManifestError(f"invalid sidecar envelope: {e}") from e

    if mode == "text-header":
        text = blob.decode("utf-8", errors="replace")
        if TEXT_MARKER_BEGIN not in text or TEXT_MARKER_END not in text:
            raise InvalidManifestError("text-header markers not found")
        start = text.index(TEXT_MARKER_BEGIN) + len(TEXT_MARKER_BEGIN)
        end = text.index(TEXT_MARKER_END, start)
        manifest_json = text[start:end]
        manifest = ContentManifest.from_json(manifest_json)
        # content is everything after the end marker (skip the trailing newline)
        rest = text[end + len(TEXT_MARKER_END):]
        if rest.startswith("\n"):
            rest = rest[1:]
        return manifest, rest.encode("utf-8")

    raise ValueError(f"unknown embed mode: {mode}")


def _to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _from_base64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))
