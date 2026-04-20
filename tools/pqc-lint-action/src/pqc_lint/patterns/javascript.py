"""JavaScript / TypeScript crypto patterns."""

from __future__ import annotations

from pqc_lint.patterns.base import PatternMatcher, compile_patterns


class JavaScriptMatcher(PatternMatcher):
    language = "javascript"
    file_extensions = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
    patterns = compile_patterns([
        # Node crypto
        ("PQC001", r"""crypto\.generateKeyPair(?:Sync)?\s*\(\s*['"]rsa['"]"""),
        ("PQC002", r"""crypto\.generateKeyPair(?:Sync)?\s*\(\s*['"]ec['"]"""),
        ("PQC002", r"""crypto\.createSign\s*\(\s*['"]SHA(?:256|384|512)['"]\s*\)"""),
        ("PQC003", r"""crypto\.generateKeyPair(?:Sync)?\s*\(\s*['"]ed25519['"]"""),
        ("PQC004", r"""crypto\.generateKeyPair(?:Sync)?\s*\(\s*['"]dsa['"]"""),
        ("PQC101", r"""crypto\.createECDH\s*\("""),
        ("PQC102", r"""crypto\.createDiffieHellman\s*\("""),
        ("PQC103", r"""crypto\.generateKeyPair(?:Sync)?\s*\(\s*['"]x25519['"]"""),
        # Web Crypto API
        ("PQC001", r"""name\s*:\s*['"]RSASSA-PKCS1-v1_5['"]"""),
        ("PQC001", r"""name\s*:\s*['"]RSA-PSS['"]"""),
        ("PQC201", r"""name\s*:\s*['"]RSA-OAEP['"]"""),
        ("PQC002", r"""name\s*:\s*['"]ECDSA['"]"""),
        ("PQC101", r"""name\s*:\s*['"]ECDH['"]"""),
        # node-forge
        ("PQC001", r"""forge\.pki\.rsa\.generateKeyPair\s*\("""),
        ("PQC202", r"""forge\.pki\.rsa\.encrypt\s*\("""),
        # tweetnacl / nacl
        ("PQC003", r"""nacl\.sign\.keyPair\s*\("""),
        ("PQC103", r"""nacl\.box\.keyPair\s*\("""),
        # hashes
        ("PQC301", r"""crypto\.createHash\s*\(\s*['"]md5['"]"""),
        ("PQC302", r"""crypto\.createHash\s*\(\s*['"]sha1['"]"""),
        ("PQC301", r"""name\s*:\s*['"]MD5['"]"""),
        ("PQC302", r"""name\s*:\s*['"]SHA-1['"]"""),
    ])
