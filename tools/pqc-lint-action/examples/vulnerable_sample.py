"""Example of code that pqc-lint should flag.

Run:
    pqc-lint scan examples/vulnerable_sample.py
"""

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib


# PQC001 - RSA key generation (broken by Shor's)
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# PQC001 - RSA signing with PSS padding
signature = rsa_key.sign(
    b"data",
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
    hashes.SHA256(),
)

# PQC002 - ECDSA key generation
ec_key = ec.generate_private_key(ec.SECP256R1())

# PQC003 - Ed25519 (classical, not quantum-safe)
ed_key = ed25519.Ed25519PrivateKey.generate()

# PQC301 - MD5 (broken)
md5_digest = hashlib.md5(b"legacy").hexdigest()
