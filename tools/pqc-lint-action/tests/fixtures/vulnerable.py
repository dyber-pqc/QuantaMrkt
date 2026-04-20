# Sample file used by fixture-based tests.
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, dh
import hashlib

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
ed_key = ed25519.Ed25519PrivateKey.generate()

dh_params = dh.generate_parameters(generator=2, key_size=2048)
md5_hash = hashlib.md5(b"data").hexdigest()
sha1_hash = hashlib.sha1(b"data").hexdigest()
