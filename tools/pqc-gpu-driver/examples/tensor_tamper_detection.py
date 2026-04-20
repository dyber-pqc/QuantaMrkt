"""Show that a single-bit flip in an encrypted tensor is detected.

AES-256-GCM ties ciphertext and AAD (metadata + sequence number) into one
authentication tag. Any bit flip in ciphertext or tampering with metadata
causes decrypt_tensor() to raise DecryptionError.

Run:

    python examples/tensor_tamper_detection.py
"""

from __future__ import annotations

import os

from pqc_gpu_driver import DecryptionError, TensorMetadata, establish_channel


def main() -> None:
    cpu, gpu = establish_channel()
    tensor = os.urandom(512)
    meta = TensorMetadata(
        tensor_id="t-tamper",
        name="model.fc.weight",
        dtype="float32",
        shape=(128,),
        size_bytes=len(tensor),
    )

    print("[*] Encrypting tensor on CPU side ...")
    enc = cpu.encrypt_tensor(tensor, meta)
    print(f"    original ciphertext prefix = {enc.ciphertext[:32]}...")

    print("\n[*] Attacker flips one byte of ciphertext over PCIe ...")
    ct = bytearray(bytes.fromhex(enc.ciphertext))
    ct[0] ^= 0xFF
    enc.ciphertext = bytes(ct).hex()
    print(f"    tampered ciphertext prefix = {enc.ciphertext[:32]}...")

    print("\n[*] GPU side attempts decryption ...")
    try:
        gpu.decrypt_tensor(enc)
        print("[-] FAIL: tamper went undetected.")
    except DecryptionError as exc:
        print(f"[+] Tamper detected. DecryptionError: {exc}")


if __name__ == "__main__":
    main()
