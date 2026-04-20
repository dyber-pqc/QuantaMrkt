"""Establish an encrypted CPU<->GPU channel and round-trip a synthetic tensor.

Run:

    python examples/basic_channel.py
"""

from __future__ import annotations

import os

from pqc_gpu_driver import TensorMetadata, establish_channel


def main() -> None:
    print("[*] Establishing ML-KEM-768 channel between CPU and GPU ...")
    cpu, gpu = establish_channel(cpu_side_label="inference-host", gpu_side_label="h100-0")
    print(f"    session_id    = {cpu.session_id}")
    print(f"    algorithm     = {cpu.algorithm}")
    print(f"    key_bytes     = {len(cpu.symmetric_key)}  (AES-256-GCM)")
    print(f"    expires_at    = {cpu.expires_at}")

    # Simulate a weight tensor shipped to the GPU.
    tensor = os.urandom(2048)
    meta = TensorMetadata(
        tensor_id="layer_0.q_proj",
        name="model.layers.0.self_attn.q_proj.weight",
        dtype="float32",
        shape=(512,),
        size_bytes=len(tensor),
        transfer_direction="cpu_to_gpu",
    )

    print("\n[*] CPU side encrypting tensor with AES-256-GCM ...")
    enc = cpu.encrypt_tensor(tensor, meta)
    print(f"    sequence_number = {enc.sequence_number}")
    print(f"    nonce           = {enc.nonce}")
    print(f"    ciphertext_len  = {len(enc.ciphertext) // 2} bytes")

    print("\n[*] GPU side decrypting tensor ...")
    pt = gpu.decrypt_tensor(enc)
    assert pt == tensor, "round-trip failed!"
    print(f"    decrypted_len   = {len(pt)} bytes")
    print(f"    last_recv_seq   = {gpu.last_recv_seq}")
    print("[+] Round-trip OK. Tensor integrity + confidentiality preserved.")


if __name__ == "__main__":
    main()
