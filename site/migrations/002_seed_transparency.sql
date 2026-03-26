-- Seed transparency log with ~15 entries matching existing model/agent data
-- Hashes are placeholder values that form a valid chain for seed data.
-- In production, real SHA-256 hashes are computed by the transparency library.

-- Entry 1: Genesis - first model created
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (1, '2025-01-15 09:00:00', 'model:created', NULL, 'model', 'meta-llama-3.1-70b', 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', '0', 'f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1', NULL, '{"name":"Meta Llama 3.1 70B","author":"meta","framework":"PyTorch"}');

-- Entry 2: Manifest pushed for Llama
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (2, '2025-01-15 09:05:00', 'manifest:pushed', NULL, 'manifest', 'meta-llama-3.1-70b@1.0.0', 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3', 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', 'e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2', NULL, '{"manifestHash":"sha256:abc123","fileCount":8}');

-- Entry 3: Model signed by Meta's key
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (3, '2025-01-15 09:10:00', 'model:signed', 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', 'model', 'meta-llama-3.1-70b', 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3', 'd2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3', NULL, '{"version":"1.0.0","algorithm":"ML-DSA-65","attestationType":"creator"}');

-- Entry 4: GPT-4 model created
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (4, '2025-01-20 14:30:00', 'model:created', NULL, 'model', 'openai-gpt-4-turbo', 'd4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5', 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', 'c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4', NULL, '{"name":"GPT-4 Turbo","author":"openai","framework":"Triton"}');

-- Entry 5: First agent registered
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (5, '2025-01-22 10:00:00', 'agent:registered', 'did:key:z6MknGc3ocHs3zdPiJbnaaqDi58XEArgb1MYkWCMghYsVRXd', 'agent', 'did:key:z6MknGc3ocHs3zdPiJbnaaqDi58XEArgb1MYkWCMghYsVRXd', 'e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6', 'd4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5', 'b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5', NULL, '{"name":"CodeGuard Agent","algorithm":"ML-DSA-65","capabilities":["code:scan","model:verify"]}');

-- Entry 6: Manifest pushed for GPT-4
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (6, '2025-01-25 11:15:00', 'manifest:pushed', NULL, 'manifest', 'openai-gpt-4-turbo@2.1.0', 'f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1', 'e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6', 'a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0', NULL, '{"manifestHash":"sha256:def456","fileCount":12}');

-- Entry 7: GPT-4 signed
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (7, '2025-01-25 11:20:00', 'model:signed', 'did:key:z6MkpTHR8VNs3HxFGp6hVMQQfGiGdRd3NAhbrKXqb2bZ4j9B', 'model', 'openai-gpt-4-turbo', 'a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2', 'f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1', '0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e', NULL, '{"version":"2.1.0","algorithm":"ML-DSA-87","attestationType":"creator"}');

-- Entry 8: Mistral model created
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (8, '2025-02-01 08:45:00', 'model:created', NULL, 'model', 'mistral-7b-instruct-v03', 'b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3', 'a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2', '1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d', NULL, '{"name":"Mistral 7B Instruct v0.3","author":"mistralai","framework":"PyTorch"}');

-- Entry 9: Second agent registered
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (9, '2025-02-05 16:30:00', 'agent:registered', 'did:key:z6MkwFKiH8QGqBZ8BpXhNYVTKsmXB7GqPJVn6q3XD7Z8puQp', 'agent', 'did:key:z6MkwFKiH8QGqBZ8BpXhNYVTKsmXB7GqPJVn6q3XD7Z8puQp', 'c3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4', 'b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3', '2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c', NULL, '{"name":"AuditBot","algorithm":"ML-DSA-65","capabilities":["model:audit","compliance:check"]}');

-- Entry 10: Manifest pushed for Mistral
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (10, '2025-02-10 13:00:00', 'manifest:pushed', NULL, 'manifest', 'mistral-7b-instruct-v03@1.0.0', 'd4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5', 'c3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4', '3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b', NULL, '{"manifestHash":"sha256:789abc","fileCount":5}');

-- Entry 11: Mistral signed
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (11, '2025-02-10 13:05:00', 'model:signed', 'did:key:z6MkjRagNi8SqXkax5Gbs3aDf2AHTbwUqMbM11ieu2KPWEdx', 'model', 'mistral-7b-instruct-v03', 'e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6', 'd4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5', '4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a', NULL, '{"version":"1.0.0","algorithm":"ML-DSA-65","attestationType":"creator"}');

-- Entry 12: Anthropic model created
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (12, '2025-02-15 10:20:00', 'model:created', NULL, 'model', 'anthropic-claude-3-opus', 'f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6', 'e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6', '5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f', NULL, '{"name":"Claude 3 Opus","author":"anthropic","framework":"JAX"}');

-- Entry 13: Third agent registered
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (13, '2025-02-20 09:00:00', 'agent:registered', 'did:key:z6MksNZwi2r6Lxj1LZc48HiZ2C3bRHCVFs3NRdKzmAY93eAT', 'agent', 'did:key:z6MksNZwi2r6Lxj1LZc48HiZ2C3bRHCVFs3NRdKzmAY93eAT', 'a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7', 'f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6', 'a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1', NULL, '{"name":"SupplyChain Sentinel","algorithm":"ML-DSA-87","capabilities":["supply:verify","provenance:track"]}');

-- Entry 14: Model verified (independent verification of Llama)
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (14, '2025-03-01 15:45:00', 'model:verified', 'did:key:z6MknGc3ocHs3zdPiJbnaaqDi58XEArgb1MYkWCMghYsVRXd', 'model', 'meta-llama-3.1-70b', 'b7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8', 'a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7', '0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e', NULL, '{"verifier":"CodeGuard Agent","result":"pass","version":"1.0.0"}');

-- Entry 15: Anthropic Claude signed
INSERT INTO transparency_log (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
VALUES (15, '2025-03-05 11:30:00', 'model:signed', 'did:key:z6MkqRYqQiSgFjBEp8PsD9pvhjxjGg1W2cSCBjM52P1bKKTe', 'model', 'anthropic-claude-3-opus', 'c8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9', 'b7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8', 'f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2d3c4b5a0f1e2', NULL, '{"version":"1.0.0","algorithm":"ML-DSA-87","attestationType":"creator"}');
