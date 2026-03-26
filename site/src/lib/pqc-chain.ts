// PQC Block Chain Engine
// Certificate transparency log with block headers, Merkle trees, and ML-DSA signatures
// Not a full consensus blockchain — a verifiable, hash-chained block structure

import { sha256 } from './transparency';

// ---- Types ----

export interface Block {
  id: number;
  block_number: number;
  timestamp: string;
  previous_block_hash: string;
  merkle_root: string;
  entries_count: number;
  entry_range_start: number;
  entry_range_end: number;
  block_hash: string;
  signature: string | null;
  signer_did: string;
}

export interface ChainVerification {
  valid: boolean;
  blocks_checked: number;
  first_invalid?: number;
  latest_block?: number;
  errors: string[];
}

const SIGNER_DID = 'did:web:quantamrkt.com:chain:authority';

// ---- Merkle Tree ----

/** Compute Merkle root from a list of hex hash strings */
export async function computeMerkleRoot(hashes: string[]): Promise<string> {
  if (hashes.length === 0) {
    return await sha256('empty');
  }
  if (hashes.length === 1) {
    return hashes[0];
  }

  let level = [...hashes];

  while (level.length > 1) {
    const nextLevel: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        nextLevel.push(await sha256(level[i] + level[i + 1]));
      } else {
        // Odd node: hash with itself
        nextLevel.push(await sha256(level[i] + level[i]));
      }
    }
    level = nextLevel;
  }

  return level[0];
}

// ---- Block Header Hash ----

async function computeBlockHash(
  blockNumber: number,
  previousBlockHash: string,
  merkleRoot: string,
  timestamp: string,
): Promise<string> {
  const data = `${blockNumber}|${previousBlockHash}|${merkleRoot}|${timestamp}`;
  return sha256(data);
}

// ---- Stub ML-DSA Signature ----

async function signBlockHash(blockHash: string): Promise<string> {
  // Stub: in production this would use ML-DSA-87 signing with a platform private key
  // For now, produce a deterministic pseudo-signature
  return sha256(`ml-dsa-87:sign:${SIGNER_DID}:${blockHash}`);
}

// ---- Core Functions ----

/** Create the genesis block (block 0) */
export async function createGenesisBlock(db: D1Database): Promise<Block> {
  // Check if genesis already exists
  const existing = await db
    .prepare('SELECT * FROM chain_blocks WHERE block_number = 0')
    .first();

  if (existing) {
    return parseBlock(existing);
  }

  const timestamp = new Date().toISOString().replace('T', ' ').replace('Z', '').split('.')[0];
  const previousBlockHash = '0000000000000000000000000000000000000000000000000000000000000000';
  const merkleRoot = await sha256('genesis:quantamrkt:pqc-chain');
  const blockHash = await computeBlockHash(0, previousBlockHash, merkleRoot, timestamp);
  const signature = await signBlockHash(blockHash);

  const result = await db
    .prepare(
      `INSERT INTO chain_blocks (block_number, timestamp, previous_block_hash, merkle_root, entries_count, entry_range_start, entry_range_end, block_hash, signature, signer_did)
       VALUES (0, ?, ?, ?, 0, 0, 0, ?, ?, ?)
       RETURNING *`,
    )
    .bind(timestamp, previousBlockHash, merkleRoot, blockHash, signature, SIGNER_DID)
    .first();

  if (!result) throw new Error('Failed to create genesis block');
  return parseBlock(result);
}

/** Create the next block from unblocked transparency log entries */
export async function createBlock(db: D1Database): Promise<Block | null> {
  // Ensure genesis exists
  const latestBlock = await getLatestBlock(db);
  if (!latestBlock) {
    // Create genesis first, then try again
    await createGenesisBlock(db);
    return createBlock(db);
  }

  // Get transparency log entries after the last block's range
  const lastEnd = latestBlock.entry_range_end;
  const entries = await db
    .prepare(
      'SELECT sequence_number, payload_hash FROM transparency_log WHERE sequence_number > ? ORDER BY sequence_number ASC',
    )
    .bind(lastEnd)
    .all<{ sequence_number: number; payload_hash: string }>();

  const rows = entries.results ?? [];
  if (rows.length === 0) return null;

  // Compute Merkle root from entry payload hashes
  const hashes = rows.map((r) => r.payload_hash);
  const merkleRoot = await computeMerkleRoot(hashes);

  const timestamp = new Date().toISOString().replace('T', ' ').replace('Z', '').split('.')[0];
  const blockNumber = latestBlock.block_number + 1;
  const previousBlockHash = latestBlock.block_hash;
  const entryRangeStart = rows[0].sequence_number;
  const entryRangeEnd = rows[rows.length - 1].sequence_number;

  const blockHash = await computeBlockHash(blockNumber, previousBlockHash, merkleRoot, timestamp);
  const signature = await signBlockHash(blockHash);

  const result = await db
    .prepare(
      `INSERT INTO chain_blocks (block_number, timestamp, previous_block_hash, merkle_root, entries_count, entry_range_start, entry_range_end, block_hash, signature, signer_did)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       RETURNING *`,
    )
    .bind(
      blockNumber,
      timestamp,
      previousBlockHash,
      merkleRoot,
      rows.length,
      entryRangeStart,
      entryRangeEnd,
      blockHash,
      signature,
      SIGNER_DID,
    )
    .first();

  if (!result) throw new Error('Failed to create block');
  return parseBlock(result);
}

/** Verify the entire chain integrity */
export async function verifyBlockChain(db: D1Database): Promise<ChainVerification> {
  const blocksResult = await db
    .prepare('SELECT * FROM chain_blocks ORDER BY block_number ASC')
    .all();

  const blocks = (blocksResult.results ?? []).map(parseBlock);

  if (blocks.length === 0) {
    return { valid: true, blocks_checked: 0, errors: [] };
  }

  const errors: string[] = [];

  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];

    // Verify block number sequence
    if (block.block_number !== i) {
      errors.push(`Block ${i}: expected block_number ${i}, got ${block.block_number}`);
      return {
        valid: false,
        blocks_checked: i,
        first_invalid: block.block_number,
        latest_block: blocks[blocks.length - 1].block_number,
        errors,
      };
    }

    // Verify hash chain (skip genesis)
    if (i > 0) {
      const prevBlock = blocks[i - 1];
      if (block.previous_block_hash !== prevBlock.block_hash) {
        errors.push(
          `Block ${block.block_number}: previous_block_hash mismatch. Expected ${prevBlock.block_hash}, got ${block.previous_block_hash}`,
        );
        return {
          valid: false,
          blocks_checked: i,
          first_invalid: block.block_number,
          latest_block: blocks[blocks.length - 1].block_number,
          errors,
        };
      }
    }

    // Verify block hash
    const expectedHash = await computeBlockHash(
      block.block_number,
      block.previous_block_hash,
      block.merkle_root,
      block.timestamp,
    );
    if (block.block_hash !== expectedHash) {
      errors.push(
        `Block ${block.block_number}: block_hash mismatch. Expected ${expectedHash}, got ${block.block_hash}`,
      );
      return {
        valid: false,
        blocks_checked: i,
        first_invalid: block.block_number,
        latest_block: blocks[blocks.length - 1].block_number,
        errors,
      };
    }

    // Verify Merkle root for non-genesis blocks
    if (block.block_number > 0 && block.entries_count > 0) {
      const entriesResult = await db
        .prepare(
          'SELECT payload_hash FROM transparency_log WHERE sequence_number >= ? AND sequence_number <= ? ORDER BY sequence_number ASC',
        )
        .bind(block.entry_range_start, block.entry_range_end)
        .all<{ payload_hash: string }>();

      const entryHashes = (entriesResult.results ?? []).map((r) => r.payload_hash);
      const expectedMerkle = await computeMerkleRoot(entryHashes);

      if (block.merkle_root !== expectedMerkle) {
        errors.push(
          `Block ${block.block_number}: merkle_root mismatch. Expected ${expectedMerkle}, got ${block.merkle_root}`,
        );
        return {
          valid: false,
          blocks_checked: i + 1,
          first_invalid: block.block_number,
          latest_block: blocks[blocks.length - 1].block_number,
          errors,
        };
      }
    }
  }

  return {
    valid: true,
    blocks_checked: blocks.length,
    latest_block: blocks[blocks.length - 1].block_number,
    errors: [],
  };
}

/** Get a block by number */
export async function getBlock(db: D1Database, blockNumber: number): Promise<Block | null> {
  const row = await db
    .prepare('SELECT * FROM chain_blocks WHERE block_number = ?')
    .bind(blockNumber)
    .first();

  if (!row) return null;
  return parseBlock(row);
}

/** Get the latest block */
export async function getLatestBlock(db: D1Database): Promise<Block | null> {
  const row = await db
    .prepare('SELECT * FROM chain_blocks ORDER BY block_number DESC LIMIT 1')
    .first();

  if (!row) return null;
  return parseBlock(row);
}

/** Get blocks with pagination (latest first) */
export async function getBlocks(
  db: D1Database,
  opts: { limit?: number; offset?: number } = {},
): Promise<{ blocks: Block[]; total: number }> {
  const limit = opts.limit ?? 20;
  const offset = opts.offset ?? 0;

  const countResult = await db
    .prepare('SELECT COUNT(*) as total FROM chain_blocks')
    .first<{ total: number }>();
  const total = countResult?.total ?? 0;

  const result = await db
    .prepare('SELECT * FROM chain_blocks ORDER BY block_number DESC LIMIT ? OFFSET ?')
    .bind(limit, offset)
    .all();

  const blocks = (result.results ?? []).map(parseBlock);
  return { blocks, total };
}

/** Get entries for a specific block */
export async function getBlockEntries(
  db: D1Database,
  blockNumber: number,
): Promise<Record<string, unknown>[]> {
  const block = await getBlock(db, blockNumber);
  if (!block || block.entries_count === 0) return [];

  const result = await db
    .prepare(
      'SELECT * FROM transparency_log WHERE sequence_number >= ? AND sequence_number <= ? ORDER BY sequence_number ASC',
    )
    .bind(block.entry_range_start, block.entry_range_end)
    .all();

  return result.results ?? [];
}

// ---- Helpers ----

function parseBlock(row: Record<string, unknown>): Block {
  return {
    id: row.id as number,
    block_number: row.block_number as number,
    timestamp: row.timestamp as string,
    previous_block_hash: row.previous_block_hash as string,
    merkle_root: row.merkle_root as string,
    entries_count: row.entries_count as number,
    entry_range_start: row.entry_range_start as number,
    entry_range_end: row.entry_range_end as number,
    block_hash: row.block_hash as string,
    signature: (row.signature as string) || null,
    signer_did: (row.signer_did as string) || SIGNER_DID,
  };
}
