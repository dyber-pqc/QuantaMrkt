// QuantaMrkt Transparency Log Library
// Append-only, hash-chained, publicly auditable log using Web Crypto API (CF Workers compatible)

// ---- Types ----

export interface TransparencyEntry {
  id: number;
  sequence_number: number;
  timestamp: string;
  action: string;
  actor_did: string | null;
  target_type: string;
  target_id: string;
  payload_hash: string;
  previous_hash: string;
  merkle_root: string | null;
  signature: string | null;
  metadata: Record<string, unknown>;
}

export interface ChainProof {
  previous_hash: string;
  computed_hash: string;
  valid: boolean;
}

export interface VerifyResult {
  valid: boolean;
  entries_checked: number;
  first_invalid?: number;
  latest_sequence?: number;
  latest_hash?: string;
}

// ---- Hashing ----

/** Compute SHA-256 hex digest using Web Crypto API (available in CF Workers) */
export async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const buffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---- Core Operations ----

/** Get the latest log entry to chain from */
export async function getLatestEntry(db: D1Database): Promise<TransparencyEntry | null> {
  const row = await db
    .prepare('SELECT * FROM transparency_log ORDER BY sequence_number DESC LIMIT 1')
    .first();

  if (!row) return null;
  return parseEntry(row);
}

/** Append a new entry to the transparency log (append-only, auto-computes chain hash) */
export async function appendLogEntry(
  db: D1Database,
  entry: {
    action: string;
    actor_did?: string;
    target_type: string;
    target_id: string;
    metadata?: Record<string, unknown>;
  },
): Promise<TransparencyEntry> {
  // 1. Get latest entry for previous_hash (or '0' for genesis)
  const latest = await getLatestEntry(db);
  const previousHash = latest ? latest.payload_hash : '0';
  const nextSequence = latest ? latest.sequence_number + 1 : 1;

  // 2. Compute payload_hash from action + target + timestamp
  const timestamp = new Date().toISOString().replace('T', ' ').replace('Z', '').split('.')[0];
  const payloadData = `${entry.action}|${entry.target_type}|${entry.target_id}|${timestamp}`;
  const payloadHash = await sha256(payloadData);

  // 3. Compute chain hash: sha256(previous_hash + payload_hash)
  const chainHash = await sha256(previousHash + payloadHash);

  // 4. Compute simple Merkle root (hash of chain so far)
  const merkleRoot = await sha256(chainHash + (latest?.merkle_root || '0'));

  const metadataJson = JSON.stringify(entry.metadata || {});

  // 5. Insert with next sequence_number
  const result = await db
    .prepare(
      `INSERT INTO transparency_log
       (sequence_number, timestamp, action, actor_did, target_type, target_id, payload_hash, previous_hash, merkle_root, signature, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
       RETURNING *`,
    )
    .bind(
      nextSequence,
      timestamp,
      entry.action,
      entry.actor_did ?? null,
      entry.target_type,
      entry.target_id,
      payloadHash,
      previousHash,
      merkleRoot,
      metadataJson,
    )
    .first();

  if (!result) throw new Error('Failed to insert transparency log entry');

  return parseEntry(result);
}

/** Verify the chain integrity, optionally within a range */
export async function verifyChain(
  db: D1Database,
  fromSeq?: number,
  toSeq?: number,
): Promise<VerifyResult> {
  let sql = 'SELECT * FROM transparency_log';
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (fromSeq != null) {
    conditions.push('sequence_number >= ?');
    params.push(fromSeq);
  }
  if (toSeq != null) {
    conditions.push('sequence_number <= ?');
    params.push(toSeq);
  }

  if (conditions.length > 0) {
    sql += ' WHERE ' + conditions.join(' AND ');
  }
  sql += ' ORDER BY sequence_number ASC';

  const result = await db.prepare(sql).bind(...params).all();
  const entries = (result.results ?? []).map(parseEntry);

  if (entries.length === 0) {
    return { valid: true, entries_checked: 0 };
  }

  // Verify the first entry in the range
  let prevPayloadHash: string;
  if (fromSeq != null && fromSeq > 1) {
    // Get the entry just before the range to verify chain continuity
    const prevEntry = await db
      .prepare('SELECT * FROM transparency_log WHERE sequence_number = ?')
      .bind(fromSeq - 1)
      .first();
    prevPayloadHash = prevEntry ? (prevEntry.payload_hash as string) : '0';
  } else {
    // First entry should chain from '0'
    prevPayloadHash = '0';
  }

  for (const entry of entries) {
    // Verify previous_hash links correctly
    if (entry.previous_hash !== prevPayloadHash) {
      return {
        valid: false,
        entries_checked: entry.sequence_number - (fromSeq ?? 1),
        first_invalid: entry.sequence_number,
        latest_sequence: entries[entries.length - 1].sequence_number,
        latest_hash: entries[entries.length - 1].payload_hash,
      };
    }
    prevPayloadHash = entry.payload_hash;
  }

  const lastEntry = entries[entries.length - 1];
  return {
    valid: true,
    entries_checked: entries.length,
    latest_sequence: lastEntry.sequence_number,
    latest_hash: lastEntry.payload_hash,
  };
}

/** Get log entries with pagination and filtering */
export async function getLogEntries(
  db: D1Database,
  opts?: {
    limit?: number;
    offset?: number;
    action?: string;
    target_type?: string;
    target_id?: string;
  },
): Promise<{ entries: TransparencyEntry[]; total: number }> {
  const limit = opts?.limit ?? 50;
  const offset = opts?.offset ?? 0;

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (opts?.action) {
    conditions.push('action = ?');
    params.push(opts.action);
  }
  if (opts?.target_type) {
    conditions.push('target_type = ?');
    params.push(opts.target_type);
  }
  if (opts?.target_id) {
    conditions.push('target_id = ?');
    params.push(opts.target_id);
  }

  const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';

  // Count
  const countResult = await db
    .prepare(`SELECT COUNT(*) as total FROM transparency_log ${where}`)
    .bind(...params)
    .first<{ total: number }>();
  const total = countResult?.total ?? 0;

  // Data
  const dataResult = await db
    .prepare(
      `SELECT * FROM transparency_log ${where} ORDER BY sequence_number DESC LIMIT ? OFFSET ?`,
    )
    .bind(...params, limit, offset)
    .all();

  const entries = (dataResult.results ?? []).map(parseEntry);

  return { entries, total };
}

/** Get a specific entry with its chain proof */
export async function getEntryWithProof(
  db: D1Database,
  sequenceNumber: number,
): Promise<{ entry: TransparencyEntry; proof: ChainProof } | null> {
  const row = await db
    .prepare('SELECT * FROM transparency_log WHERE sequence_number = ?')
    .bind(sequenceNumber)
    .first();

  if (!row) return null;

  const entry = parseEntry(row);

  // Get the previous entry to verify chain
  let expectedPrevHash: string;
  if (sequenceNumber === 1) {
    expectedPrevHash = '0';
  } else {
    const prevRow = await db
      .prepare('SELECT payload_hash FROM transparency_log WHERE sequence_number = ?')
      .bind(sequenceNumber - 1)
      .first<{ payload_hash: string }>();
    expectedPrevHash = prevRow?.payload_hash ?? '0';
  }

  // Compute what the chain hash should be
  const computedHash = await sha256(entry.previous_hash + entry.payload_hash);

  return {
    entry,
    proof: {
      previous_hash: expectedPrevHash,
      computed_hash: computedHash,
      valid: entry.previous_hash === expectedPrevHash,
    },
  };
}

// ---- Helpers ----

function parseEntry(row: Record<string, unknown>): TransparencyEntry {
  let metadata: Record<string, unknown> = {};
  try {
    const raw = row.metadata as string;
    if (raw && raw !== '{}') {
      metadata = JSON.parse(raw);
    }
  } catch {
    metadata = {};
  }

  return {
    id: row.id as number,
    sequence_number: row.sequence_number as number,
    timestamp: row.timestamp as string,
    action: row.action as string,
    actor_did: (row.actor_did as string) || null,
    target_type: row.target_type as string,
    target_id: row.target_id as string,
    payload_hash: row.payload_hash as string,
    previous_hash: row.previous_hash as string,
    merkle_root: (row.merkle_root as string) || null,
    signature: (row.signature as string) || null,
    metadata,
  };
}
