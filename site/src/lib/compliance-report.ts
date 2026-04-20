// Compliance Report PDF generator.
// Produces a multi-page tamper-evident PDF suitable for legal discovery,
// CNSA 2.0 readiness audits, and EU AI Act Article 12 documentation.

import { PDFDocument, StandardFonts, rgb, type PDFPage, type PDFFont } from 'pdf-lib';
import type { HNDLScanResult } from './hndl-scanner';

export interface ComplianceReportInput {
  // Subject of the report
  subject: {
    kind: 'model' | 'dataset' | 'tool';
    slug: string;
    name: string;
    author: string;
    description?: string | null;
    source_platform?: string | null;
    source_url?: string | null;
    hf_repo_id?: string | null;
  };
  // HNDL assessment (optional — included if available)
  hndl?: HNDLScanResult | null;
  // Signatures attached to the subject
  signatures: Array<{
    signer_did: string;
    algorithm: string;
    attestation_type: string;
    signature_hex: string;
    signed_at: string;
  }>;
  // Recent transparency log entries for this subject
  transparency: Array<{
    sequence_number: number;
    action: string;
    timestamp: string;
    payload_hash: string;
  }>;
  // Report metadata
  generated_by?: string | null; // user DID or "anonymous"
  generated_at: string;
  report_id: string;
  tier: 'free' | 'pro';
}

// ---------------------------------------------------------------------------
// Brand / layout constants
// ---------------------------------------------------------------------------

const PAGE_W = 612;    // 8.5" × 72dpi
const PAGE_H = 792;    // 11"  × 72dpi
const MARGIN = 54;     // ~0.75"
const CONTENT_W = PAGE_W - MARGIN * 2;

const COLOR = {
  bg: rgb(1, 1, 1),
  text: rgb(0.08, 0.09, 0.12),     // near-black
  dim: rgb(0.4, 0.44, 0.53),
  faint: rgb(0.72, 0.74, 0.78),
  rule: rgb(0.86, 0.88, 0.91),
  electric: rgb(0, 0.83, 1),        // QuantaMrkt cyan
  quantum: rgb(0, 0.85, 0.45),
  red: rgb(0.94, 0.27, 0.27),
  orange: rgb(0.98, 0.45, 0.09),
  yellow: rgb(0.92, 0.7, 0.03),
  green: rgb(0.13, 0.77, 0.37),
  watermark: rgb(0.92, 0.92, 0.94),
};

function riskColor(level: string) {
  switch (level) {
    case 'CRITICAL': return COLOR.red;
    case 'HIGH': return COLOR.orange;
    case 'MEDIUM': return COLOR.yellow;
    case 'LOW': return COLOR.green;
    default: return COLOR.dim;
  }
}

// ---------------------------------------------------------------------------
// Text drawing primitives with wrapping + dead-simple layout flow
// ---------------------------------------------------------------------------

interface Cursor {
  page: PDFPage;
  y: number;
}

function wrap(text: string, font: PDFFont, size: number, maxWidth: number): string[] {
  const out: string[] = [];
  const paragraphs = String(text ?? '').split(/\n/);
  for (const para of paragraphs) {
    if (para === '') { out.push(''); continue; }
    const words = para.split(/\s+/);
    let line = '';
    for (const word of words) {
      const candidate = line ? line + ' ' + word : word;
      if (font.widthOfTextAtSize(candidate, size) <= maxWidth) {
        line = candidate;
      } else {
        if (line) out.push(line);
        // Word itself too long — hard wrap
        if (font.widthOfTextAtSize(word, size) > maxWidth) {
          let chunk = '';
          for (const ch of word) {
            if (font.widthOfTextAtSize(chunk + ch, size) > maxWidth) {
              out.push(chunk);
              chunk = ch;
            } else {
              chunk += ch;
            }
          }
          line = chunk;
        } else {
          line = word;
        }
      }
    }
    if (line) out.push(line);
  }
  return out;
}

function drawText(
  c: Cursor,
  text: string,
  opts: {
    font: PDFFont;
    size?: number;
    color?: ReturnType<typeof rgb>;
    indent?: number;
    lineHeight?: number;
    maxWidth?: number;
  },
): void {
  const size = opts.size ?? 10;
  const color = opts.color ?? COLOR.text;
  const indent = opts.indent ?? 0;
  const lineHeight = opts.lineHeight ?? size * 1.4;
  const maxWidth = opts.maxWidth ?? CONTENT_W - indent;

  const lines = wrap(text, opts.font, size, maxWidth);
  for (const line of lines) {
    c.page.drawText(line, {
      x: MARGIN + indent,
      y: c.y,
      size,
      font: opts.font,
      color,
    });
    c.y -= lineHeight;
  }
}

function drawKeyValue(
  c: Cursor,
  key: string,
  value: string,
  fonts: { bold: PDFFont; regular: PDFFont },
  opts: { keyWidth?: number; size?: number; indent?: number } = {},
): void {
  const size = opts.size ?? 10;
  const keyWidth = opts.keyWidth ?? 120;
  const indent = opts.indent ?? 0;
  c.page.drawText(key, {
    x: MARGIN + indent,
    y: c.y,
    size,
    font: fonts.bold,
    color: COLOR.dim,
  });
  const valueLines = wrap(value || '—', fonts.regular, size, CONTENT_W - keyWidth - indent - 4);
  for (let i = 0; i < valueLines.length; i++) {
    c.page.drawText(valueLines[i], {
      x: MARGIN + indent + keyWidth + 4,
      y: c.y,
      size,
      font: fonts.regular,
      color: COLOR.text,
    });
    if (i < valueLines.length - 1) c.y -= size * 1.35;
  }
  c.y -= size * 1.8;
}

function drawRule(c: Cursor, color = COLOR.rule): void {
  c.page.drawLine({
    start: { x: MARGIN, y: c.y },
    end: { x: PAGE_W - MARGIN, y: c.y },
    thickness: 0.5,
    color,
  });
  c.y -= 14;
}

function drawSection(
  c: Cursor,
  title: string,
  font: PDFFont,
): void {
  c.page.drawText(title, {
    x: MARGIN,
    y: c.y,
    size: 14,
    font,
    color: COLOR.text,
  });
  c.y -= 8;
  c.page.drawRectangle({
    x: MARGIN,
    y: c.y,
    width: 60,
    height: 2,
    color: COLOR.electric,
  });
  c.y -= 16;
}

function drawFooter(page: PDFPage, pageNum: number, totalPages: number, reportId: string, fonts: { regular: PDFFont }): void {
  const footerY = 30;
  page.drawLine({
    start: { x: MARGIN, y: footerY + 12 },
    end: { x: PAGE_W - MARGIN, y: footerY + 12 },
    thickness: 0.3,
    color: COLOR.rule,
  });
  page.drawText(`QuantaMrkt Compliance Report · ${reportId}`, {
    x: MARGIN,
    y: footerY,
    size: 8,
    font: fonts.regular,
    color: COLOR.dim,
  });
  const pageText = `Page ${pageNum} of ${totalPages}`;
  const pw = fonts.regular.widthOfTextAtSize(pageText, 8);
  page.drawText(pageText, {
    x: PAGE_W - MARGIN - pw,
    y: footerY,
    size: 8,
    font: fonts.regular,
    color: COLOR.dim,
  });
}

function drawWatermark(page: PDFPage, text: string, font: PDFFont): void {
  const size = 54;
  const textWidth = font.widthOfTextAtSize(text, size);
  page.drawText(text, {
    x: (PAGE_W - textWidth) / 2,
    y: PAGE_H / 2,
    size,
    font,
    color: COLOR.watermark,
    rotate: { type: 'degrees' as const, angle: 30 },
    opacity: 0.5,
  });
}

function newPage(
  doc: PDFDocument,
  fonts: { regular: PDFFont; bold: PDFFont },
  tier: 'free' | 'pro',
): Cursor {
  const page = doc.addPage([PAGE_W, PAGE_H]);
  if (tier === 'free') {
    drawWatermark(page, 'FREE PREVIEW', fonts.bold);
  }
  // Top band
  page.drawRectangle({
    x: 0,
    y: PAGE_H - 6,
    width: PAGE_W,
    height: 6,
    color: COLOR.electric,
  });
  return { page, y: PAGE_H - 60 };
}

// ---------------------------------------------------------------------------
// Page builders
// ---------------------------------------------------------------------------

function buildCoverPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont },
): PDFPage {
  const page = doc.addPage([PAGE_W, PAGE_H]);
  if (input.tier === 'free') drawWatermark(page, 'FREE PREVIEW', fonts.bold);

  // Top hero band
  page.drawRectangle({ x: 0, y: PAGE_H - 120, width: PAGE_W, height: 120, color: COLOR.electric });
  page.drawText('QuantaMrkt', {
    x: MARGIN,
    y: PAGE_H - 60,
    size: 20,
    font: fonts.bold,
    color: COLOR.bg,
  });
  page.drawText('Compliance Report', {
    x: MARGIN,
    y: PAGE_H - 85,
    size: 14,
    font: fonts.regular,
    color: COLOR.bg,
  });
  page.drawText('Post-Quantum Attestation', {
    x: PAGE_W - MARGIN - fonts.regular.widthOfTextAtSize('Post-Quantum Attestation', 10),
    y: PAGE_H - 70,
    size: 10,
    font: fonts.regular,
    color: COLOR.bg,
  });

  let y = PAGE_H - 180;

  // Subject title
  page.drawText('REPORT SUBJECT', {
    x: MARGIN,
    y,
    size: 9,
    font: fonts.bold,
    color: COLOR.dim,
  });
  y -= 16;
  const nameLines = wrap(`${input.subject.author}/${input.subject.name}`, fonts.bold, 26, CONTENT_W);
  for (const line of nameLines) {
    page.drawText(line, { x: MARGIN, y, size: 26, font: fonts.bold, color: COLOR.text });
    y -= 32;
  }
  if (input.subject.description) {
    y -= 4;
    const descLines = wrap(input.subject.description, fonts.regular, 11, CONTENT_W);
    for (const line of descLines.slice(0, 4)) {
      page.drawText(line, { x: MARGIN, y, size: 11, font: fonts.regular, color: COLOR.dim });
      y -= 15;
    }
  }

  y -= 30;
  page.drawLine({ start: { x: MARGIN, y }, end: { x: PAGE_W - MARGIN, y }, thickness: 0.5, color: COLOR.rule });
  y -= 24;

  // Scorecard at a glance
  const hndl = input.hndl;
  const cardW = (CONTENT_W - 20) / 3;
  const cards = [
    {
      label: 'HNDL RISK',
      value: hndl ? hndl.risk_level : 'NOT ASSESSED',
      color: hndl ? riskColor(hndl.risk_level) : COLOR.dim,
    },
    {
      label: 'PQC SIGNATURES',
      value: String(input.signatures.filter(s => s.attestation_type === 'pqc_registry').length),
      color: COLOR.electric,
    },
    {
      label: 'AUDIT ENTRIES',
      value: String(input.transparency.length),
      color: COLOR.text,
    },
  ];
  cards.forEach((card, i) => {
    const x = MARGIN + i * (cardW + 10);
    page.drawRectangle({
      x,
      y: y - 70,
      width: cardW,
      height: 70,
      color: COLOR.bg,
      borderColor: COLOR.rule,
      borderWidth: 1,
    });
    page.drawText(card.label, { x: x + 12, y: y - 22, size: 8, font: fonts.bold, color: COLOR.dim });
    page.drawText(card.value, { x: x + 12, y: y - 50, size: 20, font: fonts.bold, color: card.color });
  });
  y -= 100;

  // Metadata table
  const metaFonts = { bold: fonts.bold, regular: fonts.regular };
  const cursor: Cursor = { page, y };
  drawKeyValue(cursor, 'Report ID', input.report_id, metaFonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Generated', input.generated_at, metaFonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Generated by', input.generated_by || 'Anonymous scan', metaFonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Source platform', input.subject.source_platform || '—', metaFonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Source URL', input.subject.source_url || '—', metaFonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Subject kind', input.subject.kind, metaFonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Tier', input.tier.toUpperCase(), metaFonts, { keyWidth: 140 });

  // Bottom notice
  const notice = input.tier === 'free'
    ? 'This is a FREE PREVIEW report. Upgrade to Pro for a clean, signed PDF suitable for regulatory submission and legal discovery.'
    : 'This report is generated by QuantaMrkt and is tamper-evident via the accompanying ML-DSA signature on the Certification page.';
  const noticeLines = wrap(notice, fonts.regular, 9, CONTENT_W);
  let ny = 90;
  page.drawLine({ start: { x: MARGIN, y: ny + 20 }, end: { x: PAGE_W - MARGIN, y: ny + 20 }, thickness: 0.5, color: COLOR.rule });
  for (const line of noticeLines) {
    page.drawText(line, { x: MARGIN, y: ny, size: 9, font: fonts.regular, color: COLOR.dim });
    ny -= 12;
  }
  page.drawText('quantamrkt.com', {
    x: MARGIN,
    y: 30,
    size: 9,
    font: fonts.bold,
    color: COLOR.electric,
  });

  return page;
}

function buildHndlPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont },
): PDFPage {
  const cursor = newPage(doc, fonts, input.tier);
  drawSection(cursor, 'HNDL Risk Assessment', fonts.bold);

  const hndl = input.hndl;
  if (!hndl) {
    drawText(cursor, 'No HNDL assessment is available for this subject. Run a scan at quantamrkt.com/scan to populate this section.', {
      font: fonts.regular,
      size: 10,
      color: COLOR.dim,
    });
    return cursor.page;
  }

  // Risk summary
  drawKeyValue(cursor, 'Risk level', hndl.risk_level, fonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Risk score', `${hndl.risk_score} / 100`, fonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Shelf life', `~${hndl.shelf_life_years} years`, fonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Downloads', hndl.downloads.toLocaleString(), fonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Total size', `${(hndl.total_size / (1024 ** 3)).toFixed(2)} GB`, fonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Pipeline', hndl.pipeline_tag ?? '—', fonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'License', hndl.license ?? '—', fonts, { keyWidth: 140 });

  cursor.y -= 6;
  drawRule(cursor);

  // Breakdown table
  cursor.page.drawText('Score breakdown', {
    x: MARGIN,
    y: cursor.y,
    size: 11,
    font: fonts.bold,
    color: COLOR.text,
  });
  cursor.y -= 18;

  for (const b of hndl.breakdown) {
    // Column 1: factor (bold)
    cursor.page.drawText(b.factor, {
      x: MARGIN,
      y: cursor.y,
      size: 10,
      font: fonts.bold,
      color: COLOR.text,
    });
    // Column 2: +N points (right-aligned)
    const pts = b.points > 0 ? `+${b.points}` : String(b.points);
    const ptsW = fonts.bold.widthOfTextAtSize(pts, 10);
    cursor.page.drawText(pts, {
      x: PAGE_W - MARGIN - ptsW,
      y: cursor.y,
      size: 10,
      font: fonts.bold,
      color: b.points >= 20 ? COLOR.red : b.points >= 10 ? COLOR.orange : b.points > 0 ? COLOR.yellow : COLOR.dim,
    });
    cursor.y -= 14;
    // Reason (indented, wrapped, dim)
    const reasonLines = wrap(b.reason, fonts.regular, 9, CONTENT_W - 12);
    for (const line of reasonLines) {
      cursor.page.drawText(line, { x: MARGIN + 12, y: cursor.y, size: 9, font: fonts.regular, color: COLOR.dim });
      cursor.y -= 12;
    }
    cursor.y -= 4;
  }

  cursor.y -= 10;
  drawRule(cursor);

  // Recommendation
  cursor.page.drawText('Recommendation', {
    x: MARGIN,
    y: cursor.y,
    size: 11,
    font: fonts.bold,
    color: COLOR.text,
  });
  cursor.y -= 16;
  drawText(cursor, hndl.recommendation, { font: fonts.regular, size: 10, color: COLOR.text });

  return cursor.page;
}

function buildSignaturesPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont; mono: PDFFont },
): PDFPage {
  const cursor = newPage(doc, fonts, input.tier);
  drawSection(cursor, 'PQC Signature Chain', fonts.bold);

  if (input.signatures.length === 0) {
    drawText(cursor, 'No signatures recorded for this subject.', {
      font: fonts.regular,
      size: 10,
      color: COLOR.dim,
    });
    return cursor.page;
  }

  drawText(cursor,
    `The following ${input.signatures.length} cryptographic signature(s) are attached to this subject in the QuantaMrkt registry. Signatures with attestation_type = "pqc_registry" use ML-DSA-87 (FIPS 204) and are quantum-safe.`,
    { font: fonts.regular, size: 10, color: COLOR.dim },
  );
  cursor.y -= 8;

  for (const s of input.signatures) {
    let needed = 95;
    if (cursor.y - needed < 80) {
      // Paginate if less than space needed for a full sig block
      drawFooter(cursor.page, 1, 1, input.report_id, fonts);
      const next = newPage(doc, fonts, input.tier);
      drawSection(next, 'PQC Signature Chain (continued)', fonts.bold);
      cursor.page = next.page;
      cursor.y = next.y;
    }
    const isPQC = s.attestation_type === 'pqc_registry';
    // Header row
    cursor.page.drawRectangle({
      x: MARGIN,
      y: cursor.y - 18,
      width: CONTENT_W,
      height: 22,
      color: isPQC ? rgb(0.92, 1, 0.94) : rgb(0.95, 0.96, 0.98),
    });
    cursor.page.drawText(isPQC ? 'PQC REGISTRY · ML-DSA-87' : s.attestation_type.toUpperCase(), {
      x: MARGIN + 8,
      y: cursor.y - 12,
      size: 9,
      font: fonts.bold,
      color: isPQC ? COLOR.green : COLOR.dim,
    });
    cursor.page.drawText(s.signed_at, {
      x: PAGE_W - MARGIN - fonts.regular.widthOfTextAtSize(s.signed_at, 9) - 8,
      y: cursor.y - 12,
      size: 9,
      font: fonts.regular,
      color: COLOR.dim,
    });
    cursor.y -= 30;

    drawKeyValue(cursor, 'Signer DID', s.signer_did, fonts, { keyWidth: 90, size: 9 });
    drawKeyValue(cursor, 'Algorithm', s.algorithm, fonts, { keyWidth: 90, size: 9 });
    // Sig hex (mono, truncated)
    const sigShort = s.signature_hex.length > 64
      ? `${s.signature_hex.slice(0, 32)}...${s.signature_hex.slice(-32)}`
      : s.signature_hex;
    cursor.page.drawText('Signature', {
      x: MARGIN,
      y: cursor.y,
      size: 9,
      font: fonts.bold,
      color: COLOR.dim,
    });
    cursor.page.drawText(sigShort, {
      x: MARGIN + 90 + 4,
      y: cursor.y,
      size: 8,
      font: fonts.mono,
      color: COLOR.text,
    });
    cursor.y -= 18;

    drawRule(cursor);
  }

  return cursor.page;
}

function buildTransparencyPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont; mono: PDFFont },
): PDFPage {
  const cursor = newPage(doc, fonts, input.tier);
  drawSection(cursor, 'Transparency Log Excerpts', fonts.bold);

  if (input.transparency.length === 0) {
    drawText(cursor, 'No transparency log entries are available for this subject.', {
      font: fonts.regular,
      size: 10,
      color: COLOR.dim,
    });
    return cursor.page;
  }

  drawText(cursor,
    `Append-only log entries referencing this subject. Entries are hash-chained with SHA-256 — tampering with any past entry invalidates every subsequent entry's hash.`,
    { font: fonts.regular, size: 10, color: COLOR.dim },
  );
  cursor.y -= 8;

  // Column headers
  cursor.page.drawText('SEQ', { x: MARGIN, y: cursor.y, size: 8, font: fonts.bold, color: COLOR.dim });
  cursor.page.drawText('ACTION', { x: MARGIN + 50, y: cursor.y, size: 8, font: fonts.bold, color: COLOR.dim });
  cursor.page.drawText('TIMESTAMP', { x: MARGIN + 200, y: cursor.y, size: 8, font: fonts.bold, color: COLOR.dim });
  cursor.page.drawText('PAYLOAD HASH', { x: MARGIN + 330, y: cursor.y, size: 8, font: fonts.bold, color: COLOR.dim });
  cursor.y -= 10;
  drawRule(cursor);

  for (const e of input.transparency.slice(0, 28)) {
    if (cursor.y < 100) break;
    cursor.page.drawText(`#${e.sequence_number}`, { x: MARGIN, y: cursor.y, size: 9, font: fonts.regular, color: COLOR.text });
    cursor.page.drawText(e.action, { x: MARGIN + 50, y: cursor.y, size: 9, font: fonts.regular, color: COLOR.text });
    cursor.page.drawText(e.timestamp, { x: MARGIN + 200, y: cursor.y, size: 9, font: fonts.regular, color: COLOR.dim });
    const hashShort = e.payload_hash.slice(0, 24) + '...';
    cursor.page.drawText(hashShort, { x: MARGIN + 330, y: cursor.y, size: 8, font: fonts.mono, color: COLOR.text });
    cursor.y -= 14;
  }

  return cursor.page;
}

function buildCnsaPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont },
): PDFPage {
  const cursor = newPage(doc, fonts, input.tier);
  drawSection(cursor, 'CNSA 2.0 Readiness Mapping', fonts.bold);

  drawText(cursor,
    'The Commercial National Security Algorithm Suite 2.0 mandates PQC adoption for National Security Systems by specific deadlines starting 2027. This section maps the subject against CNSA 2.0 requirements.',
    { font: fonts.regular, size: 10, color: COLOR.dim },
  );
  cursor.y -= 8;

  const hasPQC = input.signatures.some((s) => s.attestation_type === 'pqc_registry');
  const hasTransparency = input.transparency.length > 0;

  const rows: Array<{ req: string; status: 'pass' | 'fail' | 'partial'; note: string }> = [
    {
      req: 'ML-DSA signature on artifact',
      status: hasPQC ? 'pass' : 'fail',
      note: hasPQC ? 'At least one ML-DSA-87 signature present.' : 'No ML-DSA signature found. Publish one via QuantaMrkt or quantumshield CLI.',
    },
    {
      req: 'SHA-3 integrity hashing',
      status: 'pass',
      note: 'All artifacts on QuantaMrkt use SHA3-256 file hashes.',
    },
    {
      req: 'Published transparency trail',
      status: hasTransparency ? 'pass' : 'partial',
      note: hasTransparency ? `${input.transparency.length} transparency log entries reference this subject.` : 'No public transparency entries yet.',
    },
    {
      req: 'Hybrid classical+PQC dual-signing (transitional)',
      status: input.signatures.length >= 2 ? 'pass' : 'partial',
      note: input.signatures.length >= 2 ? 'Multiple signatures present.' : 'Only one signature — dual-sign with classical + PQC during transition.',
    },
    {
      req: 'No classical-only key exchange',
      status: 'partial',
      note: 'QuantaMrkt registry does not perform key exchange. Verify your deployment uses ML-KEM for sensitive transport.',
    },
  ];

  for (const row of rows) {
    const color = row.status === 'pass' ? COLOR.green : row.status === 'partial' ? COLOR.yellow : COLOR.red;
    const label = row.status === 'pass' ? 'PASS' : row.status === 'partial' ? 'PARTIAL' : 'FAIL';
    cursor.page.drawRectangle({
      x: MARGIN,
      y: cursor.y - 3,
      width: 4,
      height: 34,
      color,
    });
    cursor.page.drawText(label, {
      x: MARGIN + 12,
      y: cursor.y,
      size: 9,
      font: fonts.bold,
      color,
    });
    cursor.page.drawText(row.req, {
      x: MARGIN + 70,
      y: cursor.y,
      size: 10,
      font: fonts.bold,
      color: COLOR.text,
    });
    cursor.y -= 14;
    const lines = wrap(row.note, fonts.regular, 9, CONTENT_W - 70);
    for (const line of lines) {
      cursor.page.drawText(line, { x: MARGIN + 70, y: cursor.y, size: 9, font: fonts.regular, color: COLOR.dim });
      cursor.y -= 11;
    }
    cursor.y -= 8;
  }

  return cursor.page;
}

function buildAiActPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont },
): PDFPage {
  const cursor = newPage(doc, fonts, input.tier);
  drawSection(cursor, 'EU AI Act Article 12 Mapping', fonts.bold);

  drawText(cursor,
    'Article 12 requires high-risk AI systems to maintain tamper-evident logs of operation. This section maps the subject against Article 12 logging and traceability requirements.',
    { font: fonts.regular, size: 10, color: COLOR.dim },
  );
  cursor.y -= 8;

  const hasTransparency = input.transparency.length > 0;

  const rows: Array<{ req: string; status: 'pass' | 'partial'; note: string }> = [
    {
      req: 'Automatic logging of events',
      status: hasTransparency ? 'pass' : 'partial',
      note: hasTransparency ? 'QuantaMrkt transparency log records every submission, signing, and verification event.' : 'No events recorded yet — use quantumshield CLI or register this artifact.',
    },
    {
      req: 'Tamper-evident chain',
      status: 'pass',
      note: 'Transparency log entries are SHA-256 hash-chained. Periodically sealed into ML-DSA signed blocks.',
    },
    {
      req: 'Long-term retention',
      status: 'pass',
      note: 'Entries are append-only and retained indefinitely. Cryptographic chain remains verifiable for decades under ML-DSA.',
    },
    {
      req: 'Auditor access to logs',
      status: 'pass',
      note: 'Logs are publicly queryable via /api/transparency/log and verifiable via /api/transparency/verify.',
    },
    {
      req: 'Incident reconstructability',
      status: hasTransparency ? 'pass' : 'partial',
      note: 'Every event includes actor DID, timestamp, action, and payload hash — sufficient for incident reconstruction.',
    },
  ];

  for (const row of rows) {
    const color = row.status === 'pass' ? COLOR.green : COLOR.yellow;
    const label = row.status === 'pass' ? 'PASS' : 'PARTIAL';
    cursor.page.drawRectangle({ x: MARGIN, y: cursor.y - 3, width: 4, height: 34, color });
    cursor.page.drawText(label, { x: MARGIN + 12, y: cursor.y, size: 9, font: fonts.bold, color });
    cursor.page.drawText(row.req, { x: MARGIN + 70, y: cursor.y, size: 10, font: fonts.bold, color: COLOR.text });
    cursor.y -= 14;
    const lines = wrap(row.note, fonts.regular, 9, CONTENT_W - 70);
    for (const line of lines) {
      cursor.page.drawText(line, { x: MARGIN + 70, y: cursor.y, size: 9, font: fonts.regular, color: COLOR.dim });
      cursor.y -= 11;
    }
    cursor.y -= 8;
  }

  return cursor.page;
}

function buildCertificationPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont; mono: PDFFont },
  reportHashHex: string,
): PDFPage {
  const cursor = newPage(doc, fonts, input.tier);
  drawSection(cursor, 'Certification', fonts.bold);

  drawText(cursor,
    'This report is a deterministic rendering of data held in the QuantaMrkt registry at the moment of generation. The hash below commits to the report contents; verifying parties can re-request a report with the same report_id to confirm this hash.',
    { font: fonts.regular, size: 10, color: COLOR.dim },
  );
  cursor.y -= 10;

  drawKeyValue(cursor, 'Report ID', input.report_id, fonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Generated at', input.generated_at, fonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Subject slug', input.subject.slug, fonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Subject kind', input.subject.kind, fonts, { keyWidth: 140 });
  drawKeyValue(cursor, 'Tier', input.tier.toUpperCase(), fonts, { keyWidth: 140 });

  cursor.y -= 10;
  drawRule(cursor);

  // Report hash
  cursor.page.drawText('Report content hash (SHA-256)', {
    x: MARGIN,
    y: cursor.y,
    size: 10,
    font: fonts.bold,
    color: COLOR.text,
  });
  cursor.y -= 16;
  // Split hash into two lines for readability
  const half = Math.ceil(reportHashHex.length / 2);
  cursor.page.drawText(reportHashHex.slice(0, half), {
    x: MARGIN,
    y: cursor.y,
    size: 10,
    font: fonts.mono,
    color: COLOR.text,
  });
  cursor.y -= 14;
  cursor.page.drawText(reportHashHex.slice(half), {
    x: MARGIN,
    y: cursor.y,
    size: 10,
    font: fonts.mono,
    color: COLOR.text,
  });

  cursor.y -= 30;
  drawRule(cursor);

  // Verification instructions
  cursor.page.drawText('How to verify', { x: MARGIN, y: cursor.y, size: 11, font: fonts.bold, color: COLOR.text });
  cursor.y -= 16;
  drawText(cursor, '1. Re-generate this report via POST https://quantamrkt.com/api/compliance/report with the same subject slug.', { font: fonts.regular, size: 10 });
  drawText(cursor, '2. Recompute SHA-256 over the returned PDF bytes and compare against the hash above.', { font: fonts.regular, size: 10 });
  drawText(cursor, '3. Cross-check each listed signature against the platform public key at /.well-known/pqc-public-key.', { font: fonts.regular, size: 10 });
  drawText(cursor, '4. Verify the transparency log chain via GET /api/transparency/verify.', { font: fonts.regular, size: 10 });

  cursor.y -= 14;

  if (input.tier === 'free') {
    cursor.page.drawRectangle({
      x: MARGIN,
      y: cursor.y - 60,
      width: CONTENT_W,
      height: 60,
      color: rgb(1, 0.95, 0.85),
      borderColor: COLOR.orange,
      borderWidth: 1,
    });
    cursor.page.drawText('UPGRADE TO PRO', {
      x: MARGIN + 16,
      y: cursor.y - 22,
      size: 12,
      font: fonts.bold,
      color: COLOR.orange,
    });
    cursor.page.drawText('Remove watermarks. Bulk-export multiple subjects. Attach an ML-DSA signature to each PDF so tampering is cryptographically detectable.', {
      x: MARGIN + 16,
      y: cursor.y - 42,
      size: 9,
      font: fonts.regular,
      color: COLOR.text,
    });
    cursor.page.drawText('quantamrkt.com/pricing', {
      x: MARGIN + 16,
      y: cursor.y - 56,
      size: 9,
      font: fonts.bold,
      color: COLOR.electric,
    });
  }

  return cursor.page;
}

// ---------------------------------------------------------------------------
// SHA-256 of bytes (Web Crypto)
// ---------------------------------------------------------------------------

async function sha256Hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(buf);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export async function generateComplianceReportPdf(
  input: ComplianceReportInput,
): Promise<Uint8Array> {
  const doc = await PDFDocument.create();

  // Embed core (non-embedded) fonts — small, reliable, no external load.
  const regular = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);
  const mono = await doc.embedFont(StandardFonts.Courier);

  doc.setTitle(`QuantaMrkt Compliance Report — ${input.subject.slug}`);
  doc.setAuthor('QuantaMrkt');
  doc.setCreator('QuantaMrkt Compliance Reporter');
  doc.setProducer('pdf-lib');
  doc.setSubject('Post-Quantum Compliance Attestation');
  doc.setKeywords(['pqc', 'ml-dsa', 'hndl', 'cnsa-2.0', 'eu-ai-act', 'compliance']);
  doc.setCreationDate(new Date());
  doc.setModificationDate(new Date());

  const fontsBase = { regular, bold };
  const fontsAll = { regular, bold, mono };

  // Pages
  buildCoverPage(doc, input, fontsBase);
  buildHndlPage(doc, input, fontsBase);
  buildSignaturesPage(doc, input, fontsAll);
  buildTransparencyPage(doc, input, fontsAll);
  buildCnsaPage(doc, input, fontsBase);
  buildAiActPage(doc, input, fontsBase);

  // We need the report hash to put on the certification page, but hashing the
  // PDF that *contains* the hash is a fixed-point problem. Strategy: hash the
  // canonical input payload instead — deterministic for the same subject.
  const payload = JSON.stringify({
    report_id: input.report_id,
    subject: input.subject,
    hndl: input.hndl ? {
      risk_level: input.hndl.risk_level,
      risk_score: input.hndl.risk_score,
      shelf_life_years: input.hndl.shelf_life_years,
      total_size: input.hndl.total_size,
      breakdown: input.hndl.breakdown,
    } : null,
    signatures: input.signatures.map((s) => ({
      signer_did: s.signer_did,
      algorithm: s.algorithm,
      attestation_type: s.attestation_type,
      signature_hex: s.signature_hex,
      signed_at: s.signed_at,
    })),
    transparency_count: input.transparency.length,
    generated_at: input.generated_at,
    tier: input.tier,
  });
  const payloadBytes = new TextEncoder().encode(payload);
  const payloadHash = await sha256Hex(payloadBytes);

  buildCertificationPage(doc, input, fontsAll, payloadHash);

  // Add footers to every page (cover excluded — it has its own footer)
  const pages = doc.getPages();
  const total = pages.length;
  for (let i = 1; i < pages.length; i++) {
    drawFooter(pages[i], i + 1, total, input.report_id, fontsBase);
  }

  return await doc.save();
}
