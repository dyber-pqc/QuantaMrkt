// Compliance Report PDF generator.
// Produces a multi-page PDF suitable for legal discovery, CNSA 2.0 readiness
// audits, and EU AI Act Article 12 documentation.
//
// Design goals:
//   - Executive-document typography (restrained, clear hierarchy)
//   - Consistent baseline grid — 8pt vertical rhythm, 54pt page margins
//   - No watermarks; all reports are free and full-featured
//   - Fixed-position footer so page breaks don't overlap body text

import { PDFDocument, StandardFonts, rgb, type PDFPage, type PDFFont } from 'pdf-lib';
import type { HNDLScanResult } from './hndl-scanner';

export interface ComplianceReportInput {
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
  hndl?: HNDLScanResult | null;
  signatures: Array<{
    signer_did: string;
    algorithm: string;
    attestation_type: string;
    signature_hex: string;
    signed_at: string;
  }>;
  transparency: Array<{
    sequence_number: number;
    action: string;
    timestamp: string;
    payload_hash: string;
  }>;
  generated_by?: string | null;
  generated_at: string;
  report_id: string;
  // Kept for backwards compatibility; ignored — all reports are full.
  tier?: 'free' | 'pro';
}

// ---------------------------------------------------------------------------
// Layout constants — 8pt vertical rhythm throughout
// ---------------------------------------------------------------------------

const PAGE_W = 612;
const PAGE_H = 792;
const MARGIN_X = 56;
const MARGIN_Y_TOP = 64;
const MARGIN_Y_BOTTOM = 72;      // leaves room for footer
const CONTENT_W = PAGE_W - MARGIN_X * 2;
const CONTENT_MIN_Y = MARGIN_Y_BOTTOM;

// Typography scale (pt)
const FS_MICRO = 8;
const FS_SMALL = 9;
const FS_BODY = 10;
const FS_LABEL = 9;
const FS_H3 = 12;
const FS_H2 = 15;
const FS_H1 = 28;

// Line heights (line-height = size * factor)
const LH_BODY = 1.45;
const LH_TIGHT = 1.2;

// Brand palette — muted, not neon
const C = {
  text: rgb(0.09, 0.1, 0.13),
  secondary: rgb(0.34, 0.39, 0.47),
  muted: rgb(0.54, 0.58, 0.64),
  faint: rgb(0.78, 0.81, 0.86),
  rule: rgb(0.88, 0.90, 0.93),
  panel: rgb(0.97, 0.98, 0.99),
  // Accent used sparingly — only on rules and labels
  accent: rgb(0.02, 0.42, 0.76),    // calmer blue than neon cyan
  green: rgb(0.08, 0.55, 0.30),
  red: rgb(0.80, 0.15, 0.15),
  orange: rgb(0.83, 0.42, 0.06),
  yellow: rgb(0.71, 0.53, 0.03),
  bg: rgb(1, 1, 1),
};

function riskColor(level: string) {
  switch (level) {
    case 'CRITICAL': return C.red;
    case 'HIGH': return C.orange;
    case 'MEDIUM': return C.yellow;
    case 'LOW': return C.green;
    default: return C.muted;
  }
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

interface Cursor { page: PDFPage; y: number; }

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
        if (font.widthOfTextAtSize(word, size) > maxWidth) {
          let chunk = '';
          for (const ch of word) {
            if (font.widthOfTextAtSize(chunk + ch, size) > maxWidth) {
              out.push(chunk);
              chunk = ch;
            } else chunk += ch;
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

function textLine(
  page: PDFPage,
  text: string,
  x: number,
  y: number,
  opts: { font: PDFFont; size: number; color?: ReturnType<typeof rgb>; maxChars?: number },
): void {
  const str = opts.maxChars && text.length > opts.maxChars
    ? text.slice(0, opts.maxChars - 1) + '...'
    : text;
  page.drawText(str, {
    x,
    y,
    size: opts.size,
    font: opts.font,
    color: opts.color ?? C.text,
  });
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
    paragraphGap?: number;
  },
): void {
  const size = opts.size ?? FS_BODY;
  const color = opts.color ?? C.text;
  const indent = opts.indent ?? 0;
  const lineHeight = opts.lineHeight ?? size * LH_BODY;
  const maxWidth = opts.maxWidth ?? CONTENT_W - indent;

  const lines = wrap(text, opts.font, size, maxWidth);
  for (const line of lines) {
    if (c.y < CONTENT_MIN_Y) break;
    c.page.drawText(line, { x: MARGIN_X + indent, y: c.y, size, font: opts.font, color });
    c.y -= lineHeight;
  }
  if (opts.paragraphGap) c.y -= opts.paragraphGap;
}

function drawLabelValue(
  c: Cursor,
  label: string,
  value: string,
  fonts: { bold: PDFFont; regular: PDFFont },
  opts: { labelWidth?: number } = {},
): void {
  const size = FS_BODY;
  const labelWidth = opts.labelWidth ?? 120;
  const labelSize = FS_SMALL;

  c.page.drawText(label, {
    x: MARGIN_X,
    y: c.y,
    size: labelSize,
    font: fonts.bold,
    color: C.secondary,
  });

  const valueLines = wrap(value || '—', fonts.regular, size, CONTENT_W - labelWidth - 8);
  let localY = c.y + 1;
  for (let i = 0; i < valueLines.length; i++) {
    c.page.drawText(valueLines[i], {
      x: MARGIN_X + labelWidth,
      y: localY,
      size,
      font: fonts.regular,
      color: C.text,
    });
    if (i < valueLines.length - 1) localY -= size * LH_BODY;
  }
  // Drop cursor to below the taller of label/value
  c.y -= Math.max(size * LH_BODY, valueLines.length * size * LH_BODY) + 2;
}

function drawRule(c: Cursor, gap = 14, color = C.rule): void {
  c.page.drawLine({
    start: { x: MARGIN_X, y: c.y },
    end: { x: PAGE_W - MARGIN_X, y: c.y },
    thickness: 0.5,
    color,
  });
  c.y -= gap;
}

function drawSectionHeader(c: Cursor, title: string, fonts: { bold: PDFFont }): void {
  c.page.drawText(title, {
    x: MARGIN_X,
    y: c.y,
    size: FS_H2,
    font: fonts.bold,
    color: C.text,
  });
  c.y -= 6;
  c.page.drawRectangle({
    x: MARGIN_X,
    y: c.y,
    width: 40,
    height: 1.5,
    color: C.accent,
  });
  c.y -= 22;
}

function drawFooter(
  page: PDFPage,
  pageNum: number,
  totalPages: number,
  reportId: string,
  fonts: { regular: PDFFont },
): void {
  const y = 36;
  page.drawLine({
    start: { x: MARGIN_X, y: y + 14 },
    end: { x: PAGE_W - MARGIN_X, y: y + 14 },
    thickness: 0.4,
    color: C.rule,
  });
  // Truncate long report IDs to keep the footer on one line
  const idShort = reportId.length > 40 ? reportId.slice(0, 40) + '...' : reportId;
  page.drawText(`QuantaMrkt Compliance Report · ${idShort}`, {
    x: MARGIN_X,
    y,
    size: FS_MICRO,
    font: fonts.regular,
    color: C.muted,
  });
  const pageText = `${pageNum} / ${totalPages}`;
  const w = fonts.regular.widthOfTextAtSize(pageText, FS_MICRO);
  page.drawText(pageText, {
    x: PAGE_W - MARGIN_X - w,
    y,
    size: FS_MICRO,
    font: fonts.regular,
    color: C.muted,
  });
}

function newPage(
  doc: PDFDocument,
  fonts: { regular: PDFFont; bold: PDFFont },
): Cursor {
  const page = doc.addPage([PAGE_W, PAGE_H]);
  // Subtle top rule instead of big colored band
  page.drawRectangle({
    x: MARGIN_X,
    y: PAGE_H - MARGIN_Y_TOP / 2,
    width: CONTENT_W,
    height: 0.5,
    color: C.rule,
  });
  // Running header: brand on left, doc type on right
  page.drawText('QuantaMrkt', {
    x: MARGIN_X,
    y: PAGE_H - MARGIN_Y_TOP / 2 - 12,
    size: FS_MICRO,
    font: fonts.bold,
    color: C.accent,
  });
  const rightLabel = 'Compliance Report';
  const rw = fonts.regular.widthOfTextAtSize(rightLabel, FS_MICRO);
  page.drawText(rightLabel, {
    x: PAGE_W - MARGIN_X - rw,
    y: PAGE_H - MARGIN_Y_TOP / 2 - 12,
    size: FS_MICRO,
    font: fonts.regular,
    color: C.muted,
  });
  return { page, y: PAGE_H - MARGIN_Y_TOP - 20 };
}

// ---------------------------------------------------------------------------
// Cover page
// ---------------------------------------------------------------------------

function buildCoverPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont },
): PDFPage {
  const page = doc.addPage([PAGE_W, PAGE_H]);

  // Minimal brand header (no giant cyan block)
  page.drawText('QuantaMrkt', {
    x: MARGIN_X,
    y: PAGE_H - MARGIN_Y_TOP,
    size: 13,
    font: fonts.bold,
    color: C.accent,
  });
  const subtitle = 'Post-Quantum Compliance Report';
  const subW = fonts.regular.widthOfTextAtSize(subtitle, FS_SMALL);
  page.drawText(subtitle, {
    x: PAGE_W - MARGIN_X - subW,
    y: PAGE_H - MARGIN_Y_TOP,
    size: FS_SMALL,
    font: fonts.regular,
    color: C.muted,
  });

  page.drawLine({
    start: { x: MARGIN_X, y: PAGE_H - MARGIN_Y_TOP - 14 },
    end: { x: PAGE_W - MARGIN_X, y: PAGE_H - MARGIN_Y_TOP - 14 },
    thickness: 0.5,
    color: C.rule,
  });

  // Title block — plenty of vertical space so the label doesn't crash the title
  let y = PAGE_H - 180;

  page.drawText('REPORT SUBJECT', {
    x: MARGIN_X,
    y,
    size: FS_MICRO,
    font: fonts.bold,
    color: C.muted,
  });
  y -= 22;

  const authorSlug = `${input.subject.author}/${input.subject.name}`;
  const titleLines = wrap(authorSlug, fonts.bold, FS_H1, CONTENT_W);
  for (const line of titleLines.slice(0, 2)) {
    page.drawText(line, {
      x: MARGIN_X,
      y,
      size: FS_H1,
      font: fonts.bold,
      color: C.text,
    });
    y -= FS_H1 * LH_TIGHT;
  }

  if (input.subject.description) {
    y -= 12;
    const descLines = wrap(input.subject.description, fonts.regular, FS_BODY + 1, CONTENT_W);
    for (const line of descLines.slice(0, 3)) {
      page.drawText(line, {
        x: MARGIN_X,
        y,
        size: FS_BODY + 1,
        font: fonts.regular,
        color: C.secondary,
      });
      y -= (FS_BODY + 1) * LH_BODY;
    }
  }

  // Clear gap
  y -= 40;
  page.drawLine({ start: { x: MARGIN_X, y }, end: { x: PAGE_W - MARGIN_X, y }, thickness: 0.5, color: C.rule });
  y -= 30;

  // 3 scorecard panels — light borders, no fills
  const hndl = input.hndl;
  const cardGap = 16;
  const cardW = (CONTENT_W - cardGap * 2) / 3;
  const cardH = 84;
  const cards = [
    {
      label: 'HNDL RISK',
      value: hndl ? hndl.risk_level : 'NOT ASSESSED',
      sub: hndl ? `${hndl.risk_score} / 100` : '—',
      color: hndl ? riskColor(hndl.risk_level) : C.muted,
    },
    {
      label: 'PQC SIGNATURES',
      value: String(input.signatures.filter(s => s.attestation_type === 'pqc_registry').length),
      sub: `of ${input.signatures.length} total`,
      color: C.accent,
    },
    {
      label: 'AUDIT ENTRIES',
      value: String(input.transparency.length),
      sub: input.transparency.length >= 30 ? '30+ recent' : 'recent events',
      color: C.text,
    },
  ];

  cards.forEach((card, i) => {
    const x = MARGIN_X + i * (cardW + cardGap);
    page.drawRectangle({
      x, y: y - cardH,
      width: cardW,
      height: cardH,
      color: C.bg,
      borderColor: C.rule,
      borderWidth: 0.75,
    });
    page.drawText(card.label, {
      x: x + 14,
      y: y - 20,
      size: FS_MICRO,
      font: fonts.bold,
      color: C.muted,
    });
    page.drawText(card.value, {
      x: x + 14,
      y: y - 50,
      size: 22,
      font: fonts.bold,
      color: card.color,
    });
    page.drawText(card.sub, {
      x: x + 14,
      y: y - 70,
      size: FS_MICRO,
      font: fonts.regular,
      color: C.muted,
    });
  });

  y -= cardH + 36;

  // Metadata block
  const c: Cursor = { page, y };
  drawLabelValue(c, 'Report ID', input.report_id, fonts);
  drawLabelValue(c, 'Generated', input.generated_at, fonts);
  drawLabelValue(c, 'Generated by', input.generated_by || 'Anonymous scan', fonts);
  drawLabelValue(c, 'Source', input.subject.source_url || input.subject.source_platform || '—', fonts);
  drawLabelValue(c, 'Subject kind', input.subject.kind, fonts);

  // Footer — cover has its own footer style (no page numbers on cover)
  const footerY = 52;
  page.drawLine({
    start: { x: MARGIN_X, y: footerY + 18 },
    end: { x: PAGE_W - MARGIN_X, y: footerY + 18 },
    thickness: 0.5,
    color: C.rule,
  });
  const footerLines = [
    'This report is deterministically generated by the QuantaMrkt registry.',
    'Its contents are committed to by the SHA-256 hash printed on the Certification page.',
  ];
  footerLines.forEach((line, i) => {
    page.drawText(line, {
      x: MARGIN_X,
      y: footerY + (footerLines.length - 1 - i) * 12,
      size: FS_MICRO,
      font: fonts.regular,
      color: C.muted,
    });
  });
  const url = 'quantamrkt.com';
  const urlW = fonts.bold.widthOfTextAtSize(url, FS_SMALL);
  page.drawText(url, {
    x: PAGE_W - MARGIN_X - urlW,
    y: footerY,
    size: FS_SMALL,
    font: fonts.bold,
    color: C.accent,
  });

  return page;
}

// ---------------------------------------------------------------------------
// HNDL Risk page
// ---------------------------------------------------------------------------

function buildHndlPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont },
): PDFPage {
  const c = newPage(doc, fonts);
  drawSectionHeader(c, 'HNDL Risk Assessment', fonts);

  const hndl = input.hndl;
  if (!hndl) {
    drawText(c, 'No HNDL assessment is available for this subject. Run a scan at quantamrkt.com/scan to populate this section.', {
      font: fonts.regular,
      size: FS_BODY,
      color: C.secondary,
    });
    return c.page;
  }

  drawText(c, 'HNDL ("Harvest Now, Decrypt Later") is the quantifiable risk that classically-encrypted data about this artifact, if harvested today, will be decrypted once cryptographically relevant quantum computers exist.', {
    font: fonts.regular,
    size: FS_BODY,
    color: C.secondary,
    paragraphGap: 8,
  });

  // Summary
  drawLabelValue(c, 'Risk level', hndl.risk_level, fonts);
  drawLabelValue(c, 'Risk score', `${hndl.risk_score} / 100`, fonts);
  drawLabelValue(c, 'Shelf life', `~${hndl.shelf_life_years} years`, fonts);
  drawLabelValue(c, 'Downloads', hndl.downloads.toLocaleString(), fonts);
  drawLabelValue(c, 'Total size', `${(hndl.total_size / (1024 ** 3)).toFixed(2)} GB`, fonts);
  drawLabelValue(c, 'Pipeline', hndl.pipeline_tag ?? '—', fonts);
  drawLabelValue(c, 'License', hndl.license ?? '—', fonts);

  c.y -= 6;
  drawRule(c, 18);

  // Breakdown
  c.page.drawText('Score Breakdown', {
    x: MARGIN_X,
    y: c.y,
    size: FS_H3,
    font: fonts.bold,
    color: C.text,
  });
  c.y -= 18;

  for (const b of hndl.breakdown) {
    if (c.y < CONTENT_MIN_Y + 50) break;
    const pts = b.points > 0 ? `+${b.points}` : String(b.points);
    const ptsColor = b.points >= 20 ? C.red : b.points >= 10 ? C.orange : b.points > 0 ? C.yellow : C.muted;
    const ptsW = fonts.bold.widthOfTextAtSize(pts, FS_BODY);

    // Factor + points row
    c.page.drawText(b.factor, {
      x: MARGIN_X,
      y: c.y,
      size: FS_BODY,
      font: fonts.bold,
      color: C.text,
    });
    c.page.drawText(pts, {
      x: PAGE_W - MARGIN_X - ptsW,
      y: c.y,
      size: FS_BODY,
      font: fonts.bold,
      color: ptsColor,
    });
    c.y -= FS_BODY * LH_BODY;

    // Reason (indented)
    const reasonLines = wrap(b.reason, fonts.regular, FS_SMALL, CONTENT_W - 14);
    for (const line of reasonLines) {
      if (c.y < CONTENT_MIN_Y) break;
      c.page.drawText(line, {
        x: MARGIN_X + 14,
        y: c.y,
        size: FS_SMALL,
        font: fonts.regular,
        color: C.secondary,
      });
      c.y -= FS_SMALL * LH_BODY;
    }
    c.y -= 6;
  }

  c.y -= 8;
  drawRule(c, 16);

  // Recommendation
  c.page.drawText('Recommendation', {
    x: MARGIN_X,
    y: c.y,
    size: FS_H3,
    font: fonts.bold,
    color: C.text,
  });
  c.y -= 18;
  drawText(c, hndl.recommendation, { font: fonts.regular, size: FS_BODY });

  return c.page;
}

// ---------------------------------------------------------------------------
// Signatures page
// ---------------------------------------------------------------------------

function buildSignaturesPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont; mono: PDFFont },
): PDFPage {
  const c = newPage(doc, fonts);
  drawSectionHeader(c, 'PQC Signature Chain', fonts);

  if (input.signatures.length === 0) {
    drawText(c, 'No signatures recorded for this subject.', {
      font: fonts.regular,
      size: FS_BODY,
      color: C.secondary,
    });
    return c.page;
  }

  drawText(c,
    `${input.signatures.length} signature${input.signatures.length === 1 ? '' : 's'} are attached to this subject in the registry. Signatures with attestation_type pqc_registry use ML-DSA-87 (FIPS 204) and remain verifiable after quantum computers exist.`,
    {
      font: fonts.regular,
      size: FS_BODY,
      color: C.secondary,
      paragraphGap: 8,
    },
  );

  for (const s of input.signatures) {
    const isPQC = s.attestation_type === 'pqc_registry';
    if (c.y < CONTENT_MIN_Y + 90) {
      drawFooter(c.page, 0, 0, input.report_id, fonts); // placeholder, real numbers applied later
      const next = newPage(doc, fonts);
      drawSectionHeader(next, 'PQC Signature Chain (cont.)', fonts);
      c.page = next.page;
      c.y = next.y;
    }

    // Attestation tag
    const tag = isPQC ? 'PQC REGISTRY · ML-DSA-87' : s.attestation_type.toUpperCase();
    const tagColor = isPQC ? C.green : C.muted;
    const tagW = fonts.bold.widthOfTextAtSize(tag, FS_MICRO) + 14;
    c.page.drawRectangle({
      x: MARGIN_X,
      y: c.y - 4,
      width: tagW,
      height: 14,
      color: C.bg,
      borderColor: tagColor,
      borderWidth: 0.75,
    });
    c.page.drawText(tag, {
      x: MARGIN_X + 7,
      y: c.y,
      size: FS_MICRO,
      font: fonts.bold,
      color: tagColor,
    });
    // Timestamp on the right
    const ts = s.signed_at || '—';
    const tsW = fonts.regular.widthOfTextAtSize(ts, FS_MICRO);
    c.page.drawText(ts, {
      x: PAGE_W - MARGIN_X - tsW,
      y: c.y,
      size: FS_MICRO,
      font: fonts.regular,
      color: C.muted,
    });
    c.y -= 22;

    drawLabelValue(c, 'Signer DID', s.signer_did, fonts, { labelWidth: 90 });
    drawLabelValue(c, 'Algorithm', s.algorithm, fonts, { labelWidth: 90 });

    // Signature hex — monospace, truncated
    const sigShort = s.signature_hex.length > 72
      ? `${s.signature_hex.slice(0, 36)}...${s.signature_hex.slice(-36)}`
      : s.signature_hex;
    c.page.drawText('Signature', {
      x: MARGIN_X,
      y: c.y,
      size: FS_SMALL,
      font: fonts.bold,
      color: C.secondary,
    });
    c.page.drawText(sigShort, {
      x: MARGIN_X + 90,
      y: c.y,
      size: FS_MICRO,
      font: fonts.mono,
      color: C.text,
    });
    c.y -= 16;

    drawRule(c, 14);
  }

  return c.page;
}

// ---------------------------------------------------------------------------
// Transparency page
// ---------------------------------------------------------------------------

function buildTransparencyPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont; mono: PDFFont },
): PDFPage {
  const c = newPage(doc, fonts);
  drawSectionHeader(c, 'Transparency Log Excerpts', fonts);

  if (input.transparency.length === 0) {
    drawText(c, 'No transparency log entries are available for this subject.', {
      font: fonts.regular,
      size: FS_BODY,
      color: C.secondary,
    });
    return c.page;
  }

  drawText(c,
    'Append-only log entries referencing this subject. Entries are hash-chained with SHA-256 — tampering with any past entry invalidates every subsequent entry\'s hash.',
    {
      font: fonts.regular,
      size: FS_BODY,
      color: C.secondary,
      paragraphGap: 8,
    },
  );

  // Table header
  const colSeq = MARGIN_X;
  const colAction = MARGIN_X + 48;
  const colTime = MARGIN_X + 200;
  const colHash = MARGIN_X + 330;

  c.page.drawText('SEQ', { x: colSeq, y: c.y, size: FS_MICRO, font: fonts.bold, color: C.muted });
  c.page.drawText('ACTION', { x: colAction, y: c.y, size: FS_MICRO, font: fonts.bold, color: C.muted });
  c.page.drawText('TIMESTAMP', { x: colTime, y: c.y, size: FS_MICRO, font: fonts.bold, color: C.muted });
  c.page.drawText('PAYLOAD HASH', { x: colHash, y: c.y, size: FS_MICRO, font: fonts.bold, color: C.muted });
  c.y -= 8;
  drawRule(c, 10);

  for (const e of input.transparency.slice(0, 30)) {
    if (c.y < CONTENT_MIN_Y) break;
    c.page.drawText(`#${e.sequence_number}`, { x: colSeq, y: c.y, size: FS_SMALL, font: fonts.regular, color: C.text });
    textLine(c.page, e.action, colAction, c.y, { font: fonts.regular, size: FS_SMALL, color: C.text, maxChars: 26 });
    textLine(c.page, e.timestamp, colTime, c.y, { font: fonts.regular, size: FS_SMALL, color: C.secondary, maxChars: 22 });
    const hashShort = e.payload_hash.slice(0, 20) + '...';
    c.page.drawText(hashShort, { x: colHash, y: c.y, size: FS_MICRO, font: fonts.mono, color: C.text });
    c.y -= 14;
  }

  return c.page;
}

// ---------------------------------------------------------------------------
// Compliance mappings (CNSA 2.0 + EU AI Act Article 12)
// ---------------------------------------------------------------------------

type Status = 'pass' | 'partial' | 'fail';
interface Requirement { req: string; status: Status; note: string; }

function drawRequirement(
  c: Cursor,
  row: Requirement,
  fonts: { regular: PDFFont; bold: PDFFont },
): void {
  const color = row.status === 'pass' ? C.green : row.status === 'partial' ? C.yellow : C.red;
  const label = row.status.toUpperCase();

  // Status pill
  const labelW = fonts.bold.widthOfTextAtSize(label, FS_MICRO);
  const pillW = labelW + 14;
  c.page.drawRectangle({
    x: MARGIN_X,
    y: c.y - 2,
    width: pillW,
    height: 13,
    color: C.bg,
    borderColor: color,
    borderWidth: 0.75,
  });
  c.page.drawText(label, {
    x: MARGIN_X + 7,
    y: c.y,
    size: FS_MICRO,
    font: fonts.bold,
    color,
  });

  // Requirement heading
  c.page.drawText(row.req, {
    x: MARGIN_X + pillW + 12,
    y: c.y,
    size: FS_BODY,
    font: fonts.bold,
    color: C.text,
  });
  c.y -= 16;

  // Note (full-width, indented)
  const noteLines = wrap(row.note, fonts.regular, FS_SMALL, CONTENT_W - (pillW + 12));
  for (const line of noteLines) {
    if (c.y < CONTENT_MIN_Y) break;
    c.page.drawText(line, {
      x: MARGIN_X + pillW + 12,
      y: c.y,
      size: FS_SMALL,
      font: fonts.regular,
      color: C.secondary,
    });
    c.y -= FS_SMALL * LH_BODY;
  }
  c.y -= 10;
}

function buildCnsaPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont },
): PDFPage {
  const c = newPage(doc, fonts);
  drawSectionHeader(c, 'CNSA 2.0 Readiness Mapping', fonts);

  drawText(c,
    'The Commercial National Security Algorithm Suite 2.0 mandates post-quantum cryptographic adoption for National Security Systems by specific deadlines starting in 2027. This section maps the subject against the five CNSA 2.0 requirements most relevant to AI artifact provenance.',
    {
      font: fonts.regular,
      size: FS_BODY,
      color: C.secondary,
      paragraphGap: 12,
    },
  );

  const hasPQC = input.signatures.some(s => s.attestation_type === 'pqc_registry');
  const hasTransparency = input.transparency.length > 0;

  const rows: Requirement[] = [
    {
      req: 'ML-DSA signature on artifact',
      status: hasPQC ? 'pass' : 'fail',
      note: hasPQC
        ? 'At least one ML-DSA-87 signature is present on the subject.'
        : 'No ML-DSA signature found. Publish one via QuantaMrkt or the quantumshield CLI.',
    },
    {
      req: 'SHA-3 integrity hashing',
      status: 'pass',
      note: 'All artifacts in the QuantaMrkt registry use SHA3-256 file hashes.',
    },
    {
      req: 'Published transparency trail',
      status: hasTransparency ? 'pass' : 'partial',
      note: hasTransparency
        ? `${input.transparency.length} transparency log entries reference this subject.`
        : 'No public transparency entries yet for this subject.',
    },
    {
      req: 'Hybrid classical + PQC signing (transitional)',
      status: input.signatures.length >= 2 ? 'pass' : 'partial',
      note: input.signatures.length >= 2
        ? 'Multiple signatures present, covering classical + PQC paths during transition.'
        : 'Only one signature is attached. Dual-sign with classical + PQC during the migration window.',
    },
    {
      req: 'No classical-only key exchange',
      status: 'partial',
      note: 'QuantaMrkt itself does not perform key exchange. Verify your downstream deployment uses ML-KEM for sensitive transport (see pqc-mcp-transport, pqc-kv-cache-encryption).',
    },
  ];

  for (const row of rows) drawRequirement(c, row, fonts);
  return c.page;
}

function buildAiActPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont },
): PDFPage {
  const c = newPage(doc, fonts);
  drawSectionHeader(c, 'EU AI Act — Article 12 Mapping', fonts);

  drawText(c,
    'Article 12 requires high-risk AI systems to maintain tamper-evident logs of operation. This section maps the subject against the five Article 12 logging and traceability requirements.',
    {
      font: fonts.regular,
      size: FS_BODY,
      color: C.secondary,
      paragraphGap: 12,
    },
  );

  const hasTransparency = input.transparency.length > 0;

  const rows: Requirement[] = [
    {
      req: 'Automatic logging of events',
      status: hasTransparency ? 'pass' : 'partial',
      note: hasTransparency
        ? 'QuantaMrkt records every submission, signing, and verification event for this subject.'
        : 'No events recorded yet. Register this artifact via the quantumshield CLI to start the trail.',
    },
    {
      req: 'Tamper-evident chain',
      status: 'pass',
      note: 'Transparency log entries are SHA-256 hash-chained and periodically sealed into ML-DSA signed blocks.',
    },
    {
      req: 'Long-term retention',
      status: 'pass',
      note: 'Entries are append-only and retained indefinitely. Cryptographic integrity remains verifiable for decades under ML-DSA.',
    },
    {
      req: 'Auditor access to logs',
      status: 'pass',
      note: 'Logs are publicly queryable via /api/transparency/log and verifiable via /api/transparency/verify.',
    },
    {
      req: 'Incident reconstructability',
      status: hasTransparency ? 'pass' : 'partial',
      note: 'Each event includes actor DID, timestamp, action, and payload hash — sufficient for reconstructing the decision pathway of a flagged output.',
    },
  ];

  for (const row of rows) drawRequirement(c, row, fonts);
  return c.page;
}

// ---------------------------------------------------------------------------
// Certification page
// ---------------------------------------------------------------------------

function buildCertificationPage(
  doc: PDFDocument,
  input: ComplianceReportInput,
  fonts: { regular: PDFFont; bold: PDFFont; mono: PDFFont },
  reportHashHex: string,
): PDFPage {
  const c = newPage(doc, fonts);
  drawSectionHeader(c, 'Certification', fonts);

  drawText(c,
    'This report is a deterministic rendering of registry data at the moment of generation. The hash below commits to the canonical contents. Verifying parties can request a report with the same report_id and expect the identical hash.',
    {
      font: fonts.regular,
      size: FS_BODY,
      color: C.secondary,
      paragraphGap: 16,
    },
  );

  drawLabelValue(c, 'Report ID', input.report_id, fonts);
  drawLabelValue(c, 'Generated at', input.generated_at, fonts);
  drawLabelValue(c, 'Subject slug', input.subject.slug, fonts);
  drawLabelValue(c, 'Subject kind', input.subject.kind, fonts);

  c.y -= 8;
  drawRule(c, 16);

  // Report hash — block style
  c.page.drawText('Report Content Hash (SHA-256)', {
    x: MARGIN_X,
    y: c.y,
    size: FS_H3,
    font: fonts.bold,
    color: C.text,
  });
  c.y -= 18;

  // Half + half on two lines, monospace
  const half = Math.ceil(reportHashHex.length / 2);
  c.page.drawRectangle({
    x: MARGIN_X,
    y: c.y - 34,
    width: CONTENT_W,
    height: 40,
    color: C.panel,
    borderColor: C.rule,
    borderWidth: 0.75,
  });
  c.page.drawText(reportHashHex.slice(0, half), {
    x: MARGIN_X + 12,
    y: c.y - 12,
    size: 10,
    font: fonts.mono,
    color: C.text,
  });
  c.page.drawText(reportHashHex.slice(half), {
    x: MARGIN_X + 12,
    y: c.y - 26,
    size: 10,
    font: fonts.mono,
    color: C.text,
  });
  c.y -= 60;

  drawRule(c, 16);

  // Verification steps
  c.page.drawText('How to Verify', {
    x: MARGIN_X,
    y: c.y,
    size: FS_H3,
    font: fonts.bold,
    color: C.text,
  });
  c.y -= 18;

  const steps = [
    'Re-generate this report via POST https://quantamrkt.com/api/compliance/report with the same subject slug.',
    'Recompute SHA-256 over the canonical contents and compare against the hash above.',
    'Cross-check each listed signature against the platform public key at /.well-known/pqc-public-key.',
    'Verify the transparency log chain via GET /api/transparency/verify.',
  ];
  steps.forEach((step, i) => {
    drawText(c,
      `${i + 1}. ${step}`,
      { font: fonts.regular, size: FS_BODY, paragraphGap: 2 },
    );
  });

  return c.page;
}

// ---------------------------------------------------------------------------
// SHA-256 of bytes (Web Crypto)
// ---------------------------------------------------------------------------

async function sha256Hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(buf);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export async function generateComplianceReportPdf(
  input: ComplianceReportInput,
): Promise<Uint8Array> {
  const doc = await PDFDocument.create();

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

  // Build pages
  buildCoverPage(doc, input, fontsBase);
  buildHndlPage(doc, input, fontsBase);
  buildSignaturesPage(doc, input, fontsAll);
  buildTransparencyPage(doc, input, fontsAll);
  buildCnsaPage(doc, input, fontsBase);
  buildAiActPage(doc, input, fontsBase);

  // Hash canonical input (not the PDF itself — avoids the fixed-point problem
  // of hashing bytes that contain the hash)
  const payload = JSON.stringify({
    report_id: input.report_id,
    subject: input.subject,
    hndl: input.hndl
      ? {
          risk_level: input.hndl.risk_level,
          risk_score: input.hndl.risk_score,
          shelf_life_years: input.hndl.shelf_life_years,
          total_size: input.hndl.total_size,
          breakdown: input.hndl.breakdown,
        }
      : null,
    signatures: input.signatures.map(s => ({
      signer_did: s.signer_did,
      algorithm: s.algorithm,
      attestation_type: s.attestation_type,
      signature_hex: s.signature_hex,
      signed_at: s.signed_at,
    })),
    transparency_count: input.transparency.length,
    generated_at: input.generated_at,
  });
  const payloadHash = await sha256Hex(new TextEncoder().encode(payload));

  buildCertificationPage(doc, input, fontsAll, payloadHash);

  // Apply footers with correct page numbers
  const pages = doc.getPages();
  const total = pages.length;
  for (let i = 1; i < pages.length; i++) {
    drawFooter(pages[i], i + 1, total, input.report_id, fontsBase);
  }

  return await doc.save();
}
