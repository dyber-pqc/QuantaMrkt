// File fetcher — resolves source_url + file path into raw content from
// GitHub or HuggingFace. Binary / large files return metadata only.

export interface FetchedFile {
  path: string;
  raw_url: string;
  source_host: 'github' | 'huggingface' | 'unknown';
  content: string | null;      // null when binary or too large
  size: number;                // bytes
  is_binary: boolean;
  is_too_large: boolean;
  language: string;            // derived from extension (python, typescript, ...)
  etag: string | null;
  fetched_at: string;
}

const MAX_TEXT_BYTES = 512 * 1024;   // 512 KB — enough for any source file

// Extensions we render as text
const TEXT_EXTENSIONS = new Set([
  'py', 'pyi', 'pyx',
  'js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx',
  'go', 'rs', 'c', 'h', 'cc', 'cpp', 'cxx', 'hpp',
  'java', 'kt', 'kts', 'swift',
  'rb', 'php', 'lua', 'sh', 'bash', 'zsh', 'fish',
  'md', 'mdx', 'rst', 'txt', 'adoc',
  'json', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'env', 'properties',
  'xml', 'html', 'htm', 'svg', 'css', 'scss', 'sass', 'less',
  'sql', 'graphql', 'gql',
  'dockerfile', 'makefile', 'cmake',
  'proto', 'thrift',
  'astro', 'vue', 'svelte',
  'lock', 'gitignore', 'gitattributes', 'editorconfig',
  'license', 'readme', 'changelog',
]);

// Extensions that strongly suggest binary (don't even try to decode as text)
const KNOWN_BINARY_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'ico', 'tiff',
  'mp3', 'mp4', 'wav', 'ogg', 'flac', 'avi', 'mov', 'webm',
  'zip', 'tar', 'gz', 'bz2', 'xz', '7z', 'rar',
  'exe', 'dll', 'so', 'dylib', 'a', 'o',
  'bin', 'pb', 'pkl', 'pickle', 'npz', 'npy',
  'safetensors', 'gguf', 'ggml', 'onnx', 'pt', 'pth', 'ckpt',
  'h5', 'hdf5', 'parquet', 'arrow', 'feather',
  'pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx',
  'otf', 'ttf', 'woff', 'woff2',
  'wasm',
]);

function extOf(path: string): string {
  const last = path.split('/').pop() || path;
  // Special-case files with no extension
  const lower = last.toLowerCase();
  if (['license', 'readme', 'changelog', 'dockerfile', 'makefile'].includes(lower)) {
    return lower;
  }
  const dotIdx = last.lastIndexOf('.');
  if (dotIdx <= 0) return '';
  return last.slice(dotIdx + 1).toLowerCase();
}

function languageForExt(ext: string): string {
  const map: Record<string, string> = {
    py: 'python', pyi: 'python', pyx: 'python',
    js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
    ts: 'typescript', tsx: 'typescript',
    go: 'go', rs: 'rust',
    c: 'c', h: 'c', cc: 'cpp', cpp: 'cpp', cxx: 'cpp', hpp: 'cpp',
    java: 'java', kt: 'kotlin', kts: 'kotlin', swift: 'swift',
    rb: 'ruby', php: 'php', lua: 'lua',
    sh: 'bash', bash: 'bash', zsh: 'bash', fish: 'bash',
    md: 'markdown', mdx: 'markdown', rst: 'rst', txt: 'plaintext', adoc: 'asciidoc',
    json: 'json', yaml: 'yaml', yml: 'yaml', toml: 'toml',
    ini: 'ini', cfg: 'ini', env: 'bash', properties: 'ini',
    xml: 'xml', html: 'html', htm: 'html', svg: 'xml',
    css: 'css', scss: 'scss', sass: 'sass', less: 'less',
    sql: 'sql', graphql: 'graphql', gql: 'graphql',
    dockerfile: 'dockerfile', makefile: 'makefile', cmake: 'cmake',
    proto: 'protobuf', thrift: 'thrift',
    astro: 'astro', vue: 'vue', svelte: 'svelte',
    lock: 'yaml', gitignore: 'gitignore', gitattributes: 'gitattributes', editorconfig: 'ini',
    license: 'plaintext', readme: 'markdown', changelog: 'markdown',
  };
  return map[ext] || 'plaintext';
}

function isLikelyBinary(ext: string, bytes: Uint8Array): boolean {
  if (KNOWN_BINARY_EXTENSIONS.has(ext)) return true;
  if (TEXT_EXTENSIONS.has(ext)) return false;
  // Heuristic: look for NUL byte in first 8 KB
  const sample = bytes.slice(0, Math.min(8192, bytes.byteLength));
  for (let i = 0; i < sample.length; i++) {
    if (sample[i] === 0) return true;
  }
  return false;
}

// ---- Source URL -> raw URL conversion -------------------------------------

export function resolveRawUrl(sourceUrl: string, filePath: string): { rawUrl: string; host: 'github' | 'huggingface' | 'unknown' } {
  const cleanPath = filePath.replace(/^\/+/, '');

  // GitHub: .../tree/{branch}/{subdir} -> raw.githubusercontent.com/{repo}/{branch}/{subdir}/{path}
  if (sourceUrl.includes('github.com')) {
    // Handle both /tree/ and bare /repo URLs
    const treeMatch = sourceUrl.match(/github\.com\/([^/]+)\/([^/]+)\/tree\/([^/]+)(\/.*)?$/);
    if (treeMatch) {
      const [, owner, repo, branch, subPath = ''] = treeMatch;
      const sub = subPath.replace(/^\//, '').replace(/\/$/, '');
      const joined = sub ? `${sub}/${cleanPath}` : cleanPath;
      return {
        rawUrl: `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${joined}`,
        host: 'github',
      };
    }
    // Bare repo URL — assume main branch
    const repoMatch = sourceUrl.match(/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/);
    if (repoMatch) {
      const [, owner, repo] = repoMatch;
      return {
        rawUrl: `https://raw.githubusercontent.com/${owner}/${repo}/main/${cleanPath}`,
        host: 'github',
      };
    }
  }

  // HuggingFace: huggingface.co/{repo} -> huggingface.co/{repo}/raw/main/{path}
  if (sourceUrl.includes('huggingface.co')) {
    // Strip trailing slash
    const base = sourceUrl.replace(/\/+$/, '');
    // If URL already contains /resolve/ or /raw/ pass through
    if (base.includes('/resolve/') || base.includes('/raw/')) {
      return {
        rawUrl: `${base}/${cleanPath}`,
        host: 'huggingface',
      };
    }
    return {
      rawUrl: `${base}/raw/main/${cleanPath}`,
      host: 'huggingface',
    };
  }

  return {
    rawUrl: `${sourceUrl.replace(/\/+$/, '')}/${cleanPath}`,
    host: 'unknown',
  };
}

// ---- Fetcher --------------------------------------------------------------

export async function fetchFile(sourceUrl: string, filePath: string): Promise<FetchedFile> {
  const { rawUrl, host } = resolveRawUrl(sourceUrl, filePath);
  const ext = extOf(filePath);
  const language = languageForExt(ext);

  let headRes: Response | null = null;
  try {
    headRes = await fetch(rawUrl, {
      method: 'HEAD',
      headers: { 'User-Agent': 'QuantaMrkt-FileViewer/1.0' },
    });
  } catch {
    // HEAD isn't universally supported — we'll rely on GET's Content-Length
  }

  const sizeHeader = headRes?.headers.get('content-length');
  let size = sizeHeader ? parseInt(sizeHeader, 10) : 0;

  // Fast reject for known binaries with known size
  if (KNOWN_BINARY_EXTENSIONS.has(ext) && size > 0) {
    return {
      path: filePath,
      raw_url: rawUrl,
      source_host: host,
      content: null,
      size,
      is_binary: true,
      is_too_large: false,
      language,
      etag: headRes?.headers.get('etag') ?? null,
      fetched_at: new Date().toISOString(),
    };
  }

  // Fetch the actual file
  const res = await fetch(rawUrl, {
    headers: { 'User-Agent': 'QuantaMrkt-FileViewer/1.0' },
  });
  if (!res.ok) {
    throw new Error(`upstream ${host} returned HTTP ${res.status} for ${filePath}`);
  }

  // Respect size cap
  const bodyBuf = await res.arrayBuffer();
  const bytes = new Uint8Array(bodyBuf);
  size = bytes.byteLength;

  const isTooLarge = size > MAX_TEXT_BYTES;
  if (isTooLarge) {
    return {
      path: filePath,
      raw_url: rawUrl,
      source_host: host,
      content: null,
      size,
      is_binary: false,
      is_too_large: true,
      language,
      etag: res.headers.get('etag') ?? null,
      fetched_at: new Date().toISOString(),
    };
  }

  const isBinary = isLikelyBinary(ext, bytes);
  if (isBinary) {
    return {
      path: filePath,
      raw_url: rawUrl,
      source_host: host,
      content: null,
      size,
      is_binary: true,
      is_too_large: false,
      language,
      etag: res.headers.get('etag') ?? null,
      fetched_at: new Date().toISOString(),
    };
  }

  // Decode as UTF-8
  let content: string;
  try {
    content = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    content = '';
  }

  return {
    path: filePath,
    raw_url: rawUrl,
    source_host: host,
    content,
    size,
    is_binary: false,
    is_too_large: false,
    language,
    etag: res.headers.get('etag') ?? null,
    fetched_at: new Date().toISOString(),
  };
}

// ---- Helpers for the viewer ----------------------------------------------

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
