import {
  App,
  ButtonComponent,
  DropdownComponent,
  Modal,
  Notice,
  Platform,
  Plugin,
  PluginSettingTab,
  Setting,

  requestUrl,
  TFile,
  normalizePath,
  setIcon,
} from "obsidian";


const QUILDEN_BASE = "https://quilden.com";

interface QuildenSyncSettings {
  githubToken: string;
  githubUsername: string;
  repoOwner: string;
  repoName: string;
  branch: string;
  autoSyncInterval: number;
  syncOnSave: boolean;
  encryptionEnabled: boolean;
  encryptionScope: "markdown" | "media" | "all";
  syncOnStartup: boolean;
  excludePatterns: string[];
  commitMessage: string;
  conflictStrategy: "local" | "remote" | "newer";
  notificationLocation: "notice" | "statusbar" | "none";
}

interface SyncedFileState {
  mtime: number;
  size: number;
}

interface SyncHistoryEntry {
  time: string;    // ISO timestamp
  pushed: number;
  pulled: number;
  files: string[]; // changed file paths (union of pushed + pulled)
}

interface PersistedPluginData {
  settings?: Partial<QuildenSyncSettings>;
  syncState?: {
    repoKey: string;
    files: Record<string, SyncedFileState>;
  };
  // Small AES-GCM ciphertext of "LM_ENCRYPTION_VERIFY" — used to validate
  // that the user's password matches the one originally used to encrypt the repo.
  encryptionVerifyToken?: string;
  syncHistory?: SyncHistoryEntry[];
}

type IncrementalCandidateReason = "dirty-path" | "missing-sync-state" | "metadata-changed";

interface IncrementalCandidateDiagnostic {
  path: string;
  reason: IncrementalCandidateReason;
  previous?: SyncedFileState;
  current: SyncedFileState;
}

const MAX_SYNC_DIAGNOSTIC_SAMPLE = 20;

const DEFAULT_SETTINGS: QuildenSyncSettings = {
  githubToken: "",
  githubUsername: "",
  repoOwner: "",
  repoName: "",
  branch: "main",
  autoSyncInterval: 0,
  syncOnSave: true,
  encryptionEnabled: false,
  encryptionScope: "markdown" as const,
  syncOnStartup: false,
  excludePatterns: [".obsidian/", ".trash/", ".DS_Store"],
  commitMessage: "Quilden Sync: Update from Obsidian",
  conflictStrategy: "newer",
  notificationLocation: "notice",
};

const REQUIRED_EXCLUDE_PATTERNS = [".obsidian/", ".trash/", ".DS_Store"];


const ENCRYPTED_PREFIX = "QENC:1:";
const PBKDF2_ITERATIONS = 600_000;
const IV_LENGTH = 12;

let derivedKey: CryptoKey | null = null;

// Salt derived from user identity — nothing stored in the repo.
// Must match the same logic in the Quilden website's crypto.ts.
async function contextSalt(login: string, owner: string, repo: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(`quilden:${login}/${owner}/${repo}`);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

async function buildKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function setupEncryptionKey(password: string, login: string, owner: string, repo: string): Promise<void> {
  const salt = await contextSalt(login, owner, repo);
  derivedKey = await buildKey(password, salt);
}

function clearEncryptionKey(): void {
  derivedKey = null;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function encryptContent(plaintext: string): Promise<string> {
  if (!derivedKey) throw new Error("Encryption not configured");
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, derivedKey, new TextEncoder().encode(plaintext));
  const combined = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), IV_LENGTH);
  return ENCRYPTED_PREFIX + toBase64(combined);
}

const LEGACY_ENCRYPTED_PREFIX = "LMENC:1:";

async function decryptContent(encrypted: string): Promise<string | null> {
  if (!derivedKey) return null;
  const prefix = encrypted.startsWith(ENCRYPTED_PREFIX) ? ENCRYPTED_PREFIX
    : encrypted.startsWith(LEGACY_ENCRYPTED_PREFIX) ? LEGACY_ENCRYPTED_PREFIX
    : null;
  if (!prefix) return null;
  try {
    const bytes = fromBase64(encrypted.slice(prefix.length));
    const iv = bytes.slice(0, IV_LENGTH);
    const ciphertext = bytes.slice(IV_LENGTH);
    const plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, derivedKey, ciphertext);
    return new TextDecoder().decode(plainBuffer);
  } catch {
    return null;
  }
}

function isEncryptedContent(content: string): boolean {
  return content.startsWith(ENCRYPTED_PREFIX) || content.startsWith(LEGACY_ENCRYPTED_PREFIX);
}

const ENCRYPTION_VERIFY_PLAINTEXT = "LM_ENCRYPTION_VERIFY";

// Returns { ok: true, token } on success, { ok: false } on wrong password.
// Pass storedToken=undefined the first time (no token yet) — any password is accepted
// and a fresh verification token is returned for storage.
async function verifyOrInitEncryption(
  password: string,
  login: string,
  owner: string,
  repo: string,
  storedToken: string | undefined
): Promise<{ ok: boolean; token: string | null; isNew: boolean }> {
  const salt = await contextSalt(login, owner, repo);
  const candidateKey = await buildKey(password, salt);

  if (storedToken) {
    // Temporarily swap in the candidate key so decryptContent can use it.
    const previousKey = derivedKey;
    derivedKey = candidateKey;
    const result = await decryptContent(storedToken);
    derivedKey = previousKey;

    if (result === ENCRYPTION_VERIFY_PLAINTEXT) {
      derivedKey = candidateKey;
      return { ok: true, token: storedToken, isNew: false };
    }
    return { ok: false, token: null, isNew: false };
  }

  // First time — accept the password and create the token.
  derivedKey = candidateKey;
  const token = await encryptContent(ENCRYPTION_VERIFY_PLAINTEXT);
  return { ok: true, token, isNew: true };
}

// Compute the same SHA-1 git uses for blob objects: SHA1("blob {size}\0{content}")
// Lets us compare local files against the remote tree without fetching content.
async function gitBlobSha(bytes: Uint8Array): Promise<string> {
  const header = new TextEncoder().encode(`blob ${bytes.length}\0`);
  const combined = new Uint8Array(header.length + bytes.length);
  combined.set(header);
  combined.set(bytes, header.length);
  const hash = await crypto.subtle.digest("SHA-1", combined);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}


const BINARY_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tiff", "tif", "svg",
  "pdf", "zip", "gz", "tar", "7z", "rar",
  "mp3", "mp4", "wav", "ogg", "m4a", "flac", "aac",
  "mov", "avi", "mkv", "webm",
  "woff", "woff2", "ttf", "otf", "eot",
  "doc", "docx", "xls", "xlsx", "ppt", "pptx",
  "db", "sqlite", "exe", "dll", "so", "dylib",
]);

function isBinaryPath(path: string): boolean {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  return BINARY_EXTENSIONS.has(ext);
}

const MEDIA_ENCRYPT_EXTENSIONS = new Set([
  "md", "png", "jpg", "jpeg", "gif", "webp", "bmp", "tiff", "tif", "svg", "pdf",
]);

function shouldEncryptPath(path: string, scope: "markdown" | "media" | "all"): boolean {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  if (scope === "markdown") return ext === "md";
  if (scope === "media") return MEDIA_ENCRYPT_EXTENSIONS.has(ext);
  return true; // "all"
}

// ── Line-level diff ──────────────────────────────────────────────────────────

type DiffLineType = "add" | "remove" | "context" | "collapse";

interface DiffLine {
  type: DiffLineType;
  content: string;
  oldLine: number | null;
  newLine: number | null;
  collapseCount?: number;
}

function computeLineDiff(oldText: string, newText: string, ctx = 3): DiffLine[] {
  const a = oldText === "" ? [] : oldText.split("\n");
  const b = newText === "" ? [] : newText.split("\n");
  if (a.length + b.length > 5000) {
    return [{ type: "context", content: `(File too large for inline diff — ${a.length} + ${b.length} lines)`, oldLine: null, newLine: null }];
  }

  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }

  const raw: Array<{ op: "keep" | "add" | "remove"; text: string }> = [];
  let i = m, j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) { raw.push({ op: "keep", text: a[i - 1] }); i--; j--; }
    else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) { raw.push({ op: "add", text: b[j - 1] }); j--; }
    else { raw.push({ op: "remove", text: a[i - 1] }); i--; }
  }
  raw.reverse();

  const lines: DiffLine[] = [];
  let oldNo = 1, newNo = 1;
  for (const r of raw) {
    if (r.op === "keep") { lines.push({ type: "context", content: r.text, oldLine: oldNo++, newLine: newNo++ }); }
    else if (r.op === "add") { lines.push({ type: "add", content: r.text, oldLine: null, newLine: newNo++ }); }
    else { lines.push({ type: "remove", content: r.text, oldLine: oldNo++, newLine: null }); }
  }

  // Context collapsing
  if (lines.every(l => l.type === "context")) {
    if (lines.length <= 2 * ctx + 1) return lines;
    return [
      ...lines.slice(0, ctx),
      { type: "collapse", content: "", oldLine: null, newLine: null, collapseCount: lines.length - 2 * ctx },
      ...lines.slice(lines.length - ctx),
    ];
  }

  const keep = new Set<number>();
  lines.forEach((l, idx) => {
    if (l.type !== "context") {
      for (let k = Math.max(0, idx - ctx); k <= Math.min(lines.length - 1, idx + ctx); k++) keep.add(k);
    }
  });

  const result: DiffLine[] = [];
  let collapseFrom = -1;
  for (let idx = 0; idx < lines.length; idx++) {
    if (keep.has(idx)) {
      if (collapseFrom >= 0) {
        result.push({ type: "collapse", content: "", oldLine: null, newLine: null, collapseCount: idx - collapseFrom });
        collapseFrom = -1;
      }
      result.push(lines[idx]);
    } else if (collapseFrom < 0) {
      collapseFrom = idx;
    }
  }
  if (collapseFrom >= 0) {
    result.push({ type: "collapse", content: "", oldLine: null, newLine: null, collapseCount: lines.length - collapseFrom });
  }
  return result;
}


const GH_HEADERS = {
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "User-Agent": "quilden-sync/1.0",
};

function ghHeaders(token: string, extra?: Record<string, string>): Record<string, string> {
  return { ...GH_HEADERS, Authorization: `Bearer ${token}`, ...extra };
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function computeGitBlobSha(content: string, encoding: "utf-8" | "base64"): Promise<string> {
  const contentBytes = encoding === "base64"
    ? fromBase64(content)
    : new TextEncoder().encode(content);
  const prefixBytes = new TextEncoder().encode(`blob ${contentBytes.length}\0`);
  const payload = new Uint8Array(prefixBytes.length + contentBytes.length);
  payload.set(prefixBytes, 0);
  payload.set(contentBytes, prefixBytes.length);
  const digest = await crypto.subtle.digest("SHA-1", payload);
  return bytesToHex(new Uint8Array(digest));
}

interface RepoPermissionSummary {
  admin?: boolean;
  maintain?: boolean;
  push?: boolean;
}

async function uploadBatchBlobs(
  api: GitHubAPI,
  batch: Array<{ path: string; content: string; encoding: "utf-8" | "base64" }>,
  batchNumber: number
): Promise<Array<{ path: string; sha: string; mode: string }>> {
  const concurrency = Math.min(4, batch.length);
  const treeItems = new Array<{ path: string; sha: string; mode: string }>(batch.length);
  let nextIndex = 0;
  let completed = 0;

  const worker = async (): Promise<void> => {
    while (nextIndex < batch.length) {
      const currentIndex = nextIndex;
      nextIndex += 1;

      const file = batch[currentIndex];
      const blobSha = await api.createBlob(file.content, file.encoding);
      console.log(`[LM]   blob ${file.path} → ${blobSha}`);
      treeItems[currentIndex] = { path: file.path, sha: blobSha, mode: "100644" };

      completed += 1;
      if (completed % 5 === 0 || completed === batch.length) {
        console.log(`[LM] batch ${batchNumber}: uploaded ${completed}/${batch.length} blobs`);
      }
    }
  };

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return treeItems;
}

class GitHubAPI {
  private token: string;
  private owner: string;
  private repo: string;
  private branch: string;

  constructor(token: string, owner: string, repo: string, branch: string) {
    this.token = token;
    this.owner = owner;
    this.repo = repo;
    this.branch = branch;
  }

  private async request(method: string, path: string, body?: unknown): Promise<any> {
    const url = `https://api.github.com${path}`;
    const res = await requestUrl({
      url,
      method,
      headers: ghHeaders(this.token, body ? { "Content-Type": "application/json" } : {}),
      body: body ? JSON.stringify(body) : undefined,
      throw: false,
    });
    if (res.status >= 400) {
      const msg = res.json?.message ?? res.status;
      console.error(`[LM] GitHub API ${method} ${path} → ${res.status}:`, msg);
      throw new Error(`GitHub API error ${res.status} on ${method} ${path}: ${msg}`);
    }
    return res.json;
  }

  static async verifyToken(token: string): Promise<{ login: string; avatar_url: string }> {
    const res = await requestUrl({
      url: "https://api.github.com/user",
      method: "GET",
      headers: ghHeaders(token),
      throw: false,
    });
    if (res.status !== 200) throw new Error(`Invalid token (${res.status})`);
    return res.json;
  }

  static async fetchRepos(token: string): Promise<Array<{ full_name: string; private: boolean }>> {
    const res = await requestUrl({
      url: "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator",
      method: "GET",
      headers: ghHeaders(token),
      throw: false,
    });
    const scopes = res.headers?.["x-oauth-scopes"] ?? "n/a";
    const remaining = res.headers?.["x-ratelimit-remaining"] ?? "?";
    const resetEpoch = res.headers?.["x-ratelimit-reset"];
    const resetTime = resetEpoch ? new Date(Number(resetEpoch) * 1000).toLocaleTimeString() : "unknown";
    console.log(`[LM] fetchRepos status=${res.status} scopes="${scopes}" rate=${remaining} remaining reset=${resetTime}`);
    if (res.status === 403 || res.status === 429) {
      throw new Error(`GitHub rate limit exceeded — resets at ${resetTime}. Wait and try again.`);
    }
    if (res.status >= 400) {
      const msg = res.json?.message ?? res.status;
      throw new Error(`${res.status}: ${msg}`);
    }
    return res.json;
  }

  static async createRepo(
    token: string,
    name: string,
    isPrivate: boolean
  ): Promise<{ full_name: string; private: boolean }> {
    const res = await requestUrl({
      url: "https://api.github.com/user/repos",
      method: "POST",
      headers: ghHeaders(token, { "Content-Type": "application/json" }),
      body: JSON.stringify({ name, private: isPrivate, auto_init: true }),
      throw: false,
    });
    if (res.status !== 201) throw new Error(res.json?.message || "Failed to create repo");
    return res.json;
  }

  static async fetchBranches(token: string, owner: string, repo: string): Promise<string[]> {
    const res = await requestUrl({
      url: `https://api.github.com/repos/${owner}/${repo}/branches?per_page=100`,
      method: "GET",
      headers: ghHeaders(token),
      throw: false,
    });
    if (res.status >= 400) throw new Error(`${res.status}: ${res.json?.message ?? "failed"}`);
    return (res.json as Array<{ name: string }>).map((b) => b.name);
  }

  async getTree(): Promise<{ blobs: Array<{ path: string; sha: string; type: string }>; truncated: boolean }> {
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/git/trees/${encodeURIComponent(this.branch)}?recursive=true`
    );
    return {
      blobs: (data.tree || []).filter((item: any) => item.type === "blob"),
      truncated: !!data.truncated,
    };
  }

  async getFileContent(path: string): Promise<{ content: string; sha: string }> {
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(this.branch)}`
    );
    const raw = atob(data.content.replace(/\n/g, ""));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return { content: new TextDecoder().decode(bytes), sha: data.sha };
  }

  async getBinaryContent(path: string): Promise<{ buffer: ArrayBuffer; sha: string }> {
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(this.branch)}`
    );
    const b64 = data.content.replace(/\n/g, "");
    const raw = atob(b64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return { buffer: bytes.buffer, sha: data.sha };
  }

  async getRef(): Promise<string> {
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/git/ref/heads/${encodeURIComponent(this.branch)}`
    );
    return data.object.sha;
  }

  async getCommit(sha: string): Promise<{ treeSha: string }> {
    const data = await this.request("GET", `/repos/${this.owner}/${this.repo}/git/commits/${sha}`);
    return { treeSha: data.tree.sha };
  }

  async createBlob(content: string, encoding: "utf-8" | "base64" = "utf-8"): Promise<string> {
    const data = await this.request("POST", `/repos/${this.owner}/${this.repo}/git/blobs`, { content, encoding });
    return data.sha;
  }

  async createTree(baseTreeSha: string, items: Array<{ path: string; sha: string | null; mode: string }>): Promise<string> {
    const data = await this.request("POST", `/repos/${this.owner}/${this.repo}/git/trees`, {
      base_tree: baseTreeSha,
      tree: items.map((i) => ({ path: i.path, mode: i.mode, type: "blob", sha: i.sha })),
    });
    return data.sha;
  }

  async createCommit(message: string, treeSha: string, parentSha: string): Promise<string> {
    const data = await this.request("POST", `/repos/${this.owner}/${this.repo}/git/commits`, {
      message,
      tree: treeSha,
      parents: [parentSha],
    });
    return data.sha;
  }

  async updateRef(sha: string): Promise<void> {
    await this.request("PATCH", `/repos/${this.owner}/${this.repo}/git/refs/heads/${encodeURIComponent(this.branch)}`, {
      sha,
      force: true,
    });
  }

  async getFileCommits(path: string): Promise<Array<{ sha: string; parentSha: string | null; message: string; author: string; date: string }>> {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/commits?path=${encoded}&sha=${encodeURIComponent(this.branch)}&per_page=30`
    );
    return (data as any[]).map((c: any) => ({
      sha: c.sha,
      parentSha: (c.parents as any[])?.[0]?.sha ?? null,
      message: (c.commit.message as string).split("\n")[0].slice(0, 80),
      author: c.commit.author?.name ?? c.commit.committer?.name ?? "Unknown",
      date: c.commit.author?.date ? new Date(c.commit.author.date).toLocaleString() : "",
    }));
  }

  async getFileAtCommit(path: string, commitSha: string): Promise<{ content: string }> {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/contents/${encoded}?ref=${commitSha}`
    );
    const raw = atob(data.content.replace(/\n/g, ""));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return { content: new TextDecoder().decode(bytes) };
  }

  async getBinaryContentAtCommit(path: string, commitSha: string): Promise<{ buffer: ArrayBuffer }> {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/contents/${encoded}?ref=${commitSha}`
    );
    const raw = atob(data.content.replace(/\n/g, ""));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return { buffer: bytes.buffer };
  }

  async getBranchCommits(page = 1, perPage = 100): Promise<{
    commits: Array<{ sha: string; message: string; author: string; date: string; treeSha: string }>;
    hasMore: boolean;
  }> {
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/commits?sha=${encodeURIComponent(this.branch)}&per_page=${perPage}&page=${page}`
    );
    const commits = (data as any[]).map((c: any) => ({
      sha: c.sha,
      message: (c.commit.message as string).split("\n")[0].slice(0, 80),
      author: c.commit.author?.name ?? c.commit.committer?.name ?? "Unknown",
      date: c.commit.author?.date ?? c.commit.committer?.date ?? "",
      treeSha: c.commit.tree?.sha ?? "",
    }));
    return { commits, hasMore: commits.length === perPage };
  }

  getCommitUrl(sha: string): string {
    return `https://github.com/${this.owner}/${this.repo}/commit/${sha}`;
  }

  async restoreToCommit(targetSha: string, message: string): Promise<string> {
    // Get the tree SHA of the target commit
    const targetCommit = await this.request("GET", `/repos/${this.owner}/${this.repo}/git/commits/${targetSha}`);
    const treeSha = targetCommit.tree.sha;

    // Get current HEAD to use as parent
    const currentHeadSha = await this.getRef();

    // Create a new commit with the old tree on top of current HEAD
    const newCommitSha = await this.createCommit(message, treeSha, currentHeadSha);

    // Point the branch ref to the new commit
    await this.updateRef(newCommitSha);

    return newCommitSha;
  }

  // Create or update a single file via the Contents API (one-shot, no tree/commit dance).
  async putFile(path: string, textContent: string, message: string): Promise<void> {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    // Need existing SHA when updating, so the API knows it's an update not a collision.
    let existingSha: string | undefined;
    try {
      const existing = await this.request(
        "GET",
        `/repos/${this.owner}/${this.repo}/contents/${encoded}?ref=${encodeURIComponent(this.branch)}`
      );
      existingSha = existing.sha;
    } catch { /* file doesn't exist yet — that's fine */ }

    // GitHub Contents API expects base64-encoded file content.
    const b64 = btoa(unescape(encodeURIComponent(textContent)));
    await this.request("PUT", `/repos/${this.owner}/${this.repo}/contents/${encoded}`, {
      message,
      content: b64,
      branch: this.branch,
      ...(existingSha ? { sha: existingSha } : {}),
    });
  }
}


// ── File History Modal ─────────────────────────────────────────────────────────

class FileHistoryModal extends Modal {
  private file: TFile;
  private api: GitHubAPI;
  private encryptionEnabled: boolean;
  private commits: Array<{ sha: string; parentSha: string | null; message: string; author: string; date: string }> = [];
  private selectedIdx = -1;
  private selectedContent: string | null = null; // null = not loaded, "__binary__" = binary
  private diffEl!: HTMLElement;
  private restoreBtn!: HTMLButtonElement;
  private leftEl?: HTMLElement;
  private mobileSelect?: HTMLSelectElement;
  private isMobileLayout = false;

  constructor(app: App, file: TFile, api: GitHubAPI, encryptionEnabled: boolean) {
    super(app);
    this.file = file;
    this.api = api;
    this.encryptionEnabled = encryptionEnabled;
  }

  async onOpen() {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    contentEl.addClass("lm-history-modal");

    // Bigger modal
    modalEl.style.width = "min(90vw, 1000px)";
    modalEl.style.height = "85vh";
    modalEl.style.maxHeight = "85vh";

    this.isMobileLayout = Platform.isMobile || modalEl.offsetWidth < 550;

    contentEl.createEl("h3", { text: `History: ${this.file.name}`, cls: "lm-history-title" });

    if (this.isMobileLayout) {
      this.buildMobileLayout(contentEl);
    } else {
      this.buildDesktopLayout(contentEl);
    }

    await this.loadCommits();
  }

  private buildDesktopLayout(contentEl: HTMLElement) {
    const body = contentEl.createDiv({ cls: "lm-history-body" });

    this.leftEl = body.createDiv({ cls: "lm-history-left" });
    this.leftEl.createEl("p", { text: "Loading…", cls: "lm-history-status" });

    const rightEl = body.createDiv({ cls: "lm-history-right" });
    this.diffEl = rightEl.createDiv({ cls: "lm-history-diff" });
    this.diffEl.createEl("p", { text: "Select a version to view diff.", cls: "lm-history-status" });

    const footer = contentEl.createDiv({ cls: "lm-history-footer" });
    this.restoreBtn = footer.createEl("button", { text: "Restore this version", cls: "lm-restore-btn mod-cta" });
    this.restoreBtn.disabled = true;
    this.restoreBtn.addEventListener("click", () => this.restore());
  }

  private buildMobileLayout(contentEl: HTMLElement) {
    const selectWrap = contentEl.createDiv({ cls: "lm-history-mobile-select-wrap" });
    this.mobileSelect = selectWrap.createEl("select", { cls: "lm-history-mobile-select" });
    const placeholder = this.mobileSelect.createEl("option");
    placeholder.value = "";
    placeholder.textContent = "Loading…";
    placeholder.disabled = true;
    placeholder.selected = true;

    this.diffEl = contentEl.createDiv({ cls: "lm-history-diff lm-history-diff-mobile" });
    this.diffEl.createEl("p", { text: "Select a version to view diff.", cls: "lm-history-status" });

    const footer = contentEl.createDiv({ cls: "lm-history-footer" });
    this.restoreBtn = footer.createEl("button", { text: "Restore this version", cls: "lm-restore-btn mod-cta" });
    this.restoreBtn.disabled = true;
    this.restoreBtn.addEventListener("click", () => this.restore());

    this.mobileSelect.addEventListener("change", () => {
      const idx = parseInt(this.mobileSelect!.value);
      if (!isNaN(idx)) this.selectCommit(idx);
    });
  }

  private async loadCommits() {
    try {
      this.commits = await this.api.getFileCommits(this.file.path);

      if (this.isMobileLayout && this.mobileSelect) {
        this.mobileSelect.innerHTML = "";
        if (this.commits.length === 0) {
          const opt = this.mobileSelect.createEl("option");
          opt.textContent = "No history found";
          opt.disabled = true;
          opt.selected = true;
        } else {
          const ph = this.mobileSelect.createEl("option");
          ph.value = "";
          ph.textContent = "Select a version…";
          ph.disabled = true;
          ph.selected = true;
          this.commits.forEach((c, idx) => {
            const opt = this.mobileSelect!.createEl("option");
            opt.value = String(idx);
            opt.textContent = `${c.message} — ${c.date}`;
          });
        }
      } else if (this.leftEl) {
        this.leftEl.empty();
        if (this.commits.length === 0) {
          this.leftEl.createEl("p", { text: "No history found for this file.", cls: "lm-history-status" });
          return;
        }
        this.commits.forEach((c, idx) => {
          const item = this.leftEl!.createDiv({ cls: "lm-commit-item" });
          item.createEl("div", { text: c.message, cls: "lm-commit-msg" });
          item.createEl("div", { text: `${c.author} · ${c.date}`, cls: "lm-commit-meta" });
          item.addEventListener("click", () => {
            this.leftEl!.querySelectorAll<HTMLElement>(".lm-commit-item").forEach(el =>
              el.classList.remove("lm-commit-selected")
            );
            item.classList.add("lm-commit-selected");
            this.selectCommit(idx);
          });
        });
      }
    } catch (e: any) {
      const msg = e.message?.includes("401")
        ? "Authentication failed — token may be expired. Reconnect in settings."
        : `Error: ${e.message}`;
      if (this.isMobileLayout && this.mobileSelect) {
        this.mobileSelect.innerHTML = "";
        const opt = this.mobileSelect.createEl("option");
        opt.textContent = msg;
        opt.disabled = true;
        opt.selected = true;
      } else if (this.leftEl) {
        this.leftEl.empty();
        this.leftEl.createEl("p", { text: msg, cls: "lm-history-error" });
      }
    }
  }

  private async selectCommit(idx: number) {
    this.selectedIdx = idx;
    this.selectedContent = null;
    this.restoreBtn.disabled = true;
    this.diffEl.empty();
    this.diffEl.createEl("p", { text: "Loading diff…", cls: "lm-history-status" });

    const commit = this.commits[idx];
    if (!commit) return;

    try {
      if (isBinaryPath(this.file.path)) {
        this.diffEl.empty();
        this.diffEl.createEl("p", { text: "Binary file — diff not available.", cls: "lm-history-status" });
        this.selectedContent = "__binary__";
        this.restoreBtn.disabled = false;
        return;
      }

      // Fetch this version
      const { content: currentRaw } = await this.api.getFileAtCommit(this.file.path, commit.sha);
      let current = currentRaw;
      if (this.encryptionEnabled && isEncryptedContent(currentRaw)) {
        current = (await decryptContent(currentRaw)) ?? currentRaw;
      }
      this.selectedContent = currentRaw;

      // Fetch parent version for diff
      let parent = "";
      if (commit.parentSha) {
        try {
          const { content: parentRaw } = await this.api.getFileAtCommit(this.file.path, commit.parentSha);
          parent = parentRaw;
          if (this.encryptionEnabled && isEncryptedContent(parentRaw)) {
            parent = (await decryptContent(parentRaw)) ?? parentRaw;
          }
        } catch {
          parent = ""; // File didn't exist in parent commit
        }
      }

      const diff = computeLineDiff(parent, current);
      this.diffEl.empty();
      this.renderDiff(this.diffEl, diff, commit);
      this.restoreBtn.disabled = false;
    } catch (e: any) {
      this.diffEl.empty();
      this.diffEl.createEl("p", { text: `Error: ${e.message}`, cls: "lm-history-error" });
    }
  }

  private renderDiff(
    container: HTMLElement,
    diff: DiffLine[],
    commit: { message: string; author: string; date: string }
  ) {
    const header = container.createDiv({ cls: "lm-diff-header" });
    header.createEl("span", { text: commit.message, cls: "lm-diff-commit-msg" });
    header.createEl("span", { text: ` · ${commit.author}, ${commit.date}`, cls: "lm-diff-commit-meta" });

    if (diff.length === 0) {
      container.createEl("p", { text: "No changes to this file in this commit.", cls: "lm-history-status" });
      return;
    }

    const table = container.createEl("table", { cls: "lm-diff-table" });
    const tbody = table.createEl("tbody");

    for (const line of diff) {
      if (line.type === "collapse") {
        const tr = tbody.createEl("tr", { cls: "lm-diff-collapse" });
        tr.createEl("td", { cls: "lm-diff-ln" });
        tr.createEl("td", { cls: "lm-diff-ln" });
        tr.createEl("td", { cls: "lm-diff-sign" });
        tr.createEl("td", {
          text: `… ${line.collapseCount} unchanged line${line.collapseCount !== 1 ? "s" : ""}`,
          cls: "lm-diff-code",
        });
        continue;
      }

      const tr = tbody.createEl("tr", { cls: `lm-diff-${line.type}` });
      tr.createEl("td", { text: line.oldLine !== null ? String(line.oldLine) : "", cls: "lm-diff-ln lm-diff-ln-old" });
      tr.createEl("td", { text: line.newLine !== null ? String(line.newLine) : "", cls: "lm-diff-ln lm-diff-ln-new" });
      tr.createEl("td", {
        text: line.type === "add" ? "+" : line.type === "remove" ? "−" : " ",
        cls: "lm-diff-sign",
      });
      tr.createEl("td", { text: line.content, cls: "lm-diff-code" });
    }
  }

  private async restore() {
    if (this.selectedIdx < 0 || this.selectedContent === null) return;
    this.restoreBtn.disabled = true;
    this.restoreBtn.textContent = "Restoring…";

    const commit = this.commits[this.selectedIdx];
    try {
      if (this.selectedContent === "__binary__") {
        const { buffer } = await this.api.getBinaryContentAtCommit(this.file.path, commit.sha);
        await this.app.vault.modifyBinary(this.file, buffer);
      } else {
        let final = this.selectedContent;
        if (this.encryptionEnabled && isEncryptedContent(this.selectedContent)) {
          final = (await decryptContent(this.selectedContent)) ?? this.selectedContent;
        }
        await this.app.vault.modify(this.file, final);
      }
      new Notice(`Restored: ${this.file.name}`);
      this.close();
    } catch (e: any) {
      new Notice(`Restore failed: ${e.message}`);
      this.restoreBtn.disabled = false;
      this.restoreBtn.textContent = "Restore this version";
    }
  }

  onClose() {
    this.contentEl.empty();
  }
}


// ── Branch Timeline Modal ──────────────────────────────────────────────────────

class BranchTimelineModal extends Modal {
  private api: GitHubAPI;
  private plugin: QuildenSyncPlugin;
  private commits: Array<{ sha: string; message: string; author: string; date: string; treeSha: string }> = [];
  private selectedSha: string | null = null;
  private restoreBtn!: HTMLButtonElement;
  private itemEls: HTMLElement[] = [];
  private listEl!: HTMLElement;
  private loadMoreBtn!: HTMLButtonElement;
  private currentPage = 1;
  private hasMore = false;
  private loadingMore = false;

  constructor(app: App, api: GitHubAPI, plugin: QuildenSyncPlugin) {
    super(app);
    this.api = api;
    this.plugin = plugin;
  }

  async onOpen() {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    contentEl.addClass("lm-timeline-modal");

    modalEl.style.width = "min(90vw, 700px)";
    modalEl.style.height = "85vh";
    modalEl.style.maxHeight = "85vh";

    contentEl.createEl("h3", { text: "Branch Timeline", cls: "lm-timeline-title" });
    contentEl.createEl("p", {
      text: "Select a past commit to restore the entire repo to that state. A new commit is created on the branch — no history is lost.",
      cls: "lm-timeline-subtitle",
    });

    const scrollEl = contentEl.createDiv({ cls: "lm-timeline-scroll" });
    scrollEl.createEl("p", { text: "Loading timeline…", cls: "lm-history-status" });

    const footer = contentEl.createDiv({ cls: "lm-timeline-footer" });
    this.restoreBtn = footer.createEl("button", {
      text: "Restore to selected point",
      cls: "lm-restore-btn mod-cta",
    });
    this.restoreBtn.disabled = true;
    this.restoreBtn.addEventListener("click", () => this.confirmAndRestore());

    await this.loadPage(scrollEl, true);
  }

  private async loadPage(scrollEl: HTMLElement, isFirst: boolean) {
    try {
      const { commits, hasMore } = await this.api.getBranchCommits(this.currentPage);
      this.hasMore = hasMore;

      if (isFirst) {
        scrollEl.empty();
        if (commits.length === 0) {
          scrollEl.createEl("p", { text: "No commits found on this branch.", cls: "lm-history-status" });
          return;
        }
        this.listEl = scrollEl.createDiv({ cls: "lm-timeline-list" });
        this.loadMoreBtn = scrollEl.createEl("button", { cls: "lm-timeline-load-more" });
        this.loadMoreBtn.addEventListener("click", async () => {
          if (this.loadingMore) return;
          this.loadingMore = true;
          this.loadMoreBtn.textContent = "Loading…";
          this.loadMoreBtn.disabled = true;
          this.currentPage++;
          await this.loadPage(scrollEl, false);
          this.loadingMore = false;
        });
      }

      const globalOffset = this.commits.length;
      this.commits.push(...commits);
      this.appendCommitItems(commits, globalOffset);

      // Update "Load more" button visibility
      if (hasMore) {
        this.loadMoreBtn.textContent = "Load more commits";
        this.loadMoreBtn.disabled = false;
        this.loadMoreBtn.style.display = "";
      } else {
        this.loadMoreBtn.style.display = "none";
      }
    } catch (e: any) {
      if (isFirst) {
        scrollEl.empty();
        scrollEl.createEl("p", { text: `Failed to load timeline: ${e.message}`, cls: "lm-history-error" });
      } else {
        new Notice(`Failed to load more commits: ${e.message}`, 5000);
        this.loadMoreBtn.textContent = "Load more commits";
        this.loadMoreBtn.disabled = false;
      }
    }
  }

  private appendCommitItems(
    commits: Array<{ sha: string; message: string; author: string; date: string; treeSha: string }>,
    startIdx: number
  ) {
    commits.forEach((commit, localIdx) => {
      const globalIdx = startIdx + localIdx;
      const isHead = globalIdx === 0;

      // Remove connector from previous last item before adding new ones
      if (localIdx === 0 && globalIdx > 0 && this.itemEls.length > 0) {
        const prevLast = this.itemEls[this.itemEls.length - 1];
        const prevNodeCol = prevLast.querySelector<HTMLElement>(".lm-timeline-node-col");
        if (prevNodeCol && !prevNodeCol.querySelector(".lm-timeline-connector")) {
          prevNodeCol.createDiv({ cls: "lm-timeline-connector" });
        }
      }

      const item = this.listEl.createDiv({
        cls: "lm-timeline-item" + (isHead ? " lm-timeline-item-head" : ""),
      });
      this.itemEls.push(item);

      // Left column: node dot + connector line
      const nodeCol = item.createDiv({ cls: "lm-timeline-node-col" });
      nodeCol.createDiv({ cls: "lm-timeline-node" + (isHead ? " lm-timeline-node-head" : "") });
      // Connector is added for all except the last item; we add it when more items load
      if (localIdx < commits.length - 1 || this.hasMore) {
        nodeCol.createDiv({ cls: "lm-timeline-connector" });
      }

      // Right column: commit details
      const content = item.createDiv({ cls: "lm-timeline-content" });

      const topRow = content.createDiv({ cls: "lm-timeline-top-row" });
      if (isHead) {
        topRow.createEl("span", { text: "LATEST", cls: "lm-timeline-badge" });
      }

      // GitHub link button — opens the commit page on GitHub
      const ghLink = topRow.createEl("a", { cls: "lm-timeline-gh-link", text: "View on GitHub ↗" });
      ghLink.href = this.api.getCommitUrl(commit.sha);
      ghLink.target = "_blank";
      ghLink.rel = "noopener";
      ghLink.title = `Open commit ${commit.sha.slice(0, 7)} on GitHub`;
      ghLink.addEventListener("click", (e) => e.stopPropagation());

      content.createEl("div", { text: commit.message, cls: "lm-timeline-msg" });

      const meta = content.createDiv({ cls: "lm-timeline-meta-row" });
      meta.createEl("span", { text: commit.author, cls: "lm-timeline-author" });
      meta.createEl("span", { text: " · ", cls: "lm-timeline-sep" });
      meta.createEl("span", { text: this.relativeTime(commit.date), cls: "lm-timeline-date" });
      meta.createEl("code", { text: commit.sha.slice(0, 7), cls: "lm-timeline-sha" });

      if (!isHead) {
        item.style.cursor = "pointer";
        item.addEventListener("click", () => this.selectCommit(globalIdx, item));
      } else {
        item.title = "Current HEAD — nothing to restore to";
      }
    });
  }

  private selectCommit(idx: number, itemEl: HTMLElement) {
    this.itemEls.forEach(el => el.classList.remove("lm-timeline-item-selected"));
    itemEl.classList.add("lm-timeline-item-selected");
    this.selectedSha = this.commits[idx].sha;
    this.restoreBtn.disabled = false;
    const msg = this.commits[idx].message;
    const label = msg.length > 42 ? msg.slice(0, 42) + "…" : msg;
    this.restoreBtn.textContent = `Restore to "${label}"`;
  }

  private relativeTime(isoDate: string): string {
    if (!isoDate) return "";
    const diffMs = Date.now() - new Date(isoDate).getTime();
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    if (days < 30) return `${days}d ago`;
    return new Date(isoDate).toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
  }

  private async confirmAndRestore() {
    if (!this.selectedSha) return;
    const commit = this.commits.find(c => c.sha === this.selectedSha);
    if (!commit) return;

    const confirmed = confirm(
      `Restore entire repo to commit:\n"${commit.message.slice(0, 72)}"\n\n` +
      `SHA: ${commit.sha.slice(0, 7)}  ·  ${commit.author}  ·  ${this.relativeTime(commit.date)}\n\n` +
      "A new commit will be created on the branch with all files reverted to this state.\n" +
      "Your current state will remain accessible in the git history."
    );
    if (!confirmed) return;

    this.restoreBtn.disabled = true;
    this.restoreBtn.textContent = "Restoring…";

    try {
      await this.api.restoreToCommit(
        commit.sha,
        `Quilden: Restore to ${commit.sha.slice(0, 7)} — ${commit.message.slice(0, 60)}`
      );
      new Notice(`Restored to "${commit.message.slice(0, 40)}" ✓ — pulling restored state…`, 6000);
      this.close();
      await this.plugin.runSync("pull");
    } catch (e: any) {
      new Notice(`Restore failed: ${e.message}`, 8000);
      this.restoreBtn.disabled = false;
      this.restoreBtn.textContent = "Restore to selected point";
    }
  }

  onClose() {
    this.contentEl.empty();
  }
}


export default class QuildenSyncPlugin extends Plugin {
  settings: QuildenSyncSettings = DEFAULT_SETTINGS;
  private syncInterval: number | null = null;
  private saveDebounce: number | null = null;
  private syncing = false;
  private statusBarEl: HTMLElement | null = null;
  private statusIconEl: HTMLElement | null = null;
  private statusMsgEl: HTMLElement | null = null;
  private ribbonEl: HTMLElement | null = null;
  private syncHistory: SyncHistoryEntry[] = [];
  private lastSyncTime: Date | null = null;
  // Accumulates paths during a sync run, reset at start of runSync
  private _syncPushedPaths: string[] = [];
  private _syncPulledPaths: string[] = [];
  private encryptionVerifyToken: string | null = null;

  get hasExistingEncryption(): boolean {
    return !!this.encryptionVerifyToken;
  }

  // ── Password localStorage helpers ────────────────────────────────────────
  // Stored device-locally (not in vault files / GitHub) so the vault stays
  // secure even if someone obtains a copy of the repo or data.json.
  private pwStorageKey(): string {
    return `quilden:enc-pw:${this.settings.repoOwner}/${this.settings.repoName}`;
  }

  loadSavedPassword(): string | null {
    try { return window.localStorage.getItem(this.pwStorageKey()) || null; }
    catch { return null; }
  }

  savePassword(password: string): void {
    try { window.localStorage.setItem(this.pwStorageKey(), password); }
    catch { /* localStorage unavailable */ }
  }

  clearSavedPassword(): void {
    try { window.localStorage.removeItem(this.pwStorageKey()); }
    catch { /* localStorage unavailable */ }
  }

  get hasSavedPassword(): boolean {
    return !!this.loadSavedPassword();
  }

  // ── SyncState localStorage helpers ───────────────────────────────────────
  // Stored device-locally so iCloud (or any other vault sync) can't overwrite
  // sync progress saved on this device.
  private syncStateStorageKey(): string {
    return `quilden:syncstate:${this.settings.repoOwner}/${this.settings.repoName}/${this.settings.branch}`;
  }

  private saveSyncStateToLocalStorage(): void {
    try {
      const key = this.syncStateStorageKey();
      window.localStorage.setItem(key, JSON.stringify(this.syncState));
    } catch { /* localStorage unavailable */ }
  }

  private loadSyncStateFromLocalStorage(): { repoKey: string; files: Record<string, SyncedFileState> } | null {
    try {
      const key = this.syncStateStorageKey();
      const raw = window.localStorage.getItem(key);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed.repoKey === "string" && typeof parsed.files === "object") {
        return parsed as { repoKey: string; files: Record<string, SyncedFileState> };
      }
      return null;
    } catch { return null; }
  }

  private syncState: { repoKey: string; files: Record<string, SyncedFileState> } = {
    repoKey: "",
    files: {},
  };

  async onload() {
    await this.loadSettings();

    // Auto-unlock encryption with saved password (stored in localStorage, device-local)
    if (this.settings.encryptionEnabled && this.isConfigured()) {
      const saved = this.loadSavedPassword();
      if (saved) {
        this.tryUnlockEncryption(saved).catch(() => {});
      }
    }

    this.statusBarEl = this.addStatusBarItem();
    this.statusBarEl.addClass("quilden-sync-status");
    this.statusBarEl.title = "Quilden Sync — click for history";
    this.statusBarEl.addEventListener("click", () => this.showSyncHistoryPopup());
    this.statusIconEl = this.statusBarEl.createSpan({ cls: "lm-status-icon", text: "⇅" });
    this.statusMsgEl = this.statusBarEl.createSpan({ cls: "lm-status-msg" });
    this.updateStatusBar("idle");

    this.ribbonEl = this.addRibbonIcon("refresh-cw", "Quilden Sync", async () => {
      await this.runSync();
    });

    this.addCommand({ id: "sync-now", name: "Sync now", callback: () => this.runSync() });
    this.addCommand({ id: "sync-pull", name: "Pull from GitHub", callback: () => this.runSync("pull") });
    this.addCommand({ id: "sync-push", name: "Push to GitHub", callback: () => this.runSync("push") });
    this.addCommand({
      id: "copy-token-for-quilden",
      name: "Copy GitHub token for Quilden sign-in",
      callback: () => this.copyTokenForQuilden(),
    });
    this.addCommand({
      id: "branch-timeline",
      name: "Restore from branch timeline",
      callback: () => {
        if (!this.isConfigured()) {
          new Notice("Quilden Sync: Configure your repo first.");
          return;
        }
        const api = new GitHubAPI(
          this.settings.githubToken, this.settings.repoOwner,
          this.settings.repoName, this.settings.branch
        );
        new BranchTimelineModal(this.app, api, this).open();
      },
    });

    this.addCommand({
      id: "file-history",
      name: "Browse file history",
      checkCallback: (checking) => {
        const file = this.app.workspace.getActiveFile();
        if (!file || !this.isConfigured()) return false;
        if (!checking) this.openFileHistory(file);
        return true;
      },
    });

    // Right-click → file menu
    this.registerEvent(
      this.app.workspace.on("file-menu", (menu, file) => {
        if (!(file instanceof TFile) || !this.isConfigured()) return;
        menu.addItem((item) => {
          item
            .setTitle("Browse file history")
            .setIcon("history")
            .onClick(() => this.openFileHistory(file));
        });
      })
    );

    this.addSettingTab(new QuildenSyncSettingTab(this.app, this));

    // Sync on save — debounced 5 s after last edit
    this.registerEvent(
      this.app.vault.on("modify", (file) => {
        if (this.pulling) return; // ignore writes caused by our own pull
        if (file instanceof TFile) {
          this.dirtyPaths.add(file.path);
          console.log(`[LM] modify event: ${file.path} (dirtyPaths size: ${this.dirtyPaths.size})`);
        }
        if (!this.settings.syncOnSave || !this.isConfigured()) return;
        if (this.saveDebounce !== null) window.clearTimeout(this.saveDebounce);
        this.saveDebounce = window.setTimeout(() => {
          this.saveDebounce = null;
          console.log(`[LM] save debounce fired — dirty: ${[...this.dirtyPaths].join(", ")}`);
          this.runSync("push");
        }, 5000);
      })
    );

    this.setupAutoSync();

    if (this.settings.syncOnStartup && this.isConfigured()) {
      setTimeout(() => this.runSync(), 3000);
    }
  }

  onunload() {
    if (this.syncInterval !== null) window.clearInterval(this.syncInterval);
    if (this.saveDebounce !== null) window.clearTimeout(this.saveDebounce);
    clearEncryptionKey();
  }

  private getRepoSyncKey(): string {
    return [
      this.settings.githubUsername || "unknown",
      this.settings.repoOwner,
      this.settings.repoName,
      this.settings.branch,
      // Note: encryption state intentionally excluded — toggling encryption
      // must NOT clear syncState or every file appears as a new candidate.
    ].join(":");
  }

  private ensureSyncStateRepoKey(): void {
    const repoKey = this.getRepoSyncKey();
    if (this.syncState.repoKey !== repoKey) {
      this.syncState = { repoKey, files: {} };
    }
  }

  private getFileSyncState(file: TFile): SyncedFileState {
    return {
      mtime: file.stat.mtime,
      size: file.stat.size,
    };
  }

  private isFileUnchangedSinceLastSync(file: TFile): boolean {
    const previous = this.syncState.files[file.path];
    if (!previous) return false;

    return previous.mtime === file.stat.mtime && previous.size === file.stat.size;
  }

  private getIncrementalCandidateDiagnostic(
    file: TFile,
    dirtyPaths: ReadonlySet<string>
  ): IncrementalCandidateDiagnostic | null {
    if (dirtyPaths.has(file.path)) {
      return {
        path: file.path,
        reason: "dirty-path",
        previous: this.syncState.files[file.path],
        current: this.getFileSyncState(file),
      };
    }

    const previous = this.syncState.files[file.path];
    if (!previous) {
      return {
        path: file.path,
        reason: "missing-sync-state",
        current: this.getFileSyncState(file),
      };
    }

    if (previous.mtime !== file.stat.mtime || previous.size !== file.stat.size) {
      return {
        path: file.path,
        reason: "metadata-changed",
        previous,
        current: this.getFileSyncState(file),
      };
    }

    return null;
  }

  private logIncrementalCandidateDiagnostics(diagnostics: IncrementalCandidateDiagnostic[]): void {
    if (diagnostics.length === 0) return;

    const counts = diagnostics.reduce<Record<IncrementalCandidateReason, number>>(
      (accumulator, diagnostic) => {
        accumulator[diagnostic.reason] += 1;
        return accumulator;
      },
      { "dirty-path": 0, "missing-sync-state": 0, "metadata-changed": 0 }
    );

    console.log(
      `[LM] incremental candidate reasons: dirty-path=${counts["dirty-path"]}, missing-sync-state=${counts["missing-sync-state"]}, metadata-changed=${counts["metadata-changed"]}`
    );

    diagnostics.slice(0, MAX_SYNC_DIAGNOSTIC_SAMPLE).forEach((diagnostic) => {
      if (diagnostic.reason === "metadata-changed" && diagnostic.previous) {
        console.log(
          `[LM] candidate [metadata-changed] ${diagnostic.path} | prev(mtime=${diagnostic.previous.mtime}, size=${diagnostic.previous.size}) -> current(mtime=${diagnostic.current.mtime}, size=${diagnostic.current.size})`
        );
        return;
      }

      if (diagnostic.reason === "dirty-path") {
        console.log(`[LM] candidate [dirty-path] ${diagnostic.path}`);
        return;
      }

      console.log(`[LM] candidate [missing-sync-state] ${diagnostic.path}`);
    });

    if (diagnostics.length > MAX_SYNC_DIAGNOSTIC_SAMPLE) {
      console.log(
        `[LM] incremental candidate diagnostics truncated: showing ${MAX_SYNC_DIAGNOSTIC_SAMPLE}/${diagnostics.length}`
      );
    }
  }

  private logRemoteComparisonDiagnostics(
    diagnostics: Array<{ path: string; localReason: IncrementalCandidateReason; changed: boolean }>
  ): void {
    if (diagnostics.length === 0) return;

    const summary = diagnostics.reduce<
      Record<IncrementalCandidateReason, { changed: number; unchanged: number }>
    >(
      (accumulator, diagnostic) => {
        accumulator[diagnostic.localReason][diagnostic.changed ? "changed" : "unchanged"] += 1;
        return accumulator;
      },
      {
        "dirty-path": { changed: 0, unchanged: 0 },
        "missing-sync-state": { changed: 0, unchanged: 0 },
        "metadata-changed": { changed: 0, unchanged: 0 },
      }
    );

    console.log(
      `[LM] remote comparison summary: dirty-path changed=${summary["dirty-path"].changed} unchanged=${summary["dirty-path"].unchanged}; missing-sync-state changed=${summary["missing-sync-state"].changed} unchanged=${summary["missing-sync-state"].unchanged}; metadata-changed changed=${summary["metadata-changed"].changed} unchanged=${summary["metadata-changed"].unchanged}`
    );

    const changedDiagnostics = diagnostics.filter((diagnostic) => diagnostic.changed);
    const changedSamples = changedDiagnostics.slice(0, MAX_SYNC_DIAGNOSTIC_SAMPLE);
    changedSamples.forEach((diagnostic) => {
      console.log(`[LM] remote mismatch [${diagnostic.localReason}] ${diagnostic.path}`);
    });

    if (changedDiagnostics.length > MAX_SYNC_DIAGNOSTIC_SAMPLE) {
      console.log(
        `[LM] remote mismatch diagnostics truncated: showing ${MAX_SYNC_DIAGNOSTIC_SAMPLE}/${changedDiagnostics.length}`
      );
    }
  }

  private markFilesSynced(files: TFile[]): void {
    const nextFiles = { ...this.syncState.files };
    for (const file of files) {
      nextFiles[file.path] = this.getFileSyncState(file);
    }
    this.syncState = {
      ...this.syncState,
      files: nextFiles,
    };
  }

  private pruneSyncState(activeFiles: TFile[]): void {
    const activePaths = new Set(activeFiles.map((file) => file.path));
    const nextFiles = Object.fromEntries(
      Object.entries(this.syncState.files).filter(([path]) => activePaths.has(path))
    );
    this.syncState = {
      ...this.syncState,
      files: nextFiles,
    };
  }

  private normalizeExcludePatterns(patterns: unknown): string[] {
    if (!Array.isArray(patterns)) {
      console.warn("[LM] excludePatterns is not an array; resetting to an empty user-defined list");
      return [];
    }

    return Array.from(new Set(patterns.map((pattern) => String(pattern).trim()).filter(Boolean)));
  }

  private getEffectiveExcludePatterns(): string[] {
    return Array.from(new Set([...this.settings.excludePatterns, ...REQUIRED_EXCLUDE_PATTERNS]));
  }

  async loadSettings() {
    const stored = (await this.loadData()) as PersistedPluginData | Partial<QuildenSyncSettings> | null;

    if (stored && "settings" in stored) {
      this.settings = Object.assign({}, DEFAULT_SETTINGS, stored.settings ?? {});
      // Migration: data.json syncState (may be stale if iCloud overwrote it).
      // Will be superseded by localStorage state after settings are applied.
      const rawSyncState = stored.syncState ?? { repoKey: "", files: {} };
      this.syncState = {
        repoKey: rawSyncState.repoKey.replace(/:(enc|plain)$/, ""),
        files: rawSyncState.files,
      };
      this.encryptionVerifyToken = stored.encryptionVerifyToken ?? null;
      this.syncHistory = stored.syncHistory ?? [];
    } else {
      this.settings = Object.assign({}, DEFAULT_SETTINGS, stored ?? {});
      this.syncState = { repoKey: "", files: {} };
      this.encryptionVerifyToken = null;
    }

    this.settings = {
      ...this.settings,
      excludePatterns: this.normalizeExcludePatterns(this.settings.excludePatterns),
    };

    // Prefer localStorage syncState (device-local, immune to iCloud overwrite).
    // localStorage key uses the repo coordinates from settings, which are now set.
    const lsSyncState = this.loadSyncStateFromLocalStorage();
    if (lsSyncState && Object.keys(lsSyncState.files).length >= Object.keys(this.syncState.files).length) {
      this.syncState = {
        repoKey: lsSyncState.repoKey.replace(/:(enc|plain)$/, ""),
        files: lsSyncState.files,
      };
      console.log(`[LM] loadSettings: using localStorage syncState (${Object.keys(lsSyncState.files).length} files)`);
    } else {
      console.log(`[LM] loadSettings: using data.json syncState (${Object.keys(this.syncState.files).length} files); localStorage had ${lsSyncState ? Object.keys(lsSyncState.files).length : 0}`);
    }

    this.ensureSyncStateRepoKey();
    console.log(`[LM] loadSettings: final syncState key="${this.syncState.repoKey}" files=${Object.keys(this.syncState.files).length}`);
  }

  private async savePluginData() {
    // Persist syncState to device-local localStorage first (primary store).
    // This prevents iCloud (or any other vault-sync) from overwriting sync
    // progress saved on this device when it pushes an older data.json.
    this.saveSyncStateToLocalStorage();

    const data: PersistedPluginData = {
      settings: this.settings,
      syncState: this.syncState, // keep in data.json for migration / other devices
    };
    if (this.encryptionVerifyToken) data.encryptionVerifyToken = this.encryptionVerifyToken;
    if (this.syncHistory.length > 0) data.syncHistory = this.syncHistory;
    await this.saveData(data);
  }

  async saveSettings() {
    this.ensureSyncStateRepoKey();
    await this.savePluginData();
    this.setupAutoSync();
  }

  isConfigured(): boolean {
    return !!(this.settings.githubToken && this.settings.repoOwner && this.settings.repoName);
  }

  private setupAutoSync() {
    if (this.syncInterval !== null) {
      window.clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
    if (this.settings.autoSyncInterval > 0 && this.isConfigured()) {
      this.syncInterval = window.setInterval(() => this.runSync(), this.settings.autoSyncInterval * 60 * 1000);
    }
  }

  updateStatusBar(status: "idle" | "syncing" | "done" | "error") {
    // Ribbon icon: spin while syncing, regardless of notification mode
    if (this.ribbonEl) {
      const svgEl = this.ribbonEl.querySelector("svg");
      if (svgEl) {
        if (status === "syncing") {
          svgEl.addClass("lm-ribbon-spinning");
        } else {
          svgEl.removeClass("lm-ribbon-spinning");
        }
      }
    }

    if (!this.statusIconEl) return;
    const loc = this.settings.notificationLocation ?? "notice";

    if (loc !== "statusbar") {
      // For notice/none modes: keep icon static, never animate
      this.statusIconEl.textContent = "⇅";
      this.statusIconEl.removeClass("lm-spinning");
      if (this.statusMsgEl) this.statusMsgEl.textContent = "";
      return;
    }

    // Statusbar mode: update icon and animate during sync
    const icons: Record<string, string> = { idle: "⇅", syncing: "↻", done: "✓", error: "✗" };
    this.statusIconEl.textContent = icons[status];

    if (status === "syncing") {
      this.statusIconEl.addClass("lm-spinning");
    } else {
      this.statusIconEl.removeClass("lm-spinning");
    }

    if (status === "idle" && this.statusMsgEl) {
      this.statusMsgEl.textContent = "";
    }
  }

  notify(message: string, duration?: number): void {
    const loc = this.settings.notificationLocation ?? "notice";
    if (loc === "notice") {
      new Notice(message, duration);
    } else if (loc === "statusbar" && this.statusMsgEl) {
      this.statusMsgEl.textContent = " " + message.slice(0, 60);
      window.setTimeout(() => {
        if (this.statusMsgEl) this.statusMsgEl.textContent = "";
      }, duration ?? 4000);
    }
    // "none" = silent
  }

  private showSyncHistoryPopup() {
    // Remove any existing popup first
    document.querySelector(".lm-sync-popup-backdrop")?.remove();

    const rect = this.statusBarEl!.getBoundingClientRect();
    const backdrop = document.body.createDiv({ cls: "lm-sync-popup-backdrop" });
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) backdrop.remove();
    });

    const popup = backdrop.createDiv({ cls: "lm-sync-popup" });
    popup.style.bottom = `${window.innerHeight - rect.top + 8}px`;
    popup.style.right = `${window.innerWidth - rect.right}px`;

    const header = popup.createDiv({ cls: "lm-sync-popup-header" });
    header.createSpan({ text: "Sync History" });
    const closeBtn = header.createEl("button", { cls: "lm-sync-popup-close", text: "✕" });
    closeBtn.addEventListener("click", () => backdrop.remove());

    if (this.syncHistory.length === 0) {
      popup.createDiv({ cls: "lm-sync-empty", text: "No syncs yet this session." });
    } else {
      for (const entry of this.syncHistory) {
        const row = popup.createDiv({ cls: "lm-sync-entry" });

        const t = new Date(entry.time);
        const diffMs = Date.now() - t.getTime();
        const diffMin = Math.round(diffMs / 60000);
        let timeLabel: string;
        if (diffMin < 1) timeLabel = "Just now";
        else if (diffMin === 1) timeLabel = "1 min ago";
        else if (diffMin < 60) timeLabel = `${diffMin} min ago`;
        else timeLabel = t.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

        row.createEl("div", { cls: "lm-sync-entry-time", text: timeLabel });

        const parts: string[] = [];
        if (entry.pushed > 0) parts.push(`↑ ${entry.pushed} pushed`);
        if (entry.pulled > 0) parts.push(`↓ ${entry.pulled} pulled`);
        if (parts.length === 0) parts.push("No changes");
        row.createEl("div", { cls: "lm-sync-entry-stats", text: parts.join("   ") });

        if (entry.files.length > 0) {
          const filesEl = row.createEl("div", { cls: "lm-sync-entry-files" });
          const shown = entry.files.slice(0, 5);
          filesEl.textContent = shown.map(f => "· " + f.split("/").pop()).join("\n");
          if (entry.files.length > 5) {
            filesEl.textContent += `\n· +${entry.files.length - 5} more`;
          }
        }
      }
    }
  }

  private shouldExclude(path: string): boolean {
    return this.getEffectiveExcludePatterns().some((pattern) => path.startsWith(pattern) || path.includes("/" + pattern));
  }

  async encryptExistingContent(): Promise<void> {
    if (!this.isConfigured()) {
      new Notice("Configure GitHub connection first.");
      return;
    }
    if (!derivedKey) {
      new Notice("Unlock encryption first by entering your password.");
      return;
    }

    const api = new GitHubAPI(
      this.settings.githubToken,
      this.settings.repoOwner,
      this.settings.repoName,
      this.settings.branch
    );

    new Notice("Scanning repo for unencrypted files…");
    const { blobs: tree } = await api.getTree();
    const filesToCheck = tree.filter((f) => shouldEncryptPath(f.path, this.settings.encryptionScope));

    const toEncrypt: Array<{ path: string; content: string }> = [];
    for (const file of filesToCheck) {
      const { content } = await api.getFileContent(file.path);
      if (isEncryptedContent(content)) continue; // already encrypted (any key) — skip to avoid double-encryption
      if (isBinaryPath(file.path)) {
        // Unencrypted binary: read raw bytes, encode as base64 for encryption
        const { buffer } = await api.getBinaryContent(file.path);
        const bytes = new Uint8Array(buffer);
        let binary = "";
        bytes.forEach((b) => (binary += String.fromCharCode(b)));
        toEncrypt.push({ path: file.path, content: btoa(binary) });
      } else {
        toEncrypt.push({ path: file.path, content });
      }
    }

    if (toEncrypt.length === 0) {
      new Notice("All markdown files are already encrypted.");
      return;
    }

    new Notice(`Encrypting ${toEncrypt.length} file(s)…`);

    const BATCH_SIZE = 50;
    for (let i = 0; i < toEncrypt.length; i += BATCH_SIZE) {
      const batch = toEncrypt.slice(i, i + BATCH_SIZE);
      const latestSha = await api.getRef();
      const { treeSha } = await api.getCommit(latestSha);
      const treeItems = await Promise.all(
        batch.map(async (f) => ({
          path: f.path,
          sha: await api.createBlob(await encryptContent(f.content)),
          mode: "100644",
        }))
      );
      const newTreeSha = await api.createTree(treeSha, treeItems);
      const commitSha = await api.createCommit(
        "Quilden: Encrypt existing content",
        newTreeSha,
        latestSha
      );
      await api.updateRef(commitSha);
    }

    new Notice(`✓ Encrypted ${toEncrypt.length} file(s) successfully.`);
  }

  async decryptExistingContent(): Promise<void> {
    if (!this.isConfigured()) {
      new Notice("Configure GitHub connection first.");
      return;
    }
    if (!derivedKey) {
      new Notice("Unlock encryption first by entering your password.");
      return;
    }

    const api = new GitHubAPI(
      this.settings.githubToken,
      this.settings.repoOwner,
      this.settings.repoName,
      this.settings.branch
    );

    new Notice("Scanning repo for encrypted files…");
    const { blobs: tree } = await api.getTree();
    const filesToCheck = tree.filter((f) => shouldEncryptPath(f.path, this.settings.encryptionScope));

    const toDecrypt: Array<{ path: string; content: string; binary: boolean }> = [];
    for (const file of filesToCheck) {
      const { content } = await api.getFileContent(file.path);
      if (!isEncryptedContent(content)) continue;
      const dec = await decryptContent(content);
      if (dec === null) continue; // encrypted with a different key — skip
      toDecrypt.push({ path: file.path, content: dec, binary: isBinaryPath(file.path) });
    }

    if (toDecrypt.length === 0) {
      new Notice("No encrypted files found that can be decrypted with the current password.");
      return;
    }

    new Notice(`Decrypting ${toDecrypt.length} file(s)…`);

    const BATCH_SIZE = 50;
    for (let i = 0; i < toDecrypt.length; i += BATCH_SIZE) {
      const batch = toDecrypt.slice(i, i + BATCH_SIZE);
      const latestSha = await api.getRef();
      const { treeSha } = await api.getCommit(latestSha);
      const treeItems = await Promise.all(
        batch.map(async (f) => ({
          path: f.path,
          // Binary files: decrypted content is the original base64, push back as binary.
          // Text files: push as plain UTF-8.
          sha: await api.createBlob(f.content, f.binary ? "base64" : "utf-8"),
          mode: "100644",
        }))
      );
      const newTreeSha = await api.createTree(treeSha, treeItems);
      const commitSha = await api.createCommit(
        "Quilden: Decrypt existing content",
        newTreeSha,
        latestSha
      );
      await api.updateRef(commitSha);
    }

    new Notice(`✓ Decrypted ${toDecrypt.length} file(s) successfully.`);
  }

  async tryUnlockEncryption(password: string): Promise<void> {
    if (!password) return;
    const { githubUsername, repoOwner, repoName, branch, githubToken } = this.settings;
    if (!githubUsername || !repoOwner || !repoName) {
      new Notice("Connect GitHub and select a repo first.");
      return;
    }

    // ── Fast path: local verification token already stored ──────────────────
    if (this.encryptionVerifyToken) {
      const result = await verifyOrInitEncryption(
        password, githubUsername, repoOwner, repoName,
        this.encryptionVerifyToken
      );
      if (!result.ok) {
        new Notice("Wrong password — this vault uses a different encryption password.", 6000);
        return;
      }
      new Notice("Quilden Sync: Password verified ✓");
      return;
    }

    // ── New device: no local token — verify via repo ─────────────────────────
    const VERIFY_PATH = ".quilden/encryption-verify";
    const api = new GitHubAPI(githubToken, repoOwner, repoName, branch);
    const salt = await contextSalt(githubUsername, repoOwner, repoName);
    const candidateKey = await buildKey(password, salt);

    // Helper: swap in candidate key, attempt decrypt, restore previous key.
    const tryDecrypt = async (ciphertext: string): Promise<string | null> => {
      const prev = derivedKey;
      derivedKey = candidateKey;
      const result = await decryptContent(ciphertext);
      derivedKey = prev;
      return result;
    };

    // Step 1 — dedicated verify file (primary)
    try {
      const { content } = await api.getFileContent(VERIFY_PATH);
      const repoToken = content.trim();
      const check = await tryDecrypt(repoToken);
      if (check !== ENCRYPTION_VERIFY_PLAINTEXT) {
        new Notice("Wrong password — could not verify against repo encryption file.", 6000);
        return;
      }
      // Password correct via verify file.
      derivedKey = candidateKey;
      this.encryptionVerifyToken = repoToken;
      await this.savePluginData();
      new Notice("Quilden Sync: Password verified ✓");
      return;
    } catch { /* verify file missing — fall through to md sampling */ }

    // Step 2 — fallback: sample encrypted .md files from the remote tree
    let foundEncrypted = false;
    let passwordCorrect = false;
    try {
      const { blobs: tree } = await api.getTree();
      const mdCandidates = tree
        .filter(f => f.path.endsWith(".md") && !f.path.startsWith("."))
        .slice(0, 8);

      for (const entry of mdCandidates) {
        try {
          const { content } = await api.getFileContent(entry.path);
          if (!isEncryptedContent(content)) continue; // plaintext file — skip

          foundEncrypted = true;
          const dec = await tryDecrypt(content);
          if (dec !== null) {
            passwordCorrect = true;
          } else {
            new Notice("Wrong password — could not decrypt existing encrypted files.", 6000);
            return;
          }
          break; // one encrypted file is enough to decide
        } catch { continue; }
      }
    } catch (e: any) {
      new Notice(`Could not reach repo for verification: ${e.message}`, 5000);
      return;
    }

    if (foundEncrypted && !passwordCorrect) return; // already notified above

    // Password accepted — either verified via md file, or no encrypted files yet (first setup).
    derivedKey = candidateKey;
    const token = await encryptContent(ENCRYPTION_VERIFY_PLAINTEXT);
    this.encryptionVerifyToken = token;
    await this.savePluginData();

    // Upload verify file so future new-device logins skip the md sampling.
    try {
      await api.putFile(VERIFY_PATH, token, "chore: add Quilden encryption verification token");
    } catch { /* non-critical — md sampling is the fallback */ }

    if (foundEncrypted) {
      new Notice("Quilden Sync: Password verified ✓");
    } else {
      new Notice(
        "Quilden Sync: Encryption set up ✓\n\n" +
        "⚠️ Keep your password safe — it cannot be changed later. " +
        "Losing it means your encrypted files cannot be recovered.",
        12000
      );
    }
  }

  private openFileHistory(file: TFile) {
    const { githubToken, repoOwner, repoName, branch, encryptionEnabled } = this.settings;
    if (!githubToken || !repoOwner || !repoName) {
      new Notice("Quilden Sync: Configure your repo first.");
      return;
    }
    console.log(`[LM] openFileHistory: token=${githubToken.slice(0, 8)}… repo=${repoOwner}/${repoName}@${branch}`);
    const api = new GitHubAPI(githubToken, repoOwner, repoName, branch);
    new FileHistoryModal(this.app, file, api, encryptionEnabled).open();
  }

  private async copyTokenForQuilden() {
    if (!this.settings.githubToken) {
      new Notice("Quilden Sync: No GitHub token configured.");
      return;
    }
    try {
      await navigator.clipboard.writeText(this.settings.githubToken);
      new Notice("Token copied! Paste it into Quilden's sign-in form.");
    } catch {
      new Notice("Clipboard unavailable. Copy the token manually from settings.", 5000);
    }
  }

  async openQuildenWebsite(statusEl?: HTMLElement): Promise<void> {
    if (!this.settings.githubToken) {
      new Notice("Quilden Sync: No GitHub token configured.");
      return;
    }
    if (statusEl) { statusEl.setText("Connecting…"); statusEl.style.color = "var(--text-muted)"; }

    try {
      const res = await requestUrl({
        url: `${QUILDEN_BASE}/api/auth/from-pat`,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: this.settings.githubToken }),
        throw: false,
      });

      if (res.status === 401) {
        if (statusEl) statusEl.setText("Token rejected by server.");
        new Notice("Quilden: GitHub token is invalid or expired. Reconnect with a fresh token.", 6000);
        return;
      }
      if (res.status >= 400) {
        const msg = res.json?.error ?? `Server error ${res.status}`;
        if (statusEl) statusEl.setText("Failed.");
        new Notice(`Quilden: ${msg}`, 5000);
        return;
      }

      const { url } = res.json as { url: string; login: string };
      if (statusEl) { statusEl.setText("Opening browser…"); }
      window.open(url, "_blank");
      if (statusEl) setTimeout(() => statusEl.setText(""), 3000);
    } catch (e: any) {
      if (statusEl) statusEl.setText("Network error.");
      new Notice(`Quilden: Could not reach server — ${e.message}`, 5000);
    }
  }

  private async verifySyncAccess(): Promise<void> {
    const tokenCheck = await requestUrl({
      url: "https://api.github.com/user",
      method: "GET",
      headers: ghHeaders(this.settings.githubToken),
      throw: false,
    });

    if (tokenCheck.status === 401) {
      throw new Error("GitHub token is invalid or expired. Disconnect and reconnect.");
    }

    if (tokenCheck.status >= 400) {
      const message = tokenCheck.json?.message ?? tokenCheck.status;
      throw new Error(`Unable to verify GitHub token (${tokenCheck.status}: ${message})`);
    }

    const scopes = tokenCheck.headers?.["x-oauth-scopes"] ?? "";
    console.log(`[LM] token scopes: "${scopes}"`);

    const repoUrl = `https://api.github.com/repos/${this.settings.repoOwner}/${this.settings.repoName}`;
    const repoCheck = await requestUrl({
      url: repoUrl,
      method: "GET",
      headers: ghHeaders(this.settings.githubToken),
      throw: false,
    });

    if (repoCheck.status === 404) {
      throw new Error(
        `GitHub token cannot access ${this.settings.repoOwner}/${this.settings.repoName}. ` +
        "Reconnect and grant that repository, or choose a different repo."
      );
    }

    if (repoCheck.status === 403) {
      const resetEpoch = repoCheck.headers?.["x-ratelimit-reset"];
      const resetTime = resetEpoch ? new Date(Number(resetEpoch) * 1000).toLocaleTimeString() : "unknown";
      const message = repoCheck.json?.message ?? repoCheck.status;
      if (repoCheck.headers?.["x-ratelimit-remaining"] === "0") {
        throw new Error(`GitHub rate limit exceeded — resets at ${resetTime}. Wait and try again.`);
      }
      throw new Error(`GitHub denied access to ${this.settings.repoOwner}/${this.settings.repoName} (${message}).`);
    }

    if (repoCheck.status >= 400) {
      const message = repoCheck.json?.message ?? repoCheck.status;
      throw new Error(`Unable to verify repo access (${repoCheck.status}: ${message})`);
    }

    const permissions = repoCheck.json?.permissions as RepoPermissionSummary | undefined;
    if (permissions && !permissions.admin && !permissions.maintain && !permissions.push) {
      throw new Error(
        `GitHub token can read ${this.settings.repoOwner}/${this.settings.repoName} but cannot push to it. ` +
        "Reconnect and grant write access."
      );
    }

    if (!scopes) {
      console.log("[LM] token uses permission-based access; repo capability check passed");
    }
  }

  async runSync(mode: "full" | "push" | "pull" = "full") {
    if (this.syncing) {
      console.log(`[LM] runSync(${mode}) skipped — already syncing`);
      return;
    }
    if (!this.isConfigured()) {
      new Notice("Quilden Sync: Please connect GitHub first.");
      return;
    }

    console.log(`[LM] runSync(${mode}) started`);
  // Obsidian plugin callbacks run on the single JS event loop, so setting this
  // immediately after the guard is sufficient to serialize sync execution.
    this.syncing = true;
    this._syncPushedPaths = [];
    this._syncPulledPaths = [];
    this.updateStatusBar("syncing");

    try {
      await this.verifySyncAccess();

      const api = new GitHubAPI(
        this.settings.githubToken,
        this.settings.repoOwner,
        this.settings.repoName,
        this.settings.branch
      );

      if (mode === "push" || mode === "full") await this.pushChanges(api, "incremental");
      if (mode === "pull" || mode === "full") await this.pullChanges(api);

      // Record sync history entry
      this.lastSyncTime = new Date();
      const allFiles = [...new Set([...this._syncPushedPaths, ...this._syncPulledPaths])];
      const entry: SyncHistoryEntry = {
        time: this.lastSyncTime.toISOString(),
        pushed: this._syncPushedPaths.length,
        pulled: this._syncPulledPaths.length,
        files: allFiles,
      };
      this.syncHistory = [entry, ...this.syncHistory].slice(0, 25);
      if (this.statusBarEl) {
        this.statusBarEl.title = `Last sync: ${this.lastSyncTime.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
      }
      await this.savePluginData();

      this.updateStatusBar("done");
      this.notify("Quilden Sync: Complete");
      setTimeout(() => this.updateStatusBar("idle"), 3000);
    } catch (e) {
      console.error("[LM] Sync error:", e);
      this.updateStatusBar("error");
      this.notify(`Quilden Sync: Failed — ${e instanceof Error ? e.message : "Unknown error"}`, 8000);
      setTimeout(() => this.updateStatusBar("idle"), 5000);
    } finally {
      this.syncing = false;
      console.log(`[LM] runSync(${mode}) finished`);
    }
  }

  // Tracks files modified locally since last push (for incremental syncs)
  private dirtyPaths = new Set<string>();

  private async pushChanges(api: GitHubAPI, scope: "full" | "incremental" = "full") {
    const allVaultFiles = this.app.vault.getFiles();
    const preEnsureCount = Object.keys(this.syncState.files).length;
    const preEnsureKey = this.syncState.repoKey;
    this.ensureSyncStateRepoKey();
    const postEnsureCount = Object.keys(this.syncState.files).length;
    console.log(`[LM] pushChanges: syncState before ensureKey: key="${preEnsureKey}" files=${preEnsureCount}; after: key="${this.syncState.repoKey}" files=${postEnsureCount}; computed="${this.getRepoSyncKey()}"`);
    if (postEnsureCount === 0 && preEnsureCount > 0) {
      console.warn(`[LM] BUG: pushChanges ensureSyncStateRepoKey() wiped ${preEnsureCount} entries!`);
    }
    const prePruneCount = Object.keys(this.syncState.files).length;
    this.pruneSyncState(allVaultFiles);
    const postPruneCount = Object.keys(this.syncState.files).length;
    console.log(`[LM] pushChanges: after pruneSyncState: ${postPruneCount} entries (pruned ${prePruneCount - postPruneCount} stale paths from ${allVaultFiles.length} vault files)`);

    // Decide which files to push
    let candidateFiles = allVaultFiles.filter((f) => !this.shouldExclude(f.path));
    const candidateDiagnostics = new Map<string, IncrementalCandidateDiagnostic>();

    if (scope === "incremental") {
      const dirtyPaths = new Set(this.dirtyPaths);
      candidateFiles = candidateFiles.filter((file) => {
        const diagnostic = this.getIncrementalCandidateDiagnostic(file, dirtyPaths);
        if (!diagnostic) return false;
        candidateDiagnostics.set(file.path, diagnostic);
        return true;
      });
      console.log(`[LM] incremental push: ${candidateFiles.length} candidate file(s) after local change scan`);
      this.logIncrementalCandidateDiagnostics(Array.from(candidateDiagnostics.values()));
    } else {
      console.log(`[LM] full sync scan: ${candidateFiles.length} local file(s)`);
    }

    if (candidateFiles.length === 0) {
      console.log("[LM] pushChanges: nothing to push");
      return;
    }

    const filesToPush: Array<{ file: TFile; path: string; content: string; encoding: "utf-8" | "base64" }> = [];

    for (const file of candidateFiles) {
      if (isBinaryPath(file.path)) {
        const buffer = await this.app.vault.readBinary(file);
        if (buffer.byteLength === 0 && file.stat.size > 0) {
          // readBinary returned empty but the file has content — iCloud eviction or similar.
          // Uploading an empty blob would corrupt the remote; skip silently.
          console.log(`[LM] skip push ${file.path}: not locally available (size=${file.stat.size})`);
          continue;
        }
        const bytes = new Uint8Array(buffer);
        let binary = "";
        bytes.forEach((b) => (binary += String.fromCharCode(b)));
        const b64 = btoa(binary);
        const willEncrypt = this.settings.encryptionEnabled && !!derivedKey
          && shouldEncryptPath(file.path, this.settings.encryptionScope);
        // If encrypting, tag as utf-8 so the QENC ciphertext is pushed as text; otherwise base64 binary.
        filesToPush.push({ file, path: file.path, content: b64, encoding: willEncrypt ? "utf-8" : "base64" });
      } else {
        const content = await this.app.vault.read(file);
        // Store plaintext — encryption happens later only for files that actually changed.
        filesToPush.push({ file, path: file.path, content, encoding: "utf-8" });
      }
    }

    console.log(`[LM] pushChanges: prepared ${filesToPush.length} local file(s) for comparison`);

    const { blobs: remoteTree, truncated: remoteTreeTruncated } = await api.getTree();
    if (remoteTreeTruncated) {
      console.warn(`[LM] remote tree is truncated (repo too large for single tree fetch). Missing-sync-state files absent from the partial tree will be skipped to avoid re-uploading unchanged content.`);
    }
    console.log(`[LM] remote tree: ${remoteTree.length} entries${remoteTreeTruncated ? " (TRUNCATED)" : ""}`);
    const remoteShaByPath = new Map(remoteTree.map((entry) => [entry.path, entry.sha]));
    const changedFilesToPush: Array<{ file: TFile; path: string; content: string; encoding: "utf-8" | "base64" }> = [];
    const unchangedFiles: TFile[] = [];
    const remoteComparisonDiagnostics: Array<{
      path: string;
      localReason: IncrementalCandidateReason;
      changed: boolean;
    }> = [];

    for (const file of filesToPush) {
      // Guard: never re-encrypt content that's already encrypted (e.g. pulled with a mismatched key).
      const shouldEnc = this.settings.encryptionEnabled && !!derivedKey
        && shouldEncryptPath(file.path, this.settings.encryptionScope)
        && !isEncryptedContent(file.content);

      let changed: boolean;
      if (shouldEnc) {
        // AES-GCM uses a random IV so each encryption of the same plaintext
        // produces a different SHA. SHA comparison is useless here.
        // Use mtime+size to decide whether the local file has actually changed.
        const prev = this.syncState.files[file.path];
        changed = !prev
          || prev.mtime !== file.file.stat.mtime
          || prev.size !== file.file.stat.size;
      } else {
        const localSha = await computeGitBlobSha(file.content, file.encoding);
        const remoteSha = remoteShaByPath.get(file.path);
        // When the remote tree is truncated, a missing entry may just mean
        // the file is beyond the truncation cutoff — not that it's absent.
        // Treat missing-sync-state files absent from a truncated tree as
        // unchanged (they'll still be compared properly once in syncState).
        const localDiag = candidateDiagnostics.get(file.path);
        if (remoteSha === undefined && remoteTreeTruncated && localDiag?.reason === "missing-sync-state") {
          changed = false; // can't verify — assume unchanged to avoid spurious upload
        } else {
          changed = localSha !== remoteSha;
        }
      }

      const localDiagnostic = candidateDiagnostics.get(file.path);
      if (localDiagnostic) {
        remoteComparisonDiagnostics.push({ path: file.path, localReason: localDiagnostic.reason, changed });
      }

      if (changed) {
        let uploadContent = file.content;
        let uploadEncoding = file.encoding;
        if (shouldEnc) {
          uploadContent = await encryptContent(file.content);
          uploadEncoding = "utf-8"; // encrypted output is always UTF-8 text
        }
        changedFilesToPush.push({ ...file, content: uploadContent, encoding: uploadEncoding });
      } else {
        // BUG GUARD: if encryption is enabled but the key isn't unlocked yet,
        // don't record encryptable files as synced. They remain without sync-state so the
        // next sync (after the user unlocks) will see them as candidates and
        // encrypt+upload them properly.
        const encPending = this.settings.encryptionEnabled && !derivedKey
          && shouldEncryptPath(file.path, this.settings.encryptionScope);
        if (!encPending) {
          this.dirtyPaths.delete(file.path);
          unchangedFiles.push(file.file);
        }
      }
    }

    if (unchangedFiles.length > 0) {
      this.markFilesSynced(unchangedFiles);
      await this.savePluginData();
    }

    this.logRemoteComparisonDiagnostics(remoteComparisonDiagnostics);

    console.log(`[LM] pushChanges: ${changedFilesToPush.length}/${filesToPush.length} file(s) changed vs remote`);

    if (changedFilesToPush.length === 0) {
      console.log("[LM] pushChanges: nothing changed vs remote");
      return;
    }

    const BATCH_SIZE = 20;
    let totalCommits = 0;
    let currentSha = await api.getRef();

    for (let i = 0; i < changedFilesToPush.length; i += BATCH_SIZE) {
      const batch = changedFilesToPush.slice(i, i + BATCH_SIZE);
      const batchNumber = Math.floor(i / BATCH_SIZE) + 1;
      console.log(`[LM] batch ${batchNumber}: creating blobs for`, batch.map((f) => f.path));

      const { treeSha } = await api.getCommit(currentSha);
      console.log(`[LM] base tree SHA: ${treeSha}`);

      const treeItems = await uploadBatchBlobs(api, batch, batchNumber);

      const newTreeSha = await api.createTree(treeSha, treeItems);
      console.log(`[LM] new tree SHA: ${newTreeSha}`);

      if (newTreeSha === treeSha) {
        console.log("[LM] tree unchanged — skipping empty commit for this batch");
        batch.forEach((f) => this.dirtyPaths.delete(f.path));
        this.markFilesSynced(batch.map((f) => f.file));
        await this.savePluginData();
        continue;
      }

      const timestamp = new Date().toISOString().slice(0, 19).replace("T", " ");
      const commitSha = await api.createCommit(`${this.settings.commitMessage} - ${timestamp}`, newTreeSha, currentSha);
      await api.updateRef(commitSha);
      currentSha = commitSha;
      batch.forEach((f) => {
        this.dirtyPaths.delete(f.path);
        this._syncPushedPaths.push(f.path);
      });
      this.markFilesSynced(batch.map((f) => f.file));
      await this.savePluginData();
      totalCommits++;
      console.log(`[LM] committed ${commitSha} (${batch.length} file(s) in batch)`);
    }

    if (totalCommits > 0) {
      console.log(`[LM] push done — ${totalCommits} commit(s) created`);
    } else {
      console.log("[LM] push done — no commits needed (all trees identical)");
    }
  }

  private pulling = false;

  private async pullChanges(api: GitHubAPI) {
    const vault = this.app.vault;

    // One API call to get all remote SHAs — no content fetched yet
    const { blobs: remoteTree } = await api.getTree();
    console.log(`[LM] pull: ${remoteTree.length} remote entries`);

    let created = 0, updated = 0, unchanged = 0;
    const syncedFiles: TFile[] = [];

    this.pulling = true;
    try {
      for (const remote of remoteTree) {
        if (this.shouldExclude(remote.path)) continue;
        if (/^\.\.\/|\/\.\.\//g.test(remote.path) || remote.path.startsWith("/")) continue;
        // Skip hidden-dir paths that Obsidian's vault API can't manage
        // (e.g. .infio_json_db/, .smtcmp_chat_histories/, .obsidian-mobile/)
        // getAbstractFileByPath returns null for these so we'd try to create
        // them every time and fail with "File already exists".
        const firstSegment = remote.path.split("/")[0];
        if (firstSegment.startsWith(".") && firstSegment !== ".obsidian") continue;

        try {
          const normalized = normalizePath(remote.path);
          const existing = vault.getAbstractFileByPath(normalized);

          if (existing instanceof TFile) {
            // ── File exists: compare SHA before downloading anything ──
            let needsUpdate: boolean;

            if (this.settings.encryptionEnabled && shouldEncryptPath(remote.path, this.settings.encryptionScope)) {
              // Encrypted: local is plaintext/binary, remote is ciphertext — SHAs will never match.
              // Fall back to sync-state tracking: only download if remote SHA changed since last pull.
              needsUpdate = this.syncState.files[remote.path]?.mtime !== existing.stat.mtime
                || !(this.syncState.files[remote.path]);
            } else {
              // Unencrypted: compute local git blob SHA and compare with remote tree SHA.
              // gitBlobSha() operates on raw bytes — identical to how git computes object SHAs.
              const localBytes = isBinaryPath(remote.path)
                ? new Uint8Array(await vault.readBinary(existing))
                : new TextEncoder().encode(await vault.read(existing));
              const localSha = await gitBlobSha(localBytes);
              needsUpdate = localSha !== remote.sha;
            }

            if (!needsUpdate) {
              unchanged++;
              syncedFiles.push(existing);
              continue;
            }

            // SHA differs — download and apply
            const isEncBinary = isBinaryPath(remote.path)
              && this.settings.encryptionEnabled
              && shouldEncryptPath(remote.path, this.settings.encryptionScope);

            if (isBinaryPath(remote.path) && !isEncBinary) {
              const { buffer } = await api.getBinaryContent(remote.path);
              if (buffer.byteLength === 0 && existing.stat.size > 0) {
                // Remote has an empty blob but local file has content.
                // This means a previous push corrupted the remote (iCloud eviction during push).
                // Keep local; mark as unchanged so we don't loop.
                console.log(`[LM] pull skip ${remote.path}: remote empty, local has content (size=${existing.stat.size})`);
                unchanged++;
                syncedFiles.push(existing);
                continue;
              }
              await vault.modifyBinary(existing, buffer);
            } else {
              const { content } = await api.getFileContent(remote.path);
              let final: string | null = content;
              if (this.settings.encryptionEnabled && derivedKey && isEncryptedContent(content)) {
                final = await decryptContent(content);
              }
              if (final === null) {
                // Decryption failed (wrong key) — leave local file untouched
              } else if (isEncBinary) {
                // Encrypted binary: decrypt gives us the base64 of the original bytes
                const binaryStr = atob(final);
                const bytes = new Uint8Array(binaryStr.length);
                for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
                await vault.modifyBinary(existing, bytes.buffer);
              } else {
                await vault.modify(existing, final);
              }
            }
            syncedFiles.push(existing);
            console.log(`[LM] pull update: ${remote.path}`);
            this._syncPulledPaths.push(remote.path);
            updated++;

          } else {
            // ── File missing locally: ensure parent dir then create ──
            const dir = remote.path.includes("/") ? remote.path.slice(0, remote.path.lastIndexOf("/")) : null;
            if (dir) {
              const dirPath = normalizePath(dir);
              if (!vault.getAbstractFileByPath(dirPath)) {
                try { await vault.createFolder(dirPath); } catch { /* already exists */ }
              }
            }

            const isEncBinaryNew = isBinaryPath(remote.path)
              && this.settings.encryptionEnabled
              && shouldEncryptPath(remote.path, this.settings.encryptionScope);

            if (isBinaryPath(remote.path) && !isEncBinaryNew) {
              const { buffer } = await api.getBinaryContent(remote.path);
              await vault.createBinary(normalized, buffer);
            } else {
              const { content } = await api.getFileContent(remote.path);
              let final: string | null = content;
              if (this.settings.encryptionEnabled && derivedKey && isEncryptedContent(content)) {
                final = await decryptContent(content);
              }
              if (final !== null) {
                if (isEncBinaryNew) {
                  // Encrypted binary: decrypt gives us the base64 of the original bytes
                  const binaryStr = atob(final);
                  const bytes = new Uint8Array(binaryStr.length);
                  for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
                  await vault.createBinary(normalized, bytes.buffer);
                } else {
                  await vault.create(normalized, final);
                }
              }
            }
            const newFile = vault.getAbstractFileByPath(normalized);
            if (newFile instanceof TFile) syncedFiles.push(newFile);
            console.log(`[LM] pull create: ${remote.path}`);
            this._syncPulledPaths.push(remote.path);
            created++;
          }
        } catch (e) {
          console.warn(`[LM] pull error ${remote.path}:`, e);
        }
      }
    } finally {
      this.pulling = false;
    }

    if (syncedFiles.length > 0) {
      this.ensureSyncStateRepoKey();
      this.markFilesSynced(syncedFiles);
      await this.savePluginData();
    }

    console.log(`[LM] pullChanges done: created=${created} updated=${updated} unchanged=${unchanged}`);
    const pulled = created + updated;
    if (pulled > 0) this.notify(`Quilden Sync: Pulled ${pulled} file(s)`);
  }
}


function confirmDialog(app: App, title: string, message: string): Promise<boolean> {
  return new Promise((resolve) => {
    const modal = new Modal(app);
    modal.titleEl.setText(title);
    modal.contentEl.createEl("p", { text: message });
    const btnRow = modal.contentEl.createDiv({ cls: "modal-button-container" });
    btnRow.createEl("button", { text: "Cancel" }).addEventListener("click", () => {
      modal.close();
      resolve(false);
    });
    const confirmBtn = btnRow.createEl("button", { text: "Continue", cls: "mod-cta" });
    confirmBtn.addEventListener("click", () => {
      modal.close();
      resolve(true);
    });
    modal.open();
  });
}

class QuildenSyncSettingTab extends PluginSettingTab {
  plugin: QuildenSyncPlugin;
  private showAdvanced = false;
  private showEncryption = false;
  private allRepos: Array<{ full_name: string; private: boolean }> = [];
  private renderGeneration = 0;
  private activePollingTimer: number | null = null;
  private unlockFeedback: { ok: boolean; msg: string } | null = null;
  private encToggleMsg: "on" | "off" | null = null;
  private changingPassword = false;

  constructor(app: App, plugin: QuildenSyncPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  hide(): void {
    this.stopActivePolling();
  }

  private stopActivePolling(): void {
    if (this.activePollingTimer !== null) {
      window.clearInterval(this.activePollingTimer);
      this.activePollingTimer = null;
    }
  }

  display(): void {
    this.stopActivePolling();
    const { containerEl } = this;
    const generation = ++this.renderGeneration;
    containerEl.empty();
    containerEl.addClass("quilden-sync-settings");

    const titleRow = containerEl.createDiv({ cls: "lm-settings-title-row" });
    const titleEl = titleRow.createDiv({ cls: "lm-settings-title-heading" });
    titleEl.createEl("h2", { text: "Quilden Sync" });
    titleEl.createEl("span", { text: `v${this.plugin.manifest.version}`, cls: "lm-settings-version-badge" });
    const websiteLink = titleRow.createEl("a", {
      text: "Open Quilden Website",
      href: QUILDEN_BASE,
      cls: "lm-settings-title-link",
    });
    websiteLink.setAttr("target", "_blank");
    websiteLink.setAttr("rel", "noopener noreferrer");

    const connectionSection = containerEl.createDiv({ cls: "lm-settings-section" });
    this.renderConnectionWizard(connectionSection, generation);

    if (!this.plugin.isConfigured()) {
      containerEl.createDiv({
        cls: "quilden-not-connected-hint",
        text: "Connect a GitHub repository above to access sync settings.",
      });
      return;
    }

    // ── Sync now ──
    new Setting(containerEl).setName("Sync now").addButton((btn) =>
      btn.setButtonText("Sync").setCta().onClick(() => this.plugin.runSync())
    );

    // ── Encryption ──
    const encHeader = containerEl.createEl("h3", {
      cls: "setting-item-heading quilden-collapsible-heading",
    });
    encHeader.style.cursor = "pointer";

    const encHeaderText = encHeader.createSpan({ text: this.showEncryption ? "▼ Encryption" : "▶ Encryption" });

    // Status tag — visible even when collapsed
    const encTag = encHeader.createSpan({ cls: "quilden-enc-tag" });
    if (this.plugin.settings.encryptionEnabled && derivedKey) {
      encTag.addClass("quilden-enc-tag--active");
      setIcon(encTag, "lock");
      encTag.createSpan({ text: "active" });
    } else if (this.plugin.settings.encryptionEnabled) {
      encTag.addClass("quilden-enc-tag--locked");
      setIcon(encTag, "lock");
      encTag.createSpan({ text: "locked" });
    } else {
      encTag.addClass("quilden-enc-tag--off");
      setIcon(encTag, "lock-open");
      encTag.createSpan({ text: "off" });
    }

    encHeader.addEventListener("click", () => {
      this.showEncryption = !this.showEncryption;
      this.display();
    });

    if (this.showEncryption) {
      // ── Group 1: Status & enable toggle ──
      const encGroup1 = containerEl.createDiv("setting-group").createDiv("setting-items");

      const encStatus = encGroup1.createDiv("encryption-status");
      if (this.plugin.settings.encryptionEnabled && derivedKey) {
        encStatus.addClass("active");
        const scopeLabel = this.plugin.settings.encryptionScope === "all"
        ? "all files"
        : this.plugin.settings.encryptionScope === "media"
          ? "notes, images & PDFs"
          : "markdown notes";
      encStatus.setText(`🔒 Encryption active — ${scopeLabel} are encrypted before upload`);
      } else if (this.plugin.settings.encryptionEnabled) {
        encStatus.addClass("inactive");
        encStatus.setText("🔒 Encryption enabled — enter your password below to activate");
      } else {
        encStatus.addClass("inactive");
        encStatus.setText("🔓 Encryption disabled — files are stored as plain text in GitHub");
      }

      new Setting(encGroup1)
        .setName("Enable encryption")
        .setDesc("Encrypts files before pushing to GitHub.")
        .addToggle((t) =>
          t.setValue(this.plugin.settings.encryptionEnabled).onChange(async (v) => {
            this.unlockFeedback = null;
            this.encToggleMsg = v ? "on" : "off";
            this.plugin.settings.encryptionEnabled = v;
            if (!v) clearEncryptionKey();
            await this.plugin.saveSettings();
            this.display();
          })
        );

      if (this.encToggleMsg === "on") {
        encGroup1.createDiv({ cls: "enc-toggle-change-msg enc-toggle-change-msg--on",
          text: "Encryption enabled. New syncs will encrypt matching files. Files already in GitHub are not affected — use 'Encrypt existing repo content' below to encrypt them.",
        });
      } else if (this.encToggleMsg === "off") {
        encGroup1.createDiv({ cls: "enc-toggle-change-msg enc-toggle-change-msg--off",
          text: "Encryption disabled. New syncs will push files as plain text. Files already encrypted in GitHub remain encrypted — use 'Decrypt existing repo content' below to restore them as plain text.",
        });
      }

      if (this.plugin.settings.encryptionEnabled) {
        const encNote = encGroup1.createDiv("enc-toggle-note");
        if (this.plugin.hasExistingEncryption) {
          encNote.setText("This vault already has an encryption password set. Enter it below to unlock.");
        } else {
          encNote.setText("⚠️ Your encryption password cannot be changed later. If you forget it, your encrypted files cannot be recovered. Choose carefully.");
        }

        new Setting(encGroup1)
          .setName("Encrypt")
          .setDesc("Which file types to encrypt before pushing.")
          .addDropdown((dd) =>
            dd
              .addOption("markdown", "Markdown notes only")
              .addOption("media", "Notes, images & PDFs")
              .addOption("all", "Everything")
              .setValue(this.plugin.settings.encryptionScope ?? "markdown")
              .onChange(async (v) => {
                this.plugin.settings.encryptionScope = v as "markdown" | "media" | "all";
                await this.plugin.saveSettings();
                this.display();
              })
          );

        // ── Group 2: Password ──
        const pwGroup = containerEl.createDiv("setting-group").createDiv("setting-items");

        const hasSaved = this.plugin.hasSavedPassword;
        const showSavedState = !derivedKey && hasSaved && !this.changingPassword;
        const showInputState = (!derivedKey && (!hasSaved || this.changingPassword)) || (!!derivedKey && this.changingPassword);

        const pwSetting = new Setting(pwGroup)
          .setName("Vault password")
          .setDesc(
            derivedKey && !this.changingPassword
              ? "Encryption is active — files are encrypted on each sync."
              : showSavedState
                ? "Password saved on this device — auto-applied on startup."
                : "Enter your password to activate encryption."
          );

        if (derivedKey && !this.changingPassword) {
          pwSetting.addButton((btn) =>
            btn.setButtonText("Change password").onClick(() => {
              this.changingPassword = true;
              this.unlockFeedback = null;
              this.display();
            })
          );
        }

        if (showSavedState) {
          // Show filled-bullet placeholder + action buttons
          const savedInput = pwSetting.controlEl.createEl("input", {
            type: "password",
            cls: "enc-saved-pw-display",
          });
          savedInput.value = "••••••••";
          savedInput.readOnly = true;

          pwSetting
            .addButton((btn) =>
              btn.setButtonText("Unlock").setCta().onClick(async () => {
                const saved = this.plugin.loadSavedPassword() ?? "";
                this.unlockFeedback = null;
                await this.plugin.tryUnlockEncryption(saved);
                this.unlockFeedback = derivedKey
                  ? { ok: true, msg: "✓ Password correct — encryption unlocked." }
                  : { ok: false, msg: "✗ Saved password is wrong. Try changing it." };
                this.display();
              })
            )
            .addButton((btn) =>
              btn.setButtonText("Change").onClick(() => {
                this.changingPassword = true;
                this.unlockFeedback = null;
                this.display();
              })
            )
            .addButton((btn) =>
              btn.setButtonText("Forget").onClick(() => {
                this.plugin.clearSavedPassword();
                this.changingPassword = false;
                this.unlockFeedback = null;
                this.display();
              })
            );
        }

        if (showInputState) {
          const doUnlock = async (password: string) => {
            // If changing password while already unlocked, clear first so tryUnlockEncryption re-derives
            if (derivedKey) clearEncryptionKey();
            this.unlockFeedback = null;
            await this.plugin.tryUnlockEncryption(password);
            if (derivedKey) {
              this.plugin.savePassword(password);
              this.changingPassword = false;
              this.unlockFeedback = { ok: true, msg: "✓ Password saved on this device." };
            } else {
              this.unlockFeedback = { ok: false, msg: "✗ Wrong password. Please try again." };
            }
            this.display();
          };

          pwSetting.addText((text) => {
            text.setPlaceholder("Password");
            text.inputEl.type = "password";
            text.inputEl.addEventListener("keydown", async (e) => {
              if (e.key !== "Enter") return;
              await doUnlock(text.getValue().trim());
            });
          });

          if (this.changingPassword) {
            pwSetting
              .addButton((btn) =>
                btn.setButtonText("Save new password").setCta().onClick(async () => {
                  const input = pwSetting.controlEl.querySelector("input") as HTMLInputElement | null;
                  await doUnlock(input?.value.trim() ?? "");
                })
              )
              .addButton((btn) =>
                btn.setButtonText("Cancel").onClick(() => {
                  this.changingPassword = false;
                  this.unlockFeedback = null;
                  this.display();
                })
              );
          } else {
            pwSetting.addButton((btn) =>
              btn.setButtonText("Unlock").onClick(async () => {
                const input = pwSetting.controlEl.querySelector("input") as HTMLInputElement | null;
                await doUnlock(input?.value.trim() ?? "");
              })
            );
          }
        }

        if (this.unlockFeedback) {
          pwGroup.createDiv({
            cls: this.unlockFeedback.ok ? "enc-feedback-ok" : "enc-feedback-err",
            text: this.unlockFeedback.msg,
          });
        }

        const repoContentSetting = new Setting(pwGroup)
          .setName("Existing repo content")
          .setDesc(
            derivedKey
              ? "Apply or remove encryption on files already in your GitHub repo."
              : "Unlock encryption above first."
          );

        if (derivedKey) {
          repoContentSetting
            .addButton((btn) =>
              btn.setButtonText("Encrypt all").onClick(async () => {
                const confirmed = await confirmDialog(
                  this.app,
                  "Encrypt existing repo content",
                  "This will re-upload all matching unencrypted files in your GitHub repo with encryption applied. Files already encrypted will be skipped. Continue?"
                );
                if (!confirmed) return;
                try {
                  await this.plugin.encryptExistingContent();
                } catch (e) {
                  new Notice(`Failed: ${e instanceof Error ? e.message : "Unknown error"}`);
                }
              })
            )
            .addButton((btn) =>
              btn.setButtonText("Decrypt all").onClick(async () => {
                const confirmed = await confirmDialog(
                  this.app,
                  "Decrypt existing repo content",
                  "This will re-upload all encrypted files in your GitHub repo as plain text. This cannot be undone without re-encrypting. Continue?"
                );
                if (!confirmed) return;
                try {
                  await this.plugin.decryptExistingContent();
                } catch (e) {
                  new Notice(`Failed: ${e instanceof Error ? e.message : "Unknown error"}`);
                }
              })
            );
        } else {
          repoContentSetting.addButton((btn) =>
            btn.setButtonText("Locked").setDisabled(true)
          );
        }
      }
    }

    // ── Advanced ──
    const advHeader = containerEl.createEl("h3", {
      text: this.showAdvanced ? "▼ Advanced" : "▶ Advanced",
      cls: "setting-item-heading",
    });
    advHeader.style.cursor = "pointer";
    advHeader.addEventListener("click", () => {
      this.showAdvanced = !this.showAdvanced;
      this.display();
    });

    if (this.showAdvanced) {
      // ── Group 1: Sync behaviour ──
      const syncGroup = containerEl.createDiv("setting-group").createDiv("setting-items");

      new Setting(syncGroup)
        .setName("Sync on save")
        .setDesc("Automatically push changes 5 seconds after you finish editing a note.")
        .addToggle((t) =>
          t.setValue(this.plugin.settings.syncOnSave).onChange(async (v) => {
            this.plugin.settings.syncOnSave = v;
            await this.plugin.saveSettings();
          })
        );

      new Setting(syncGroup)
        .setName("Sync on startup")
        .setDesc("Automatically sync when Obsidian opens.")
        .addToggle((t) =>
          t.setValue(this.plugin.settings.syncOnStartup).onChange(async (v) => {
            this.plugin.settings.syncOnStartup = v;
            await this.plugin.saveSettings();
          })
        );

      new Setting(syncGroup)
        .setName("Auto sync interval")
        .setDesc("Minutes between auto syncs. 0 to disable.")
        .addText((text) =>
          text
            .setPlaceholder("0")
            .setValue(String(this.plugin.settings.autoSyncInterval))
            .onChange(async (v) => {
              this.plugin.settings.autoSyncInterval = Math.max(0, parseInt(v) || 0);
              await this.plugin.saveSettings();
            })
        );

      new Setting(syncGroup)
        .setName("Notification location")
        .setDesc("Where sync status messages appear.")
        .addDropdown((d) =>
          d
            .addOption("notice", "Pop-up notification")
            .addOption("statusbar", "Status bar only")
            .addOption("none", "None (silent)")
            .setValue(this.plugin.settings.notificationLocation ?? "notice")
            .onChange(async (v) => {
              this.plugin.settings.notificationLocation = v as "notice" | "statusbar" | "none";
              await this.plugin.saveSettings();
            })
        );

      // ── Group 2: GitHub ──
      const ghGroup = containerEl.createDiv("setting-group").createDiv("setting-items");

      new Setting(ghGroup)
        .setName("Commit message")
        .setDesc("Custom commit message for pushes.")
        .addText((text) =>
          text
            .setPlaceholder("Quilden Sync: Update from Obsidian")
            .setValue(this.plugin.settings.commitMessage)
            .onChange(async (v) => {
              this.plugin.settings.commitMessage = v || DEFAULT_SETTINGS.commitMessage;
              await this.plugin.saveSettings();
            })
        );

      new Setting(ghGroup)
        .setName("Conflict strategy")
        .setDesc("How to resolve conflicts between local and remote.")
        .addDropdown((d) =>
          d
            .addOption("newer", "Keep newer")
            .addOption("local", "Keep local")
            .addOption("remote", "Keep remote")
            .setValue(this.plugin.settings.conflictStrategy)
            .onChange(async (v) => {
              this.plugin.settings.conflictStrategy = v as "local" | "remote" | "newer";
              await this.plugin.saveSettings();
            })
        );

      new Setting(ghGroup)
        .setName("Exclude patterns")
        .setDesc("Comma-separated path prefixes to exclude from sync.")
        .addTextArea((text) =>
          text
            .setPlaceholder("User patterns only; .obsidian/, .trash/, and .DS_Store are always excluded")
            .setValue(this.plugin.settings.excludePatterns.join(", "))
            .onChange(async (v) => {
              this.plugin.settings.excludePatterns = this.plugin.normalizeExcludePatterns(
                v.split(",").map((s) => s.trim()).filter(Boolean)
              );
              await this.plugin.saveSettings();
            })
        );

      if (this.plugin.isConfigured()) {
        new Setting(ghGroup)
          .setName("Restore from branch timeline")
          .setDesc("View all commits on this branch and restore the repo to any past state. A new commit is created — no history is lost.")
          .addButton((btn) =>
            btn.setButtonText("Open timeline").onClick(() => {
              const { githubToken, repoOwner, repoName, branch } = this.plugin.settings;
              const api = new GitHubAPI(githubToken, repoOwner, repoName, branch);
              new BranchTimelineModal(this.plugin.app, api, this.plugin).open();
            })
          );
      }
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Interactive GitHub connection wizard
  // ─────────────────────────────────────────────────────────────
  private renderConnectionWizard(containerEl: HTMLElement, generation: number) {
    containerEl.createEl("h3", { text: "GitHub Connection", cls: "lm-settings-section-title" });
    const isConnected = !!(this.plugin.settings.githubToken && this.plugin.settings.githubUsername);
    if (isConnected) {
      this.renderConnectedState(containerEl, generation);
    } else {
      this.renderConnectSteps(containerEl, generation);
    }
  }

  // ── Connected state ──────────────────────────────────────────
  private renderConnectedState(containerEl: HTMLElement, generation: number) {
    const { settings } = this.plugin;
    const activeBranch = settings.branch || "main";
    const currentRepo = settings.repoOwner ? `${settings.repoOwner}/${settings.repoName}` : "";

    // ── Username + Disconnect ──
    new Setting(containerEl)
      .setName(`@${settings.githubUsername}`)
      .setDesc("Connected to GitHub ✓")
      .addButton((btn) =>
        btn.setButtonText("Disconnect").onClick(async () => {
          this.plugin.settings.githubToken = "";
          this.plugin.settings.githubUsername = "";
          this.plugin.settings.repoOwner = "";
          this.plugin.settings.repoName = "";
          this.plugin.settings.branch = "main";
          this.allRepos = [];
          await this.plugin.saveSettings();
          this.display();
        })
      );

    // ── Quilden website access ──
    const quildenStatusEl = containerEl.createEl("div", { cls: "setting-item-description lm-quilden-status" });
    new Setting(containerEl)
      .setName("Use on Quilden website")
      .setDesc("Open your vault in the browser, or copy your token to sign in manually.")
      .addButton((btn) =>
        btn.setButtonText("Open in Quilden").setCta().onClick(() =>
          this.plugin.openQuildenWebsite(quildenStatusEl)
        )
      )
      .addButton((btn) =>
        btn.setButtonText("Copy token").onClick(async () => {
          if (!this.plugin.settings.githubToken) {
            new Notice("No token configured.");
            return;
          }
          try {
            await navigator.clipboard.writeText(this.plugin.settings.githubToken);
            btn.setButtonText("Copied!");
            new Notice(
              "⚠️ Keep this token secret! Anyone with it can access your connected GitHub repositories.",
              6000
            );
            setTimeout(() => btn.setButtonText("Copy token"), 2000);
          } catch {
            new Notice("Clipboard unavailable. Copy the token manually from settings.", 5000);
          }
        })
      );

    // ── Repository ──
    if (currentRepo) {
      const repoSetting = new Setting(containerEl)
        .setName("Repository")
        .setDesc(currentRepo)
        .addButton((btn) =>
          btn.setButtonText("Change").onClick(async () => {
            this.plugin.settings.repoOwner = "";
            this.plugin.settings.repoName = "";
            this.plugin.settings.branch = "main";
            await this.plugin.saveSettings();
            this.display();
          })
        );

      const branchMetaRow = repoSetting.descEl.createDiv({ cls: "lm-inline-branch-row" });
      branchMetaRow.createSpan({ text: `Branch: ${activeBranch}`, cls: "lm-inline-branch-label" });
      const changeBranchButton = branchMetaRow.createEl("button", {
        text: "Change branch",
        cls: "clickable-icon lm-inline-branch-button",
      });

      const branchControls = repoSetting.descEl.createDiv({ cls: "lm-inline-branch-controls is-hidden" });
      const branchStatus = branchControls.createDiv({ cls: "lm-inline-branch-status", text: "Loading branches…" });
      const branchDropdownHost = branchControls.createDiv({ cls: "lm-inline-branch-dropdown" });
      const branchDropdown = new DropdownComponent(branchDropdownHost);
      branchDropdown.addOption(activeBranch, activeBranch);
      branchDropdown.setValue(activeBranch);

      let branchesLoaded = false;
      let branchLoadInFlight = false;

      const loadBranches = async () => {
        if (branchesLoaded || branchLoadInFlight) return;
        branchLoadInFlight = true;
        branchStatus.setText("Loading branches…");
        changeBranchButton.disabled = true;

        try {
          const branches = await GitHubAPI.fetchBranches(settings.githubToken, settings.repoOwner, settings.repoName);
          if (this.renderGeneration !== generation || !branchDropdown.selectEl.isConnected) return;

          const nextValue = branches.includes(this.plugin.settings.branch || "main")
            ? (this.plugin.settings.branch || "main")
            : (branches[0] ?? "main");

          if (!branchDropdown.selectEl.isConnected) return;
          branchDropdown.selectEl.empty();
          branches.forEach((branch) => branchDropdown.addOption(branch, branch));
          branchDropdown.setValue(nextValue);
          branchStatus.setText("Select a branch if you want to sync something other than main.");
          branchesLoaded = true;
        } catch (error) {
          if (this.renderGeneration !== generation || !branchDropdown.selectEl.isConnected) return;
          const message = error instanceof Error ? error.message : "unknown error";
          branchStatus.setText(`Failed to load branches: ${message}`);
        } finally {
          branchLoadInFlight = false;
          if (this.renderGeneration === generation && changeBranchButton.isConnected) {
            changeBranchButton.disabled = false;
          }
        }
      };

      branchDropdown.onChange(async (value) => {
        this.plugin.settings.branch = value || "main";
        await this.plugin.saveSettings();
        this.display();
      });

      changeBranchButton.addEventListener("click", () => {
        const isHidden = branchControls.classList.contains("is-hidden");
        branchControls.classList.toggle("is-hidden", !isHidden);
        changeBranchButton.setText(isHidden ? "Hide branch" : "Change branch");
        if (isHidden) {
          void loadBranches();
        }
      });
    } else {
      let selectedRepo = "";
      let repoDropdown: DropdownComponent | null = null;
      let selectRepoButton: ButtonComponent | null = null;
      let loadingRepos = false;

      const repoPickerSetting = new Setting(containerEl)
        .setName("Repository")
        .setDesc("Loading repositories…")
        .addDropdown((dropdown) => {
          repoDropdown = dropdown;
          dropdown.addOption("", "Loading repositories…");
          dropdown.setValue("");
          dropdown.onChange((value) => {
            selectedRepo = value;
            selectRepoButton?.setDisabled(!selectedRepo);
          });
        })
        .addButton((btn) => {
          selectRepoButton = btn;
          btn.setButtonText("Use repo").setDisabled(true).onClick(async () => {
            if (!selectedRepo) return;
            const [owner, repo] = selectedRepo.split("/");
            this.plugin.settings.repoOwner = owner;
            this.plugin.settings.repoName = repo;
            this.plugin.settings.branch = "main";
            await this.plugin.saveSettings();
            this.display();
          });
        })
        .addButton((btn) =>
          btn.setButtonText("Manage on GitHub").onClick(() => {
            window.open(`${QUILDEN_BASE}/api/auth/manage-repos`, "_blank");
          })
        );

      const populateDropdown = () => {
        if (!repoDropdown) return;
        repoDropdown.selectEl.empty();
        if (this.allRepos.length === 0) {
          repoDropdown.addOption("", "No repositories found");
          repoDropdown.setValue("");
          selectedRepo = "";
          selectRepoButton?.setDisabled(true);
          repoPickerSetting.setDesc('No repositories found. Use "Manage on GitHub" to grant access.');
          return;
        }
        repoDropdown.addOption("", "Select a repository");
        this.allRepos.slice(0, 100).forEach((repo) => {
          repoDropdown?.addOption(repo.full_name, repo.full_name);
        });
        const extraCount = Math.max(this.allRepos.length - 100, 0);
        repoPickerSetting.setDesc(
          extraCount > 0
            ? `Showing 100 of ${this.allRepos.length} repositories.`
            : `${this.allRepos.length} repositor${this.allRepos.length === 1 ? "y" : "ies"} available.`
        );
        const preserved = this.allRepos.some((r) => r.full_name === selectedRepo) ? selectedRepo : "";
        selectedRepo = preserved;
        repoDropdown.setValue(preserved);
        selectRepoButton?.setDisabled(!preserved);
      };

      const loadRepos = async () => {
        if (loadingRepos) return;
        if (this.allRepos.length > 0) { populateDropdown(); return; }
        loadingRepos = true;
        try {
          this.allRepos = await GitHubAPI.fetchRepos(settings.githubToken);
          if (this.renderGeneration !== generation || !containerEl.isConnected) return;
          populateDropdown();
        } catch (error) {
          if (this.renderGeneration !== generation || !containerEl.isConnected) return;
          const message = error instanceof Error ? error.message : "unknown error";
          repoPickerSetting.setDesc(`Failed to load repositories: ${message}`);
          repoDropdown?.selectEl.empty();
          repoDropdown?.addOption("", "Failed to load");
          repoDropdown?.setValue("");
          selectedRepo = "";
          selectRepoButton?.setDisabled(true);
        } finally {
          loadingRepos = false;
        }
      };

      void loadRepos();
    }
  }

  private async loadBranchSection(
    sel: HTMLSelectElement,
    token: string,
    owner: string,
    repo: string,
    currentBranch: string
  ) {
    sel.empty();
    sel.createEl("option", { text: "Loading…" });

    try {
      const branches = await GitHubAPI.fetchBranches(token, owner, repo);
      sel.empty();
      branches.forEach((b) => {
        const opt = sel.createEl("option", { text: b });
        opt.value = b;
        if (b === currentBranch) opt.selected = true;
      });
    } catch {
      sel.empty();
      sel.createEl("option", { text: "Failed to load" });
    }

    sel.addEventListener("change", async () => {
      this.plugin.settings.branch = sel.value;
      await this.plugin.saveSettings();
    });
  }

  // ── Not connected: OAuth flow via Quilden ────────────────
  private renderConnectSteps(containerEl: HTMLElement, generation: number) {
    const statusEl = containerEl.createEl("div", { cls: "setting-item-description" });
    const errorEl = containerEl.createEl("div", { cls: "setting-item-description" });

    let pollCount = 0;
    const MAX_POLLS = 100; // ~5 minutes at 3 s intervals

    const stopPolling = () => {
      this.stopActivePolling();
    };

    new Setting(containerEl)
      .setName("GitHub account")
      .setDesc("Sign in with GitHub through Quilden. You choose exactly which repositories to share.")
      .addButton((btn) =>
        btn.setButtonText("Connect with GitHub").setCta().onClick(async () => {
          stopPolling();
          pollCount = 0;
          errorEl.setText("");

          const state = Array.from(crypto.getRandomValues(new Uint8Array(18)))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");

          let githubOAuthUrl = `${QUILDEN_BASE}/api/auth/plugin-login?state=${state}`;
          try {
            const initRes = await requestUrl({
              url: `${QUILDEN_BASE}/api/auth/plugin-login?state=${state}&json=1`,
              method: "GET",
              throw: false,
            });
            if (initRes.status === 200 && initRes.json?.url) {
              githubOAuthUrl = initRes.json.url;
            }
          } catch {
            // fall back to redirect flow
          }
          if (this.renderGeneration !== generation || !containerEl.isConnected || !btn.buttonEl.isConnected) return;
          console.log("[LM] opening OAuth URL:", githubOAuthUrl);
          const authWindow = window.open(githubOAuthUrl, "_blank");
          if (!authWindow) {
            // Popup blocked — show a clickable link and still start polling
            errorEl.empty();
            errorEl.appendText("Popup blocked. ");
            const link = errorEl.createEl("a", {
              text: "Click here to sign in",
              href: githubOAuthUrl,
            });
            link.setAttr("target", "_blank");
            link.setAttr("rel", "noopener noreferrer");
          }

          btn.setDisabled(true);
          btn.setButtonText("Waiting for GitHub…");
          statusEl.setText("Complete sign-in in the browser window, then return here.");

          this.activePollingTimer = window.setInterval(async () => {
            pollCount++;
            if (pollCount > MAX_POLLS) {
              stopPolling();
              btn.setDisabled(false);
              btn.setButtonText("Connect with GitHub");
              statusEl.setText("");
              errorEl.setText("Timed out. Please try again.");
              return;
            }

            try {
              const res = await requestUrl({
                url: `${QUILDEN_BASE}/api/auth/plugin-token?state=${state}`,
                method: "GET",
              });
              if (this.renderGeneration !== generation || !containerEl.isConnected) {
                stopPolling();
                return;
              }
              const data = res.json as { status: string; token?: string; login?: string };

              if (data.status === "ok" && data.token && data.login) {
                stopPolling();
                this.plugin.settings.githubToken = data.token;
                this.plugin.settings.githubUsername = data.login;
                await this.plugin.saveSettings();
                new Notice(`Quilden Sync: Connected as @${data.login} ✓`);
                this.display();
              } else if (data.status === "expired") {
                stopPolling();
                btn.setDisabled(false);
                btn.setButtonText("Connect with GitHub");
                statusEl.setText("");
                errorEl.setText("Session expired. Please try again.");
              }
            } catch {
              // Network error — keep trying
            }
          }, 3000);
        })
      );

  }
}
