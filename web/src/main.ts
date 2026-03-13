import JSZip from "jszip";
import "./styles.css";
import init, {
  decrypt_secure_delivery_to_bundle,
  inspect_secure_delivery
} from "../pkg/obsidianq_web.js";

type Inspection = {
  kind: string;
  containerType: string;
  schemaVersion: number;
  packageId?: string | null;
  createdUtc: string;
  obsidianqVersion?: string | null;
  packageName: string;
  recipientMode?: string | null;
  packageFormat: string;
  sourceItemCount: number;
  sourceTotalBytes: number;
  hasInstructions: boolean;
  payloadSha256: string;
  signed: boolean;
  signingIdentity?: string | null;
  signingFingerprint?: string | null;
  signingEmail?: string | null;
  signingDevice?: string | null;
  signatureAlgorithm?: string | null;
  files: Array<{ path: string; size: number; sha256: string }>;
  verification: {
    packageSignatureValid: boolean;
    signingIdentityPresent: boolean;
    contentsMatchManifest: boolean;
    noTamperingDetected: boolean;
    error?: string | null;
  };
};

type DecryptedEntry = {
  path: string;
  data: Uint8Array;
  mime: string;
  kind: "text" | "image" | "binary";
};

const state: {
  bytes: Uint8Array | null;
  fileName: string;
  inspection: Inspection | null;
  decryptedEntries: DecryptedEntry[];
} = {
  bytes: null,
  fileName: "",
  inspection: null,
  decryptedEntries: []
};

const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("Missing app root.");
}

app.innerHTML = `
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">ObsidianQ Web Decrypt PoC</p>
      <h1>Inspect and decrypt Secure Delivery packages in the browser.</h1>
      <p class="lede">
        This proof of concept runs entirely client-side. Drop a Secure Delivery ZIP,
        self-extracting EXE package, or a password-mode <code>.obsq</code> file to inspect it and
        decrypt locally without running a desktop executable.
      </p>
    </section>

    <section class="grid">
      <div class="card drop-card">
        <div id="dropzone" class="dropzone">
          <div>
            <p class="drop-title">Drop package here</p>
            <p class="drop-subtitle">Supported in this PoC: Secure Delivery ZIP, self-extracting EXE package, and password-mode .obsq files</p>
            <button id="pickButton" class="button secondary" type="button">Choose File</button>
            <input id="fileInput" type="file" hidden />
          </div>
        </div>
        <p id="status" class="status">Waiting for a package.</p>
      </div>

      <div class="card action-card">
        <div class="sample-box">
          <p class="sample-title">Need a test package?</p>
          <p class="sample-copy">
            <a class="sample-link" href="./WebDecryptSample_v2_SecureDelivery.zip">Download sample package</a>
            <span>Password: <code>obsidianq-demo</code></span>
          </p>
        </div>
        <label class="field">
          <span>Password</span>
          <input id="passwordInput" type="password" placeholder="Enter package password" />
        </label>
        <button id="decryptButton" class="button" type="button" disabled>Decrypt</button>
        <button id="downloadBundleButton" class="button secondary" type="button" disabled>Download Decrypted Output</button>
        <p class="hint">
          Secure Delivery packages are unpacked in-browser after decryption so you can download
          individual files. Password-mode <code>.obsq</code> files decrypt directly to the original file output.
        </p>
      </div>
    </section>

    <section class="card results-card">
      <div class="section-head">
        <h2>Package Inspection</h2>
        <span id="fileNameLabel" class="chip">No file loaded</span>
      </div>
      <pre id="inspectionOutput" class="output">Drop a package to inspect it.</pre>
    </section>

    <section class="card decrypted-card">
      <div class="section-head">
        <h2>Decrypted Contents</h2>
        <span id="decryptedSummary" class="chip">Nothing decrypted yet</span>
      </div>
      <div id="decryptedEmpty" class="empty-state">Decrypt a file or package to browse its contents here.</div>
      <div id="decryptedPane" class="decrypted-pane hidden">
        <div id="decryptedList" class="decrypted-list"></div>
        <div id="previewPane" class="preview-pane">
          <p class="preview-empty">Select a decrypted entry to preview it.</p>
        </div>
      </div>
    </section>
  </main>
`;

const dropzone = document.querySelector<HTMLDivElement>("#dropzone")!;
const fileInput = document.querySelector<HTMLInputElement>("#fileInput")!;
const pickButton = document.querySelector<HTMLButtonElement>("#pickButton")!;
const passwordInput = document.querySelector<HTMLInputElement>("#passwordInput")!;
const decryptButton = document.querySelector<HTMLButtonElement>("#decryptButton")!;
const downloadBundleButton = document.querySelector<HTMLButtonElement>("#downloadBundleButton")!;
const statusEl = document.querySelector<HTMLParagraphElement>("#status")!;
const outputEl = document.querySelector<HTMLElement>("#inspectionOutput")!;
const fileNameLabel = document.querySelector<HTMLElement>("#fileNameLabel")!;
const decryptedSummary = document.querySelector<HTMLElement>("#decryptedSummary")!;
const decryptedEmpty = document.querySelector<HTMLElement>("#decryptedEmpty")!;
const decryptedPane = document.querySelector<HTMLElement>("#decryptedPane")!;
const decryptedList = document.querySelector<HTMLElement>("#decryptedList")!;
const previewPane = document.querySelector<HTMLElement>("#previewPane")!;

let lastRawOutput: Uint8Array | null = null;
let activePreviewUrl: string | null = null;

void bootstrap();

async function bootstrap(): Promise<void> {
  await init();

  pickButton.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    if (file) {
      await loadFile(file);
    }
  });

  decryptButton.addEventListener("click", async () => {
    if (!state.bytes || !state.inspection) {
      return;
    }
    const password = passwordInput.value;
    if (!password) {
      setStatus("Password is required.", true);
      return;
    }

    decryptButton.disabled = true;
    setStatus("Decrypting in browser...");
    try {
    const rawOutput = decrypt_secure_delivery_to_bundle(state.bytes, password);
      lastRawOutput = rawOutput;
      downloadBundleButton.disabled = false;
      updateDownloadButtonLabel(state.inspection);
      await hydrateDecryptedOutput(rawOutput, state.inspection, state.fileName);
      setStatus("Decryption complete.");
    } catch (error) {
      lastRawOutput = null;
      downloadBundleButton.disabled = true;
      clearDecryptedPane();
      setStatus(asMessage(error), true);
    } finally {
      decryptButton.disabled = false;
    }
  });

  downloadBundleButton.addEventListener("click", () => {
    if (!lastRawOutput || !state.inspection) {
      return;
    }
    const outName = state.inspection.kind === "obsq"
      ? defaultObsqOutputName(state.fileName)
      : `${sanitizeBaseName(state.inspection.packageName || state.fileName)}_decrypted_bundle.zip`;
    const mime = state.inspection.kind === "obsq"
      ? makeEntry(outName, lastRawOutput).mime
      : "application/zip";
    downloadBytes(lastRawOutput, outName, mime);
  });

  for (const eventName of ["dragenter", "dragover"]) {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.add("active");
    });
  }

  for (const eventName of ["dragleave", "drop"]) {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.remove("active");
    });
  }

  dropzone.addEventListener("drop", async (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (file) {
      await loadFile(file);
    }
  });
}

async function loadFile(file: File): Promise<void> {
  setStatus("Reading package...");
  const bytes = new Uint8Array(await file.arrayBuffer());
  try {
    const inspection = inspect_secure_delivery(bytes) as Inspection;
    state.bytes = bytes;
    state.fileName = file.name;
    state.inspection = inspection;
    state.decryptedEntries = [];
    lastRawOutput = null;
    decryptButton.disabled = false;
    downloadBundleButton.disabled = true;
    updateDownloadButtonLabel(inspection);
    fileNameLabel.textContent = file.name;
    outputEl.textContent = renderInspection(file.name, inspection);
    clearDecryptedPane();
    setStatus(inspection.verification.error ?? "Package inspection complete.", Boolean(inspection.verification.error));
  } catch (error) {
    state.bytes = null;
    state.fileName = "";
    state.inspection = null;
    state.decryptedEntries = [];
    lastRawOutput = null;
    decryptButton.disabled = true;
    downloadBundleButton.disabled = true;
    updateDownloadButtonLabel(null);
    fileNameLabel.textContent = "No file loaded";
    outputEl.textContent = "Drop a package to inspect it.";
    clearDecryptedPane();
    setStatus(asMessage(error), true);
  }
}

async function hydrateDecryptedOutput(rawOutput: Uint8Array, inspection: Inspection, fileName: string): Promise<void> {
  if (inspection.kind === "obsq") {
    const entryName = stripObsQExtension(fileName) || "decrypted-output.bin";
    const entry = makeEntry(entryName, rawOutput);
    state.decryptedEntries = [entry];
    renderDecryptedPane(entryName);
    return;
  }

  const zip = await JSZip.loadAsync(rawOutput);
  const entries: DecryptedEntry[] = [];
  const paths = Object.keys(zip.files).sort((a, b) => a.localeCompare(b));
  for (const path of paths) {
    const file = zip.files[path];
    if (file.dir) {
      continue;
    }
    const data = await file.async("uint8array");
    entries.push(makeEntry(path, data));
  }
  state.decryptedEntries = entries;
  renderDecryptedPane(inspection.packageName || fileName);
}

function renderDecryptedPane(contextName: string): void {
  decryptedList.innerHTML = "";
  previewPane.innerHTML = `<p class="preview-empty">Select a decrypted entry to preview it.</p>`;

  if (state.decryptedEntries.length === 0) {
    clearDecryptedPane();
    setStatus(`Decryption succeeded, but no files were found in ${contextName}.`, true);
    return;
  }

  decryptedEmpty.classList.add("hidden");
  decryptedPane.classList.remove("hidden");
  decryptedSummary.textContent = `${state.decryptedEntries.length} decrypted file${state.decryptedEntries.length === 1 ? "" : "s"}`;

  state.decryptedEntries.forEach((entry, index) => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "decrypted-item";
    item.innerHTML = `
      <span>
        <span class="decrypted-name">${escapeHtml(entry.path)}</span>
        <span class="decrypted-meta">${formatBytes(entry.data.byteLength)}</span>
      </span>
    `;
    item.addEventListener("click", () => {
      document.querySelectorAll(".decrypted-item.active").forEach((el) => el.classList.remove("active"));
      item.classList.add("active");
      renderPreview(entry);
    });
    const dl = document.createElement("button");
    dl.type = "button";
    dl.className = "mini-button";
    dl.textContent = "Download";
    dl.addEventListener("click", (event) => {
      event.stopPropagation();
      downloadBytes(entry.data, entry.path.split("/").pop() || entry.path, entry.mime);
    });
    item.appendChild(dl);
    decryptedList.appendChild(item);

    if (index === 0) {
      item.classList.add("active");
      renderPreview(entry);
    }
  });
}

function renderPreview(entry: DecryptedEntry): void {
  if (activePreviewUrl) {
    URL.revokeObjectURL(activePreviewUrl);
    activePreviewUrl = null;
  }

  const header = `
    <div class="preview-head">
      <strong>${escapeHtml(entry.path)}</strong>
      <span>${formatBytes(entry.data.byteLength)}</span>
    </div>
  `;

  if (entry.kind === "image") {
    const url = URL.createObjectURL(new Blob([entry.data], { type: entry.mime }));
    activePreviewUrl = url;
    previewPane.innerHTML = `${header}<img class="preview-image" src="${url}" alt="${escapeHtml(entry.path)}">`;
    return;
  }

  if (entry.kind === "text") {
    const text = new TextDecoder().decode(entry.data);
    previewPane.innerHTML = `${header}<pre class="preview-text">${escapeHtml(text)}</pre>`;
    return;
  }

  previewPane.innerHTML = `
    ${header}
    <div class="preview-binary">
      <p>No inline preview for this file type.</p>
      <button id="previewDownload" class="button secondary" type="button">Download File</button>
    </div>
  `;
  previewPane.querySelector<HTMLButtonElement>("#previewDownload")?.addEventListener("click", () => {
    downloadBytes(entry.data, entry.path.split("/").pop() || entry.path, entry.mime);
  });
}

function clearDecryptedPane(): void {
  if (activePreviewUrl) {
    URL.revokeObjectURL(activePreviewUrl);
    activePreviewUrl = null;
  }
  state.decryptedEntries = [];
  decryptedList.innerHTML = "";
  previewPane.innerHTML = `<p class="preview-empty">Select a decrypted entry to preview it.</p>`;
  decryptedEmpty.classList.remove("hidden");
  decryptedPane.classList.add("hidden");
  decryptedSummary.textContent = "Nothing decrypted yet";
}

function makeEntry(path: string, data: Uint8Array): DecryptedEntry {
  const lower = path.toLowerCase();
  if (/\.(txt|md|json|csv|xml|log|ini|yaml|yml|html|htm)$/i.test(lower)) {
    return { path, data, mime: "text/plain", kind: "text" };
  }
  if (/\.(png|jpg|jpeg|gif|webp|bmp|svg)$/i.test(lower)) {
    return {
      path,
      data,
      mime: lower.endsWith(".png")
        ? "image/png"
        : lower.endsWith(".gif")
          ? "image/gif"
          : lower.endsWith(".webp")
            ? "image/webp"
            : lower.endsWith(".bmp")
              ? "image/bmp"
              : lower.endsWith(".svg")
                ? "image/svg+xml"
                : "image/jpeg",
      kind: "image"
    };
  }
  return { path, data, mime: "application/octet-stream", kind: "binary" };
}

function renderInspection(fileName: string, inspection: Inspection): string {
  const mark = (ok: boolean): string => ok ? "\u2713" : "X";

  const lines: string[] = [
    `Path: ${fileName}`,
    `Container: ${inspection.containerType}`,
    `Schema version: ${inspection.schemaVersion}`,
    `Package ID: ${inspection.packageId ?? "-"}`,
    `Created: ${inspection.createdUtc}`,
    `Created by version: ${inspection.obsidianqVersion ?? "-"}`,
    `Package name: ${inspection.packageName}`,
    `Recipient mode: ${inspection.recipientMode ?? "-"}`,
    `Package format: ${inspection.packageFormat}`,
    `Source item count: ${inspection.sourceItemCount}`,
    `Source total bytes: ${inspection.sourceTotalBytes}`,
    `Has instructions: ${inspection.hasInstructions}`,
    `Payload SHA-256: ${inspection.payloadSha256}`,
    `Signed: ${inspection.signed}`,
    `Signing identity: ${inspection.signingIdentity ?? "-"}`,
    `Signing fingerprint: ${inspection.signingFingerprint ?? "-"}`,
    `Signature algorithm: ${inspection.signatureAlgorithm ?? "-"}`,
    ""
  ];

  if (inspection.files.length > 0) {
    lines.push("Files:");
    for (const file of inspection.files) {
      lines.push(`- ${file.path}`);
    }
    lines.push("");
  }

  lines.push("Verification:");
  lines.push(`${mark(inspection.verification.packageSignatureValid)} ${inspection.signed ? "Package signature valid" : "Package is not signed"}`);
  lines.push(`${mark(inspection.verification.signingIdentityPresent)} ${inspection.verification.signingIdentityPresent ? "Signing identity present" : "Signing identity missing"}`);
  lines.push(`${mark(inspection.verification.contentsMatchManifest)} ${inspection.verification.contentsMatchManifest ? "Contents match manifest" : "Contents do not match manifest"}`);
  lines.push(`${mark(inspection.verification.noTamperingDetected)} ${inspection.verification.noTamperingDetected ? "No tampering detected" : "Tampering or verification failure detected"}`);

  if (inspection.verification.error) {
    lines.push("");
    lines.push(`Note: ${inspection.verification.error}`);
  }

  return lines.join("\n");
}

function downloadBytes(bytes: Uint8Array, fileName: string, mimeType: string): void {
  const blob = new Blob([bytes], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function updateDownloadButtonLabel(inspection: Inspection | null): void {
  if (!inspection) {
    downloadBundleButton.textContent = "Download Decrypted Output";
    return;
  }
  downloadBundleButton.textContent = inspection.kind === "obsq"
    ? "Download Decrypted File"
    : "Download Decrypted ZIP";
}

function sanitizeBaseName(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) {
    return "package";
  }
  return trimmed.replace(/[<>:"/\\|?*]+/g, "_");
}

function stripObsQExtension(input: string): string {
  return input.replace(/\.obsq$/i, "");
}

function defaultObsqOutputName(input: string): string {
  const stripped = sanitizeBaseName(stripObsQExtension(input));
  if (!stripped) {
    return "decrypted-output";
  }
  return stripped;
}

function setStatus(message: string, isError = false): void {
  statusEl.textContent = message;
  statusEl.classList.toggle("error", isError);
}

function asMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function escapeHtml(input: string): string {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;");
}
