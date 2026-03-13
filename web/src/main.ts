import "./styles.css";
import init, {
  decrypt_secure_delivery_to_bundle,
  inspect_secure_delivery
} from "../pkg/obsidianq_web.js";

type Inspection = {
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

const state: {
  bytes: Uint8Array | null;
  fileName: string;
  inspection: Inspection | null;
} = {
  bytes: null,
  fileName: "",
  inspection: null
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
        This proof of concept runs entirely client-side. Drop a Secure Delivery ZIP or
        self-extracting EXE package, inspect the metadata, then decrypt to a plaintext
        bundle ZIP without running a local executable.
      </p>
    </section>

    <section class="grid">
      <div class="card drop-card">
        <div id="dropzone" class="dropzone">
          <div>
            <p class="drop-title">Drop package here</p>
            <p class="drop-subtitle">Supported in this PoC: Secure Delivery ZIP and self-extracting EXE package</p>
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
        <button id="decryptButton" class="button" type="button" disabled>Decrypt To Bundle ZIP</button>
        <p class="hint">
          Current output is the decrypted plaintext bundle ZIP. Direct file extraction and
          single-file <code>.obsq</code> support can be layered in after this PoC.
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
  </main>
`;

const dropzone = document.querySelector<HTMLDivElement>("#dropzone")!;
const fileInput = document.querySelector<HTMLInputElement>("#fileInput")!;
const pickButton = document.querySelector<HTMLButtonElement>("#pickButton")!;
const passwordInput = document.querySelector<HTMLInputElement>("#passwordInput")!;
const decryptButton = document.querySelector<HTMLButtonElement>("#decryptButton")!;
const statusEl = document.querySelector<HTMLParagraphElement>("#status")!;
const outputEl = document.querySelector<HTMLElement>("#inspectionOutput")!;
const fileNameLabel = document.querySelector<HTMLElement>("#fileNameLabel")!;

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
    setStatus("Decrypting package in browser...");
    try {
      const plainBundle = decrypt_secure_delivery_to_bundle(state.bytes, password);
      const outName = `${sanitizeBaseName(state.inspection.packageName || state.fileName)}_decrypted_bundle.zip`;
      downloadBytes(plainBundle, outName, "application/zip");
      setStatus("Decryption complete. Plaintext bundle ZIP downloaded.");
    } catch (error) {
      setStatus(asMessage(error), true);
    } finally {
      decryptButton.disabled = false;
    }
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
    decryptButton.disabled = false;
    fileNameLabel.textContent = file.name;
    outputEl.textContent = renderInspection(file.name, inspection);
    setStatus("Package inspection complete.");
  } catch (error) {
    state.bytes = null;
    state.fileName = "";
    state.inspection = null;
    decryptButton.disabled = true;
    fileNameLabel.textContent = "No file loaded";
    outputEl.textContent = "Drop a package to inspect it.";
    setStatus(asMessage(error), true);
  }
}

function renderInspection(fileName: string, inspection: Inspection): string {
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
  lines.push(`${inspection.verification.packageSignatureValid ? "✓" : "X"} ${inspection.signed ? "Package signature valid" : "Package is not signed"}`);
  lines.push(`${inspection.verification.signingIdentityPresent ? "✓" : "X"} ${inspection.verification.signingIdentityPresent ? "Signing identity present" : "Signing identity missing"}`);
  lines.push(`${inspection.verification.contentsMatchManifest ? "✓" : "X"} ${inspection.verification.contentsMatchManifest ? "Contents match manifest" : "Contents do not match manifest"}`);
  lines.push(`${inspection.verification.noTamperingDetected ? "✓" : "X"} ${inspection.verification.noTamperingDetected ? "No tampering detected" : "Tampering or verification failure detected"}`);

  if (inspection.verification.error) {
    lines.push("");
    lines.push(`Error: ${inspection.verification.error}`);
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

function sanitizeBaseName(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) {
    return "package";
  }
  return trimmed.replace(/[<>:"/\\|?*]+/g, "_");
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
