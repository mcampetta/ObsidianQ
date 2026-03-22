import fs from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const distDir = path.join(root, "dist");
const outputDir = path.join(root, "offline");
const indexPath = path.join(distDir, "index.html");

const html = await fs.readFile(indexPath, "utf8");
const jsMatch = html.match(/<script type="module" crossorigin src="\.\/(assets\/[^"]+\.js)"><\/script>/);
const cssMatch = html.match(/<link rel="stylesheet" crossorigin href="\.\/(assets\/[^"]+\.css)">/);

if (!jsMatch || !cssMatch) {
  throw new Error("Unable to locate built JS/CSS assets in web/dist/index.html");
}

const jsPath = path.join(distDir, jsMatch[1]);
const cssPath = path.join(distDir, cssMatch[1]);

const js = await fs.readFile(jsPath, "utf8");
const css = await fs.readFile(cssPath, "utf8");

const wasmNameMatch = js.match(/obsidianq_web_bg-[A-Za-z0-9_-]+\.wasm/);
if (!wasmNameMatch) {
  throw new Error("Unable to locate wasm asset reference in built JS bundle");
}

const wasmPath = path.join(distDir, "assets", wasmNameMatch[0]);
const wasmB64 = (await fs.readFile(wasmPath)).toString("base64");

const patchedJs = js.replace(
  /x===void 0&&\(x=new URL\(""\+new URL\("obsidianq_web_bg-[A-Za-z0-9_-]+\.wasm",import\.meta\.url\)\.href,import\.meta\.url\)\);/,
  `x===void 0&&(
    typeof window<"u"&&window.__OBSQ_WASM_BASE64
      ? x=Uint8Array.from(atob(window.__OBSQ_WASM_BASE64),C=>C.charCodeAt(0))
      : x=new URL(""+new URL("${wasmNameMatch[0]}",import.meta.url).href,import.meta.url)
  );`
);

const offlineConfig = {
  title: "ObsidianQ Secure Delivery",
  eyebrow: "ObsidianQ Secure Delivery",
  heading: "Decrypt your package locally in the browser.",
  lede:
    "This tool runs entirely in your browser. No data is uploaded or transmitted. Drag the included package ZIP into this page or choose it manually, then enter the password provided separately.",
  dropTitle: "Drop package ZIP here",
  dropSubtitle: "Supports the included Secure Delivery package ZIP and password-mode .obsq files.",
  waitingStatus: "Waiting for the included package ZIP.",
  hint:
    "Secure Delivery packages are unpacked in-browser after decryption so you can download individual files. Password-mode .obsq files decrypt directly to the original file output.",
  showSampleBox: false,
  sampleHref: "",
  samplePassword: ""
};

const offlineHtml = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${offlineConfig.title}</title>
    <style>
${css}
    </style>
  </head>
  <body>
    <div id="app"></div>
    <script>
window.__OBSQ_WASM_BASE64 = "${wasmB64}";
window.__OBSQ_WEB_DECRYPT_CONFIG = ${JSON.stringify(offlineConfig)};
    </script>
    <script type="module">
${patchedJs}
    </script>
  </body>
</html>
`;

await fs.mkdir(outputDir, { recursive: true });
await fs.writeFile(path.join(outputDir, "decrypt.html"), offlineHtml, "utf8");

console.log(`offline decryptor written to ${path.join("offline", "decrypt.html")}`);
