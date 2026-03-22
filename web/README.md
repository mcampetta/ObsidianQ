# ObsidianQ Web Decrypt

This is a static, GitHub Pages-friendly browser decryptor for inspecting and decrypting Secure Delivery packages.

Current scope:
- inspect Secure Delivery ZIP packages
- inspect self-extracting EXE packages by extracting the embedded ZIP payload
- decrypt password-mode Secure Delivery payloads to a plaintext bundle ZIP
- generate a self-contained offline `decrypt.html` artifact for Secure Delivery ZIP bundles

Not implemented yet:
- single-file `.obsq` decrypt flow
- vault browsing and decrypt
- direct extraction to multiple downloaded files
- server-backed approval workflows

## Local build

Prerequisites:
- Rust with `wasm-pack`
- Node.js

Commands:

```powershell
cd web
npm install
npm run dev
```

Production build:

```powershell
cd web
npm run build
npm run build:offline
```

## GitHub Pages

This app is designed as a static site. The simplest publish options are:
- deploy `web/dist` to a `gh-pages` branch
- or copy the built output under a Pages-served directory such as `docs/`

If you later publish under a repo subpath, update `vite.config.ts` `base` accordingly.
