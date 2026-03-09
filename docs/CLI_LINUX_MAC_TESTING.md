# Linux and macOS CLI Testing

This checklist helps validate `obsidianq` CLI behavior outside Windows.

## 1. Build

On each machine:

```bash
cargo build -p obsidianq-cli --release
```

Expected binary:

- Linux/macOS: `target/release/obsidianq`

## 2. Smoke Tests

Create a quick sample:

```bash
echo "hello obsidianq" > hello.txt
```

Password mode:

```bash
printf "StrongPass123!\n" | target/release/obsidianq encrypt --in hello.txt --out hello.obsq --password-stdin
printf "StrongPass123!\n" | target/release/obsidianq decrypt --in hello.obsq --out hello.out.txt --password-stdin
cmp hello.txt hello.out.txt
```

Key mode:

```bash
target/release/obsidianq keygen --pubkey pub.bin --privkey priv.bin
target/release/obsidianq encrypt --in hello.txt --out hello.k.obsq --pubkey pub.bin
target/release/obsidianq decrypt --in hello.k.obsq --out hello.k.out.txt --privkey priv.bin
cmp hello.txt hello.k.out.txt
```

Public identity:

```bash
target/release/obsidianq key export-public --output identity.obsqpub
target/release/obsidianq contacts import identity.obsqpub
```

## 3. Validate Common Commands

```bash
target/release/obsidianq --help
target/release/obsidianq benchmark --sizes 1
target/release/obsidianq inspect hello.obsq
```

## 4. What to Record

For each OS, capture:

- `obsidianq --version` output
- Command(s) that fail
- Error text and reproduction steps
- Whether output files decrypt correctly

## 5. CI Artifacts

A GitHub Actions workflow (`.github/workflows/cli-matrix.yml`) builds CLI binaries for:

- `ubuntu-latest`
- `macos-latest`
- `windows-latest`

On version tags (`v*`), binaries are also attached to the GitHub Release.
