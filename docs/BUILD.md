# Build

## Requirements

- Linux x86_64 build host
- Android NDK r29
- `make`
- Python 3.10+
- `zip` / standard Python `zipfile`

## Build `exp99491`

```sh
export NDK=/path/to/android-ndk-r29
make build/exp
```

Expected output: `build/exp` (arm64, API 24), sha256
`a692f1a712352776ad903d80c53a0b78161b30c245e74d6f0d2027dc830da67f`,
size 187352.

The exact toolchain used for the published binary:

```text
NDK=android-ndk-r29 API=24 ARCH=arm64
```

## Build the plugin ZIP

```sh
python3 tools/pack_plugin.py \
  --exp build/exp \
  --profiles profiles \
  --index profiles/index.tsv \
  --out dist/hapt-99491-plugin-2.1.0.zip \
  --source-url https://github.com/FatBrother1/hapt-99491 \
  --source-asset CVE-2026-99491-source-20261122.tar.gz \
  --source-sha 51f94975624dc99ab404b6127d11241689407faa3092ae9cc32c38e815e70130
```

Optional: `--per-kernel-out dist/per-kernel` builds one ZIP per token.

## Verify

```sh
sha256sum dist/hapt-99491-plugin-2.1.0.zip
unzip -l dist/hapt-99491-plugin-2.1.0.zip
python3 -m zipfile -t dist/hapt-99491-plugin-2.1.0.zip
```

The ZIP must contain `LICENSE`, `SOURCE-OFFER.txt`, `MANIFEST.tsv`,
`kernels.tsv`, `plugin.json`, `exp99491`, and one
`kernels/<token>/{profile,syms}` per token.

## No network

The build does not require a server, card key, or network access. Do not add
private endpoints or secrets to this repository.
