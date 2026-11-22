# hapt-99491

**CVE-2026-99491 HAPT plugin — GPL-2.0-only**

This repository is the open-source, separately distributed component used by
HAPT for CVE-2026-99491. It contains the exploit source, 48 kernel profiles,
and a prebuilt plugin ZIP. It does **not** contain the HAPT host application,
its card system, or any private server.

## What is included

| Path | Content |
|---|---|
| `src/` | Complete source used to build `exp99491` (`exp.c`, `ko_patch.c`, `ksu_boot.c/.h`, `vuln_precheck.h`, `ko_syms_5.15.178.txt`) |
| `profiles/` | 48 per-kernel `profile` + `syms` (one directory per kernel token) |
| `profiles/index.tsv` | release / token / status mapping |
| `dist/` | Prebuilt `hapt-99491-plugin-2.1.2.zip`, source tarball, checksums |
| `tools/pack_plugin.py` | Reproducible plugin ZIP builder |
| `docs/` | Profile format, build, usage |

## What is NOT included

- HAPT host APK or its source (closed source).
- HAPT server, card-key system, or any private endpoint.
- KernelSU source or vendor kernel images.
- Any device-specific secret, token, key, or server address.

The plugin is executed by HAPT as a separate component. HAPT does not link or
include this source.

## Attribution and thanks

This work is based on the public CVE-2026-99491 research and exploit:

- **Original upstream:** [woshigenm/CVE-2026-99491](https://github.com/woshigenm/CVE-2026-99491) — GPL-2.0-only
- **Source snapshot used here:** [Aoki-Shinshi/CVE-2026-99491](https://github.com/Aoki-Shinshi/CVE-2026-99491), commit `db85108f872ba673291790c0fa72d598abaadc02`
- **Thanks to 青木信史 (Aoki-Shinshi)** for the public 5.15 EXP and the adaptation work.
- **Thanks to woshigenm** for the original upstream research and exploit.
- **Thanks to the KernelSU project** for the LKM/ksud/su infrastructure.
- Thanks to the HAPT testers who verified the f171 6.6.118 build on real hardware.

See [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md) and [NOTICE](NOTICE).

## Compatibility

- ABI: `arm64-v8a`
- Plugin version: `2.1.2`
- 48 kernel tokens: 1 `verified-local` (Honor PTP-AN70 / 6.6.118-gf171), 46 `static`, 1 `static-ref`
- 5.10 is not supported (no BTF; upstream does not publish 5.x profiles).
- The plugin must match the running kernel token. Do not force a profile from
  another build.

## Use with HAPT

1. Install a HAPT build that supports the separate 99491 plugin (1.0.49+ recommended).
2. Open the **99491** tab → **手动导入 / 调试页**.
3. Import `dist/hapt-99491-plugin-2.1.2.zip`.
4. Connect Shizuku or su, then run.

The plugin ZIP contains `LICENSE` and `SOURCE-OFFER.txt`. There is no server
address or card key in this repository.

## Build

See [docs/BUILD.md](docs/BUILD.md). Short version:

```sh
# Build exp99491 with Android NDK r29, arm64, API 24
make build/exp

# Rebuild the plugin ZIP from source/profiles
python3 tools/pack_plugin.py \
  --exp build/exp \
  --profiles profiles \
  --index profiles/index.tsv \
  --out dist/hapt-99491-plugin-2.1.2.zip \
  --source-url https://github.com/FatBrother1/hapt-99491
```

## Security and license

- For authorized security testing and research on devices you own or are
  explicitly permitted to test. Do not use against third-party devices.
- GPL-2.0-only. See [LICENSE](LICENSE).
- No warranty. Flashing/loading kernel modules can brick a device.
- This project is not affiliated with Honor, KernelSU, or the upstream authors.

## Source offer

The complete corresponding source is this repository and the release asset
`CVE-2026-99491-source-20261122.tar.gz` (sha256
`51f94975624dc99ab404b6127d11241689407faa3092ae9cc32c38e815e70130`).
See [SOURCE-OFFER.md](SOURCE-OFFER.md).
