# Acknowledgements

This project would not exist without the public work below.

## Upstream

- **woshigenm/CVE-2026-99491** — original CVE-2026-99491 research and exploit.
  https://github.com/woshigenm/CVE-2026-99491
  License: GPL-2.0-only.
- **Aoki-Shinshi/CVE-2026-99491** — public fork used as the source snapshot
  (commit `db85108f872ba673291790c0fa72d598abaadc02`), including the 5.15 EXP.
  https://github.com/Aoki-Shinshi/CVE-2026-99491
  Thanks to **青木信史 (Aoki-Shinshi)** for publishing the exploit and the
  adaptation notes.

## Infrastructure

- **KernelSU** — LKM, `ksud`, `su` and manager infrastructure.
  https://github.com/tiann/KernelSU
- **Android NDK** — build toolchain.

## HAPT

- **K' / HAPT** — host application and the separate-plugin integration model.
- HAPT testers — real-device verification of the f171 6.6.118 build, the
  boot.img profile generation path and the KernelSU manager detection fix.

## Data

- Kernel profiles and symbol tables were generated from vendor boot images
  for interoperability testing. Kernel images themselves are not included.
