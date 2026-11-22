# Changelog

## 2.1.0 — 2026-11-22

- Public GPL-2.0-only release.
- 39 kernel profiles (f171 verified-local, 37 static, 1 static-ref).
- Multi-kernel plugin ZIP and per-kernel ZIP bundle.
- Source offer points to this repository, not a private server.
- Upstream attribution: woshigenm/CVE-2026-99491 and
  Aoki-Shinshi/CVE-2026-99491 (青木信史).

## 2.1.1 — 2026-11-22

- Fix the fresh-boot userspace stage: keep the SELinux permissive window
  open through ksud copy/install. The exploit child runs in u:r:shell:s0;
  under enforcing it cannot search /data/adb (`adb_data_file`), so
  `ensure_ksud()` failed with EACCES and `GRANT_ROOT` never ran. This hit
  every flavor on a boot with no pre-existing `/data/adb/ksud`.
- exp99491 rebuilt: sha256 `26f0d82847c2504cfd4cfa5d495a63fe2488b486d955ef5d68fda9ff4f0dffce`
  (187,160 B).
