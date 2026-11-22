#!/usr/bin/env python3
"""Build the GPL-2.0 CVE-2026-99491 plugin ZIP from source/profiles.

The output contains no server address, card key, or private endpoint.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

PLUGIN_ID = "cve-2026-99491"
PLUGIN_NAME = "CVE-2026-99491 HAPT plugin"
EXPECTED_EXP_SHA = "26f0d82847c2504cfd4cfa5d495a63fe2488b486d955ef5d68fda9ff4f0dffce"
EXPECTED_EXP_SIZE = 187160
UPSTREAM = "https://github.com/woshigenm/CVE-2026-99491"
SNAPSHOT = "https://github.com/Aoki-Shinshi/CVE-2026-99491"
SNAPSHOT_COMMIT = "db85108f872ba673291790c0fa72d598abaadc02"
ZIP_DATE = (2026, 11, 22, 0, 0, 0)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_index(path: Path) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise SystemExit(f"bad index row: {line!r}")
        release, token, status = parts
        if status not in {"verified-local", "static", "static-ref"}:
            raise SystemExit(f"bad status: {status!r}")
        rows.append((release, token, status))
    if not rows:
        raise SystemExit("empty index")
    return rows


def source_offer(source_url: str, source_asset: str, source_sha: str) -> str:
    return (
        "CVE-2026-99491 component - source offer\n"
        "\n"
        "This separately distributed plugin ZIP contains the executable\n"
        "exp99491 for CVE-2026-99491, derived from\n"
        f"{UPSTREAM} (GPL-2.0-only), with the public adaptation snapshot at\n"
        f"{SNAPSHOT} (commit {SNAPSHOT_COMMIT}).\n"
        "\n"
        "It is NOT bundled inside the HAPT APK; the user imports this ZIP as a\n"
        "separate GPL-2.0 plugin. HAPT only executes it and does not link or\n"
        "include this source.\n"
        "\n"
        "Corresponding source:\n"
        f"  Repository: {source_url}\n"
        f"  Release asset: {source_asset}\n"
        f"  SHA-256: {source_sha}\n"
        "\n"
        "The source tree contains the complete source used to build exp99491\n"
        "(exp.c, ko_patch.c, ksu_boot.c/.h, vuln_precheck.h,\n"
        "ko_syms_5.15.178.txt), GPL-2.0 LICENSE, Makefile and BUILD-INFO.\n"
        "\n"
        "License: GPL-2.0-only. The full license text is in LICENSE in this ZIP.\n"
        "\n"
        "GPL-2.0 permits copying, modification and redistribution of this plugin\n"
        "and its corresponding source. No card key or private server is required\n"
        "to build this source.\n"
    )


def zip_write(zip_path: Path, files: list[tuple[str, bytes, int]]) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = zip_path.with_suffix(zip_path.suffix + ".tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for name, data, mode in files:
            info = zipfile.ZipInfo(name, ZIP_DATE)
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    tmp.replace(zip_path)


def build(
    out: Path,
    exp: Path,
    license_path: Path,
    profiles: Path,
    rows: list[tuple[str, str, str]],
    version: str,
    source_url: str,
    source_asset: str,
    source_sha: str,
) -> dict:
    exp_bytes = exp.read_bytes()
    exp_sha = sha256_bytes(exp_bytes)
    if exp_sha != EXPECTED_EXP_SHA or len(exp_bytes) != EXPECTED_EXP_SIZE:
        raise SystemExit(
            f"exp99491 mismatch: sha={exp_sha} size={len(exp_bytes)}; "
            f"expected {EXPECTED_EXP_SHA} / {EXPECTED_EXP_SIZE}"
        )
    license_bytes = license_path.read_bytes()
    if b"GNU GENERAL PUBLIC LICENSE" not in license_bytes:
        raise SystemExit("LICENSE does not look like GPL text")

    entries: list[tuple[str, bytes, int]] = []
    kernels = ["# release\ttoken\tstatus\tprofilePath\tprofileSha\tsymsPath\tsymsSha"]
    for release, token, status in rows:
        prof = profiles / token / "profile"
        syms = profiles / token / "syms"
        if not prof.is_file() or not syms.is_file():
            raise SystemExit(f"missing profile/syms for {token}")
        pbytes = prof.read_bytes()
        sbytes = syms.read_bytes()
        if not pbytes.strip() or not sbytes.strip():
            raise SystemExit(f"empty profile/syms for {token}")
        psha = sha256_bytes(pbytes)
        ssha = sha256_bytes(sbytes)
        entries.append((f"kernels/{token}/profile", pbytes, 0o644))
        entries.append((f"kernels/{token}/syms", sbytes, 0o644))
        kernels.append(
            f"{release}\t{token}\t{status}\tkernels/{token}/profile\t{psha}"
            f"\tkernels/{token}/syms\t{ssha}"
        )

    plugin_json = {
        "id": PLUGIN_ID,
        "name": PLUGIN_NAME,
        "version": version,
        "abi": "arm64-v8a",
        "kernel": "multi",
        "license": "GPL-2.0-only",
        "source": source_asset,
    }
    files = [
        ("LICENSE", license_bytes, 0o644),
        ("MANIFEST.tsv", f"{exp_sha}\t755\t{len(exp_bytes)}\texp99491\n".encode(), 0o644),
        ("SOURCE-OFFER.txt", source_offer(source_url, source_asset, source_sha).encode(), 0o644),
        ("exp99491", exp_bytes, 0o755),
        ("kernels.tsv", ("\n".join(kernels) + "\n").encode(), 0o644),
        ("plugin.json", (json.dumps(plugin_json, ensure_ascii=False, indent=2) + "\n").encode(), 0o644),
    ] + entries
    zip_write(out, files)
    return {
        "out": str(out),
        "sha256": sha256_file(out),
        "size": out.stat().st_size,
        "tokens": len(rows),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", type=Path, required=True)
    ap.add_argument("--license", type=Path, default=Path("LICENSE"))
    ap.add_argument("--profiles", type=Path, required=True)
    ap.add_argument("--index", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--per-kernel-out", type=Path)
    ap.add_argument("--version", default="2.1.0")
    ap.add_argument("--source-url", default="https://github.com/FatBrother1/hapt-99491")
    ap.add_argument("--source-asset", default="CVE-2026-99491-source-20261122.tar.gz")
    ap.add_argument(
        "--source-sha",
        default="51f94975624dc99ab404b6127d11241689407faa3092ae9cc32c38e815e70130",
    )
    args = ap.parse_args()

    rows = read_index(args.index)
    result = build(
        args.out, args.exp, args.license, args.profiles, rows, args.version,
        args.source_url, args.source_asset, args.source_sha,
    )
    print(json.dumps(result, ensure_ascii=False))

    if args.per_kernel_out:
        args.per_kernel_out.mkdir(parents=True, exist_ok=True)
        for release, token, status in rows:
            one = build(
                args.per_kernel_out / f"{token}.zip",
                args.exp, args.license, args.profiles, [(release, token, status)],
                args.version, args.source_url, args.source_asset, args.source_sha,
            )
            print(json.dumps(one, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
