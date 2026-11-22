# Profile format

A profile is a text `key=value` file for one kernel build. Comments start with
`#`; the body is what matters.

## Fields

| Field | Meaning |
|---|---|
| `worker_link` | kernel address anchor |
| `kaslr_idx` | KASLR leak index |
| `trace_layout` | trace structure layout version |
| `dev_evbit` / `dev_swbit` / `dev_sw` | wacom device offsets |
| `dev_num_vals` / `dev_max_vals` / `dev_vals` | `vals` offsets |
| `cred_req` | cred request size |
| `blob_req_min` / `blob_req_max` | heap spray blob sizes |
| `avc_req` | AVC request size |
| `cred_euid_off` | euid offset in `cred` |
| `cred_cap1/2/3` | capability offsets |
| `cred_fsuid_off` | fsuid offset |
| `min_pairs` | minimum pairs |
| `cred_site_low21` / `blob_site_low21` / `avc_site_low21` | low-21-bit call-site hints |

## cred offset by kernel family

| Kernel | `cred_euid_off` |
|---|---|
| 5.10 / 5.15 / 6.1 | `0x10` |
| 6.6 / 6.12 / 6.18 | `0x14` |

Using `0x18` on 6.6 produces euid `0x000E0005`, not 0.

## Status values

- `verified-local` — verified on a real device for this exact kernel build.
- `static` — generated from a boot image / symbols, not device-verified.
- `static-ref` — static reference profile.

Only the exact kernel token should be used. A profile from another build can
crash or fail to get root.

## `syms`

`kernels/<token>/syms` is the symbol table for that kernel build. It is paired
with the profile and must be updated together.
