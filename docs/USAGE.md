# Usage

## Requirements

- arm64 Android device
- HAPT build with the separate 99491 plugin support (1.0.49+ recommended)
- Shizuku or a working `su`
- The plugin must match the running kernel token

## Import the plugin

1. Open HAPT.
2. Go to the **99491** tab.
3. Open **手动导入 / 调试页**.
4. Select `hapt-99491-plugin-2.1.0.zip`.
5. Confirm the plugin version, profile and syms hashes are shown as ready.

## Run

1. Connect Shizuku or su.
2. Tap **运行 99491**.
3. Wait for `[+] DONE · root 已就绪`.
4. Verify with `su -c id`; expected `uid=0(root)` and `context=u:r:ksu:s0`.

If the module is already live, HAPT verifies `su` and returns immediately.
If it is not live, HAPT runs `exp99491` and loads the matching `kernelsu.ko`.

## KernelSU manager

On LKM mode, the manager needs `/data/adb/ksu/bin/ksud`. HAPT 1.0.49+ creates
this symlink after obtaining root. Without it the manager may show
“未安装” even while `su` works; this is a UI detection issue, not a failed load.

## No server

This repository does not include a server or card system. The plugin is
imported manually. Do not add private endpoints, tokens or server addresses
to this repository.

## Safety

- Only use on devices you own or are explicitly authorized to test.
- Loading a kernel module can crash or brick a device.
- Reboot removes the temporary root.
