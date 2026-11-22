#ifndef KSU_BOOT_H
#define KSU_BOOT_H

/*
 * KernelSU bootstrap for the 5.15 endgame.
 *
 * The caller runs with fsuid 0 and the patched capability set while the
 * parent's AVC grant holds the shell domain's setenforce decision open,
 * so Enforcing is 0 for the finit_module call and restored right after.
 * The module is already patched by the parent (the loader's fsuid 0
 * cannot create files in /data/local/tmp); the load then skips the
 * ksu_file label, which does not exist before KernelSU is live.
 *
 * Returns 0 when the module is live and the ksud userspace was installed.
 */
int ksu_boot_inline(unsigned long long slide, const char *syms_path);

/* Patch the KernelSU module for this boot into /data/local/tmp without
 * loading it.  The caller must still have a writable fsuid on that
 * directory; the loader later reuses the file. */
int ksu_preprepare_module(unsigned long long slide, const char *syms_path);

#endif
