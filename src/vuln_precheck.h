/*
 * Vulnerability and environment pre-check.
 *
 * Add the exact tested kernel release(s) to vuln_precheck_known[].  A release
 * that is not listed is treated as unconfirmed and the program refuses to run
 * unless --force (or VULN_FORCE=1) is given.
 *
 * This is a profile gate, not a runtime probe.  A probe that reaches the
 * vulnerable path can itself leave destructive kernel state behind.
 *
 * The header is self-contained so each binary can include it directly.
 */
#ifndef VULN_PRECHECK_H
#define VULN_PRECHECK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

#define VULN_TRACEFS "/sys/kernel/tracing"

/* Returned for --check: the caller exits without running the exploit. */
#define VULN_PRECHECK_EXIT_OK   100
#define VULN_PRECHECK_EXIT_FAIL 101

static const char *const vuln_precheck_known[] = {
    /* Tested release: redmi-k70-vermeer 5.15.178 vendor build. */
    "5.15.178-android13-8-00021-g6f2f96be86b9-ab13729987",
    NULL,
};

static int vuln_precheck_flag(int argc, char **argv, const char *flag)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], flag))
            return 1;
    }
    return 0;
}

static int vuln_precheck_force(int argc, char **argv)
{
    const char *env = getenv("VULN_FORCE");

    if (env && *env && strcmp(env, "0"))
        return 1;
    return vuln_precheck_flag(argc, argv, "--force");
}

static int vuln_precheck_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

static int vuln_precheck_readable(const char *path)
{
    return access(path, R_OK) == 0;
}

static int vuln_precheck_writable(const char *path)
{
    return access(path, W_OK) == 0;
}

static int vuln_precheck_read_int(const char *path)
{
    FILE *f = fopen(path, "r");
    int v = -1;

    if (!f)
        return -1;
    if (fscanf(f, "%d", &v) != 1)
        v = -1;
    fclose(f);
    return v;
}

static int vuln_precheck(const char *who, int argc, char **argv,
                         int need_tracefs, int fake_cred_chain)
{
    struct utsname u;
    const char *release = "?";
    const char *machine = "?";
    const char *build = "?";
    const char *verdict;
    long page = sysconf(_SC_PAGESIZE);
    int force = vuln_precheck_force(argc, argv);
    int check_only = vuln_precheck_flag(argc, argv, "--check");
    int known = 0;
    int blocked = 0;
    int ok;
    int i;

    if (uname(&u) == 0) {
        release = u.release;
        machine = u.machine;
        build = u.version;
    }
    for (i = 0; vuln_precheck_known[i]; i++) {
        if (!strcmp(release, vuln_precheck_known[i])) {
            known = 1;
            break;
        }
    }

    printf("[precheck] %s: release=%s machine=%s page=%ld uid=%d euid=%d\n",
           who, release, machine, page, (int)getuid(), (int)geteuid());
    printf("[precheck] build: %s\n", build);
    printf("[precheck] profile: %s\n",
           known ? "known-vulnerable" : "unknown, vulnerability not confirmed");

    if (strcmp(machine, "aarch64") && strcmp(machine, "arm64")) {
        printf("[precheck] unsupported machine: this chain is arm64-only\n");
        blocked = 1;
    }
    if (page != 4096) {
        printf("[precheck] unsupported page size %ld: this chain assumes 4 KiB pages\n",
               page);
        blocked = 1;
    }
    if (geteuid() == 0)
        printf("[precheck] warning: euid is 0; the tested condition is an unprivileged shell\n");

    if (need_tracefs) {
        int events = vuln_precheck_exists(VULN_TRACEFS "/events/kmem");
        int pipe = vuln_precheck_readable(VULN_TRACEFS "/per_cpu/cpu0/trace_pipe_raw");
        int trigger = vuln_precheck_writable(VULN_TRACEFS "/events/kmem/rss_stat/trigger");
        int on = vuln_precheck_writable(VULN_TRACEFS "/tracing_on");

        printf("[precheck] tracefs: kmem=%s trace_pipe_raw=%s trigger=%s tracing_on=%s\n",
               events ? "ok" : "no", pipe ? "ok" : "no",
               trigger ? "ok" : "no", on ? "ok" : "no");
        if (!events || !pipe || !trigger || !on) {
            printf("[precheck] tracefs is not usable for the leak/reclaim stage\n");
            blocked = 1;
        }
    }

    if (fake_cred_chain) {
        int v = vuln_precheck_read_int("/proc/sys/kernel/panic_on_warn");

        if (v < 0) {
            if (known) {
                printf("[precheck] panic_on_warn: unreadable; assuming 0 for the "
                       "known profile (validate it)\n");
            } else {
                printf("[precheck] panic_on_warn: unreadable; cannot confirm it for "
                       "an unknown profile\n");
                blocked = 1;
            }
        } else {
            printf("[precheck] panic_on_warn=%d\n", v);
            if (v != 0) {
                printf("[precheck] the fake-cred chain triggers a WARN; "
                       "panic_on_warn must be 0\n");
                blocked = 1;
            }
        }
    }

    if (known && !blocked) {
        verdict = "vulnerable (known profile)";
        ok = 1;
    } else if (known) {
        verdict = "known-vulnerable profile but environment check failed";
        ok = force;
    } else if (force) {
        verdict = "unconfirmed release, forced";
        ok = 1;
    } else {
        verdict = "cannot confirm the vulnerability";
        ok = 0;
    }

    printf("[precheck] verdict: %s\n", verdict);
    if (ok && (blocked || !known))
        printf("[precheck] --force: proceeding despite the failed check\n");

    if (check_only) {
        printf("[precheck] --check: %s\n", ok ? "would proceed" : "would refuse");
        fflush(stdout);
        return ok ? VULN_PRECHECK_EXIT_OK : VULN_PRECHECK_EXIT_FAIL;
    }
    if (!ok) {
        printf("[precheck] refusing to run; verify the kernel first and rerun with "
               "--force (or VULN_FORCE=1)\n");
        fflush(stdout);
        return 2;
    }
    fflush(stdout);
    return 0;
}

#endif /* VULN_PRECHECK_H */
