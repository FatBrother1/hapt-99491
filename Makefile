# CVE-2026-99491 - Android PoC/EXP build
# Usage: make [target] [NDK=/path] [API=24] [ARCH=arm64|arm]

NDK        ?= /opt/android-ndk-r29
API        ?= 24
ARCH       ?= arm64
BUILD      ?= build
SRC        ?= src
DEVICE_DIR ?= /data/local/tmp
ADB        ?= adb
SDK        ?= /opt/android-sdk
BUILD_TOOLS?= $(SDK)/build-tools/37.0.0
JDK        ?= /usr
APP_DEPS   ?= $(HOME)/.cache/android-cve-env/deps/CVE-2026-99491
KEYSTORE   ?=

NDK_BIN := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin

ifeq ($(ARCH),arm64)
TRIPLE := aarch64-linux-android$(API)
else ifeq ($(ARCH),arm)
TRIPLE := armv7a-linux-androideabi$(API)
else
$(error ARCH must be "arm64" or "arm")
endif

CC       := $(NDK_BIN)/$(TRIPLE)-clang
CFLAGS   ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -fPIE -fstack-protector-strong
CPPFLAGS ?=
LDFLAGS  ?= -pie
LDLIBS   ?=

POC_SRC := $(SRC)/poc.c
EXP_SRC := $(SRC)/exp.c
KSU_SRC := $(SRC)/ko_patch.c
KSU_BOOT_SRC := $(SRC)/ksu_boot.c
KSU_SYMS := $(SRC)/ko_syms_5.15.178.txt
UID0_SRC := $(SRC)/uid0.c
PRECHECK_H := $(SRC)/vuln_precheck.h
POC     := $(BUILD)/poc
EXP     := $(BUILD)/exp
UID0    := $(BUILD)/uid0

.DELETE_ON_ERROR:
.PHONY: all poc exp uid0 leakgen build-all apk push run logs clean help

all: poc

$(BUILD):
	@mkdir -p $@

$(POC): $(POC_SRC) $(PRECHECK_H) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

poc: $(POC)

exp:
	@if [ ! -f "$(EXP_SRC)" ]; then \
		echo "[-] $(EXP_SRC) not found: this repository ships a PoC only"; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory $(EXP)

$(EXP): $(EXP_SRC) $(KSU_SRC) $(KSU_BOOT_SRC) $(SRC)/ksu_boot.h $(PRECHECK_H) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(EXP_SRC) $(KSU_SRC) $(KSU_BOOT_SRC) $(LDLIBS)

uid0:
	@if [ ! -f "$(UID0_SRC)" ]; then \
		echo "[-] $(UID0_SRC) not found"; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory $(UID0)

$(UID0): $(UID0_SRC) $(PRECHECK_H) | $(BUILD)
	$(CC) $(CPPFLAGS) -O2 -g -Wall -Wextra -fno-pie -no-pie -static -o $@ $< $(LDLIBS)

# Path B leak harness (wacom ToolSerialNumber OOB read), see scripts/leak/
LEAKGEN_SRC := scripts/leak/leakgen.c
LEAKGEN     := $(BUILD)/leakgen

$(LEAKGEN): $(LEAKGEN_SRC) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

leakgen: $(LEAKGEN)

apk:
	@if [ -f app/build_apk.sh ]; then \
		sh app/build_apk.sh; \
	else \
		echo "[-] app/build_apk.sh not found"; \
		exit 1; \
	fi

# Build the PoC and any optional components present in the repository.
build-all: poc
	@if [ -f "$(EXP_SRC)" ]; then $(MAKE) --no-print-directory $(EXP); fi
	@if [ -f "$(UID0_SRC)" ]; then $(MAKE) --no-print-directory $(UID0); fi
	@if [ -f "app/build_apk.sh" ]; then $(MAKE) --no-print-directory apk; fi

push: poc
	$(ADB) push $(POC) $(DEVICE_DIR)/poc
	@if [ -f "$(EXP)" ]; then \
		$(ADB) push $(EXP) $(DEVICE_DIR)/exp; \
		$(ADB) shell chmod 755 $(DEVICE_DIR)/exp; \
	fi
	@if [ -f "$(UID0)" ]; then \
		$(ADB) push $(UID0) $(DEVICE_DIR)/uid0; \
		$(ADB) shell chmod 755 $(DEVICE_DIR)/uid0; \
	fi
	@if [ -f "$(KSU_SYMS)" ]; then \
		$(ADB) push $(KSU_SYMS) $(DEVICE_DIR)/ko-syms-5.15.178.txt; \
	fi
	$(ADB) shell chmod 755 $(DEVICE_DIR)/poc

run: push
	$(ADB) shell $(DEVICE_DIR)/poc

logs:
	@mkdir -p logs
	$(ADB) logcat -d -b all -v threadtime > logs/logcat-$$(date +%Y%m%d-%H%M%S).log
	-$(ADB) shell dmesg > logs/dmesg-$$(date +%Y%m%d-%H%M%S).log

clean:
	rm -rf $(BUILD)

help:
	@echo "Targets:"
	@echo "  all/poc   build PoC for $(ARCH) (API $(API))"
	@echo "  exp       build EXP when src/exp.c exists"
	@echo "  uid0      build uid-0 shell stage when src/uid0.c exists"
	@echo "  build-all build PoC and any optional components"
	@echo "  apk       build App APK when app/build_apk.sh exists"
	@echo "  push      push binaries to $(DEVICE_DIR)"
	@echo "  run       push and execute PoC on device (destructive)"
	@echo "  logs      dump logcat and dmesg into logs/"
	@echo "  clean     remove $(BUILD)/"
