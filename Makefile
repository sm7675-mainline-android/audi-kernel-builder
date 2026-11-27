PYTHON ?= python3
FORGE := $(CURDIR)/forge.py
.DEFAULT_GOAL := test
-include local.mk
TARGET ?= $(CURDIR)/targets/cliffs/sm7675.toml
OUT ?= $(CURDIR)/out/current
KERNEL_SRC ?= $(CURDIR)/src/kernel
MSM_SRC ?= $(CURDIR)/src/msm
VENDOR_SRC ?= $(CURDIR)/src/vendor
COMPAT_SRC ?= $(MSM_SRC)/oneplus-6.18-compat
TOOLCHAIN ?= $(CURDIR)/src/llvm/bin
TOOLS_DIR ?=
MATERIALS ?= $(CURDIR)/device-materials
RECOVERY_BASE ?=
MAGISKBOOT ?=
BOOT_CMDLINE ?=
PARTITION ?= all
GROUP_ID ?=
MODULE_JOBS ?=
MODULES ?=
KERNELSU_SRC ?= $(CURDIR)/src/KernelSU
INCREMENTAL ?= 0
FORGE_ARGS ?=
KERNELSU_ARGS ?=

BASE_ARGS = --target "$(TARGET)" --out "$(OUT)" \
	--kernel-src "$(KERNEL_SRC)" --msm-src "$(MSM_SRC)" \
	--vendor-src "$(VENDOR_SRC)" --compat-src "$(COMPAT_SRC)" \
	--toolchain "$(TOOLCHAIN)"
ifneq ($(TOOLS_DIR),)
BASE_ARGS += --tools-dir "$(TOOLS_DIR)"
endif
ifneq ($(MODULE_JOBS),)
BASE_ARGS += --module-jobs "$(MODULE_JOBS)"
endif
ifneq ($(MATERIALS),)
BASE_ARGS += --materials "$(MATERIALS)"
endif
ifneq ($(BOOT_CMDLINE),)
BOOT_ARGS += --boot-cmdline "$(BOOT_CMDLINE)"
endif

.PHONY: test doctor plan config kernel build-modules kernelsu check-group stage image boot system-dlkm recovery verify all

test:
	$(PYTHON) -m py_compile forge.py buildsys/*.py
	PYTHONPATH=. $(PYTHON) -m unittest discover -s tests -v

doctor:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) doctor

plan:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) plan

config:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) config

kernel:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) kernel

build-modules:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) build-modules $(foreach module,$(MODULES),--module $(module)) $(if $(filter 1,$(INCREMENTAL)),--incremental,)

kernelsu:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) kernelsu --kernelsu-src "$(KERNELSU_SRC)" $(KERNELSU_ARGS)

check-group:
	@test -n "$(GROUP_ID)" || (echo "GROUP_ID is required" >&2; exit 2)
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) check-group --group-id "$(GROUP_ID)"

stage:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) stage

image:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) image --partition $(PARTITION)

boot:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) boot $(BOOT_ARGS)

system-dlkm:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) system-dlkm

recovery:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) recovery --recovery-base "$(RECOVERY_BASE)" $(if $(MAGISKBOOT),--magiskboot "$(MAGISKBOOT)",)

verify:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) verify

all:
	$(PYTHON) $(FORGE) $(BASE_ARGS) $(FORGE_ARGS) all $(BOOT_ARGS) $(if $(filter 1,$(INCREMENTAL)),--incremental,)
