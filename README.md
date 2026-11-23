# SM7675 kernel, module, and image builder

[简体中文](README.zh-CN.md)

`forge.py` builds the Android 6.18 GKI kernel and vendor modules for the OnePlus Ace 3V (Audi / SM7675). It packages four Android partition images (`boot`, `vendor_boot`, `vendor_dlkm`, and `system_dlkm`). The kernel, Qualcomm MSM drivers, OnePlus vendor drivers, LLVM toolchain, target manifest, output directory, and device materials are explicit inputs. The builder uses the Python standard library and requires Python 3.12 or later.

The target's `images.vendor_boot.recovery_modules_list` selects extra modules for recovery from the build output. Staging copies these modules, their hard dependencies, and any available soft dependencies into the ramdisk and writes `modules.load.recovery`. Normal boot uses its own `modules.load` and retains the same `vendor_dlkm` module set. Recovery verification resolves symbols against the kernel and ramdisk modules only. The host needs libbpf with split and distilled BTF support. The build receipt records the shared library used and its SHA-256 hash.

The module catalog draws on Kbuild declarations in the three source trees and source lists in OnePlus `oplus_local_modules.bzl` files. The builder parses the lists without executing Bazel code. Target manifests can specify output aliases, Kconfig requirements, source generation rules, Make variables, and group-local `KCFLAGS`. Each active cross-repository symlink in MSM must match exactly one rule mapping it into the vendor tree. External modules are grouped by source directory and compatible build variables. Each group runs a symbol-index pass followed by a strict final pass in isolated build directories.

Targets can apply hashed `source_patches` and exact `source_replacements` to isolated source views. Each replacement specifies an expected match count. The build fails if the count differs. `module_parallelism` controls how many independent groups run concurrently in each pass, while `jobs` limits the total number of compiler jobs. Use `--module-jobs N` to override group concurrency locally. Each group has its own output and log.

## Build inputs

Use matching SM7675 port trees. The `Makefile` uses these input paths by default.

| Variable | Default path | Contents |
| --- | --- | --- |
| `KERNEL_SRC` | `src/kernel/` | Android 6.18 GKI kernel adapted for SM7675 |
| `MSM_SRC` | `src/msm/` | Adapted Qualcomm MSM drivers, including `oneplus-6.18-compat/` |
| `VENDOR_SRC` | `src/vendor/` | Adapted OnePlus driver repository containing `vendor/` |
| `TOOLCHAIN` | `src/llvm/bin/` | Android LLVM toolchain executables |
| `MATERIALS` | `device-materials/` | Matching ROM [device materials](#device-materials) |

Override paths with Make variables, environment variables, or a local `local.mk`. The builder accepts local changes. Receipts record each repository's Git commit, digests of changes to tracked files and unignored untracked files, and a digest of the compatibility tree. Use matching, tested commits and toolchain versions for releases.

The SM7675 target sets `build.kernel_defconfig = "gki_defconfig"`. Kconfig reads it from `arch/arm64/configs/` in the selected kernel and expands it into `out/current/kernel-out/.config`. Custom targets can set `build.kernel_config` instead. Choose one configuration input per target.

`make config FORGE_ARGS=--reuse-output` regenerates `.config` from the latest defconfig, saves `.config.previous`, and writes a normalized `kernel-out/defconfig`. The next `make kernel` reuses the existing Kbuild objects and rebuilds affected parts. When the configuration changes, explicitly allow output reuse and finish the new kernel build before packaging.

For iterative development, `--reuse-output` lets you reuse the same output directory with changed inputs and saves the previous build identity as `build-identity.previous.json`. Module and staging receipts still need to be validated or regenerated. Use a clean output directory for release builds. When only repackaging images, older receipts can still be used if the recorded source contents and other inputs match.

Module resolution uses the port trees above. WLAN variants use vendor Kbuild and their respective Pineapple GKI profiles.

## Build commands

Run the following commands from the build-system directory. Use the same source and toolchain overrides at each stage.

```sh
make doctor MATERIALS=/absolute/device-materials
make all MATERIALS=/absolute/device-materials

make boot
make system-dlkm MATERIALS=/absolute/device-materials
make verify MATERIALS=/absolute/device-materials
```

The `Makefile` accepts `KERNEL_SRC`, `MSM_SRC`, `VENDOR_SRC`, `TOOLCHAIN`, `TOOLS_DIR`, `OUT`, `TARGET`, `MATERIALS`, `BOOT_CMDLINE`, and `PARTITION`. Compatibility sources default to `oneplus-6.18-compat` in the selected MSM tree. Override this with `COMPAT_SRC` or `--compat-src`. Use `FORGE_ARGS` to pass additional options such as `--extra-src NAME=PATH` or `--module-jobs 2`.

You can also invoke `forge.py` from any directory. Keep whitespace out of Kbuild source, output, and toolchain paths.

```sh
python3 /path/to/build-system/forge.py \
  --target /path/to/build-system/targets/cliffs/sm7675.toml \
  --kernel-src /src/android17-6.18-port \
  --msm-src /src/android_kernel_oneplus_sm7675 \
  --vendor-src /src/android_kernel_modules_and_devicetree_oneplus_sm7675 \
  --toolchain /opt/llvm/bin \
  --tools-dir /opt/android-host-tools \
  --out /build/sm7675 \
  plan
```

### Build stages

1. `doctor` checks the source layout, target manifest, module inventory, LLVM, host tools, and device material hashes, then writes `doctor.json` and `plan.json`.
2. `plan` resolves both vendor module lists and writes `plan.json`.
3. `config` expands the kernel configuration and runs `savedefconfig`. `kernel` prepares an isolated output directory, applies the target configuration, and builds the kernel and in-tree modules.
4. `build-modules` compiles external modules and checks their names and `vermagic` against the kernel build.
5. `reuse-staged-modules` handles changes limited to in-tree kernel modules when a matching staging receipt already exists. It checks external module groups, staging tree digests, and module `vermagic`, and records each reused artifact. This stage requires a completed external module build.
6. `stage` combines compiled modules with device materials, regenerates `modules.dep` and `modules.load`, and writes reproducible staging trees for the vendor images.
7. `image` builds both vendor images. Use `--partition vendor_boot` or `--partition vendor_dlkm` to build one. For SM7675, `vendor_boot` packaging adds fixed `splashlog_bb` and `ramoops_window` reserved memory regions to every DTB in the concatenated blob. The receipts and verification cover each embedded FDT and the corresponding boot command line.
8. `boot` packages the existing kernel `Image` with the target boot parameters using the completed kernel output.
9. `system-dlkm` takes GKI modules from the same `kernel-out`, creates the filesystem using the target's module order, and adds the specified `etc` materials. The 6.18 modules are installed under `lib/modules/android17-6.1/` for ROM compatibility.
10. `verify` checks receipts, AVB footers, EROFS filesystems, and modules read back from the images. `all` builds the kernel and vendor modules, packages and verifies all four images, and writes the final build receipt.

`verify` extracts modules from `vendor_boot`, `vendor_dlkm`, and `system_dlkm`, then compares each imported symbol's CRC with the exports in the actual delivered modules and `vmlinux`. It also checks symbol providers and the kernel release. Results go to `logs/delivered-abi-audit.json`. An external group's `Module.symvers` lists symbol providers, while this check confirms the providers are in the images.

For BTF verification, libbpf parses the modules from the images against the current `vmlinux` and handles relocation of distilled `.BTF.base` metadata. `logs/delivered-btf-audit.json` lists the results, including modules missing BTF. Module receipts record the kernel's `.BTF` digest. When it changes, incremental builds refresh ordinary split-BTF modules even if the symbol CRCs still match. Builds also refresh modules with invalid distilled BTF. Staging rejects outdated BTF receipts.

To investigate an external module group, find its ID in `plan.json` and run `check-group --group-id ID`. This runs only the group's index pass and writes `group-checks/ID.json` and a dedicated log. The complete module stage produces the delivery receipt. On failure, `module-failures.json` identifies the groups and their logs.

### Incremental builds

When changing individual external modules, rebuild them in the same output directory.

```sh
make build-modules FORGE_ARGS=--reuse-output MODULES='clk-dummy' INCREMENTAL=1
```

The equivalent CLI is `build-modules --module clk-dummy --incremental`. Repeat `--module` to select more modules. The builder compiles modules that share a Kbuild group together and rebuilds affected consumers when a provider's CRC changes. Incremental builds retain objects from both passes, verify reused binaries by per-module SHA-256, and update delivered modules after every final group succeeds. After editing kernel sources, first run `make kernel FORGE_ARGS=--reuse-output`. Then rerun staging, repackage both vendor images, and run `verify`.

To build all module groups incrementally and refresh the images, run the following command.

```sh
make all MATERIALS=/absolute/device-materials INCREMENTAL=1 FORGE_ARGS=--reuse-output
```

### KernelSU LKM

`make kernelsu KERNELSU_SRC=/path/to/KernelSU` builds a separate LKM against the completed `out/current/kernel-out`. The output is `out/current/kernelsu/android17-6.18_kernelsu.ko`, with source and build receipts and ABI/BTF validation. The KernelSU loader resolves non-exported symbols through kallsyms, so modpost permits their use if each symbol exists in the actual `vmlinux`. Exported symbols still undergo CRC checks. Select the custom LKM in KernelSU Manager or use `ksud` to patch an `init_boot` image with the custom module.

## Device materials

The builder packages images from compiled kernel and module outputs. It generates the module trees and depmod indexes for both DLKM partitions. Ordered module lists, blocklists, and compatibility soft dependencies live in `targets/cliffs/modules/`. A separate device materials repository can contain the following files.

- `vendor_ramdisk.tar` provides first-stage userspace and fstab, without `lib/modules`.
- `vendor_boot.dtb` and `vendor_boot.bootconfig` come from the matching ROM.
- `vendor_dlkm/etc/` and `system_dlkm/etc/` each retain `NOTICE.xml.gz`, `build.prop`, `fs_config_dirs`, and `fs_config_files` for ROM compatibility.

`targets/cliffs/materials.lock.toml` records the SHA-256 hash of each input file. To prepare the materials from a matching ROM, unpack the inputs and export them with GNU tar using the script below. Choose an output directory that does not already exist.

```sh
bash tools/export-device-materials.sh /absolute/device-materials \
  /inputs/vendor_ramdisk /inputs/vendor_boot.dtb /inputs/vendor_boot.bootconfig \
  /inputs/vendor_dlkm/etc /inputs/system_dlkm/etc
```

The script prints a candidate lock for comparison. Review the differences before updating the release lock when the ROM or file contents change. Commit `vendor_ramdisk.tar` itself to preserve file permissions that Git cannot represent in an unpacked tree.

## GitHub Actions

Run **Build Audi 6.18** manually from the Actions tab. The workflow in `.github/workflows/build-audi-6.18.yml` checks out the repositories below.

| Purpose | Repository |
| --- | --- |
| GKI kernel | `sm7675-mainline-android/kernel_common` |
| MSM drivers | `sm7675-mainline-android/android_kernel_oneplus_sm7675` |
| OnePlus vendor drivers | `sm7675-mainline-android/android_kernel_modules_and_devicetree_oneplus_sm7675` |
| Device materials | `sm7675-mainline-android/audi-device-materials` |

The **Use workflow from** selector chooses the branch of this builder repository or fork. The three source repositories and their refs are separate inputs. Set `kernel_repository`, `msm_repository`, or `vendor_repository` to your own `owner/repository`, and use the matching `*_ref` input to select a branch, tag, or commit. The default repositories are public and their default branch for this build is `oneplus/sm7675-6.18`. For releases, use the full commit hashes you tested.

The workflow checks out the default branch of the repository selected by `materials_repository`. Private materials repositories require a read-only `MATERIALS_REPO_TOKEN` secret. The builder checks the SHA-256 hashes of the material files against `targets/cliffs/materials.lock.toml`.

The workflow runs directly on the GitHub-hosted `ubuntu-24.04` x64 runner by default. It installs host dependencies with APT and sets up the Android image tools, erofs-utils, pahole, libbpf, and Rust tools. No container image or repository variables are required to start a build with the public defaults.

The workflow downloads `clang-r584948` from the `android17-release` branch of Google's `platform/prebuilts/clang/host/linux-x86` repository, logs the toolchain source commit, and passes `src/llvm/clang-r584948/bin` to the builder. Clang runs on an x86-64 host and cross-compiles for arm64. The build receipt records the LLVM binary hashes.

The workflow frees space on GitHub-hosted runners before checking out the sources. If more space is needed, use `AUDI_RUNNER` or the `runner` input to select an Ubuntu 24.04 x64 runner with `sudo`, `rustup`, and at least 24 GiB free after checkout and tool setup. The workflow runs the tests, `doctor`, the full build, and four-image verification. If redistribution of the ROM-derived contents is permitted, set `UPLOAD_IMAGES` to `true` to upload the four images, a SHA-256 manifest with relative paths, build receipts, and ABI/BTF reports.

## License

The builder is available under the [MIT License](LICENSE). Qualcomm's two module blocklists, [vendor](targets/cliffs/modules/modules.blocklist) and [system DLKM](targets/cliffs/modules/system_dlkm.modules.blocklist), retain their [GPL-2.0-only license](LICENSES/GPL-2.0-only.txt). The source repositories, toolchain, and device materials are distributed separately under their respective terms.

## Output and reuse

Each `--out` directory has a `build-identity.json` that records target and configuration hashes, source commits and working tree digests, hashes of LLVM and packaging tools, the Python runtime, and the pipeline implementation. The builder generates files with a fixed `umask`. After source changes, use a clean output directory or explicitly enable incremental reuse. Module and staging receipts prevent artifacts from different builds from being mixed. `SHA256SUMS.txt` and the image receipts record the final hashes and packaging inputs. With matching kernel output, you can repackage `boot` and `system-dlkm` independently.

Staging sets file timestamps to the target's `source_date_epoch`. cpio uses reproducible mode, and EROFS fixes the UUID, timestamps, path order, and worker count. The EROFS packer reads `security.selinux` entries from a generated PAX archive so it can build labeled images without elevated privileges.

Bit-for-bit reproducibility also requires the same host environment, including Make, Python, depmod, cpio, lz4, erofs-utils, mkbootimg, avbtool, and the kernel's host build dependencies. Receipts record the packaging and LLVM executables called by the build.

## Tests

```sh
make test
```

Tests use temporary source trees and do not compile actual kernel modules.
