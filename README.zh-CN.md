# SM7675 内核、模块与镜像构建

[English](README.md)

`forge.py` 为 OnePlus Ace 3V（Audi / SM7675）构建 Android 6.18 GKI 内核和厂商模块，并打包 `boot`、`vendor_boot`、`vendor_dlkm`、`system_dlkm` 四个 Android 分区镜像。构建时显式指定内核、Qualcomm MSM 驱动、OnePlus vendor 驱动、LLVM 工具链、目标清单、输出目录和设备材料。构建器使用 Python 3.12 或更新版本的标准库。

目标配置中的 `images.vendor_boot.recovery_modules_list` 从已构建的模块中选择 recovery 需要额外加载的模块。暂存阶段会把这些模块及其硬依赖和可用的软依赖一并复制进 ramdisk，并写入 `modules.load.recovery`。正常启动的 `modules.load` 与 `vendor_dlkm` 的模块归属保持原样。校验 recovery 时，符号提供者仅限内核和 ramdisk 中的模块。宿主机需要支持 split BTF 和 distilled BTF 的 libbpf，构建收据会记录实际使用的共享库及其 SHA-256。

模块目录来自三个源码树的 Kbuild 声明，以及 OnePlus `oplus_local_modules.bzl` 中的源文件列表。构建器仅读取该列表，不执行 Bazel 代码。目标配置可以指定模块输出别名、Kconfig 依赖、生成源码的规则、Make 变量和组内 `KCFLAGS`。MSM 中用于当前模块的跨仓符号链接按配置映射到 vendor 树，每个链接必须匹配唯一规则。外部模块按源码目录和兼容的构建变量分组，在独立目录中先构建符号索引，再严格校验并生成交付模块。

目标配置可通过带哈希的 `source_patches` 和要求精确匹配的 `source_replacements` 在隔离的源码视图中应用适配。每条替换规则都声明预期匹配次数，次数有出入时构建失败。两个阶段都可通过 `module_parallelism` 并行构建独立模块组，总编译任务数受 `jobs` 限制。本地可用 `--module-jobs N` 覆盖模块组并发数。每组有独立的构建输出和日志，可直接定位故障组。

## 构建输入

请使用同一套 SM7675 移植源码。`Makefile` 默认从以下位置读取输入。

| 变量 | 默认路径 | 内容 |
| --- | --- | --- |
| `KERNEL_SRC` | `src/kernel/` | 已适配 SM7675 的 Android 6.18 GKI 内核 |
| `MSM_SRC` | `src/msm/` | 已适配的 Qualcomm MSM 驱动，含 `oneplus-6.18-compat/` |
| `VENDOR_SRC` | `src/vendor/` | 已适配的 OnePlus 驱动仓库，包含 `vendor/` |
| `TOOLCHAIN` | `src/llvm/bin/` | Android LLVM 工具链的可执行文件 |
| `MATERIALS` | `device-materials/` | 对应 ROM 的[设备材料](#设备材料) |

可用 Make 变量、环境变量或本地 `local.mk` 覆盖路径。构建器接受本地源码改动，构建收据记录各仓 Git 提交、已跟踪文件与未被忽略的未跟踪文件的改动摘要，以及兼容层源码摘要。发布时请指定彼此匹配、经过测试的提交和工具链版本。
SM7675 目标使用 `build.kernel_defconfig = "gki_defconfig"`，从所选内核的 `arch/arm64/configs/` 读取配置，再由 Kconfig 展开到 `out/current/kernel-out/.config`。自定义目标也可以用 `build.kernel_config` 指定配置。两种方式只能选一种。

`make config FORGE_ARGS=--reuse-output` 根据最新 defconfig 重新生成 `.config`，保存 `.config.previous`，并输出规范化的 `kernel-out/defconfig`。后续 `make kernel` 利用保留的 Kbuild 对象文件重编受影响的部分。配置变化时，需要显式允许复用已有输出，打包阶段也会等新内核构建完成后再接受新的内核收据。

迭代开发时，`--reuse-output` 允许在输入身份变化后复用同一输出目录，旧身份保存在 `build-identity.previous.json`。模块与暂存收据仍须重新验证或生成。发布构建使用干净的输出目录。只重打镜像时，如果旧版收据记录的源码内容与其他输入仍然匹配，也可继续使用该收据。

模块解析仅使用上述移植源码。不同 WLAN 芯片的模块使用 vendor Kbuild 和各自的 Pineapple GKI 配置。

## 构建命令

在构建系统目录运行下列命令。如果覆盖源码或工具链路径，请在各阶段使用相同的参数。

```sh
make doctor MATERIALS=/absolute/device-materials
make all MATERIALS=/absolute/device-materials

make boot
make system-dlkm MATERIALS=/absolute/device-materials
make verify MATERIALS=/absolute/device-materials
```

`Makefile` 支持 `KERNEL_SRC`、`MSM_SRC`、`VENDOR_SRC`、`TOOLCHAIN`、`TOOLS_DIR`、`OUT`、`TARGET`、`MATERIALS`、`BOOT_CMDLINE` 和 `PARTITION`。兼容层默认取所选 MSM 源码下的 `oneplus-6.18-compat`，可用 `COMPAT_SRC` 或 `--compat-src` 覆盖。通过 `FORGE_ARGS` 可传入额外选项，如 `--extra-src NAME=PATH` 或 `--module-jobs 2`。

也可以在任意目录直接调用 `forge.py`。Kbuild 的源码、输出和工具链路径须避免空白字符。

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

### 构建阶段

1. `doctor` 检查源码布局、目标清单、模块清单、LLVM、宿主工具和设备材料的哈希，写入 `doctor.json` 和 `plan.json`。
2. `plan` 解析两份厂商模块列表并生成 `plan.json`。
3. `config` 展开内核配置并运行 `savedefconfig`。`kernel` 准备隔离的输出目录，应用目标配置，编译内核和树内模块。
4. `build-modules` 编译外部模块，检查模块名以及与所构建内核对应的 `vermagic`。
5. `reuse-staged-modules` 用于仅新增或修改内核树内模块、且已有匹配暂存收据的情况。它核对外部模块组、暂存树摘要和模块 `vermagic`，记录每个复用的产物。外部模块仍须先完成构建。
6. `stage` 将已编译模块与设备材料合并，重新生成 `modules.dep` 和 `modules.load`，输出确定性的厂商镜像暂存目录。
7. `image` 生成两个厂商镜像，可用 `--partition vendor_boot` 或 `--partition vendor_dlkm` 只生成其中一个。SM7675 的 `vendor_boot` 会在拼接的每份 DTB 中加入固定的 `splashlog_bb` 和 `ramoops_window` 保留区。收据与校验阶段会核对每份内嵌 FDT 和相应的 boot cmdline。
8. `boot` 直接打包已有内核 `Image` 和目标启动参数。此步只需现成的内核输出。
9. `system-dlkm` 从同一 `kernel-out` 取出 GKI 模块，按目标列表顺序生成文件系统，并加入指定的 `etc` 材料。为兼容 ROM，镜像内仍使用 `lib/modules/android17-6.1/` 路径，模块来自 6.18 内核。
10. `verify` 校验四镜像的收据、AVB footer 和 EROFS 文件系统，并读回模块进行检查。`all` 完成内核与厂商模块编译、四镜像打包及校验，最后写入构建收据。

`verify` 会解包 `vendor_boot`、`vendor_dlkm` 和 `system_dlkm`，用实际交付的模块及 `vmlinux` 核对每个导入符号的 CRC，同时检查符号提供者与内核发行版本。结果写入 `logs/delivered-abi-audit.json`。仅有外部模块组的 `Module.symvers` 无法确认对应模块已打包。

BTF 检查用 libbpf 将实际交付模块与当前 `vmlinux` 配对解析，包括 distilled `.BTF.base` 的重定位。结果写入 `logs/delivered-btf-audit.json`，缺少 BTF 的模块会单独列出。模块收据记录内核 `.BTF` 摘要。摘要变化后，增量构建会刷新使用普通 split BTF 的模块，即使符号 CRC 没变。BTF 失效的 distilled 模块也会重新构建。暂存阶段会拒绝过期的 BTF 收据。

排查某个外部模块组时，可从 `plan.json` 查找组 ID，再运行 `check-group --group-id ID`。该命令只运行该组的索引阶段，写入 `group-checks/ID.json` 和专用日志。用于交付的模块收据由完整模块阶段生成。构建失败时，可从 `module-failures.json` 找到失败组及各组日志。

### 增量构建

只改了个别外部模块时，可以在同一输出目录定向更新。

```sh
make build-modules FORGE_ARGS=--reuse-output MODULES='clk-dummy' INCREMENTAL=1
```

对应的 CLI 为 `build-modules --module clk-dummy --incremental`，`--module` 可重复指定。共享 Kbuild 组会一起编译，提供者的 CRC 改变时也会重编受影响的现有消费者。增量构建保留两个阶段的对象文件，用逐模块 SHA-256 验证复用的二进制，并在所有交付组成功后更新交付模块。修改内核源码后，先运行 `make kernel FORGE_ARGS=--reuse-output`。之后重新暂存、打包两份厂商镜像并执行 `verify`。

要对所有模块组执行增量构建并刷新镜像，可使用以下命令。

```sh
make all MATERIALS=/absolute/device-materials INCREMENTAL=1 FORGE_ARGS=--reuse-output
```

### KernelSU LKM

`make kernelsu KERNELSU_SRC=/path/to/KernelSU` 以已完成的 `out/current/kernel-out` 为基础构建独立 LKM。产物位于 `out/current/kernelsu/android17-6.18_kernelsu.ko`，附带源码和构建收据及 ABI/BTF 校验结果。KernelSU 加载器通过 kallsyms 解析未导出的符号，因此 modpost 允许这类引用，每个符号仍须存在于实际的 `vmlinux` 中。已导出符号继续校验 CRC。请通过 KernelSU 管理器的自定义 LKM 选项使用该模块，或使用ksud自定义修补init_boot镜像。

若只需基于现有 `kernel-out` 编译 KSU，且内核源码树身份已变化，可显式跳过该项源码身份比较：`make kernelsu KERNELSU_SRC=/path/to/KernelSU KERNELSU_ARGS=--allow-kernel-source-mismatch`。该选项只忽略内核源码树身份；工具链、配置、其他源码树、内核收据、运行时符号和 ABI/BTF 校验仍会检查。构建收据会记录此选项。可用 `--profile generic` 关闭 BakaSU 专用 Make 配置，也可用 `--output-subdir`、`--artifact-name` 和重复的 `--make-variable=CONFIG_NAME=value` 指定独立输出、文件名及 Kbuild 变量。

## 设备材料

构建器从内核和模块编译输出生成镜像。两份 DLKM 的模块目录和 depmod 索引由构建阶段生成，加载顺序、模块黑名单和兼容性软依赖放在 `targets/cliffs/modules/`。设备材料目录可以是独立的 Git 仓库，包含以下文件。

- `vendor_ramdisk.tar` 提供第一阶段用户态文件和 fstab，归档不含 `lib/modules`。
- `vendor_boot.dtb` 和 `vendor_boot.bootconfig` 来自匹配的 ROM。
- `vendor_dlkm/etc/` 和 `system_dlkm/etc/` 各保留 `NOTICE.xml.gz`、`build.prop`、`fs_config_dirs`、`fs_config_files`，用于兼容 ROM。

`targets/cliffs/materials.lock.toml` 记录每个输入文件的 SHA-256。设备材料存放在独立仓库，如需从匹配的 ROM 准备材料，先解包输入，再用 GNU tar 和以下脚本导出。输出目录必须尚未创建。

```sh
bash tools/export-device-materials.sh /absolute/device-materials \
  /inputs/vendor_ramdisk /inputs/vendor_boot.dtb /inputs/vendor_boot.bootconfig \
  /inputs/vendor_dlkm/etc /inputs/system_dlkm/etc
```

脚本会生成一份候选锁文件供比较。ROM 或文件内容改变时应先核对差异，再更新发布用锁文件。请提交 `vendor_ramdisk.tar` 本身，以保留 Git 工作树无法完整表示的文件权限。

## GitHub Actions

在 Actions 页面手动运行 **Build Audi 6.18**。工作流定义位于 `.github/workflows/build-audi-6.18.yml`，会检出以下仓库。四镜像校验后先上传四镜像 artifact，再依次尝试构建 BakaSU、KernelSU、SukiSU-Nova 的 LKM；KSU 源码按项目名单独克隆，并在本地构建副本的 `kernel/core/init.c` 中补入 Android GKI VFS 命名空间导入，不会改动上游仓库。各 LKM 有单独版本化文件名、构建收据和校验结果。单个 LKM 失败不会撤回已上传的四镜像；部分或全部 LKM 失败会记录在 KSU 构建摘要中。

LKM 源码仓为 `Baka-SU/BakaSU`、`tiann/KernelSU` 与 `SukiSU-Nova/SukiSU-Nova`，均从各自默认分支克隆。

| 用途 | 仓库 |
| --- | --- |
| GKI 内核 | `sm7675-mainline-android/kernel_common` |
| MSM 驱动 | `sm7675-mainline-android/android_kernel_oneplus_sm7675` |
| OnePlus vendor 驱动 | `sm7675-mainline-android/android_kernel_modules_and_devicetree_oneplus_sm7675` |
| 设备材料 | `sm7675-mainline-android/audi-device-materials` |

**Use workflow from** 选择当前构建系统仓库或 fork 中运行工作流的分支。三个源码仓的地址和版本由独立参数控制，可用 `kernel_repository`、`msm_repository`、`vendor_repository` 填入自己的 `owner/repository`，并在对应的 `*_ref` 参数中指定分支、标签或提交。默认使用上表中的公开源码仓和 `oneplus/sm7675-6.18` 分支。发布构建建议填入经过测试的三个完整提交。

工作流检出 `materials_repository` 所选仓库的默认分支。私有材料仓库需设置有只读权限的 `MATERIALS_REPO_TOKEN`。构建器按 `targets/cliffs/materials.lock.toml` 校验材料文件的 SHA-256。

工作流默认直接运行在 GitHub 托管的 `ubuntu-24.04` x64 runner 上，通过 APT 安装宿主依赖，并准备 Android 镜像工具、erofs-utils、pahole、libbpf 和 Rust 工具。使用公开仓库的默认配置即可发起构建，无需配置容器镜像或仓库变量。

工作流从 Google 的 `platform/prebuilts/clang/host/linux-x86` 仓库的 `android17-release` 分支下载 `clang-r584948`，记录来源提交，并将 `src/llvm/clang-r584948/bin` 传给构建器。工具链运行在 x86-64 宿主上，交叉编译的目标为 arm64。构建收据记录工具链二进制的哈希。

工作流在检出源码前会清理 GitHub 托管 runner 的磁盘空间。若空间仍不足，可通过 `AUDI_RUNNER` 或 `runner` 参数选择备有 `sudo` 和 `rustup` 的 Ubuntu 24.04 x64 runner，检出源码及安装工具后需至少剩余 24 GiB 空间。工作流依次运行测试、`doctor`、全量构建和四镜像校验。构建成功后自动上传四镜像、相对路径的 SHA-256 清单、构建收据和 ABI/BTF 报告，产物名为 `audi-6.18-four-images`。在已完成运行页面的 **Artifacts** 区域下载即可，无需设置上传变量。

手动运行时，`publish_nightly` 默认开启；完成四镜像上传后，会把四镜像和成功构建的 LKM 发布到当前仓库固定的 `nightly` 预发布版本。资产名标注 UTC 日期与运行编号，每次发布成功后清理旧资产；关闭该输入可只保留 Actions artifact。构建失败时，会单独上传编译日志及 `module-failures.json`，产物名为 `audi-6.18-build-logs`。

## 许可证

构建系统采用 [MIT 许可证](LICENSE)。Qualcomm 的两份模块黑名单（[vendor](targets/cliffs/modules/modules.blocklist) 和 [system DLKM](targets/cliffs/modules/system_dlkm.modules.blocklist)）沿用 [GPL-2.0-only 许可证](LICENSES/GPL-2.0-only.txt)。源码仓库、工具链和设备材料按各自的许可条款单独分发。

## 输出与复用

每个 `--out` 目录对应一份 `build-identity.json`，记录目标与配置哈希、源码提交及工作树摘要、LLVM 和打包工具的哈希、Python 运行时及构建流水线实现。生成文件使用固定的 `umask`。源码改动后可使用干净输出，也可显式启用增量复用。模块和暂存收据用于防止不同批次的产物混用。`SHA256SUMS.txt` 和镜像收据记录成品哈希与打包输入。已有匹配的内核输出时，`boot` 和 `system-dlkm` 可单独重打。

暂存阶段将文件时间统一为目标清单中的 `source_date_epoch`。cpio 使用可重复生成模式，EROFS 固定 UUID、时间戳、路径排序和工作线程数。EROFS 打包器从生成的 PAX 归档读取 `security.selinux` 条目，因此可以在普通用户权限下生成带标签的镜像。

要实现逐字节复现，还需使用相同的宿主环境，包括 Make、Python、depmod、cpio、lz4、erofs-utils、mkbootimg、avbtool 和内核宿主构建依赖。收据记录直接调用的打包工具和 LLVM 可执行文件。

## 测试

```sh
make test
```

测试使用临时源码树，不编译实际内核模块。
