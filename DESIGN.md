# 构建系统设计

## 目标

本系统把四镜像的产出拆成可独立复用的阶段，
每个阶段只接受显式输入，并把输入摘要写入收据。SM7675 需要适配过的 Android
6.18 GKI 内核、Qualcomm MSM 平台驱动和 OnePlus vendor 源码。三个输入相互独立，
不依赖宿主目录名称。旧 MSM 合并实验树不能作为 GKI `Image` 的来源。

## 阶段图

```text
doctor -> plan -> kernel -> build-modules -> stage -> vendor_boot + vendor_dlkm
                        \---------------------------> boot + system_dlkm
                                                       \-> verify
```

- `doctor` 检查源码目录、完整模块清单、工具链、主机工具和设备材料。
- `plan` 解析 Kbuild 与 Oplus DDK 清单，生成模块、分区归属和构建组。
- `kernel` 在独立 `O=` 目录生成配置、内核和树内模块。
- `build-modules` 为每个外部源目录建立隔离 source view，先做允许未解析符号的
  index pass，再做严格的 final pass，最后统一检查模块集合和 vermagic。
- `stage` 展开无模块的 ramdisk、按目标清单安装已构建模块并重新生成索引；
  两个 DLKM 从空目录开始，只复制锁定的 `etc` 文件。
- `image` 以固定时间、压缩参数和 AVB 参数打包；EROFS 通过 PAX 传入 SELinux
  标签，宿主无需写特权 xattr。GKI boot 直接打包同一内核构建的 Image，不读旧 boot。
- `all` 一次完成编译、四镜像打包和交付模块 ABI/BTF 验证。

各阶段检查对应的构建身份、计划和前一阶段收据。设备材料单独由
`materials.lock.toml` 锁定；变更材料时必须重新 staging，但不需要重编
源码不变的模块。源代码从不在原目录内生成 Kbuild 输出或临时文件。

## 可扩展点

- 新设备通过 `targets/<name>/<soc>.toml` 声明清单、Kconfig、源码映射和镜像参数。
- 当前兼容头文件位于所选 MSM 源树的 `oneplus-6.18-compat/`；也可显式传入独立
  的 compat 树。其内容摘要进入构建身份，不要求预先登记版本。构建只修改隔离的
  源码视图，不写回原始 MSM/vendor 仓库。
- Oplus DDK 单源模块通过 `kind = "bazel"` 的显式 source recipe 生成最小 Kbuild。
- 外部模块的 make 变量、include 路径和 source-link map 均来自 target manifest，
  方便在 CI 中替换源码目录而不修改构建器。

## 可复现性边界

源码不设全局版本锁。本地可以带未提交改动构建；CI 可用明确的提交 SHA 重建发布版本。
收据记录源提交、dirty tree 摘要、compat 摘要、LLVM 与主机工具哈希、Python 版本、
配置、计划、阶段输入和最终镜像 SHA-256。真正的 bit-for-bit 结果仍要求 CI 使用
同一容器或主机镜像，因为发行版的 `make`、`depmod`、EROSFS 工具和 `mkbootimg`
也会影响结果。

失败的模块构建会写入 `module-failures.json`；静态校验不代表真机可启动。
