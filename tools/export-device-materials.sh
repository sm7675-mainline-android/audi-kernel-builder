#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 6 ]]; then
    echo "Usage: bash $0 OUTPUT VENDOR_RAMDISK_DIR DTB BOOTCONFIG VENDOR_DLKM_ETC SYSTEM_DLKM_ETC" >&2
    exit 2
fi

output=$1
ramdisk=$2
mkdir "$output"
LC_ALL=C tar --format=gnu --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --exclude='./lib/modules' --exclude='*.ko' --exclude='*.ko.*' \
    -C "$ramdisk" -cf "$output/vendor_ramdisk.tar" .
install -m 0644 "$3" "$output/vendor_boot.dtb"
install -m 0644 "$4" "$output/vendor_boot.bootconfig"
for partition in vendor_dlkm system_dlkm; do
    if [[ $partition == vendor_dlkm ]]; then source_dir=$5; else source_dir=$6; fi
    mkdir -p "$output/$partition/etc"
    for name in NOTICE.xml.gz build.prop fs_config_dirs fs_config_files; do
        install -m 0644 "$source_dir/$name" "$output/$partition/etc/$name"
    done
done

printf 'schema = 1\n\n[files]\n'
(
    cd "$output"
    LC_ALL=C find . -type f -printf '%P\n' | LC_ALL=C sort | while IFS= read -r name; do
        line=$(sha256sum -- "$name")
        printf '"%s" = "%s"\n' "$name" "${line%% *}"
    done
)
