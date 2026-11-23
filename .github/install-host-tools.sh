#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  autoconf automake bc bison build-essential ca-certificates cmake cpio flex git kmod libbpf1 \
  libdw-dev libelf-dev liblz4-dev liblzma-dev libssl-dev libtool libzstd-dev \
  lz4 openssl pkg-config python3 rsync uuid-dev zlib1g-dev zstd

tools_dir=$(mktemp -d "$RUNNER_TEMP/audi-tools.XXXXXXXX")
build_dir=$(mktemp -d "$RUNNER_TEMP/audi-tools-build.XXXXXXXX")
trap 'rm -rf -- "$build_dir"' EXIT
jobs=$(nproc)
if (( jobs > 8 )); then jobs=8; fi
mkdir -p "$tools_dir/bin" "$tools_dir/share/android"

git clone --depth 1 --branch v1.7.0 https://github.com/libbpf/libbpf.git "$build_dir/libbpf"
make -C "$build_dir/libbpf/src" -j "$jobs" install PREFIX="$tools_dir" LIBDIR="$tools_dir/lib"
export PKG_CONFIG_PATH="$tools_dir/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="$tools_dir/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

git clone --depth 1 --branch v1.32 https://github.com/acmel/dwarves.git "$build_dir/pahole"
cmake -S "$build_dir/pahole" -B "$build_dir/pahole/build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$tools_dir" \
  -DCMAKE_INSTALL_LIBDIR=lib -DLIBBPF_EMBEDDED=OFF
cmake --build "$build_dir/pahole/build" --parallel "$jobs"
cmake --install "$build_dir/pahole/build"

git clone --depth 1 --branch v1.9.4 https://github.com/erofs/erofs-utils.git "$build_dir/erofs"
(
  cd "$build_dir/erofs"
  autoreconf -fi
  ./configure --prefix="$tools_dir" --enable-lz4 --enable-lzma
  make -j "$jobs"
  make install
)

android_tools="$tools_dir/share/android"
android_tag=android-16.0.0_r1
git clone --depth 1 --branch "$android_tag" \
  https://android.googlesource.com/platform/system/tools/mkbootimg "$android_tools/mkbootimg"
git clone --depth 1 --branch "$android_tag" \
  https://android.googlesource.com/platform/external/avb "$android_tools/avb"
ln -s "$android_tools/mkbootimg/mkbootimg.py" "$tools_dir/bin/mkbootimg"
ln -s "$android_tools/mkbootimg/unpack_bootimg.py" "$tools_dir/bin/unpack_bootimg"
ln -s "$android_tools/avb/avbtool.py" "$tools_dir/bin/avbtool"

rust_version=1.95.0
rustup toolchain install "$rust_version" --profile minimal --component rust-src --no-self-update
rustup run "$rust_version" cargo install --locked --version 0.73.2 \
  --root "$tools_dir" --jobs "$jobs" bindgen-cli

export PATH="$tools_dir/bin:$PATH"
pahole --version
pkg-config --modversion libbpf
mkfs.erofs -V
mkbootimg --help >/dev/null
unpack_bootimg --help >/dev/null
avbtool version
bindgen --version
rustup run "$rust_version" rustc --version

printf '%s\n' "$tools_dir/bin" >> "$GITHUB_PATH"
printf 'LD_LIBRARY_PATH=%s\nRUSTUP_TOOLCHAIN=%s\n' "$LD_LIBRARY_PATH" "$rust_version" >> "$GITHUB_ENV"
