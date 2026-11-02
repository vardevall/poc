#!/bin/bash
# Builds Frameworks/Vardevall.xcframework: the engine static library for macOS, iOS and the
# iOS simulator, with include/vardevall.h and a module map.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$root/.." && pwd)"
out="$root/Frameworks"
stage="$root/build/xcframework"
profile="${PROFILE:-ios}"
profile_dir="$profile"
[ "$profile" = dev ] && profile_dir=debug

export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"

targets=(aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim)
cargo_flags=(--manifest-path "$repo/Cargo.toml" -p vardevall-ffi --profile "$profile")

for t in "${targets[@]}"; do
  cargo build "${cargo_flags[@]}" --target "$t"
done

rm -rf "$stage" "$out/Vardevall.xcframework"
mkdir -p "$stage/include" "$out"
cp "$root/include/vardevall.h" "$stage/include/"
cat > "$stage/include/module.modulemap" <<'MAP'
module Vardevall {
    header "vardevall.h"
    export *
}
MAP

args=()
for t in "${targets[@]}"; do
  args+=(-library "$repo/target/$t/$profile_dir/libvardevall_ffi.a" -headers "$stage/include")
done
xcodebuild -create-xcframework "${args[@]}" -output "$out/Vardevall.xcframework"
