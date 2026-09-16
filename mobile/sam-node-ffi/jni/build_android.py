#!/usr/bin/env python3
"""Build the arm64 Android Go library and JNI shim without modifying source files."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def output(*args, **kwargs):
    return run(*args, stdout=subprocess.PIPE, **kwargs).stdout.strip()


def fingerprint(root):
    """Include working-tree Go/bridge edits, not just the base commit label."""
    names = output("git", "ls-files", "--cached", "--others", "--exclude-standard", cwd=root).splitlines()
    digest = hashlib.sha256()
    for name in sorted(set(names)):
        path = root / name
        digest.update(name.encode() + b"\0")
        digest.update(path.read_bytes() if path.is_file() else b"<deleted>")
        digest.update(b"\0")
    return digest.hexdigest()


def verify_alignment(readelf, library):
    headers = output(str(readelf), "--program-headers", "--wide", str(library))
    alignments = [int(line.split()[-1], 16) for line in headers.splitlines() if line.strip().startswith("LOAD ")]
    if not alignments or any(value < 16384 for value in alignments):
        raise RuntimeError(f"{library.name}: ELF LOAD alignment must be at least 16 KiB: {alignments}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", required=True, type=Path)
    parser.add_argument("--ndk-version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--debug-fixtures", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    ndk = args.ndk.resolve()
    destination = args.output.resolve()
    # Never leave a previously successful artifact stamped as current after failure.
    stamp = destination / "assets" / "sam-native-build.json"
    stamp.unlink(missing_ok=True)
    revision = output("git", "rev-parse", "HEAD", cwd=root)
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision) or revision != args.revision:
        raise RuntimeError(f"SAM revision mismatch: expected {args.revision}, checkout is {revision}")
    properties = ndk / "source.properties"
    if not properties.is_file():
        raise RuntimeError(f"Install NDK {args.ndk_version}; missing {properties}")
    match = re.search(r"^Pkg.Revision\s*=\s*(\S+)", properties.read_text(), re.MULTILINE)
    if match is None or match[1] != args.ndk_version:
        raise RuntimeError(f"Expected NDK {args.ndk_version} at {ndk}")
    host = {"Darwin": "darwin-x86_64", "Linux": "linux-x86_64"}.get(platform.system())
    if host is None:
        raise RuntimeError("This smoke build supports macOS and Linux hosts")
    toolchain = ndk / "toolchains" / "llvm" / "prebuilt" / host / "bin"
    compiler = toolchain / "aarch64-linux-android30-clang"
    go_dir = destination / "go"
    libraries = destination / "jniLibs" / "arm64-v8a"
    libraries.mkdir(parents=True, exist_ok=True)
    before = fingerprint(root)
    # Reuse SAM's existing mobile build; explicitly override its latest-NDK choice.
    # Override ambient GOFLAGS: a release build must never inherit the debug tag.
    environment = dict(os.environ, GOFLAGS="-tags=sam_debug" if args.debug_fixtures else "")
    run("make", "mobile-ffi-android", f"ANDROID_NDK_LATEST={ndk}", f"OUT_DIR={go_dir}", cwd=root, env=environment)
    source_library = go_dir / "android" / "libsam.so"
    # Use compiler/linker checks for undefined imports and explicit 16 KiB alignment.
    run(str(compiler), *(["-DSAM_DEBUG"] if args.debug_fixtures else []), "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
        "-Wl,-z,defs", "-Wl,-z,max-page-size=16384", "-Wl,-z,common-page-size=16384",
        "-Wl,-soname,libsam_jni.so", f"-I{source_library.parent}",
        str(Path(__file__).with_name("sam_jni.c")), f"-L{source_library.parent}", "-lsam",
        "-o", str(libraries / "libsam_jni.so"))
    # Copy only the artifacts Android packages; generated C headers remain in go/.
    shutil.copy2(source_library, libraries / "libsam.so")
    for library in libraries.glob("*.so"):
        verify_alignment(toolchain / "llvm-readelf", library)
        symbols = output(str(toolchain / "llvm-nm"), "-D", "--defined-only", str(library))
        debug_symbols = (
            ["StartLocalTestNode", "StartSharedMesh", "StopSharedMesh", "SharedMeshStatus", "DiscoverSharedMeshTools", "CallSharedMeshTool"]
            if library.name == "libsam.so" else
            ["SamLocalTestNative_start", "SamMeshNative_start", "SamMeshNative_stop", "SamMeshNative_status", "SamMeshNative_discover", "SamMeshNative_call"]
        )
        for debug_symbol in debug_symbols:
            if (debug_symbol in symbols) != args.debug_fixtures:
                raise RuntimeError(f"{library.name}: {debug_symbol} does not match debug build mode")
    after = fingerprint(root)
    if before != after or output("git", "rev-parse", "HEAD", cwd=root) != revision:
        raise RuntimeError("SAM source changed during the build; rerun against a stable checkout")
    manifest = {
        "samBaseRevision": revision,
        "sourceSha256": after,
        "workingTreeDirty": bool(output("git", "status", "--porcelain", cwd=root)),
        "ndkVersion": args.ndk_version,
        "goVersion": output("go", "version"),
        "abi": "arm64-v8a",
        "debugFixtures": args.debug_fixtures,
        "minimumElfPageAlignment": 16384,
        "libraries": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(libraries.glob("*.so"))},
    }
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"SAM native artifacts and provenance: {destination}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError, OSError) as error:
        print(f"SAM Android build failed: {error}", file=sys.stderr)
        sys.exit(1)
