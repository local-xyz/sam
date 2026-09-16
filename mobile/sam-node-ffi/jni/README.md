# Android JNI bridge

The Android Agents workspace builds this small shim beside the existing Go
`mobile/sam-node-ffi` C shared library. The release bridge exposes only `GetMeshInfo`, under
`com.example.appfunctions.agent.sam.SamNativeDiagnostics.meshInfoJson()`.
The release bridge does not start or enroll a node. All returned Go C strings are released using
`FreeString`, including when Java string allocation fails.

`build_android.py` takes an expected SAM HEAD, exact NDK version/path and output
directory. It reuses `make mobile-ffi-android`, compiles the shim with the NDK,
checks both ELF libraries for 16 KiB alignment, and emits an artifact provenance
manifest. It supports macOS/Linux build hosts and Android arm64 only. No CMake
installation or new Go dependency is required.

`--debug-fixtures` additionally builds the `sam_debug` Go fixture and `SAM_DEBUG`
JNI methods for `SamLocalTestNative`: start, stop and status. This starts a real
loopback-only node with a persisted peer key and an ephemeral local issuer. It is
not enrollment, device pairing or shared-mesh access. Native lifecycle operations
use the existing process-wide mobile node mutex and refuse to take over another
mode's node. UTF-8 paths and errors cross JNI as byte arrays.

Debug and release must use distinct output directories. Android Gradle generates
`app/build/generated/samNative/<variant>` and enables the fixture only for debug.
The builder replaces ambient `GOFLAGS`, records `debugFixtures` in its manifest,
and verifies that the local startup exports exist only in debug libraries.

Example from the fork root (the Android app normally invokes this itself):

```sh
python3 mobile/sam-node-ffi/jni/build_android.py \
  --revision "$(git rev-parse HEAD)" \
  --ndk "$ANDROID_HOME/ndk/28.2.13676358" \
  --ndk-version 28.2.13676358 \
  --output "$PWD/bin/android-jni"
```

Consumers must package `jniLibs/arm64-v8a/*.so` and `assets/sam-native-build.json`.
The manifest distinguishes the base commit from local edits using a source
fingerprint and dirty flag. Commit/pin both repositories together when promoting
this bridge. The diagnostic JSON is not caller identity or authorization evidence.
