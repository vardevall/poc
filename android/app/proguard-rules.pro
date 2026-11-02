# Names the engine looks up over JNI (`jni/src/native.rs`, `jni/src/bridge.rs`).
-keep class dev.vardevall.Native { native <methods>; }
-keep interface dev.vardevall.EngineCallbacks { *; }
-keep class dev.vardevall.VvException { <init>(java.lang.String); }
