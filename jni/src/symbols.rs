//! Checks that the exported `Java_dev_vardevall_Native_*` functions match the authoritative
//! `Native.kt`: the same names, and for each the same parameters and result.

use std::collections::BTreeMap;

const PREFIX: &str = "Java_dev_vardevall_Native_";
const KOTLIN: &str = "../android/app/src/main/kotlin/dev/vardevall/Native.kt";

/// The JNI type that stands for a Kotlin type.
fn jni_type(kotlin: &str) -> &'static str {
    match kotlin.trim() {
        "String" | "String?" => "JString",
        "Long" => "jlong",
        "Int" => "jint",
        "Boolean" => "jboolean",
        "Array<String>" | "Array<ByteArray>" => "JObjectArray",
        "EngineCallbacks" => "JObject",
        other => panic!("Native.kt uses {other}, which the check does not know"),
    }
}

/// The JNI type of a result; `""` for none.
fn jni_result(kotlin: &str) -> &'static str {
    match kotlin.trim() {
        "" | "Unit" => "",
        "String" => "jstring",
        "Long" => "jlong",
        "Boolean" => "jboolean",
        other => panic!("Native.kt returns {other}, which the check does not know"),
    }
}

type Signature = (Vec<String>, String);

fn kotlin_functions(src: &str) -> BTreeMap<String, Signature> {
    src.lines()
        .filter_map(|line| line.trim().strip_prefix("external fun "))
        .map(|decl| {
            let open = decl.find('(').expect("external fun without parameters");
            let close = decl.rfind(')').expect("external fun without parameters");
            let params = decl[open + 1..close]
                .split(", ")
                .filter(|p| !p.trim().is_empty())
                .map(|p| {
                    let (_, ty) = p.split_once(':').expect("parameter without a type");
                    jni_type(ty).to_owned()
                })
                .collect();
            let result = decl[close + 1..].trim().trim_start_matches(':');
            (
                decl[..open].trim().to_owned(),
                (params, jni_result(result).to_owned()),
            )
        })
        .collect()
}

fn lifetime_free(ty: &str) -> String {
    ty.trim().replace("<'l>", "")
}

fn rust_functions(src: &str) -> BTreeMap<String, Signature> {
    let mut found = BTreeMap::new();
    let mut rest = src;
    while let Some(i) = rest.find(&format!("extern \"system\" fn {PREFIX}")) {
        rest = &rest[i + "extern \"system\" fn ".len() + PREFIX.len()..];
        let name = rest[..rest.find('<').expect("generics")].to_owned();
        let open = rest.find('(').expect("parameters");
        let close = open + rest[open..].find(')').expect("parameters");
        let params: Vec<String> = rest[open + 1..close]
            .split(',')
            .filter(|p| !p.trim().is_empty())
            .map(|p| lifetime_free(p.split_once(':').expect("parameter").1))
            .collect();
        let tail = &rest[close + 1..];
        let result = tail[..tail.find('{').expect("body")]
            .trim()
            .trim_start_matches("->")
            .trim();
        assert_eq!(
            &params[..2],
            ["JNIEnv", "JObject"],
            "{name}: the environment and the object of the call"
        );
        found.insert(name, (params[2..].to_vec(), lifetime_free(result)));
    }
    found
}

#[test]
fn native_kt_matches_the_exported_functions() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let kotlin = kotlin_functions(&std::fs::read_to_string(format!("{dir}/{KOTLIN}")).unwrap());
    let rust = rust_functions(&std::fs::read_to_string(format!("{dir}/src/native.rs")).unwrap());
    assert!(kotlin.len() > 10, "Native.kt not read: {kotlin:?}");
    assert_eq!(
        kotlin.keys().collect::<Vec<_>>(),
        rust.keys().collect::<Vec<_>>(),
        "Native.kt and the exported functions name different functions"
    );
    for (name, signature) in &kotlin {
        assert_eq!(signature, &rust[name], "{name} differs from Native.kt");
    }
}
