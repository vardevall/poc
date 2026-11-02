plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "dev.vardevall"
    compileSdk = 37
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "dev.vardevall"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // No release keystore in the repository: the debug key makes the APK installable.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    jvmToolchain(21)
}

// The engine (`vardevall-jni`) goes into jniLibs with cargo-ndk, for the release profile when a
// release is built.
val cargoNdk = tasks.register<Exec>("cargoNdk") {
    val workspace = rootProject.projectDir.parentFile
    val jniLibs = layout.projectDirectory.dir("src/main/jniLibs").asFile
    val release = gradle.startParameter.taskNames.any { it.contains("Release", ignoreCase = true) }
    workingDir = workspace
    commandLine(
        listOf("cargo", "ndk", "-t", "arm64-v8a", "-t", "x86_64", "-P", "29", "-o", jniLibs.absolutePath, "build", "-p", "vardevall-jni") +
            if (release) listOf("--release") else emptyList()
    )
    val sdk = androidComponents.sdkComponents.sdkDirectory.get().asFile
    val ndk = sdk.resolve("ndk/27.2.12479018")
    if (System.getenv("ANDROID_NDK_HOME") == null && ndk.isDirectory) {
        environment("ANDROID_NDK_HOME", ndk.absolutePath)
    }
    inputs.files(fileTree(workspace) {
        include("jni/src/**", "jni/Cargo.toml", "tun/src/**", "tun/Cargo.toml", "vardevall/src/**", "proto/src/**", "switch-proto/src/**", "tls-pq/src/**", "Cargo.toml", "Cargo.lock")
    })
    outputs.dir(jniLibs)
}
tasks.named("preBuild") { dependsOn(cargoNdk) }

dependencies {
    val compose = platform("androidx.compose:compose-bom:2026.08.00")
    implementation(compose)
    // The expressive APIs are public from 1.5.0; the BOM carries 1.4.0, where they are internal.
    implementation("androidx.compose.material3:material3:1.5.0-beta02")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.navigation:navigation-compose:2.10.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    testImplementation("junit:junit:4.13.2")
}
